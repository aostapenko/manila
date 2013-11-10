# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 NetApp
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
"""
LXC Driver for shares.

"""

import ConfigParser
import libvirt
import math
import os
import re
import time
import threading

from lxml import etree
from manila import db
from manila import exception
from manila.openstack.common import fileutils
from manila.openstack.common import importutils
from manila.openstack.common import log as logging
from manila.share import driver
from manila import utils

from oslo.config import cfg


LOG = logging.getLogger(__name__)

share_opts = [
    cfg.StrOpt('share_export_root',
               default='$state_path/mnt',
               help='Base folder where exported shares are located'),
    cfg.StrOpt('share_export_ip',
               default=None,
               help='IP to be added to export string'),
    cfg.StrOpt('smb_config_path',
               default='$state_path/smb.conf',
               help="Path to smb config"),
    cfg.IntOpt('share_lvm_mirrors',
               default=0,
               help='If set, create lvms with multiple mirrors. Note that '
                    'this requires lvm_mirrors + 2 pvs with available space'),
    cfg.StrOpt('share_volume_group',
               default='stack-shares',
               help='Name for the VG that will contain exported shares'),
    cfg.ListOpt('share_lvm_helpers',
                default=[
                    'CIFS=manila.share.drivers.lxc.CIFSHelper',
                    'NFS=manila.share.drivers.lxc.UNFSHelper',
                ],
                help='Specify list of share export helpers.'),
    cfg.StrOpt('lxc_xml_template',
               default='/etc/manila/lxc_template.xml',
               help='Template XML file for LXC creation'),
    cfg.StrOpt('template_rootfs_path',
               default='$share_export_root/template/rootfs',
               help='Template rootfs'),
    cfg.StrOpt('path_to_key',
               default='~/.ssh/id_rsa.pub',
               help='SSH publick key of user, that runs manila-shr'),
]

CONF = cfg.CONF
CONF.register_opts(share_opts)

uri = 'lxc:///'
share_path_in_lxc = 'shares'


def synchronized(f):
    """Decorates function _get_domain with unique locks for each tenant
    """
    def wrapped_func(self, tenant_id, *args, **kwargs):
        with self.tenants_locks.setdefault(tenant_id, threading.RLock()):
            return f(self, tenant_id, *args, **kwargs)
    return wrapped_func


class LXCShareDriver(driver.ExecuteMixin, driver.ShareDriver):
    """Executes commands relating to Shares."""

    def __init__(self, db, *args, **kwargs):
        """Do initialization."""
        super(LXCShareDriver, self).__init__(*args, **kwargs)
        self.tenants_domains = {}
        self.tenants_locks = {}
        self.db = db
        self._helpers = None
        self.configuration.append_config_values(share_opts)

    def check_for_setup_error(self):
        """Returns an error if prerequisites aren't met."""
        out, err = self._execute('vgs', '--noheadings', '-o', 'name',
                                 run_as_root=True)
        volume_groups = out.split()
        if self.configuration.share_volume_group not in volume_groups:
            msg = (_("share volume group %s doesn't exist")
                   % self.configuration.share_volume_group)
            raise exception.InvalidParameterValue(err=msg)
        if not self.configuration.share_export_ip:
            msg = (_("share_export_ip doesn't specified"))
            raise exception.InvalidParameterValue(err=msg)
        if not os.path.exists(self.configuration.path_to_key):
            msg = (_("Hosts paublic key does not exist"))
            raise exception.InvalidParameterValue(err=msg)

    def do_setup(self, context):
        """Any initialization the volume driver does while starting."""
        super(LXCShareDriver, self).do_setup(context)
        try:
            self._conn = libvirt.open(uri)
        except Exception:
            LOG.error(_("An error occurred while trying to open connection: "
                        "%s") % uri)
            raise
        self.configuration.path_to_key = \
                    os.path.expanduser(self.configuration.path_to_key)
        self._init_helpers()

    def _init_helpers(self):
        """Initializes protocol-specific NAS drivers."""
        self._helpers = {}
        for helper_str in self.configuration.share_lvm_helpers:
            share_proto, _, import_str = helper_str.partition('=')
            helper = importutils.import_class(import_str)
            #TODO(rushiagr): better way to handle configuration
            #                   instead of just passing to the helper
            self._helpers[share_proto.upper()] = helper(self._execute,
                                                        self.configuration)

    def _local_path(self, share):
        # NOTE(vish): stops deprecation warning
        escaped_group = \
            self.configuration.share_volume_group.replace('-', '--')
        escaped_name = share['name'].replace('-', '--')
        return "/dev/mapper/%s-%s" % (escaped_group, escaped_name)

    def _allocate_container(self, share_name, sizestr):
        cmd = ['lvcreate', '-L', sizestr, '-n', share_name,
               self.configuration.share_volume_group]
        if self.configuration.share_lvm_mirrors:
            cmd += ['-m', self.configuration.share_lvm_mirrors, '--nosync']
            terras = int(sizestr[:-1]) / 1024.0
            if terras >= 1.5:
                rsize = int(2 ** math.ceil(math.log(terras) / math.log(2)))
                # NOTE(vish): Next power of two for region size. See:
                #             http://red.ht/U2BPOD
                cmd += ['-R', str(rsize)]

        self._try_execute(*cmd, run_as_root=True)

    def _deallocate_container(self, share_name):
        """Deletes a logical volume for share."""
        # zero out old volumes to prevent data leaking between users
        # TODO(ja): reclaiming space should be done lazy and low priority
        try:
            self._try_execute('lvremove', '-f', "%s/%s" %
                             (self.configuration.share_volume_group,
                              share_name),
                              run_as_root=True)
        except exception.ProcessExecutionError as exc:
            if "not found" not in exc.stderr:
                LOG.error(_("Error deleting volume: %s") % exc.stderr)
                raise
            LOG.error(_("Volume not found: %s") % exc.stderr)

    def get_share_stats(self, refresh=False):
        """Get share status.

        If 'refresh' is True, run update the stats first."""
        if refresh:
            self._update_share_status()

        return self._stats

    def _update_share_status(self):
        """Retrieve status info from share volume group."""

        LOG.debug(_("Updating share status"))
        data = {}

        # Note(zhiteng): These information are driver/backend specific,
        # each driver may define these values in its own config options
        # or fetch from driver specific configuration file.
        data["share_backend_name"] = 'LVM'
        data["vendor_name"] = 'Open Source'
        data["driver_version"] = '1.0'
        #TODO(rushiagr): Pick storage_protocol from the helper used.
        data["storage_protocol"] = 'NFS_CIFS'

        data['total_capacity_gb'] = 0
        data['free_capacity_gb'] = 0
        data['reserved_percentage'] = \
            self.configuration.reserved_share_percentage
        data['QoS_support'] = False

        try:
            out, err = self._execute('vgs', '--noheadings', '--nosuffix',
                                     '--unit=G', '-o', 'name,size,free',
                                     self.configuration.share_volume_group,
                                     run_as_root=True)
        except exception.ProcessExecutionError as exc:
            LOG.error(_("Error retrieving volume status: %s") % exc.stderr)
            out = False

        if out:
            share = out.split()
            data['total_capacity_gb'] = float(share[1])
            data['free_capacity_gb'] = float(share[2])

        self._stats = data

    def deallocate_container(self, ctx, share):
        """Remove LVM volume that will be represented as share."""
        self._deallocate_container(share['name'])

    def allocate_container(self, ctx, share):
        """Create LVM volume that will be represented as share."""
        self._allocate_container(share['name'], '%sG' % share['size'])
        #create file system
        device_name = self._local_path(share)
        self._execute('mkfs.ext4', device_name, run_as_root=True)

    def allocate_container_from_snapshot(self, context, share, snapshot):
        """Is called to create share from snapshot."""
        self._allocate_container(share['name'], '%sG' % share['size'])
        self._copy_volume(self._local_path(snapshot), self._local_path(share),
                          snapshot['share_size'])

    def create_export(self, ctx, share):
        """Exports the volume. Can optionally return a Dictionary of changes
        to the share object to be persisted."""
        device_name = self._local_path(share)
        location = self._mount_device(share, device_name)
        #TODO(rushiagr): what is the provider_location? realy needed?
        return {'provider_location': location}

    def remove_export(self, ctx, share):
        """Removes an access rules for a share."""
        mount_path = self._get_mount_path(share)
        if os.path.exists(mount_path):
            #umount, may be busy
            try:
                self._execute('umount', '-f', mount_path, run_as_root=True)
            except exception.ProcessExecutionError, exc:
                if 'device is busy' in str(exc):
                    raise exception.ShareIsBusy(share_name=share['name'])
                else:
                    LOG.info('Unable to umount: %s', exc)
            #we need this to release mount from lxc
            self._get_domain(share['project_id'], create=False, restart=True)
            #remove dir
            try:
                os.rmdir(mount_path)
            except OSError:
                LOG.info('Unable to delete %s', mount_path)

    def _get_domain_ip(self, domain, retry=0):
        """Recieves domain ip"""
        desc = etree.fromstring(domain.XMLDesc(0))
        macAddr = desc.find("devices/interface[@type='network']/mac").\
                attrib["address"].lower().strip()

        output = self._execute('arp', '-n')[0]
        lines = [line.split() for line in output.split("\n")[1:]]
        IPaddr = [line[0] for line in lines if (line and
                                                (line[2] == macAddr))]
        max_retries = 3
        if not IPaddr:
            if retry < max_retries:
                LOG.debug("Can't retrieve IP, rebooting domain")
                self._restart_domain(domain)
                IPaddr = self._get_domain_ip(domain, retry+1)
            else:
                raise exception.ManilaException("Can't get container IP")
        return IPaddr

    def _restart_domain(self, domain):
        LOG.debug('Rebooting domain %s' % domain.name())
        if domain.info()[0] == libvirt.VIR_DOMAIN_RUNNING:
            domain.destroy()
        domain.create()
        #waiting while domain starts and retrieve IP
        time.sleep(10)

    def create_share(self, ctx, share):
        """Is called after allocate_space to create share on the volume."""
        domain = self._get_domain(share['project_id'])
        location = self._get_helper(share).create_export(share['name'],
                                                         domain.ip)
        return location

    def create_snapshot(self, context, snapshot):
        """Creates a snapshot."""
        orig_lv_name = "%s/%s" % (self.configuration.share_volume_group,
                                  snapshot['share_name'])
        self._try_execute('lvcreate', '-L', '%sG' % snapshot['share_size'],
                          '--name', snapshot['name'],
                          '--snapshot', orig_lv_name, run_as_root=True)

    def ensure_share(self, ctx, share):
        """Ensure that storage are mounted and exported."""
        device_name = self._local_path(share)
        self._mount_device(share, device_name)
        domain = self._get_domain(share['project_id'])
        self._get_helper(share).create_export(share['name'], domain.ip,
                                              recreate=True)

    def delete_share(self, ctx, share):
        """Delete a share."""
        try:
            domain = self._get_domain(share['project_id'], create=False)
            if not domain:
                return None
            self._get_helper(share).remove_export(share['name'], domain.ip)
        except exception.ProcessExecutionError:
            LOG.info("Can't remove share %r" % share['id'])
        except exception.InvalidShare, exc:
            LOG.info(exc.message)

    def delete_snapshot(self, context, snapshot):
        """Deletes a snapshot."""
        self._deallocate_container(snapshot['name'])

    def allow_access(self, ctx, share, access):
        """Allow access to the share."""
        domain = self._get_domain(share['project_id'])
        self._get_helper(share).allow_access(domain.ip,
                                             share['name'],
                                             access['access_type'],
                                             access['access_to'])

    def deny_access(self, ctx, share, access):
        """Allow access to the share."""
        domain = self._get_domain(share['project_id'], create=False)
        if not domain:
            return None
        self._get_helper(share).deny_access(domain.ip,
                                            share['name'],
                                            access['access_type'],
                                            access['access_to'])

    def _get_helper(self, share):
        if share['share_proto'].startswith('NFS'):
            return self._helpers['NFS']
        elif share['share_proto'].startswith('CIFS'):
            return self._helpers['CIFS']
        else:
            raise exception.InvalidShare(reason='Wrong share type')

    def _mount_device(self, share, device_name):
        """Mount LVM share and ignore if already mounted."""
        mount_path = self._get_mount_path(share)
        self._execute('mkdir', '-p', mount_path)
        try:
            self._execute('mount', device_name, mount_path,
                          run_as_root=True, check_exit_code=True)
            self._execute('chmod', '777', mount_path,
                          run_as_root=True, check_exit_code=True)
        except exception.ProcessExecutionError as exc:
            if 'already mounted' in exc.stderr:
                LOG.warn(_("%s is already mounted"), device_name)
            else:
                raise
        self._get_domain(share['project_id'], restart=True)
        return mount_path

    def _get_mount_path(self, share):
        """Returns path where share is mounted."""
        return os.path.join(self._get_lxc_path(share['project_id']),
                            share_path_in_lxc, share['name'])

    def _get_lxc_path(self, tenant_id):
        """Returns path where container fs will be created."""
        return os.path.join(self.configuration.share_export_root,
                            tenant_id, 'rootfs')

    def _copy_volume(self, srcstr, deststr, size_in_g):
        # Use O_DIRECT to avoid thrashing the system buffer cache
        extra_flags = ['iflag=direct', 'oflag=direct']

        # Check whether O_DIRECT is supported
        try:
            self._execute('dd', 'count=0', 'if=%s' % srcstr, 'of=%s' % deststr,
                          *extra_flags, run_as_root=True)
        except exception.ProcessExecutionError:
            extra_flags = []

        # Perform the copy
        self._execute('dd', 'if=%s' % srcstr, 'of=%s' % deststr,
                      'count=%d' % (size_in_g * 1024), 'bs=1M',
                      *extra_flags, run_as_root=True)

    def _get_xml(self, tenant_id):
        try:
            templ = open(CONF.lxc_xml_template).read()
        except Exception:
            LOG.error(_("An error occurred while trying to open xml: "
                        "%s") % CONF.lxc_xml_template)
            raise
        container_rootfs = os.path.join(self.configuration.share_export_root,
                                        tenant_id, 'rootfs')
        return templ.replace('<name>lxc_template</name>',
                             '<name>%s</name>' % tenant_id).\
                     replace("<source dir='/change_path'/>",
                             "<source dir='%s'/>" % container_rootfs)

    def _get_domain_by_name(self, instance_name):
        """Retrieve libvirt domain object given an instance name."""
        try:
            return self._conn.lookupByName(instance_name)
        except libvirt.libvirtError:
            return None

    @synchronized
    def _get_domain(self, tenant_id, create=True, restart=False):
        domain = self.tenants_domains.get(tenant_id)
        if domain is None:
            self.tenants_domains[tenant_id] = \
                    self._setup_domain(tenant_id, create)
            domain = self.tenants_domains[tenant_id]
            if domain:
                # init helpers on lxc initialization
                for helper in self._helpers.values():
                    helper.init_helper(domain.ip, domain.rootfs_path)
        if domain:
            dom_state = domain.info()[0]
            if restart or dom_state != libvirt.VIR_DOMAIN_RUNNING:
                self._restart_domain(domain)
                # init helpers after lxc restart
                for helper in self._helpers.values():
                    helper.setup_helper(domain.ip)
        return domain

    def _setup_domain(self, tenant_id, create):
        domain = self._get_domain_by_name(tenant_id)
        if not domain:
            if not create:
                return None
            self._create_rootfs_for_domain(tenant_id)
            domain = self._create_domain(self._get_xml(tenant_id))
        domain.ip = self._get_domain_ip(domain)[0]
        domain.rootfs_path = self._get_lxc_path(tenant_id)
        LOG.debug("Domain %s  IP is %s" % (tenant_id, domain.ip))
        return domain

    def _create_domain(self, xml):
        """Creates a persistent domain."""
        try:
            domain = self._conn.defineXML(xml)
            domain.create()
            #waiting while domain starts and retrieves IP
            time.sleep(60)

        except Exception as e:
            LOG.error(_("An error occurred while trying to define a domain"
                        " with xml: %s") % xml)
            raise e

        return domain

    def _create_rootfs_for_domain(self, tenant_id):
        """Create a rootfs for domain from template."""
        lxc_path = self._get_lxc_path(tenant_id)
        self._try_execute('mkdir', '-p', lxc_path)
        self._try_execute('cp', '-rp', CONF.template_rootfs_path,
                          os.path.join(lxc_path, '..'),
                          run_as_root=True)
        self._try_execute('chmod', '777', lxc_path, run_as_root=True)
        pub_key = self._execute('cat', self.configuration.path_to_key)[0]
        self._try_execute('echo', pub_key, '>', os.path.join(lxc_path,
                          'root/.ssh/autorized_keys'))
        self._try_execute('chown', 'root:root', '-R',
                          os.path.join(lxc_path, 'root'),
                          run_as_root=True)


class NASHelperBase(object):
    """Interface to work with share."""

    def __init__(self, execute, config_object):
        self.configuration = config_object
        self._execute = execute

    def init_helper(self, domain_ip, lxc_path):
        pass

    def setup_helper(self, domain_ip):
        pass

    def create_export(self, share_name, domain_ip, recreate=False):
        """Create new export, delete old one if exists."""
        raise NotImplementedError()

    def remove_export(self, share_name, domain_ip):
        """Remove export."""
        raise NotImplementedError()

    def allow_access(self, domain_ip, share_name, access_type, access):
        """Allow access to the host."""
        raise NotImplementedError()

    def deny_access(self, domain_ip, share_name, access_type, access,
                    force=False):
        """Deny access to the host."""
        raise NotImplementedError()


class UNFSHelper(NASHelperBase):
    """Interface to work with share."""

    def __init__(self, execute, config_object):
        super(UNFSHelper, self).__init__(execute, config_object)
    
    def init_helper(self, domain_ip, lxc_path):
        """Setups helper on lxc first start"""
        try:
            self._execute('rm', os.path.join(lxc_path, 'etc/exports'),
                          run_as_root=True)
        except Exception as e:
            if 'No such file or directory' not in e.stderr:
                raise
        self.setup_helper(domain_ip)

    def setup_helper(self, domain_ip):
        """Setups helper on each lxc restart."""
        try:
            self._execute('ssh', 'root@%s' % domain_ip,
                          '-o StrictHostKeyChecking=no', 'unfsd')
        except Exception as e:
            if 'command not found' in e.stderr:
                raise exception.Exception('UNFS server not found')

    def create_export(self, share_name, domain_ip, recreate=False):
        """Create new export, delete old one if exists."""
        return ':'.join([domain_ip,
                    os.path.join('/', share_path_in_lxc,
                                 share_name)])

    def remove_export(self, share_name, domain_ip):
        """Remove export."""
        pass

    def allow_access(self, domain_ip, share_name, access_type, access):
        """Allow access to the host"""
        if access_type != 'ip':
            reason = 'only ip access type allowed'
            raise exception.InvalidShareAccess(reason)
        local_share_path = os.path.join('/',
                                        share_path_in_lxc,
                                        share_name)
        #check if presents in export
        out, _ = self._execute('ssh', 'root@%s' % domain_ip, 'showmount -e')
        out = re.search(re.escape(local_share_path) + '[\s\n]*' +
                        re.escape(access), out)
        if out is not None:
            raise exception.ShareAccessExists(access_type=access_type,
                                              access=access)

        self._execute('ssh', 'root@%s' % domain_ip,
                      'echo "%s    %s(rw,no_subtree_checi,all_squash'
                      'anonuid=0,anongid=0)" >> %s' %
                      (local_share_path, access, '/etc/exports'))
        self._restart_unfs(domain_ip)

    def deny_access(self, domain_ip, share_name, access_type, access,
                    force=False):
        """Deny access to the host."""
        local_share_path = os.path.join('/',
                                        share_path_in_lxc,
                                        share_name)
        out, _ = self._execute('ssh', 'root@%s' % domain_ip,
                               'cat /etc/exports')
        out = out.splitlines()
        LOG.error(out)
        for export in out:
            result = re.search(re.escape(local_share_path) + '[\s\n]*' +
                               re.escape(access), export)
            if result:
                out.remove(export)

        self._execute('ssh', 'root@%s' % domain_ip,
                      'echo "%s" > %s' %
                      ('\n'.join(out), '/etc/exports'))
        self._restart_unfs(domain_ip)

    def _restart_unfs(self, domain_ip):
        """Restarts unfsd.
        unfsd can't be restarted more civilized way"""
        self._execute('ssh', 'root@%s' % domain_ip,
                      '-o StrictHostKeyChecking=no', 'killall -9 unfsd')
        self._execute('ssh', 'root@%s' % domain_ip,
                      '-o StrictHostKeyChecking=no', 'unfsd')


class CIFSHelper(NASHelperBase):
    """Class provides functionality to operate with cifs shares"""

    def __init__(self, execute, config_object):
        """Store executor and configuration path."""
        super(CIFSHelper, self).__init__(execute, config_object)
        self.test_config = "%s_" % (self.configuration.smb_config_path)

    def init_helper(self, domain_ip, lxc_path):
        """Setups helper on lxc first start"""
        self.config = os.path.join(lxc_path, 'smb.conf')
        self.local_config_path = '/smb.conf'
        self._execute('cp', '-p', self.configuration.smb_config_path,
                      self.config, run_as_root=True)
        self._execute('chmod', '777', self.config, run_as_root=True)
        self._recreate_config(domain_ip)
        self.setup_helper(domain_ip)

    def setup_helper(self, domain_ip):
        """Setups helper on each lxc restart."""
        self._stop_service(domain_ip)
        self._start_daemon(domain_ip)
        self._ensure_daemon_started(domain_ip)

    def create_export(self, share_name, domain_ip, recreate=False):
        """Create new export, delete old one if exists."""
        local_share_path = os.path.join('/',
                                        share_path_in_lxc,
                                        share_name)
        parser = ConfigParser.ConfigParser()
        parser.read(self.config)
        #delete old one
        if parser.has_section(share_name):
            if recreate:
                parser.remove_section(share_name)
            else:
                raise exception.Error('Section exists')
        #Create new one
        parser.add_section(share_name)
        parser.set(share_name, 'path', local_share_path)
        parser.set(share_name, 'browseable', 'yes')
        parser.set(share_name, 'guest ok', 'yes')
        parser.set(share_name, 'read only', 'no')
        parser.set(share_name, 'writable', 'yes')
        parser.set(share_name, 'create mask', '0755')
        parser.set(share_name, 'hosts deny', '0.0.0.0/0')  # denying all ips
        parser.set(share_name, 'hosts allow', '127.0.0.1')
        self._update_config(parser, domain_ip)
        return '//%s/%s' % (domain_ip, share_name)

    def remove_export(self, share_name, domain_ip):
        """Remove export."""
        parser = ConfigParser.ConfigParser()
        parser.read(self.config)
        #delete old one
        if parser.has_section(share_name):
            parser.remove_section(share_name)
        self._update_config(parser, domain_ip)
        self._execute('ssh', 'root@%s' % domain_ip,
                      'smbcontrol', 'all', 'close-share', share_name)

    def allow_access(self, domain_ip, share_name, access_type, access):
        """Allow access to the host."""
        if access_type != 'ip':
            reason = 'only ip access type allowed'
            raise exception.InvalidShareAccess(reason)
        local_share_path = os.path.join('/',
                                        share_path_in_lxc,
                                        share_name)
        parser = ConfigParser.ConfigParser()
        parser.read(self.config)

        hosts = parser.get(share_name, 'hosts allow')
        if access in hosts.split():
            raise exception.ShareAccessExists(access_type=access_type,
                                              access=access)
        self._execute('ssh', 'root@%s' % domain_ip,
                      'chown nobody -R %s' % local_share_path)
        hosts += ' %s' % (access,)
        parser.set(share_name, 'hosts allow', hosts)
        self._update_config(parser, domain_ip)

    def deny_access(self, domain_ip, share_name, access_type, access,
                    force=False):
        """Deny access to the host."""
        parser = ConfigParser.ConfigParser()
        try:
            parser.read(self.config)
            hosts = parser.get(share_name, 'hosts allow')
            hosts = hosts.replace(' %s' % (access,), '', 1)
            parser.set(share_name, 'hosts allow', hosts)
            self._update_config(parser, domain_ip)
        except ConfigParser.NoSectionError:
            if not force:
                raise

    def _stop_service(self, domain_ip):
        try:
            self._execute('ssh', 'root@%s' % domain_ip,
                          '-o StrictHostKeyChecking=no',
                          'service smbd stop')
        except Exception as e:
            if 'Unknown instance' not in e.stderr:
                raise

    def _start_daemon(self, domain_ip):
        self._execute('ssh', 'root@%s' % domain_ip,
                '-o StrictHostKeyChecking=no',
                'smbd -s %s -D' % self.local_config_path)

    def _ensure_daemon_started(self, domain_ip):
        """
        FYI: smbd starts at least two processes.
        """
        out, _ = self._execute('ssh', 'root@%s' % domain_ip,
                               'ps -C smbd -o args=',
                               check_exit_code=False)
        processes = [process.strip() for process in out.split('\n')
                     if process.strip()]

        cmd = 'smbd -s %s -D' % (self.local_config_path,)

        running = False
        for process in processes:
            if not process.endswith(cmd):
                #alternatively exit
                raise exception.Error('smbd already started with wrong config')
            running = True

        if not running:
            self._execute(*cmd.split(), run_as_root=True)

    def _recreate_config(self, domain_ip):
        """create new SAMBA configuration file."""
        if os.path.exists(self.config):
            os.unlink(self.config)
        parser = ConfigParser.ConfigParser()
        parser.add_section('global')
        parser.set('global', 'security', 'user')
        parser.set('global', 'server string', '%h server (Samba, Openstack)')

        self._update_config(parser, domain_ip, restart=False)

    def _update_config(self, parser, domain_ip, restart=True):
        """Check if new configuration is correct and save it."""
        #Check that configuration is correct
        with open(self.test_config, 'w') as fp:
            parser.write(fp)
        self._execute('testparm', '-s', self.test_config,
                      check_exit_code=True)
        #save it
        with open(self.config, 'w') as fp:
            parser.write(fp)
        #restart daemon if necessary
        if restart:
            try:
                self._execute('ssh', 'root@%s' % domain_ip,
                              '-o StrictHostKeyChecking=no',
                              'killall -9 smbd')
            except Exception as e:
                if 'unknown service' not in e.stderr:
                    raise
            self._start_daemon(domain_ip)
