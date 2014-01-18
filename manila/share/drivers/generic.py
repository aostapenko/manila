# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 Mirantis Inc.
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
Generic Driver for shares.

"""

import ConfigParser
import math
import os
import re
import shutil
import time
import threading

from manila import compute
from manila import exception
from manila.image import glance
from manila import network
from manila.openstack.common import importutils
from manila.openstack.common import log as logging
from manila.share import driver
from manila import volume
from manila import utils

from oslo.config import cfg


LOG = logging.getLogger(__name__)

share_opts = [
    cfg.StrOpt('service_image_name',
               default='manila-service-image',
               help="Name of image in glance, that will be used to create "
               "service instance"),
    cfg.StrOpt('smb_template_config_path',
               default='$state_path/smb.conf',
               help="Path to smb config"),
    cfg.StrOpt('service_instance_name',
               default='manila_service_instance',
               help="Name of service instance"),
    cfg.StrOpt('service_instance_user',
               default='ubuntu',
               help="User in service instance"),
    cfg.StrOpt('volume_name_template',
               default='manila-share-',
               help="Volume name template"),
    cfg.StrOpt('volume_snapshot_name_template',
               default='manila-snapshot-',
               help="Volume name template"),
    cfg.IntOpt('max_time_to_build_instance',
               default=600,
               help="Maximum time to wait for creating service instance"),
    cfg.StrOpt('share_mount_path',
               default='/shares',
               help="Maximum time to wait for creating service instance"),
    cfg.IntOpt('max_time_to_create_volume',
               default=120,
               help="Maximum time to wait for creating cinder volume"),
    cfg.IntOpt('max_time_to_attach',
               default=120,
               help="Maximum time to wait for attaching cinder volume"),
    cfg.IntOpt('service_instance_flavor_id',
               default=100,
               help="ID of flavor, that will be used for service instance "
               "creation"),
    cfg.StrOpt('smb_config_path',
               default='$share_mount_path/smb.conf',
               help="Path to smb config"),
    cfg.ListOpt('share_lvm_helpers',
                default=[
                    'CIFS=manila.share.drivers.generic.CIFSHelper',
                    'NFS=manila.share.drivers.generic.NFSHelper',
                ],
                help='Specify list of share export helpers.'),
]

CONF = cfg.CONF
CONF.register_opts(share_opts)
network_api = network.API()

def synchronized(f):
    """Decorates function with unique locks for each tenant
    """
    def wrapped_func(self, arg, instance, *args, **kwargs):
        tenant_id = instance.get('project_id', None)
        if tenant_id is None:
            tenant_id = instance['tenant_id']
        with self.tenants_locks.setdefault(tenant_id, threading.RLock()):
            return f(self, arg, instance, *args, **kwargs)
    return wrapped_func


def _ssh_exec(server, command, execute):
    ip = _get_server_ip(server)
    net_id = [port['network_id'] for port in
              network_api.list_ports(device_id=server['id'])][0]
    netns = 'qdhcp-' + net_id
    user = CONF.service_instance_user
    cmd = ['ip', 'netns', 'exec', netns, 'ssh', user + '@' + ip,
           '-o StrictHostKeyChecking=no']
    cmd.extend(command)
    return execute(*cmd, run_as_root=True)


def _get_server_ip(server):
    return server['networks'].values()[0][0]


class GenericShareDriver(driver.ExecuteMixin, driver.ShareDriver):
    """Executes commands relating to Shares."""

    def __init__(self, db, *args, **kwargs):
        """Do initialization."""
        super(GenericShareDriver, self).__init__(*args, **kwargs)
        self.db = db
        self.tenants_locks = {}
        self.configuration.append_config_values(share_opts)
        self._helpers = None

    def check_for_setup_error(self):
        """Returns an error if prerequisites aren't met."""
        pass

    def do_setup(self, context):
        """Any initialization the volume driver does while starting."""
        super(GenericShareDriver, self).do_setup(context)
        self.compute_api = compute.API()
        self.volume_api = volume.API()
        self.image_api = glance.get_default_image_service()
        self._setup_helpers()

    def _setup_helpers(self):
        """Initializes protocol-specific NAS drivers."""
        self._helpers = {}
        for helper_str in self.configuration.share_lvm_helpers:
            share_proto, _, import_str = helper_str.partition('=')
            helper = importutils.import_class(import_str)
            self._helpers[share_proto.upper()] = helper(self._execute,
                                                        self.configuration,
                                                        self.tenants_locks)

    def create_share(self, context, share):
        server = self._get_service_instance(context, share)
        volume = self._allocate_container(context, share)
        volume = self._attach_volume(context, share, server, volume)
        self._format_device(server, volume)
        self._mount_device(context, share, server, volume)
        location = self._get_helper(share).create_export(server,
                                                         share['name'])
        return location

    def _format_device(self, server, volume):
        command = ['sudo', 'mkfs.ext4', volume['mountpoint']]
        _ssh_exec(server, command, self._execute)

    def _mount_device(self, context, share, server, volume):
        mount_path = self._get_mount_path(share)
        command = ['sudo', 'mkdir', '-p', mount_path, ';']
        command.extend(['sudo', 'mount', volume['mountpoint'], mount_path])
        _ssh_exec(server, command, self._execute)

    def _unmount_device(self, context, share, server):
        mount_path = self._get_mount_path(share)
        command = ['sudo', 'umount', mount_path, ';']
        command.extend(['sudo', 'rmdir', mount_path])
        try:
            _ssh_exec(server, command, self._execute)
        except Exception as e:
            LOG.debug(e)

    def _get_mount_path(self, share):
        return os.path.join(self.configuration.share_mount_path, share['name'])

    @synchronized
    def _attach_volume(self, context, share, server, volume):
        device_path = self._get_device_path(context, server)
        try:
            self.compute_api.instance_volume_attach(context, server['id'],
                                                    volume['id'], device_path)
        except Exception as e:
            if 'already attached' not in e.message:
                raise

        t = time.time()
        while time.time() - t < self.configuration.max_time_to_attach:
            volume = self.volume_api.get(context, volume['id'])
            if volume['status'] == 'in-use':
                break
            if volume['status'] == 'error':
                raise exception.ManilaException('Volume error')
            time.sleep(1)
        else:
            raise exception.ManilaException('Volume attach timeout')

        return volume

    def _get_volume(self, context, share_id):
        volume_name = self.configuration.volume_name_template + share_id
        volumes_list = self.volume_api.get_all(context,
                                         {'display_name': volume_name})
        volume = None
        if len(volumes_list):
            volume = volumes_list[0]
        return volume

    def _get_volume_snapshot(self, context, snapshot_id):
        volume_snapshot_name = self.configuration.\
                volume_snapshot_name_template + snapshot_id
        volume_snapshot_list = self.volume_api.get_all_snapshots(context,
                                        {'display_name': volume_snapshot_name})
        volume_snapshot = None
        if len(volume_snapshot_list):
            volume_snapshot = volume_snapshot_list[0]
        return volume_snapshot

    @synchronized
    def _detach_volume(self, context, share, server):
        attached_volumes = [vol.id for vol in
                self.compute_api.instance_volumes_list(context,
                                                       server['id'])]
        volume = self._get_volume(context, share['id'])
        if volume and volume['id'] in attached_volumes:
            self.compute_api.instance_volume_detach(context,
                                                    server['id'],
                                                    volume['id'])
            t = time.time()
            while time.time() - t < self.configuration.max_time_to_attach:
                volume = self.volume_api.get(context, volume['id'])
                if volume['status'] in ('available', 'error'):
                    break
                time.sleep(1)
            else:
                raise exception.ManilaException('Volume detach timeout')

    def _get_device_path(self, context, server):
        volumes = self.compute_api.instance_volumes_list(context, server['id'])
        if not volumes:
            return '/dev/vdb'
        last_used_name = sorted([volume.device for volume in volumes
                if '/dev/vd' in volume.device])[-1]
        device_name = last_used_name[:-1] + chr(ord(last_used_name[-1]) + 1)
        return device_name

    @synchronized
    def _get_service_instance(self, context, share, create=True):
        servers = self.compute_api.server_list(context,
                    {'name': self.configuration.service_instance_name})
        if not servers:
            if create:
                server = self._create_service_instance(context)
                self._get_helper(share).init_helper(server)
                return server
            else:
                return None
        elif len(servers) > 1:
            raise exception.ManilaException('Ambigious service instances')
        else:
            return servers[0]

    def _create_service_instance(self, context):
        images = [image['id'] for image in self.image_api.detail(context)
                if image['name'] == self.configuration.service_image_name]
        if not images:
            raise exception.ManilaException('No appropriate image was found')
        elif len(images) > 1:
            raise exception.ManilaException('Ambigious image name')

        service_instance = self.compute_api.server_create(context,
                                self.configuration.service_instance_name,
                                images[0],
                                self.configuration.service_instance_flavor_id,
                                None, None, None)

        t = time.time()
        while time.time() - t < self.configuration.max_time_to_build_instance:
            if service_instance['status'] == 'ACTIVE':
                break
            if service_instance['status'] == 'ERROR':
                raise exception.\
                        ManilaException('Service instance creating error')
            time.sleep(1)
            try:
                service_instance = self.compute_api.server_get(context,
                                    service_instance['id'])
            except Exception as e:
                LOG.debug(e.message)
        else:
            raise exception.ManilaException('Server waiting timeout')

        t = time.time()
        while time.time() - t < self.configuration.max_time_to_build_instance:
            LOG.debug('Checking server availability')
            try:
                _ssh_exec(service_instance, ['echo', 'Hello'], self._execute)
                return service_instance
            except Exception as e:
                LOG.debug(e)
                LOG.debug('Server is not available through ssh. Waiting...')
                time.sleep(5)
        else:
            raise exception.ManilaException('Server waiting timeout')

    def _allocate_container(self, context, share, snapshot=None):
        volume_snapshot = None
        if snapshot:
            volume_snapshot = self._get_volume_snapshot(context,
                                                        snapshot['id'])
        volume = self.volume_api.create(context, share['size'],
                     self.configuration.volume_name_template + share['id'], '',
                     snapshot=volume_snapshot)

        t = time.time()
        while time.time() - t < self.configuration.max_time_to_create_volume:
            if volume['status'] == 'available':
                break
            if volume['status'] == 'error':
                raise exception.ManilaException('Volume creating error')
            time.sleep(1)
            volume = self.volume_api.get(context, volume['id'])
        else:
            raise exception.ManilaException('Volume creating timeout')

        return volume

    def _deallocate_container(self, context, share):
        """Deletes cinder volume for share."""
        volume_name = self.configuration.volume_name_template + share['id']
        volumes_list = self.volume_api.get_all(context,
                                         {'display_name': volume_name})
        volume = None
        if len(volumes_list):
            volume = volumes_list[0]
        if volume:
            self.volume_api.delete(context, volume['id'])
            t = time.time()
            while time.time() - t < self.configuration.\
                                                    max_time_to_create_volume:
                try:
                    volume = self.volume_api.get(context, volume['id'])
                except Exception as e:
                    if 'could not be found' not in e.message:
                        raise
                    break
                time.sleep(1)
            else:
                raise exception.ManilaException('Volume deletion error')

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
        data["storage_protocol"] = 'NFS_CIFS'

        data['total_capacity_gb'] = 1
        data['free_capacity_gb'] = 1
        data['reserved_percentage'] = \
            self.configuration.reserved_share_percentage
        data['QoS_support'] = False

#        try:
#            out, err = self._execute('vgs', '--noheadings', '--nosuffix',
#                                     '--unit=G', '-o', 'name,size,free',
#                                     self.configuration.share_volume_group,
#                                     run_as_root=True)
#        except exception.ProcessExecutionError as exc:
#            LOG.error(_("Error retrieving volume status: %s") % exc.stderr)
#            out = False
#
#        if out:
#            share = out.split()
#            data['total_capacity_gb'] = float(share[1])
#            data['free_capacity_gb'] = float(share[2])
#
        self._stats = data

    def create_share_from_snapshot(self, context, share, snapshot):
        """Is called to create share from snapshot."""
        server = self._get_service_instance(context, share)
        volume = self._allocate_container(context, share, snapshot)
        self._attach_volume(context, share, server, volume)
        return server['networks'].values()[0][0]

    def delete_share(self, context, share):
        server = self._get_service_instance(context, share, create=False)
        if server:
            self._get_helper(share).remove_export(server, share['name'])
            self._unmount_device(context, share, server)
            self._detach_volume(context, share, server)
        self._deallocate_container(context, share)

    def create_snapshot(self, context, snapshot):
        """Creates a snapshot."""
        volume = self._get_volume(context, snapshot['share_id'])
        volume_snapshot_name = self.configuration.\
                volume_snapshot_name_template + snapshot['id']
        volume_snapshot = self.volume_api.create_snapshot_force(context,
                                              volume['id'],
                                              volume_snapshot_name,
                                              '')
        t = time.time()
        while time.time() - t < self.configuration.max_time_to_create_volume:
            if volume_snapshot['status'] == 'available':
                break
            if volume_snapshot['status'] == 'error':
                raise exception.\
                        ManilaException('Volume snapshot creating error')
            time.sleep(1)
            volume_snapshot = self.volume_api.get_snapshot(context,
                                                volume_snapshot['id'])
        else:
            raise exception.ManilaException('Volume snapshot creating timeout')

    def delete_snapshot(self, context, snapshot):
        """Deletes a snapshot."""
        volume_snapshot = self._get_volume_snapshot(context, snapshot['id'])
        if volume_snapshot:
            self.volume_api.delete_snapshot(context, volume_snapshot['id'])

    def ensure_share(self, context, share):
        """Ensure that storage are mounted and exported."""
#        server = self._get_service_instance(context, share['project_id'])
#        volume = self._allocate_container(context, share)
#        self._mount_volume(context, share['project_id'], server, volume)

    def allow_access(self, context, share, access):
        """Allow access to the share."""
        server = self._get_service_instance(context, share)
        self._get_helper(share).allow_access(server, share['name'],
                                             access['access_type'],
                                             access['access_to'])

    def deny_access(self, context, share, access):
        """Allow access to the share."""
        server = self._get_service_instance(context, share)
        if server:
            self._get_helper(share).deny_access(server, share['name'],
                                                access['access_type'],
                                                access['access_to'])

    def _get_helper(self, share):
        if share['share_proto'].startswith('NFS'):
            return self._helpers['NFS']
        elif share['share_proto'].startswith('CIFS'):
            return self._helpers['CIFS']
        else:
            raise exception.InvalidShare(reason='Wrong share type')


class NASHelperBase(object):
    """Interface to work with share."""

    def __init__(self, execute, config_object, locks):
        self.configuration = config_object
        self._execute = execute
        self.tenants_locks = locks

    def init(self):
        pass

    def create_export(self, server, share_name, recreate=False):
        """Create new export, delete old one if exists."""
        raise NotImplementedError()

    def remove_export(self, server, share_name):
        """Remove export."""
        raise NotImplementedError()

    def allow_access(self, server, share_name, access_type, access):
        """Allow access to the host."""
        raise NotImplementedError()

    def deny_access(self, local_path, share_name, access_type, access,
                    force=False):
        """Deny access to the host."""
        raise NotImplementedError()


class NFSHelper(NASHelperBase):
    """Interface to work with share."""

    def __init__(self, *args):
        super(NFSHelper, self).__init__(*args)

    def create_export(self, server, share_name, recreate=False):
        """Create new export, delete old one if exists."""
        return ':'.join([_get_server_ip(server),
            os.path.join(self.configuration.share_mount_path, share_name)])

    def remove_export(self, server, share_name):
        """Remove export."""
        pass

    def allow_access(self, server, share_name, access_type, access):
        """Allow access to the host"""
        local_path = os.path.join(self.configuration.share_mount_path,
                                  share_name)
        if access_type != 'ip':
            reason = 'only ip access type allowed'
            raise exception.InvalidShareAccess(reason)
        #check if presents in export
        out, _ = _ssh_exec(server, ['sudo', 'exportfs'], self._execute)
        out = re.search(re.escape(local_path) + '[\s\n]*' + re.escape(access),
                        out)
        if out is not None:
            raise exception.ShareAccessExists(access_type=access_type,
                                              access=access)
        _ssh_exec(server, ['sudo', 'exportfs', '-o', 'rw,no_subtree_check',
                  ':'.join([access, local_path])], self._execute)

    def deny_access(self, server, share_name, access_type, access,
                    force=False):
        """Deny access to the host."""
        local_path = os.path.join(self.configuration.share_mount_path,
                                  share_name)
        _ssh_exec(server, ['sudo', 'exportfs', '-u',
                           ':'.join([access, local_path])], self._execute)


class CIFSHelper(NASHelperBase):
    """Class provides functionality to operate with cifs shares"""

    def __init__(self, *args):
        """Store executor and configuration path."""
        super(CIFSHelper, self).__init__(*args)
        self.config_path = self.configuration.smb_config_path
        self.smb_template_config = self.configuration.smb_template_config_path
        self.test_config = "%s_" % (self.smb_template_config,)
        self.local_configs = {}

    def _create_local_config(self, tenant_id):
        path, ext = os.path.splitext(self.smb_template_config) 
        local_config = '%s-%s%s' % (path, tenant_id, ext)
        self.local_configs[tenant_id] = local_config
        if not os.path.isfile(local_config):
            shutil.copy(self.smb_template_config, local_config)
        return local_config

    def _get_local_config(self, tenant_id):
        local_config = self.local_configs.get(tenant_id, None)
        if local_config is None:
            local_config = self._create_local_config(tenant_id)
        return local_config

    def init_helper(self, server):
        self._recreate_template_config()
        local_config = self._create_local_config(server['tenant_id']) 
        _ssh_exec(server, ['sudo', 'stop', 'smbd', self._execute])
        try:
            _ssh_exec(server, ['sudo', 'mkdir',
                               os.path.dirname(self.config_path)],
                           self._execute)
            _ssh_exec(server, ['sudo', 'chown',
                               self.configuration.service_instance_user,
                               os.path.dirname(self.config_path)],
                      self._execute)
        except Exception as e:
            LOG.debug(e.message)
        try:
            _ssh_exec(server, ['touch', self.config_path], self._execute)
            self._write_remote_config(local_config, server)
        except Exception as e:
            LOG.debug(e.message)

    def create_export(self, server, share_name, recreate=False):
        """Create new export, delete old one if exists."""
        local_path = os.path.join(self.configuration.share_mount_path,
                                  share_name)
        config = self._get_local_config(server['tenant_id'])
        parser = ConfigParser.ConfigParser()
        parser.read(config)
        #delete old one
        if parser.has_section(share_name):
            if recreate:
                parser.remove_section(share_name)
            else:
                raise exception.Error('Section exists')
        #Create new one
        parser.add_section(share_name)
        parser.set(share_name, 'path', local_path)
        parser.set(share_name, 'browseable', 'yes')
        parser.set(share_name, 'guest ok', 'yes')
        parser.set(share_name, 'read only', 'no')
        parser.set(share_name, 'writable', 'yes')
        parser.set(share_name, 'create mask', '0755')
        parser.set(share_name, 'hosts deny', '0.0.0.0/0')  # denying all ips
        parser.set(share_name, 'hosts allow', '127.0.0.1')
        self._update_config(parser, config)
        self._write_remote_config(config, server)
        self._restart_service(server)
        return '//%s/%s' % (_get_server_ip(server), share_name)

    def remove_export(self, server, share_name):
        """Remove export."""
        try:
            config = self._get_local_config(server['tenant_id'])
        except Exception as e:
            LOG.debug(e.message)
        else:
            parser = ConfigParser.ConfigParser()
            parser.read(config)
            #delete old one
            if parser.has_section(share_name):
                parser.remove_section(share_name)
            self._update_config(parser, config)
            self._write_remote_config(config, server)
        _ssh_exec(server, ['sudo', 'smbcontrol', 'all', 'close-share',
                       share_name], self._execute)

    def _write_remote_config(self, config, server):
        with open(config, 'r') as f:
            cfg = "'" + f.read() + "'"
        _ssh_exec(server, ['echo %s > %s' % (cfg, self.config_path)],
                  self._execute)

    def allow_access(self, server, share_name, access_type, access):
        """Allow access to the host."""
        if access_type != 'ip':
            reason = 'only ip access type allowed'
            raise exception.InvalidShareAccess(reason)
        config = self._get_local_config(server['tenant_id'])
        parser = ConfigParser.ConfigParser()
        parser.read(config)

        hosts = parser.get(share_name, 'hosts allow')
        if access in hosts.split():
            raise exception.ShareAccessExists(access_type=access_type,
                                              access=access)
        hosts += ' %s' % (access,)
        parser.set(share_name, 'hosts allow', hosts)
        self._update_config(parser, config)
        self._write_remote_config(config, server)
        self._restart_service(server)

    def deny_access(self, server, share_name, access_type, access,
                    force=False):
        """Deny access to the host."""
        config = self._get_local_config(server['tenant_id'])
        parser = ConfigParser.ConfigParser()
        try:
            parser.read(config)
            hosts = parser.get(share_name, 'hosts allow')
            hosts = hosts.replace(' %s' % (access,), '', 1)
            parser.set(share_name, 'hosts allow', hosts)
            self._update_config(parser, config)
        except ConfigParser.NoSectionError:
            if not force:
                raise
        self._write_remote_config(config, server)
        self._restart_service(server)

    def _recreate_config(self):
        """create new SAMBA configuration file."""
        if os.path.exists(self.smb_template_config):
            os.unlink(self.smb_template_config)
        parser = ConfigParser.ConfigParser()
        parser.add_section('global')
        parser.set('global', 'security', 'user')
        parser.set('global', 'server string', '%h server (Samba, Openstack)')
        self._update_config(parser, self.smb_template_config, restart=False)

    def _restart_service(self, server):
        _ssh_exec(server, 'sudo pkill -HUP smbd'.split(), self._execute)

    def _update_config(self, parser, config):
        """Check if new configuration is correct and save it."""
        #Check that configuration is correct
        with open(self.test_config, 'w') as fp:
            parser.write(fp)
        self._execute('testparm', '-s', self.test_config,
                      check_exit_code=True)
        #save it
        with open(config, 'w') as fp:
            parser.write(fp)
