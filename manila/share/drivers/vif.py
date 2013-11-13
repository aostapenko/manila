# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (C) 2011 Midokura KK
# Copyright (C) 2011 Nicira, Inc
# Copyright 2011 OpenStack Foundation
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

"""VIF drivers for libvirt."""

import copy

from oslo.config import cfg

from manila import exception
from manila.network import linux_net
from manila.network import model as network_model
from manila.openstack.common.gettextutils import _
from manila.openstack.common import log as logging
from manila.openstack.common import processutils
from manila import utils
from manila.virt.libvirt import config as vconfig
from manila.virt.libvirt import designer

LOG = logging.getLogger(__name__)

libvirt_vif_opts = [
    cfg.StrOpt('libvirt_ovs_bridge',
               default='br-int',
               help='Name of Integration Bridge used by Open vSwitch'),
]

CONF = cfg.CONF
CONF.register_opts(libvirt_vif_opts)
CONF.import_opt('libvirt_type', 'nova.virt.libvirt.driver')

# Since libvirt 0.9.11, <interface type='bridge'>
# supports OpenVSwitch natively.
LIBVIRT_OVS_VPORT_VERSION = 9011
DEV_PREFIX_ETH = 'eth'


def is_vif_model_valid_for_virt(virt_type, vif_model):
        valid_models = {
            'qemu': ['virtio', 'ne2k_pci', 'pcnet', 'rtl8139', 'e1000'],
            'kvm': ['virtio', 'ne2k_pci', 'pcnet', 'rtl8139', 'e1000'],
            'xen': ['netfront', 'ne2k_pci', 'pcnet', 'rtl8139', 'e1000'],
            'lxc': [],
            'uml': [],
            }

        if vif_model is None:
            return True

        if virt_type not in valid_models:
            raise exception.UnsupportedVirtType(virt=virt_type)

        return vif_model in valid_models[virt_type]


class LibvirtBaseVIFDriver(object):

    def __init__(self, get_connection):
        self.get_connection = get_connection
        self.libvirt_version = None

    def has_libvirt_version(self, want):
        if self.libvirt_version is None:
            conn = self.get_connection()
            self.libvirt_version = conn.getLibVersion()

        if self.libvirt_version >= want:
            return True
        return False

    def get_vif_devname(self, vif):
        if 'devname' in vif:
            return vif['devname']
        return ("nic" + vif['id'])[:network_model.NIC_NAME_LEN]

    def get_vif_devname_with_prefix(self, vif, prefix):
        devname = self.get_vif_devname(vif)
        return prefix + devname[3:]

    def get_config(self, instance, vif, image_meta, inst_type):
        conf = vconfig.LibvirtConfigGuestInterface()
        # Default to letting libvirt / the hypervisor choose the model
        model = None
        driver = None

        # If the user has specified a 'vif_model' against the
        # image then honour that model
        if image_meta:
            vif_model = image_meta.get('properties',
                                       {}).get('hw_vif_model')
            if vif_model is not None:
                model = vif_model

        # Else if the virt type is KVM/QEMU, use virtio according
        # to the global config parameter
        if (model is None and
            CONF.libvirt_type in ('kvm', 'qemu') and
                    CONF.libvirt_use_virtio_for_bridges):
            model = "virtio"

        # Workaround libvirt bug, where it mistakenly
        # enables vhost mode, even for non-KVM guests
        if model == "virtio" and CONF.libvirt_type == "qemu":
            driver = "qemu"

        if not is_vif_model_valid_for_virt(CONF.libvirt_type,
                                           model):
            raise exception.UnsupportedHardware(model=model,
                                                virt=CONF.libvirt_type)

        designer.set_vif_guest_frontend_config(
            conf, vif['address'], model, driver)

        return conf

    def plug(self, instance, vif):
        pass

    def unplug(self, instance, vif):
        pass


class LibvirtGenericVIFDriver(LibvirtBaseVIFDriver):
    """Generic VIF driver for libvirt networking."""

    def get_bridge_name(self, vif):
        return vif['network']['bridge']

    def get_ovs_interfaceid(self, vif):
        return vif.get('ovs_interfaceid') or vif['id']

    def get_br_name(self, iface_id):
        return ("qbr" + iface_id)[:network_model.NIC_NAME_LEN]

    def get_veth_pair_names(self, iface_id):
        return (("qvb%s" % iface_id)[:network_model.NIC_NAME_LEN],
                ("qvo%s" % iface_id)[:network_model.NIC_NAME_LEN])

    def get_config_bridge(self, instance, vif, image_meta, inst_type):
        """Get VIF configurations for bridge type."""
        conf = super(LibvirtGenericVIFDriver,
                     self).get_config(instance, vif,
                                      image_meta, inst_type)

        designer.set_vif_host_backend_bridge_config(
            conf, self.get_bridge_name(vif),
            self.get_vif_devname(vif))

        mac_id = vif['address'].replace(':', '')
        name = "nova-instance-" + instance['name'] + "-" + mac_id

        designer.set_vif_bandwidth_config(conf, inst_type)

        return conf

    def get_config_ovs_ethernet(self, instance, vif,
                                image_meta, inst_type):
        conf = super(LibvirtGenericVIFDriver,
                     self).get_config(instance, vif,
                                      image_meta, inst_type)

        dev = self.get_vif_devname(vif)
        designer.set_vif_host_backend_ethernet_config(conf, dev)

        return conf

    def get_config_ovs_bridge(self, instance, vif, image_meta,
                                 inst_type):
        conf = super(LibvirtGenericVIFDriver,
                     self).get_config(instance, vif,
                                      image_meta, inst_type)

        designer.set_vif_host_backend_ovs_config(
            conf, self.get_bridge_name(vif),
            self.get_ovs_interfaceid(vif),
            self.get_vif_devname(vif))

        return conf

    def get_config_ovs(self, instance, vif, image_meta, inst_type):
        if self.has_libvirt_version(LIBVIRT_OVS_VPORT_VERSION):
            return self.get_config_ovs_bridge(instance, vif,
                                              image_meta,
                                              inst_type)
        else:
            return self.get_config_ovs_ethernet(instance, vif,
                                                image_meta,
                                                inst_type)

    def get_config_ivs(self, instance, vif, image_meta, inst_type):
        conf = super(LibvirtGenericVIFDriver,
                     self).get_config(instance,
                                      vif,
                                      image_meta,
                                      inst_type)

        dev = self.get_vif_devname(vif)
        designer.set_vif_host_backend_ethernet_config(conf, dev)

        return conf

    def get_config_802qbg(self, instance, vif, image_meta,
                            inst_type):
        conf = super(LibvirtGenericVIFDriver,
                     self).get_config(instance, vif,
                                      image_meta, inst_type)

        params = vif["qbg_params"]
        designer.set_vif_host_backend_802qbg_config(
            conf, vif['network'].get_meta('interface'),
            params['managerid'],
            params['typeid'],
            params['typeidversion'],
            params['instanceid'])

        return conf

    def get_config_802qbh(self, instance, vif, image_meta,
                            inst_type):
        conf = super(LibvirtGenericVIFDriver,
                     self).get_config(instance, vif,
                                      image_meta, inst_type)

        params = vif["qbh_params"]
        designer.set_vif_host_backend_802qbh_config(
            conf, vif['network'].get_meta('interface'),
            params['profileid'])

        return conf

    def get_config_iovisor(self, instance, vif, image_meta,
                             inst_type):
        conf = super(LibvirtGenericVIFDriver,
                     self).get_config(instance, vif,
                                      image_meta, inst_type)

        dev = self.get_vif_devname(vif)
        designer.set_vif_host_backend_ethernet_config(conf, dev)

        return conf

    def get_config_midonet(self, instance, vif, image_meta,
                           inst_type):
        conf = super(LibvirtGenericVIFDriver,
                     self).get_config(instance, vif,
                                      image_meta, inst_type)

        dev = self.get_vif_devname(vif)
        designer.set_vif_host_backend_ethernet_config(conf, dev)

        return conf

    def get_config_mlnx_direct(self, instance, vif, image_meta,
                               inst_type):
        conf = super(LibvirtGenericVIFDriver,
                     self).get_config(instance, vif,
                                      image_meta, inst_type)

        devname = self.get_vif_devname_with_prefix(vif, DEV_PREFIX_ETH)
        designer.set_vif_host_backend_direct_config(conf, devname)

        return conf

    def get_config(self, instance, vif, image_meta, inst_type):
        vif_type = vif['type']

        if vif_type is None:
            raise exception.NovaException(
                _("vif_type parameter must be present "
                  "for this vif_driver implementation"))
        elif vif_type == network_model.VIF_TYPE_BRIDGE:
            return self.get_config_bridge(instance,
                                          vif,
                                          image_meta,
                                          inst_type)
        elif vif_type == network_model.VIF_TYPE_OVS:
            return self.get_config_ovs(instance,
                                       vif,
                                       image_meta,
                                       inst_type)
        elif vif_type == network_model.VIF_TYPE_802_QBG:
            return self.get_config_802qbg(instance,
                                          vif,
                                          image_meta,
                                          inst_type)
        elif vif_type == network_model.VIF_TYPE_802_QBH:
            return self.get_config_802qbh(instance,
                                          vif,
                                          image_meta,
                                          inst_type)
        elif vif_type == network_model.VIF_TYPE_IVS:
            return self.get_config_ivs(instance,
                                       vif,
                                       image_meta,
                                       inst_type)
        elif vif_type == network_model.VIF_TYPE_IOVISOR:
            return self.get_config_iovisor(instance,
                                          vif,
                                          image_meta,
                                          inst_type)
        elif vif_type == network_model.VIF_TYPE_MLNX_DIRECT:
            return self.get_config_mlnx_direct(instance,
                                               vif,
                                               image_meta,
                                               inst_type)
        elif vif_type == network_model.VIF_TYPE_MIDONET:
            return self.get_config_midonet(instance,
                                           vif,
                                           image_meta,
                                           inst_type)
        else:
            raise exception.NovaException(
                _("Unexpected vif_type=%s") % vif_type)

    def plug_bridge(self, instance, vif):
        """Ensure that the bridge exists, and add VIF to it."""
        super(LibvirtGenericVIFDriver,
              self).plug(instance, vif)
        network = vif['network']
        if (not network.get_meta('multi_host', False) and
                    network.get_meta('should_create_bridge', False)):
            if network.get_meta('should_create_vlan', False):
                iface = CONF.vlan_interface or \
                        network.get_meta('bridge_interface')
                LOG.debug(_('Ensuring vlan %(vlan)s and bridge %(bridge)s'),
                          {'vlan': network.get_meta('vlan'),
                           'bridge': self.get_bridge_name(vif)},
                          instance=instance)
                linux_net.LinuxBridgeInterfaceDriver.ensure_vlan_bridge(
                                             network.get_meta('vlan'),
                                             self.get_bridge_name(vif),
                                             iface)
            else:
                iface = CONF.flat_interface or \
                            network.get_meta('bridge_interface')
                LOG.debug(_("Ensuring bridge %s"),
                          self.get_bridge_name(vif), instance=instance)
                linux_net.LinuxBridgeInterfaceDriver.ensure_bridge(
                                        self.get_bridge_name(vif),
                                        iface)

    def plug_ovs_ethernet(self, instance, vif):
        super(LibvirtGenericVIFDriver,
              self).plug(instance, vif)

        network = vif['network']
        iface_id = self.get_ovs_interfaceid(vif)
        dev = self.get_vif_devname(vif)
        linux_net.create_tap_dev(dev)
        linux_net.create_ovs_vif_port(self.get_bridge_name(vif),
                                      dev, iface_id, vif['address'],
                                      instance['uuid'])

    def plug_ovs_bridge(self, instance, vif):
        """No manual plugging required."""
        super(LibvirtGenericVIFDriver,
              self).plug(instance, vif)

    def plug_ovs(self, instance, vif):
        if self.has_libvirt_version(LIBVIRT_OVS_VPORT_VERSION):
            self.plug_ovs_bridge(instance, vif)
        else:
            self.plug_ovs_ethernet(instance, vif)

    def plug_ivs(self, instance, vif):
        super(LibvirtGenericVIFDriver,
              self).plug(instance, vif)

        iface_id = self.get_ovs_interfaceid(vif)
        dev = self.get_vif_devname(vif)
        linux_net.create_tap_dev(dev)
        linux_net.create_ivs_vif_port(dev, iface_id, vif['address'],
                                      instance['uuid'])

    def plug_mlnx_direct(self, instance, vif):
        super(LibvirtGenericVIFDriver,
              self).plug(instance, vif)

        network = vif['network']
        vnic_mac = vif['address']
        device_id = instance['uuid']
        fabric = network['meta']['physical_network']

        dev_name = self.get_vif_devname_with_prefix(vif, DEV_PREFIX_ETH)
        try:
            utils.execute('ebrctl', 'add-port', vnic_mac, device_id, fabric,
                          network_model.VIF_TYPE_MLNX_DIRECT, dev_name,
                          run_as_root=True)
        except processutils.ProcessExecutionError:
            LOG.exception(_("Failed while plugging vif"), instance=instance)

    def plug_802qbg(self, instance, vif):
        super(LibvirtGenericVIFDriver,
              self).plug(instance, vif)

    def plug_802qbh(self, instance, vif):
        super(LibvirtGenericVIFDriver,
              self).plug(instance, vif)

    def plug_midonet(self, instance, vif):
        """Plug into MidoNet's network port

        Bind the vif to a MidoNet virtual port.
        """
        super(LibvirtGenericVIFDriver,
              self).plug(instance, vif)
        dev = self.get_vif_devname(vif)
        port_id = vif['id']
        try:
            linux_net.create_tap_dev(dev)
            utils.execute('mm-ctl', '--bind-port', port_id, dev,
                          run_as_root=True)
        except processutils.ProcessExecutionError:
            LOG.exception(_("Failed while plugging vif"), instance=instance)

    def plug_iovisor(self, instance, vif):
        """Plug using PLUMgrid IO Visor Driver

        Connect a network device to their respective
        Virtual Domain in PLUMgrid Platform.
        """
        super(LibvirtGenericVIFDriver,
              self).plug(instance, vif)
        dev = self.get_vif_devname(vif)
        iface_id = vif['id']
        linux_net.create_tap_dev(dev)
        net_id = vif['network']['id']
        tenant_id = instance["project_id"]
        try:
            utils.execute('ifc_ctl', 'gateway', 'add_port', dev,
                          run_as_root=True)
            utils.execute('ifc_ctl', 'gateway', 'ifup', dev,
                          'access_vm',
                          vif['network']['label'] + "_" + iface_id,
                          vif['address'], 'pgtag2=%s' % net_id,
                          'pgtag1=%s' % tenant_id, run_as_root=True)
        except processutils.ProcessExecutionError:
            LOG.exception(_("Failed while plugging vif"), instance=instance)

    def plug(self, instance, vif):
        vif_type = vif['type']

        if vif_type is None:
            raise exception.NovaException(
                _("vif_type parameter must be present "
                  "for this vif_driver implementation"))
        elif vif_type == network_model.VIF_TYPE_BRIDGE:
            self.plug_bridge(instance, vif)
        elif vif_type == network_model.VIF_TYPE_OVS:
            self.plug_ovs(instance, vif)
        elif vif_type == network_model.VIF_TYPE_802_QBG:
            self.plug_802qbg(instance, vif)
        elif vif_type == network_model.VIF_TYPE_802_QBH:
            self.plug_802qbh(instance, vif)
        elif vif_type == network_model.VIF_TYPE_IVS:
            self.plug_ivs(instance, vif)
        elif vif_type == network_model.VIF_TYPE_IOVISOR:
            self.plug_iovisor(instance, vif)
        elif vif_type == network_model.VIF_TYPE_MLNX_DIRECT:
            self.plug_mlnx_direct(instance, vif)
        elif vif_type == network_model.VIF_TYPE_MIDONET:
            self.plug_midonet(instance, vif)
        else:
            raise exception.NovaException(
                _("Unexpected vif_type=%s") % vif_type)

    def unplug_bridge(self, instance, vif):
        """No manual unplugging required."""
        super(LibvirtGenericVIFDriver,
              self).unplug(instance, vif)

    def unplug_ovs_ethernet(self, instance, vif):
        """Unplug the VIF by deleting the port from the bridge."""
        super(LibvirtGenericVIFDriver,
              self).unplug(instance, vif)

        try:
            linux_net.delete_ovs_vif_port(self.get_bridge_name(vif),
                                          self.get_vif_devname(vif))
        except processutils.ProcessExecutionError:
            LOG.exception(_("Failed while unplugging vif"), instance=instance)

    def unplug_ovs_bridge(self, instance, vif):
        """No manual unplugging required."""
        super(LibvirtGenericVIFDriver,
              self).unplug(instance, vif)

    def unplug_ovs(self, instance, vif):
        if self.has_libvirt_version(LIBVIRT_OVS_VPORT_VERSION):
            self.unplug_ovs_bridge(instance, vif)
        else:
            self.unplug_ovs_ethernet(instance, vif)

    def unplug_ivs(self, instance, vif):
        """Unplug the VIF by deleting the port from the bridge."""
        super(LibvirtGenericVIFDriver,
              self).unplug(instance, vif)

        try:
            linux_net.delete_ivs_vif_port(self.get_vif_devname(vif))
        except processutils.ProcessExecutionError:
            LOG.exception(_("Failed while unplugging vif"), instance=instance)

    def unplug_mlnx_direct(self, instance, vif):
        super(LibvirtGenericVIFDriver,
              self).unplug(instance, vif)

        network = vif['network']
        vnic_mac = vif['address']
        fabric = network['meta']['physical_network']
        try:
            utils.execute('ebrctl', 'del-port', fabric,
                          vnic_mac, run_as_root=True)
        except processutils.ProcessExecutionError:
            LOG.exception(_("Failed while unplugging vif"), instance=instance)

    def unplug_802qbg(self, instance, vif):
        super(LibvirtGenericVIFDriver,
              self).unplug(instance, vif)

    def unplug_802qbh(self, instance, vif):
        super(LibvirtGenericVIFDriver,
              self).unplug(instance, vif)

    def unplug_midonet(self, instance, vif):
        """Unplug from MidoNet network port

        Unbind the vif from a MidoNet virtual port.
        """
        super(LibvirtGenericVIFDriver,
              self).unplug(instance, vif)
        dev = self.get_vif_devname(vif)
        port_id = vif['id']
        try:
            utils.execute('mm-ctl', '--unbind-port', port_id,
                          run_as_root=True)
            linux_net.delete_net_dev(dev)
        except processutils.ProcessExecutionError:
            LOG.exception(_("Failed while unplugging vif"), instance=instance)

    def unplug_iovisor(self, instance, vif):
        """Unplug using PLUMgrid IO Visor Driver

        Delete network device and to their respective
        connection to the Virtual Domain in PLUMgrid Platform.
        """
        super(LibvirtGenericVIFDriver,
              self).unplug(instance, vif)
        iface_id = vif['id']
        dev = self.get_vif_devname(vif)
        try:
            utils.execute('ifc_ctl', 'gateway', 'ifdown',
                          dev, 'access_vm',
                          vif['network']['label'] + "_" + iface_id,
                          vif['address'], run_as_root=True)
            utils.execute('ifc_ctl', 'gateway', 'del_port', dev,
                          run_as_root=True)
            linux_net.delete_net_dev(dev)
        except processutils.ProcessExecutionError:
            LOG.exception(_("Failed while unplugging vif"), instance=instance)

    def unplug(self, instance, vif):
        vif_type = vif['type']

        if vif_type is None:
            raise exception.NovaException(
                _("vif_type parameter must be present "
                  "for this vif_driver implementation"))
        elif vif_type == network_model.VIF_TYPE_BRIDGE:
            self.unplug_bridge(instance, vif)
        elif vif_type == network_model.VIF_TYPE_OVS:
            self.unplug_ovs(instance, vif)
        elif vif_type == network_model.VIF_TYPE_802_QBG:
            self.unplug_802qbg(instance, vif)
        elif vif_type == network_model.VIF_TYPE_802_QBH:
            self.unplug_802qbh(instance, vif)
        elif vif_type == network_model.VIF_TYPE_IVS:
            self.unplug_ivs(instance, vif)
        elif vif_type == network_model.VIF_TYPE_IOVISOR:
            self.unplug_iovisor(instance, vif)
        elif vif_type == network_model.VIF_TYPE_MLNX_DIRECT:
            self.unplug_mlnx_direct(instance, vif)
        elif vif_type == network_model.VIF_TYPE_MIDONET:
            self.unplug_midonet(instance, vif)
        else:
            raise exception.NovaException(
                _("Unexpected vif_type=%s") % vif_type)
