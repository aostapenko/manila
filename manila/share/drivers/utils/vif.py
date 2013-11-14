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

from oslo.config import cfg

from manila import exception
from manila.network import net_utils
from manila.openstack.common.gettextutils import _
from manila.openstack.common import log as logging
from manila.openstack.common import processutils
from manila.share.drivers.utils import config as vconfig
from manila.share.drivers.utils import designer
from manila import utils

LOG = logging.getLogger(__name__)

libvirt_vif_opts = [
    cfg.StrOpt('libvirt_ovs_bridge',
               default='br-int',
               help='Name of Integration Bridge used by Open vSwitch'),
]

CONF = cfg.CONF
CONF.register_opts(libvirt_vif_opts)

# Since libvirt 0.9.11, <interface type='bridge'>
# supports OpenVSwitch natively.
LIBVIRT_OVS_VPORT_VERSION = 9011
DEV_PREFIX_ETH = 'eth'


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
        return ("nic" + vif['id'])[:net_utils.NIC_NAME_LEN]

    def get_vif_devname_with_prefix(self, vif, prefix):
        devname = self.get_vif_devname(vif)
        return prefix + devname[3:]

    def get_config(self, vif):
        conf = vconfig.LibvirtConfigGuestInterface()
        # Default to letting libvirt / the hypervisor choose the model
        model = None
        driver = None

        designer.set_vif_guest_frontend_config(
            conf, vif['address'], model, driver)

        return conf

    def plug(self, vif):
        pass

    def unplug(self, vif):
        pass


class LibvirtGenericVIFDriver(LibvirtBaseVIFDriver):
    """Generic VIF driver for libvirt networking."""

    def get_bridge_name(self, vif):
        return vif['network']['bridge']

    def get_ovs_interfaceid(self, vif):
        return vif.get('ovs_interfaceid') or vif['id']

    def get_br_name(self, iface_id):
        return ("qbr" + iface_id)[:net_utils.NIC_NAME_LEN]

    def get_veth_pair_names(self, iface_id):
        return (("qvb%s" % iface_id)[:net_utils.NIC_NAME_LEN],
                ("qvo%s" % iface_id)[:net_utils.NIC_NAME_LEN])

    def get_config_bridge(self, vif, image_meta, inst_type):
        """Get VIF configurations for bridge type."""
        conf = super(LibvirtGenericVIFDriver, self).get_config(vif)

        designer.set_vif_host_backend_bridge_config(
            conf, self.get_bridge_name(vif),
            self.get_vif_devname(vif))

        designer.set_vif_bandwidth_config(conf, inst_type)

        return conf

    def get_config_ovs_ethernet(self, vif):
        conf = super(LibvirtGenericVIFDriver, self).get_config(vif)

        dev = self.get_vif_devname(vif)
        designer.set_vif_host_backend_ethernet_config(conf, dev)

        return conf

    def get_config_ovs_bridge(self, vif):
        conf = super(LibvirtGenericVIFDriver,
                     self).get_config(vif)

        designer.set_vif_host_backend_ovs_config(
            conf, self.get_bridge_name(vif),
            self.get_ovs_interfaceid(vif),
            self.get_vif_devname(vif))

        return conf

    def get_config_ovs(self, vif):
        if self.has_libvirt_version(LIBVIRT_OVS_VPORT_VERSION):
            return self.get_config_ovs_bridge(vif)
        else:
            return self.get_config_ovs_ethernet(vif)

    def get_config_ivs(self, vif):
        conf = super(LibvirtGenericVIFDriver,
                     self).get_config(vif)

        dev = self.get_vif_devname(vif)
        designer.set_vif_host_backend_ethernet_config(conf, dev)

        return conf

    def get_config_802qbg(self, vif):
        conf = super(LibvirtGenericVIFDriver,
                     self).get_config(vif)

        params = vif["qbg_params"]
        designer.set_vif_host_backend_802qbg_config(
            conf, vif['network'].get_meta('interface'),
            params['managerid'],
            params['typeid'],
            params['typeidversion'],
            params['instanceid'])

        return conf

    def get_config_802qbh(self, vif):
        conf = super(LibvirtGenericVIFDriver,
                     self).get_config(vif)

        params = vif["qbh_params"]
        designer.set_vif_host_backend_802qbh_config(
            conf, vif['network'].get_meta('interface'),
            params['profileid'])

        return conf

    def get_config_iovisor(self, vif):
        conf = super(LibvirtGenericVIFDriver,
                     self).get_config(vif)

        dev = self.get_vif_devname(vif)
        designer.set_vif_host_backend_ethernet_config(conf, dev)

        return conf

    def get_config_midonet(self, vif):
        conf = super(LibvirtGenericVIFDriver,
                     self).get_config(vif)

        dev = self.get_vif_devname(vif)
        designer.set_vif_host_backend_ethernet_config(conf, dev)

        return conf

    def get_config_mlnx_direct(self, vif):
        conf = super(LibvirtGenericVIFDriver,
                     self).get_config(vif)

        devname = self.get_vif_devname_with_prefix(vif, DEV_PREFIX_ETH)
        designer.set_vif_host_backend_direct_config(conf, devname)

        return conf

    def get_config(self, vif):
        vif_type = vif['type']

        if vif_type is None:
            raise exception.NovaException(
                _("vif_type parameter must be present "
                  "for this vif_driver implementation"))
        elif vif_type == net_utils.VIF_TYPE_BRIDGE:
            return self.get_config_bridge(vif)
        elif vif_type == net_utils.VIF_TYPE_OVS:
            return self.get_config_ovs(vif)
        elif vif_type == net_utils.VIF_TYPE_802_QBG:
            return self.get_config_802qbg(vif)
        elif vif_type == net_utils.VIF_TYPE_802_QBH:
            return self.get_config_802qbh(vif)
        elif vif_type == net_utils.VIF_TYPE_IVS:
            return self.get_config_ivs(vif)
        elif vif_type == net_utils.VIF_TYPE_IOVISOR:
            return self.get_config_iovisor(vif)
        elif vif_type == net_utils.VIF_TYPE_MLNX_DIRECT:
            return self.get_config_mlnx_direct(vif)
        elif vif_type == net_utils.VIF_TYPE_MIDONET:
            return self.get_config_midonet(vif)
        else:
            raise exception.NovaException(
                _("Unexpected vif_type=%s") % vif_type)

    def plug_bridge(self, vif):
        """Ensure that the bridge exists, and add VIF to it."""
        super(LibvirtGenericVIFDriver,
              self).plug(vif)
        network = vif['network']
        if (not network.get_meta('multi_host', False) and
                    network.get_meta('should_create_bridge', False)):
            if network.get_meta('should_create_vlan', False):
                iface = CONF.vlan_interface or \
                        network.get_meta('bridge_interface')
                net_utils.LinuxBridgeInterfaceDriver.ensure_vlan_bridge(
                                             network.get_meta('vlan'),
                                             self.get_bridge_name(vif),
                                             iface)
            else:
                iface = CONF.flat_interface or \
                            network.get_meta('bridge_interface')
                net_utils.LinuxBridgeInterfaceDriver.ensure_bridge(
                                        self.get_bridge_name(vif),
                                        iface)

    def plug_ovs_ethernet(self, vif):
        super(LibvirtGenericVIFDriver, self).plug(vif)

        network = vif['network']
        iface_id = self.get_ovs_interfaceid(vif)
        dev = self.get_vif_devname(vif)
        net_utils.create_tap_dev(dev)
        net_utils.create_ovs_vif_port(self.get_bridge_name(vif),
                                      dev, iface_id, vif['address'])

    def plug_ovs_bridge(self, vif):
        """No manual plugging required."""
        super(LibvirtGenericVIFDriver, self).plug(vif)

    def plug_ovs(self, vif):
        if self.has_libvirt_version(LIBVIRT_OVS_VPORT_VERSION):
            self.plug_ovs_bridge(vif)
        else:
            self.plug_ovs_ethernet(vif)

    def plug_ivs(self, vif):
        super(LibvirtGenericVIFDriver, self).plug(vif)

        iface_id = self.get_ovs_interfaceid(vif)
        dev = self.get_vif_devname(vif)
        net_utils.create_tap_dev(dev)
        net_utils.create_ivs_vif_port(dev, iface_id, vif['address'])

    def plug_mlnx_direct(self, vif):
        super(LibvirtGenericVIFDriver,
              self).plug(vif)

        network = vif['network']
        vnic_mac = vif['address']
        fabric = network['meta']['physical_network']

        dev_name = self.get_vif_devname_with_prefix(vif, DEV_PREFIX_ETH)
        try:
            utils.execute('ebrctl', 'add-port', vnic_mac, fabric,
                          net_utils.VIF_TYPE_MLNX_DIRECT, dev_name,
                          run_as_root=True)
        except processutils.ProcessExecutionError:
            LOG.exception(_("Failed while plugging vif"))

    def plug_802qbg(self, vif):
        super(LibvirtGenericVIFDriver,
              self).plug(vif)

    def plug_802qbh(self, vif):
        super(LibvirtGenericVIFDriver,
              self).plug(vif)

    def plug_midonet(self, vif):
        """Plug into MidoNet's network port

        Bind the vif to a MidoNet virtual port.
        """
        super(LibvirtGenericVIFDriver,
              self).plug(vif)
        dev = self.get_vif_devname(vif)
        port_id = vif['id']
        try:
            net_utils.create_tap_dev(dev)
            utils.execute('mm-ctl', '--bind-port', port_id, dev,
                          run_as_root=True)
        except processutils.ProcessExecutionError:
            LOG.exception(_("Failed while plugging vif"))

    def plug_iovisor(self, vif):
        """Plug using PLUMgrid IO Visor Driver

        Connect a network device to their respective
        Virtual Domain in PLUMgrid Platform.
        """
        super(LibvirtGenericVIFDriver,
              self).plug(vif)
        dev = self.get_vif_devname(vif)
        iface_id = vif['id']
        net_utils.create_tap_dev(dev)
        net_id = vif['network']['id']
        try:
            utils.execute('ifc_ctl', 'gateway', 'add_port', dev,
                          run_as_root=True)
            utils.execute('ifc_ctl', 'gateway', 'ifup', dev,
                          'access_vm',
                          vif['network']['label'] + "_" + iface_id,
                          vif['address'], 'pgtag2=%s' % net_id,
                          run_as_root=True)
        except processutils.ProcessExecutionError:
            LOG.exception(_("Failed while plugging vif"))

    def plug(self, vif):
        vif_type = vif['type']

        if vif_type is None:
            raise exception.NovaException(
                _("vif_type parameter must be present "
                  "for this vif_driver implementation"))
        elif vif_type == net_utils.VIF_TYPE_BRIDGE:
            self.plug_bridge(vif)
        elif vif_type == net_utils.VIF_TYPE_OVS:
            self.plug_ovs(vif)
        elif vif_type == net_utils.VIF_TYPE_802_QBG:
            self.plug_802qbg(vif)
        elif vif_type == net_utils.VIF_TYPE_802_QBH:
            self.plug_802qbh(vif)
        elif vif_type == net_utils.VIF_TYPE_IVS:
            self.plug_ivs(vif)
        elif vif_type == net_utils.VIF_TYPE_IOVISOR:
            self.plug_iovisor(vif)
        elif vif_type == net_utils.VIF_TYPE_MLNX_DIRECT:
            self.plug_mlnx_direct(vif)
        elif vif_type == net_utils.VIF_TYPE_MIDONET:
            self.plug_midonet(vif)
        else:
            raise exception.NovaException(
                _("Unexpected vif_type=%s") % vif_type)

    def unplug_bridge(self, vif):
        """No manual unplugging required."""
        super(LibvirtGenericVIFDriver,
              self).unplug(vif)

    def unplug_ovs_ethernet(self, vif):
        """Unplug the VIF by deleting the port from the bridge."""
        super(LibvirtGenericVIFDriver,
              self).unplug(vif)

        try:
            net_utils.delete_ovs_vif_port(self.get_bridge_name(vif),
                                          self.get_vif_devname(vif))
        except processutils.ProcessExecutionError:
            LOG.exception(_("Failed while unplugging vif"))

    def unplug_ovs_bridge(self, vif):
        """No manual unplugging required."""
        super(LibvirtGenericVIFDriver,
              self).unplug(vif)

    def unplug_ovs(self, vif):
        if self.has_libvirt_version(LIBVIRT_OVS_VPORT_VERSION):
            self.unplug_ovs_bridge(vif)
        else:
            self.unplug_ovs_ethernet(vif)

    def unplug_ivs(self, vif):
        """Unplug the VIF by deleting the port from the bridge."""
        super(LibvirtGenericVIFDriver, self).unplug(vif)

        try:
            net_utils.delete_ivs_vif_port(self.get_vif_devname(vif))
        except processutils.ProcessExecutionError:
            LOG.exception(_("Failed while unplugging vif"))

    def unplug_mlnx_direct(self, vif):
        super(LibvirtGenericVIFDriver,
              self).unplug(vif)

        network = vif['network']
        vnic_mac = vif['address']
        fabric = network['meta']['physical_network']
        try:
            utils.execute('ebrctl', 'del-port', fabric,
                          vnic_mac, run_as_root=True)
        except processutils.ProcessExecutionError:
            LOG.exception(_("Failed while unplugging vif"))

    def unplug_802qbg(self, vif):
        super(LibvirtGenericVIFDriver,
              self).unplug(vif)

    def unplug_802qbh(self, vif):
        super(LibvirtGenericVIFDriver,
              self).unplug(vif)

    def unplug_midonet(self, vif):
        """Unplug from MidoNet network port

        Unbind the vif from a MidoNet virtual port.
        """
        super(LibvirtGenericVIFDriver, self).unplug(vif)
        dev = self.get_vif_devname(vif)
        port_id = vif['id']
        try:
            utils.execute('mm-ctl', '--unbind-port', port_id,
                          run_as_root=True)
            net_utils.delete_net_dev(dev)
        except processutils.ProcessExecutionError:
            LOG.exception(_("Failed while unplugging vif"))

    def unplug_iovisor(self, vif):
        """Unplug using PLUMgrid IO Visor Driver

        Delete network device and to their respective
        connection to the Virtual Domain in PLUMgrid Platform.
        """
        super(LibvirtGenericVIFDriver, self).unplug(vif)
        iface_id = vif['id']
        dev = self.get_vif_devname(vif)
        try:
            utils.execute('ifc_ctl', 'gateway', 'ifdown',
                          dev, 'access_vm',
                          vif['network']['label'] + "_" + iface_id,
                          vif['address'], run_as_root=True)
            utils.execute('ifc_ctl', 'gateway', 'del_port', dev,
                          run_as_root=True)
            net_utils.delete_net_dev(dev)
        except processutils.ProcessExecutionError:
            LOG.exception(_("Failed while unplugging vif"))

    def unplug(self, vif):
        vif_type = vif['type']

        if vif_type is None:
            raise exception.NovaException(
                _("vif_type parameter must be present "
                  "for this vif_driver implementation"))
        elif vif_type == net_utils.VIF_TYPE_BRIDGE:
            self.unplug_bridge(vif)
        elif vif_type == net_utils.VIF_TYPE_OVS:
            self.unplug_ovs(vif)
        elif vif_type == net_utils.VIF_TYPE_802_QBG:
            self.unplug_802qbg(vif)
        elif vif_type == net_utils.VIF_TYPE_802_QBH:
            self.unplug_802qbh(vif)
        elif vif_type == net_utils.VIF_TYPE_IVS:
            self.unplug_ivs(vif)
        elif vif_type == net_utils.VIF_TYPE_IOVISOR:
            self.unplug_iovisor(vif)
        elif vif_type == net_utils.VIF_TYPE_MLNX_DIRECT:
            self.unplug_mlnx_direct(vif)
        elif vif_type == net_utils.VIF_TYPE_MIDONET:
            self.unplug_midonet(vif)
        else:
            raise exception.NovaException(
                _("Unexpected vif_type=%s") % vif_type)
