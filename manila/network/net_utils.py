from manila import exception
from manila.openstack.common import excutils
from manila.openstack.common.gettextutils import _
from manila.openstack.common import log as logging
from manila.openstack.common import processutils
from manila import utils

from oslo.config import cfg

LOG = logging.getLogger(__name__)
CONF = cfg.CONF
_execute = utils.execute


# Constants for the 'vif_type' field in VIF class
VIF_TYPE_OVS = 'ovs'
VIF_TYPE_IVS = 'ivs'
VIF_TYPE_IOVISOR = 'iovisor'
VIF_TYPE_BRIDGE = 'bridge'
VIF_TYPE_802_QBG = '802.1qbg'
VIF_TYPE_802_QBH = '802.1qbh'
VIF_TYPE_MLNX_DIRECT = 'mlnx_direct'
VIF_TYPE_OTHER = 'other'

# Constant for max length of network interface names
# eg 'bridge' in the Network class or 'devname' in
# the VIF class
NIC_NAME_LEN = 14


def device_exists(device):
    """Check if ethernet device exists."""
    (_out, err) = _execute('ip', 'link', 'show', 'dev', device,
                           check_exit_code=False, run_as_root=True)
    return not err


@utils.synchronized('lock_vlan', external=True)
def ensure_vlan(vlan_num, bridge_interface, mac_address=None):
    """Create a vlan unless it already exists."""
    interface = 'vlan%s' % vlan_num
    if not device_exists(interface):
        LOG.debug(_('Starting VLAN interface %s'), interface)
        _execute('ip', 'link', 'add', 'link', bridge_interface,
                 'name', interface, 'type', 'vlan',
                 'id', vlan_num, run_as_root=True,
                 check_exit_code=[0, 2, 254])
        # (danwent) the bridge will inherit this address, so we want to
        # make sure it is the value set from the NetworkManager
        if mac_address:
            _execute('ip', 'link', 'set', interface, 'address',
                     mac_address, run_as_root=True,
                     check_exit_code=[0, 2, 254])
        _execute('ip', 'link', 'set', interface, 'up', run_as_root=True,
                 check_exit_code=[0, 2, 254])
        if CONF.network_device_mtu:
            _execute('ip', 'link', 'set', interface, 'mtu',
                     CONF.network_device_mtu, run_as_root=True,
                     check_exit_code=[0, 2, 254])
    return interface


@utils.synchronized('lock_bridge', external=True)
def ensure_bridge(bridge, interface, net_attrs=None, gateway=True):
    """Create a bridge unless it already exists.

    :param interface: the interface to create the bridge on.
    :param net_attrs: dictionary with  attributes used to create bridge.
    :param gateway: whether or not the bridge is a gateway.
    :param filtering: whether or not to create filters on the bridge.

    If net_attrs is set, it will add the net_attrs['gateway'] to the bridge
    using net_attrs['broadcast'] and net_attrs['cidr'].  It will also add
    the ip_v6 address specified in net_attrs['cidr_v6'] if use_ipv6 is set.

    The code will attempt to move any ips that already exist on the
    interface onto the bridge and reset the default gateway if necessary.

    """
    if not device_exists(bridge):
        LOG.debug(_('Starting Bridge %s'), bridge)
        _execute('brctl', 'addbr', bridge, run_as_root=True)
        _execute('brctl', 'setfd', bridge, 0, run_as_root=True)
        # _execute('brctl setageing %s 10' % bridge, run_as_root=True)
        _execute('brctl', 'stp', bridge, 'off', run_as_root=True)
        # (danwent) bridge device MAC address can't be set directly.
        # instead it inherits the MAC address of the first device on the
        # bridge, which will either be the vlan interface, or a
        # physical NIC.
        _execute('ip', 'link', 'set', bridge, 'up', run_as_root=True)

    if interface:
        msg = _('Adding interface %(interface)s to bridge %(bridge)s')
        LOG.debug(msg, {'interface': interface, 'bridge': bridge})
        out, err = _execute('brctl', 'addif', bridge, interface,
                            check_exit_code=False, run_as_root=True)
        out, err = _execute('ip', 'link', 'set', interface, 'up',
                            check_exit_code=False, run_as_root=True)

        # NOTE(vish): This will break if there is already an ip on the
        #             interface, so we move any ips to the bridge
        # NOTE(danms): We also need to copy routes to the bridge so as
        #              not to break existing connectivity on the interface
        old_routes = []
        out, err = _execute('ip', 'route', 'show', 'dev', interface)
        for line in out.split('\n'):
            fields = line.split()
            if fields and 'via' in fields:
                old_routes.append(fields)
                _execute('ip', 'route', 'del', *fields,
                         run_as_root=True)
        out, err = _execute('ip', 'addr', 'show', 'dev', interface,
                            'scope', 'global', run_as_root=True)
        for line in out.split('\n'):
            fields = line.split()
            if fields and fields[0] == 'inet':
                if fields[-2] == 'secondary':
                    params = fields[1:-2]
                else:
                    params = fields[1:-1]
                _execute(*_ip_bridge_cmd('del', params, fields[-1]),
                         run_as_root=True, check_exit_code=[0, 2, 254])
                _execute(*_ip_bridge_cmd('add', params, bridge),
                         run_as_root=True, check_exit_code=[0, 2, 254])
        for fields in old_routes:
            _execute('ip', 'route', 'add', *fields,
                     run_as_root=True)

        if (err and err != "device %s is already a member of a bridge;"
                 "can't enslave it to bridge %s.\n" % (interface, bridge)):
            msg = _('Failed to add interface: %s') % err
            raise exception.NovaException(msg)


def ensure_vlan_bridge(vlan_num, bridge, bridge_interface,
                       net_attrs=None, mac_address=None):
    """Create a vlan and bridge unless they already exist."""
    interface = ensure_vlan(vlan_num,
                            bridge_interface, mac_address)
    ensure_bridge(bridge, interface, net_attrs)
    return interface


def delete_net_dev(dev):
    """Delete a network device only if it exists."""
    if device_exists(dev):
        try:
            utils.execute('ip', 'link', 'delete', dev, run_as_root=True,
                          check_exit_code=[0, 2, 254])
            LOG.debug(_("Net device removed: '%s'"), dev)
        except processutils.ProcessExecutionError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("Failed removing net device: '%s'"), dev)


def create_ivs_vif_port(dev, iface_id, mac):
    utils.execute('ivs-ctl', 'add-port',
                   dev, run_as_root=True)


def create_ovs_vif_port(bridge, dev, iface_id, mac):
    utils.execute('ovs-vsctl', '--', '--may-exist', 'add-port',
                  bridge, dev,
                  '--', 'set', 'Interface', dev,
                  'external-ids:iface-id=%s' % iface_id,
                  'external-ids:iface-status=active',
                  'external-ids:attached-mac=%s' % mac,
                  run_as_root=True)


def delete_ovs_vif_port(bridge, dev):
    utils.execute('ovs-vsctl', 'del-port', bridge, dev,
                  run_as_root=True)
    delete_net_dev(dev)


def create_tap_dev(dev, mac_address=None):
    if not device_exists(dev):
        try:
            # First, try with 'ip'
            utils.execute('ip', 'tuntap', 'add', dev, 'mode', 'tap',
                          run_as_root=True, check_exit_code=[0, 2, 254])
        except processutils.ProcessExecutionError:
            # Second option: tunctl
            utils.execute('tunctl', '-b', '-t', dev, run_as_root=True)
        if mac_address:
            utils.execute('ip', 'link', 'set', dev, 'address', mac_address,
                          run_as_root=True, check_exit_code=[0, 2, 254])
        utils.execute('ip', 'link', 'set', dev, 'up', run_as_root=True,
                      check_exit_code=[0, 2, 254])


def _ip_bridge_cmd(action, params, device):
    """Build commands to add/del ips to bridges/devices."""
    cmd = ['ip', 'addr', action]
    cmd.extend(params)
    cmd.extend(['dev', device])
    return cmd
