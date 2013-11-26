# Copyright 2013 OpenStack Foundation
# All Rights Reserved
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
#
# vim: tabstop=4 shiftwidth=4 softtabstop=4


from oslo.config import cfg

from manila.openstack.common import log as logging
from manila.openstack.common import uuidutils


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class API(object):
    """Fake Network API"""
    network = {
        "status": "ACTIVE",
        "subnets": ["fake_subnet_id"],
        "name": "fake_network",
        "tenant_id": "fake_tenant_id",
        "shared": False,
        "id": "fake_id",
        "router:external": False,
    }

    port = {
        "status": "ACTIVE",
        "allowed_address_pairs": [],
        "admin_state_up": True,
        "network_id": "fake_network_id",
        "tenant_id": "fake_tenant_id",
        "extra_dhcp_opts": [],
        "device_owner": "fake",
        "binding:capabilities": {"port_filter": True},
        "mac_addr": "00:00:00:00:00:00",
        "fixed_ips": [
            {"subnet_id": "56537094-98d7-430a-b513-81c4dc6d9903",
             "ip_address": "10.12.12.10"}
        ],
        "id": "fake_port_id",
        "security_groups": ["fake_sec_group_id"],
        "device_id": "fake_device_id"
    }

    def get_all_tenant_networks(self, tenant_id):
        net1 = self.network.copy()
        net1['tenant_id'] = tenant_id
        net1['id'] = uuidutils.generate_uuid()

        net2 = self.network.copy()
        net2['tenant_id'] = tenant_id
        net2['id'] = uuidutils.generate_uuid()
        return [net1, net2]

    def create_port(self, tenant_id, network_id, subnet_id=None,
                    fixed_ip=None, device_owner=None, device_id=None,
                    mac_address=None):
        port = self.port.copy()
        port['network_id'] = network_id
        port['admin_state_up'] = True
        port['tenant_id'] = tenant_id
        if fixed_ip:
                fixed_ip_dict = {'ip_address': fixed_ip}
                if subnet_id:
                    fixed_ip_dict.update({'subnet_id': subnet_id})
                port['fixed_ips'] = [fixed_ip_dict]
        if device_owner:
                port['device_owner'] = device_owner
        if device_id:
                port['device_id'] = device_id
        if mac_address:
            port['mac_addr'] = mac_address
        return port

    def list_ports(self, **search_opts):
        """List ports for the client based on search options."""
        ports = []
        for i in range(2):
            ports.append(self.port.copy())
        for port in ports:
            port['id'] = uuidutils.generate_uuid()
            for key, val in search_opts.items():
                port[key] = val
            if 'id' in search_opts:
                return ports
        return ports

    def show_port(self, port_id):
        """Return the port for the client given the port id."""
        port = self.port.copy()
        port['id'] = port_id
        return port

    def get_all_networks(self):
        """Get all networks for client."""
        net1 = self.network.copy()
        net2 = self.network.copy()
        net1['id'] = uuidutils.generate_uuid()
        net2['id'] = uuidutils.generate_uuid()
        return [net1, net2]

    def get_network(self, network_uuid):
        """Get specific network for client."""
        network = self.network.copy()
        network['id'] = network_uuid
        return network
