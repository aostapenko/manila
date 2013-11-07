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

import time

from neutronclient.common import exceptions as neutron_client_exc
from oslo.config import cfg

from manila import context
from manila.db import base
from manila import exception
from manila.openstack.common import excutils
from manila.openstack.common.gettextutils import _
from manila.openstack.common import jsonutils
from manila.openstack.common import log as logging
from manila.openstack.common import uuidutils
from manila.network import neutron

neutron_opts = [
    cfg.StrOpt('neutron_url',
               default='http://127.0.0.1:9696',
               deprecated_name='quantum_url',
               help='URL for connecting to neutron'),
    cfg.IntOpt('neutron_url_timeout',
               default=30,
               deprecated_name='quantum_url_timeout',
               help='timeout value for connecting to neutron in seconds'),
    cfg.StrOpt('neutron_admin_username',
               deprecated_name='quantum_admin_username',
               help='username for connecting to neutron in admin context'),
    cfg.StrOpt('neutron_admin_password',
               deprecated_name='quantum_admin_password',
               help='password for connecting to neutron in admin context',
               secret=True),
    cfg.StrOpt('neutron_admin_tenant_name',
               deprecated_name='quantum_admin_tenant_name',
               help='tenant name for connecting to neutron in admin context'),
    cfg.StrOpt('neutron_region_name',
               deprecated_name='quantum_region_name',
               help='region name for connecting to neutron in admin context'),
    cfg.StrOpt('neutron_admin_auth_url',
               deprecated_name='quantum_admin_auth_url',
               default='http://localhost:5000/v2.0',
               help='auth url for connecting to neutron in admin context'),
    cfg.BoolOpt('neutron_api_insecure',
                default=False,
                deprecated_name='quantum_api_insecure',
                help='if set, ignore any SSL validation issues'),
    cfg.StrOpt('neutron_auth_strategy',
               default='keystone',
               deprecated_name='quantum_auth_strategy',
               help='auth strategy for connecting to '
                    'neutron in admin context'),
    # TODO(berrange) temporary hack until Neutron can pass over the
    # name of the OVS bridge it is configured with
    cfg.StrOpt('neutron_ovs_bridge',
               default='br-int',
               deprecated_name='quantum_ovs_bridge',
               help='Name of Integration Bridge used by Open vSwitch'),
    cfg.IntOpt('neutron_extension_sync_interval',
                default=600,
                deprecated_name='quantum_extension_sync_interval',
                help='Number of seconds before querying neutron for'
                     ' extensions'),
    cfg.StrOpt('neutron_ca_certificates_file',
                help='Location of ca certificates file to use for '
                     'neutron client requests.'),
    ]

CONF = cfg.CONF
CONF.register_opts(neutron_opts)
LOG = logging.getLogger(__name__)


class API(base.Base):
    """API for interacting with the neutron 2.x API."""

    def __init__(self):
        super(API, self).__init__()
        self.last_neutron_extension_sync = None
        self.extensions = {}
        self.client = neutron.get_client(context.get_admin_context())

    def get_all_tenant_networks(self, tenant_id):
        search_opts = {'tenant_id': tenant_id, 'shared': False}
        nets = self.client.list_networks(**search_opts).get('networks', [])
        return nets

    def create_port(self, tenant_id, network_id, host_id, fixed_ip=None,
                    security_groups_ids=None, mac_address=None,
                    dhcp_opts=None):
        try:
            port_req_body = {'port': {}}
            port_req_body['port']['network_id'] = network_id
            port_req_body['port']['admin_state_up'] = True
            port_req_body['port']['tenant_id'] = tenant_id
            if fixed_ip:
                port_req_body['port']['fixed_ips'] = [{'ip_address': fixed_ip}]
            if security_group_ids:
                port_req_body['port']['security_groups'] = security_group_ids
            if mac_address:
                port_req_body['port']['mac_address'] = mac_address
            if self._has_port_binding_extension():
                port_req_body['port']['binding:host_id'] = host_id
            if dhcp_opts is not None:
                port_req_body['port']['extra_dhcp_opts'] = dhcp_opts
            port = self.client.create_port(port_req_body)
            return port
        except neutron_client_exc.NeutronClientException as e:
            LOG.exception(_('Neutron error creating port on network %s') %
                          network_id)
            if e.status_code == 409:
                raise exception.PortLimitExceeded()
            raise

    def list_ports(self, context, **search_opts):
        """List ports for the client based on search options."""
        return self.client.list_ports(**search_opts)

    def show_port(self, context, port_id):
        """Return the port for the client given the port id."""
        return self.client.show_port(port_id)

    def get_all_networks(self, context):
        """Get all networks for client."""
        return self.client.list_networks().get('networks')

    def get_network(self, context, network_uuid):
        """Get specific network for client."""
        network = self.client.show_network(network_uuid).get('network') or {}
        return network

    def _has_port_binding_extension(self, refresh_cache=False):
        if refresh_cache:
            self._refresh_neutron_extensions_cache()
        return constants.PORTBINDING_EXT in self.extensions

    def _refresh_neutron_extensions_cache(self):
        """Refresh the neutron extensions cache when necessary."""
        if (not self.last_neutron_extension_sync or
            ((time.time() - self.last_neutron_extension_sync)
             >= CONF.neutron_extension_sync_interval)):
            neutron = self.client(context.get_admin_context())
            extensions_list = neutron.list_extensions()['extensions']
            self.last_neutron_extension_sync = time.time()
            self.extensions.clear()
            self.extensions = dict((ext['name'], ext)
                                   for ext in extensions_list)

