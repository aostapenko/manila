# Copyright 2014 Mirantis Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
Handles all requests to Nova.
"""

import sys

from novaclient import exceptions as nova_exception
from novaclient import extension
from novaclient import service_catalog
from novaclient.v1_1 import client as nova_client
from novaclient.v1_1.contrib import assisted_volume_snapshots
from novaclient.v1_1 import servers as nova_servers
from oslo.config import cfg

from manila.db import base
from manila import exception
from manila.openstack.common import log as logging

nova_opts = [
    cfg.StrOpt('nova_catalog_info',
               default='compute:nova:publicURL',
               help='Info to match when looking for nova in the service '
                    'catalog. Format is : separated values of the form: '
                    '<service_type>:<service_name>:<endpoint_type>'),
    cfg.StrOpt('nova_catalog_admin_info',
               default='compute:nova:adminURL',
               help='Same as nova_catalog_info, but for admin endpoint.'),
    cfg.StrOpt('nova_endpoint_template',
               default=None,
               help='Override service catalog lookup with template for nova '
                    'endpoint e.g. http://localhost:8774/v2/%(tenant_id)s'),
    cfg.StrOpt('nova_endpoint_admin_template',
               default=None,
               help='Same as nova_endpoint_template, but for admin endpoint.'),
    cfg.StrOpt('os_region_name',
               default=None,
               help='region name of this node'),
    cfg.StrOpt('nova_ca_certificates_file',
               default=None,
               help='Location of ca certicates file to use for nova client '
                    'requests.'),
    cfg.BoolOpt('nova_api_insecure',
                default=False,
                help='Allow to perform insecure SSL requests to nova'),
]

CONF = cfg.CONF
CONF.register_opts(nova_opts)

LOG = logging.getLogger(__name__)


def novaclient(context, admin=False):
    compat_catalog = {
        'access': {'serviceCatalog': context.service_catalog or []}
    }
    sc = service_catalog.ServiceCatalog(compat_catalog)

    nova_endpoint_template = CONF.nova_endpoint_template
    nova_catalog_info = CONF.nova_catalog_info

    if admin:
        nova_endpoint_template = CONF.nova_endpoint_admin_template
        nova_catalog_info = CONF.nova_catalog_admin_info

    if nova_endpoint_template:
        url = nova_endpoint_template % context.to_dict()
    else:
        info = nova_catalog_info
        service_type, service_name, endpoint_type = info.split(':')
        # extract the region if set in configuration
        if CONF.os_region_name:
            attr = 'region'
            filter_value = CONF.os_region_name
        else:
            attr = None
            filter_value = None
        url = sc.url_for(attr=attr,
                         filter_value=filter_value,
                         service_type=service_type,
                         service_name=service_name,
                         endpoint_type=endpoint_type)

    LOG.debug(_('Novaclient connection created using URL: %s') % url)

    extensions = [assisted_volume_snapshots]

    c = nova_client.Client(context.user_id,
                           context.auth_token,
                           context.project_id,
                           auth_url=url,
                           insecure=CONF.nova_api_insecure,
                           cacert=CONF.nova_ca_certificates_file,
                           extensions=extensions)
    # noauth extracts user_id:project_id from auth_token
    c.client.auth_token = context.auth_token or '%s:%s' % (context.user_id,
                                                           context.project_id)
    c.client.management_url = url
    return c


def translate_server_exception(method):
    """Transforms the exception for the instance but keeps its traceback
    intact.
    """
    def wrapper(self, ctx, instance_id, *args, **kwargs):
        try:
            res = method(self, ctx, instance_id, *args, **kwargs)
        except nova_exception.ClientException:
            exc_type, exc_value, exc_trace = sys.exc_info()
            if isinstance(exc_value, nova_exception.NotFound):
                exc_value = exception.InstanceNotFound(instance_id=instance_id)
            elif isinstance(exc_value, nova_exception.BadRequest):
                exc_value = exception.InvalidInput(reason=exc_value.message)
            raise exc_value, None, exc_trace
        return res
    return wrapper


class API(base.Base):
    """API for interacting with novaclient."""

    def server_create(self, context, name, image, flavor, key_name, user_data,
                      security_groups, block_device_mapping=None,
                      block_device_mapping_v2=None, nics=None,
                      availability_zone=None, instance_count=1,
                      admin_pass=None):
        return novaclient(context).servers.create(
            name, image, flavor, userdata=user_data,
            security_groups=security_groups,
            key_name=key_name, block_device_mapping=block_device_mapping,
            block_device_mapping_v2=block_device_mapping_v2,
            nics=nics, availability_zone=availability_zone,
            min_count=instance_count, admin_pass=admin_pass)

    def server_delete(self, context, instance):
        novaclient(context).servers.delete(instance)

    @translate_server_exception
    def server_get(self, context, instance_id):
        return novaclient(context).servers.get(instance_id)

    def server_list(self, context, search_opts=None, all_tenants=False):
        if search_opts is None:
            search_opts = {}
        if all_tenants:
            search_opts['all_tenants'] = True
        else:
            search_opts['project_id'] = context.project_id
        servers = [s for s in novaclient(context).servers.
                                            list(True, search_opts)]

        return servers

    def server_pause(self, context, instance_id):
        novaclient(context).servers.pause(instance_id)

    def server_unpause(self, context, instance_id):
        novaclient(context).servers.unpause(instance_id)

    def server_suspend(self, context, instance_id):
        novaclient(context).servers.suspend(instance_id)

    def server_resume(self, context, instance_id):
        novaclient(context).servers.resume(instance_id)

    def server_reboot(self, context, instance_id, soft_reboot=False):
        hardness = nova_servers.REBOOT_HARD
        if soft_reboot:
            hardness = nova_servers.REBOOT_SOFT
        novaclient(context).servers.reboot(instance_id, hardness)

    def server_rebuild(self, context, instance_id, image_id, password=None):
        return novaclient(context).servers.rebuild(instance_id, image_id,
                                                   password)

    def instance_volume_attach(self, context, instance_id, volume_id, device):
        return novaclient(context).volumes.create_server_volume(instance_id,
                                                                volume_id,
                                                                device)

    def instance_volume_detach(self, context, instance_id, att_id):
        return novaclient(context).volumes.delete_server_volume(instance_id,
                                                                  att_id)

    def instance_volumes_list(self, context, instance_id):
        from manila.volume.cinder import cinderclient

        volumes = novaclient(context).volumes.get_server_volumes(instance_id)

        for volume in volumes:
            volume_data = cinderclient(context).volumes.get(volume.id)
            volume.name = volume_data.display_name

        return volumes

    def server_update(self, context, instance_id, name):
        return novaclient(context).servers.update(instance_id, name=name)

    def update_server_volume(self, context, server_id, attachment_id,
                             new_volume_id):
        novaclient(context).volumes.update_server_volume(server_id,
                                                         attachment_id,
                                                         new_volume_id)

    def keypair_create(self, context, name):
        return novaclient(context).keypairs.create(name)

    def keypair_import(self, context, name, public_key):
        return novaclient(context).keypairs.create(name, public_key)

    def keypair_delete(self, context, keypair_id):
        novaclient(context).keypairs.delete(keypair_id)

    def keypair_list(self, context):
        return novaclient(context).keypairs.list()
