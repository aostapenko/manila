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


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class FakeServer(object):
    def __init__(self, **kwargs):
        self.id = kwargs.get('id') or 'fake_id'

    def __getitem__(self, attr):
        return getattr(self, attr)


class API(object):
    """Fake Compute API"""
    def instance_volume_attach(self, ctx, server_id, volume_id, mount_path):
        pass

    def instance_volume_detach(self, ctx, server_id, volume_id):
        pass

    def instance_volumes_list(self, ctx, server_id):
        pass