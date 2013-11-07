# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Openstack Foundation
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

import manila.openstack.common.importutils
from oslo.config import cfg

network_opts = [
    cfg.StrOpt('network_api_class',
                           default='manila.network.api.API',
                           help='The full class name of the '
                                'network API class to use'),
]

cfg.CONF.register_opts(network_opts)


def API():
    importutils = manila.openstack.common.importutils
    network_api_class = cfg.CONF.network_api_class
    cls = importutils.import_class(network_api_class)
    return cls()
