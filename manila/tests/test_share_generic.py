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
"""Unit tests for the Generic driver module."""

import mock
import os

from manila import context

from manila import compute
from manila import network
from manila.share.configuration import Configuration
from manila.share.drivers import generic
from manila import test
from manila.tests.db import fakes as db_fakes
from manila.tests import fake_compute
from manila.tests import fake_network
from manila.tests import fake_utils
from manila.tests import fake_volume
from manila import volume

from oslo.config import cfg

CONF = cfg.CONF


def fake_share(**kwargs):
    share = {
        'id': 'fakeid',
        'name': 'fakename',
        'size': 1,
        'share_proto': 'NFS',
        'export_location': '127.0.0.1:/mnt/nfs/volume-00002',
    }
    share.update(kwargs)
    return db_fakes.FakeModel(share)


def fake_snapshot(**kwargs):
    snapshot = {
        'id': 'fakesnapshotid',
        'share_name': 'fakename',
        'share_id': 'fakeid',
        'name': 'fakesnapshotname',
    'share_size': 1,
        'share_proto': 'NFS',
        'export_location': '127.0.0.1:/mnt/nfs/volume-00002',
    }
    snapshot.update(kwargs)
    return db_fakes.FakeModel(snapshot)


def fake_access(**kwargs):
    access = {
        'id': 'fakeaccid',
        'access_type': 'ip',
        'access_to': '10.0.0.2',
        'state': 'active',
    }
    access.update(kwargs)
    return db_fakes.FakeModel(access)


class GenericShareDriverTestCase(test.TestCase):
    """Tests GenericShareDriver."""

    def setUp(self):
        super(GenericShareDriverTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self.stubs)
        self._execute = fake_utils.fake_execute
        self._context = context.get_admin_context()

        self._helper_cifs = mock.Mock()
        self._helper_nfs = mock.Mock()
        self.fake_conf = Configuration(None)
        self._db = mock.Mock()
        self.stubs.Set(network.neutron.api, 'API',
                       mock.Mock(return_value=fake_network.API()))
        self.stubs.Set(volume, 'API',
                       mock.Mock(return_value=fake_volume.API()))
        self.stubs.Set(compute, 'API',
                       mock.Mock(return_value=fake_compute.API()))
        self._driver = generic.GenericShareDriver(self._db,
                                                  execute=self._execute,
                                                  configuration=self.fake_conf)
        self._driver._helpers = {
            'CIFS': self._helper_cifs,
            'NFS': self._helper_nfs,
        }

        self.share = fake_share()
        self.access = fake_access()
        self.snapshot = fake_snapshot()

    def tearDown(self):
        super(GenericShareDriverTestCase, self).tearDown()
        fake_utils.fake_execute_set_repliers([])
        fake_utils.fake_execute_clear_log()

    def test_do_setup(self):
        self.stubs.Set(self._driver,
                       '_setup_connectivity_with_service_instances',
                        mock.Mock())
        self.stubs.Set(self._driver,
                       '_get_service_network',
                        mock.Mock(return_value='fake network'))
        CONF.set_default('share_helpers', ['NFS=fakenfs'])
        self.stubs.Set(generic, 'importutils',
                       mock.Mock(return_value=self._helper_nfs))
        self._driver.do_setup(self._context)
        network.neutron.api.API.assert_called_once()
        volume.API.assert_called_once()
        compute.API.assert_called_once()
        self._driver._setup_connectivity_with_service_instances.\
                                                        assert_called_once()
        generic.importutils.import_class.assert_has_calls([
            mock.call('fakenfs')
        ])
        self.assertEqual(self._driver.service_network_id, 'fake network')
