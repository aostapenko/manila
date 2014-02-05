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
"""Unit tests for the Generic driver module."""

import copy
import mock
import os

from manila import context

from manila import compute
from manila import exception
from manila.network.neutron import api as neutron
from manila import volume

from manila.share.configuration import Configuration
from manila.share.drivers import generic
from manila import test
from manila.tests.db import fakes as db_fakes
from manila.tests import fake_compute
from manila.tests import fake_network
from manila.tests import fake_utils
from manila.tests import fake_volume

from oslo.config import cfg

CONF = cfg.CONF


def fake_share(**kwargs):
    share = {
        'id': 'fakeid',
        'name': 'fakename',
        'size': 1,
        'share_proto': 'NFS',
        'share_network_id': 'fake share network id',
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
        self._driver = generic.GenericShareDriver(self._db,
                                                  execute=self._execute,
                                                  configuration=self.fake_conf)
        self._driver.service_tenant_id = 'service tenant id'
        self._driver.service_tenant_id = 'service tenant id'
        self._driver.neutron_api = fake_network.API()
        self._driver.compute_api = fake_compute.API()
        self._driver.volume_api = fake_volume.API()
        self._driver.share_networks_locks = {}
        self._driver.share_networks_servers = {}
        self.stubs.Set(generic, '_ssh_exec', mock.Mock())
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
        self.stubs.Set(neutron, 'API', mock.Mock())
        self.stubs.Set(volume, 'API', mock.Mock())
        self.stubs.Set(compute, 'API', mock.Mock())
        self.stubs.Set(self._driver,
                       '_setup_connectivity_with_service_instances',
                       mock.Mock())
        self.stubs.Set(self._driver,
                       '_get_service_network',
                       mock.Mock(return_value='fake network id'))
        self.stubs.Set(self._driver, '_setup_helpers', mock.Mock())
        self._driver.do_setup(self._context)
        neutron.API.assert_called_once()
        volume.API.assert_called_once()
        compute.API.assert_called_once()
        self._driver._setup_helpers.assert_called_once()
        self._driver._setup_connectivity_with_service_instances.\
                                                        assert_called_once()
        self.assertEqual(self._driver.service_network_id, 'fake network id')

    def test_do_setup_exception(self):
        self.stubs.Set(neutron, 'API', mock.Mock())
        neutron.API.return_value = fake_network.API()
        self.stubs.Set(volume, 'API', mock.Mock())
        self.stubs.Set(compute, 'API', mock.Mock())
        self.stubs.Set(neutron.API, 'admin_tenant_id', mock.Mock())
        neutron.API.admin_tenant_id.side_effect = Exception
        self.assertRaises(exception.ManilaException,
                          self._driver.do_setup, self._context)

    def test_get_service_network_net_exists(self):
        net1 = copy.copy(fake_network.API.network)
        net2 = copy.copy(fake_network.API.network)
        net1['name'] = CONF.service_network_name
        net1['id'] = 'fake service network id'
        self.stubs.Set(self._driver.neutron_api, 'get_all_tenant_networks',
                mock.Mock(return_value=[net1, net2]))
        result = self._driver._get_service_network()
        self.assertEqual(result, net1['id'])

    def test_get_service_network_net_does_not_exists(self):
        net = fake_network.API.network
        self.stubs.Set(self._driver.neutron_api, 'get_all_tenant_networks',
                mock.Mock(return_value=[]))
        result = self._driver._get_service_network()
        self.assertEqual(result, net['id'])

    def test_get_service_network_ambiguos(self):
        net1 = copy.copy(fake_network.API.network)
        net2 = copy.copy(fake_network.API.network)
        net1['name'] = CONF.service_network_name
        net2['name'] = CONF.service_network_name
        self.stubs.Set(self._driver.neutron_api, 'get_all_tenant_networks',
                mock.Mock(return_value=[net1, net2]))
        self.assertRaises(exception.ManilaException,
                          self._driver._get_service_network)

    def test_setup_helpers(self):
        CONF.set_default('share_helpers', ['NFS=fakenfs'])
        self.stubs.Set(generic.importutils, 'import_class',
                       mock.Mock(return_value=self._helper_nfs))
        self._driver._setup_helpers()
        generic.importutils.import_class.assert_has_calls([
            mock.call('fakenfs')
        ])
        self._helper_nfs.assert_called_once_with(self._execute,
                                             self.fake_conf,
                                             self._driver.share_networks_locks)
        self.assertEqual(len(self._driver._helpers), 1)

    def test_create_share(self):
        self._helper_nfs.create_export.return_value = 'fakelocation'
        methods = ('_get_service_instance', '_allocate_container',
                '_attach_volume', '_format_device', '_mount_device')
        for method in methods:
            self.stubs.Set(self._driver, method, mock.Mock())
        result = self._driver.create_share(self._context, self.share)
        for method in methods:
            getattr(self._driver, method).assert_called_once()
        self.assertEqual(result, 'fakelocation')

    def test_create_share_exception(self):
        share = fake_share(share_network_id=None)
        self.assertRaises(exception.ManilaException, self._driver.create_share,
                          self._context, share)

    def test_format_device(self):
        volume = {'mountpoint': 'fake_mount_point'}
        self._driver._format_device('fake_server', volume)
        generic._ssh_exec.assert_called_once_with('fake_server',
                ['sudo', 'mkfs.ext4', volume['mountpoint']])

    def test_mount_device(self):
        volume = {'mountpoint': 'fake_mount_point'}
        self.stubs.Set(self._driver, '_get_mount_path',
                mock.Mock(return_value='fake_mount_path'))
        self._driver._mount_device(self._context, self.share, 'fake_server',
                                   volume)
        generic._ssh_exec.assert_has_calls([
            mock.call('fake_server', ['sudo', 'mkdir', '-p',
                                      'fake_mount_path',
                                      ';', 'sudo', 'mount',
                                      volume['mountpoint'],
                                      'fake_mount_path']),
            mock.call('fake_server', ['sudo', 'chmod', '777',
                      'fake_mount_path'])
            ])

    def test_mount_device_exception_01(self):
        volume = {'mountpoint': 'fake_mount_point'}
        generic._ssh_exec.side_effect = [Exception('already mounted'), None]
        self.stubs.Set(self._driver, '_get_mount_path',
                mock.Mock(return_value='fake_mount_path'))
        self._driver._mount_device(self._context, self.share, 'fake_server',
                                   volume)
        generic._ssh_exec.assert_has_calls([
            mock.call('fake_server', ['sudo', 'mkdir', '-p',
                                      'fake_mount_path',
                                      ';', 'sudo', 'mount',
                                      volume['mountpoint'],
                                      'fake_mount_path']),
            mock.call('fake_server', ['sudo', 'chmod', '777',
                      'fake_mount_path'])
            ])

    def test_mount_device_exception_02(self):
        volume = {'mountpoint': 'fake_mount_point'}
        generic._ssh_exec.side_effect = Exception
        self.stubs.Set(self._driver, '_get_mount_path',
                mock.Mock(return_value='fake_mount_path'))
        self.assertRaises(Exception, self._driver._mount_device,
                          self._context, self.share, 'fake_server', volume)
