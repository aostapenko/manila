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
        self._context = context.get_admin_context()
        self._execute = mock.Mock(return_value=('', ''))

        self._helper_cifs = mock.Mock()
        self._helper_nfs = mock.Mock()
        self.fake_conf = Configuration(None)
        self._db = mock.Mock()
        self._driver = generic.GenericShareDriver(self._db,
                                                  execute=self._execute,
                                                  configuration=self.fake_conf)
        self._driver.service_tenant_id = 'service tenant id'
        self._driver.service_network_id = 'service network id'
        self._driver.neutron_api = fake_network.API()
        self._driver.compute_api = fake_compute.API()
        self._driver.volume_api = fake_volume.API()
        self._driver.share_networks_locks = {}
        self._driver.share_networks_servers = {}
        self._driver.admin_context = self._context
        self.stubs.Set(generic, '_ssh_exec', mock.Mock())
        self.stubs.Set(generic, 'synchronized', mock.Mock(side_effect=
                                                          lambda f: f))
        self.stubs.Set(generic.os.path, 'exists', mock.Mock(return_value=True))
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
        net = fake_network.FakeNetwork()
        self.stubs.Set(self._driver.neutron_api, 'get_all_tenant_networks',
                mock.Mock(return_value=[]))
        self.stubs.Set(self._driver.neutron_api, 'network_create',
                mock.Mock(return_value=net))
        result = self._driver._get_service_network()
        self.assertEqual(result, net['id'])

    def test_get_service_network_ambiguos(self):
        net = fake_network.FakeNetwork(name=CONF.service_network_name)
        self.stubs.Set(self._driver.neutron_api, 'get_all_tenant_networks',
                mock.Mock(return_value=[net, net]))
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

    def _test_mount_device(self):
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

    def test_umount_device(self):
        self.stubs.Set(self._driver, '_get_mount_path',
                mock.Mock(return_value='fake_mount_path'))
        self._driver._unmount_device(self._context, self.share, 'fake_server')
        generic._ssh_exec.assert_called_once_with('fake_server',
            ['sudo', 'umount', 'fake_mount_path', ';', 'sudo', 'rmdir',
             'fake_mount_path'])

    def test_get_mount_path(self):
        result = self._driver._get_mount_path(self.share)
        self.assertEqual(result, os.path.join(CONF.share_mount_path,
                                              self.share['name']))

    def test_attach_volume_not_attached(self):
        fake_server = fake_compute.FakeServer()
        availiable_volume = fake_volume.FakeVolume()
        attached_volume = fake_volume.FakeVolume(status='in-use')
        self.stubs.Set(self._driver, '_get_device_path',
                       mock.Mock(return_value='fake_device_path'))
        self.stubs.Set(self._driver.compute_api, 'instance_volume_attach',
                       mock.Mock())
        self.stubs.Set(self._driver.volume_api, 'get',
                       mock.Mock(return_value=attached_volume))
        result = self._driver._attach_volume(self._context, self.share,
                                             fake_server, availiable_volume)
        self._driver._get_device_path.assert_called_once_with(self._context,
                                                              fake_server)
        self._driver.compute_api.instance_volume_attach.\
                assert_called_once_with(self._context, fake_server['id'],
                        availiable_volume['id'], 'fake_device_path')
        self._driver.volume_api.get.\
                assert_called_once_with(self._context, attached_volume['id'])
        self.assertEqual(result, attached_volume)

    def test_attach_volume_attached_correct(self):
        fake_server = fake_compute.FakeServer()
        attached_volume = fake_volume.FakeVolume(status='in-use')
        self.stubs.Set(self._driver.compute_api, 'instance_volumes_list',
                       mock.Mock(return_value=[attached_volume]))
        result = self._driver._attach_volume(self._context, self.share,
                                             fake_server, attached_volume)
        self.assertEqual(result, attached_volume)

    def test_attach_volume_attached_incorrect(self):
        fake_server = fake_compute.FakeServer()
        attached_volume = fake_volume.FakeVolume(status='in-use')
        anoter_volume = fake_volume.FakeVolume(id='fake_id2', status='in-use')
        self.stubs.Set(self._driver.compute_api, 'instance_volumes_list',
                       mock.Mock(return_value=[anoter_volume]))
        self.assertRaises(exception.ManilaException,
                          self._driver._attach_volume, self._context,
                          self.share, fake_server, attached_volume)

    def test_attach_volume_failed_attach(self):
        fake_server = fake_compute.FakeServer()
        availiable_volume = fake_volume.FakeVolume()
        self.stubs.Set(self._driver, '_get_device_path',
                       mock.Mock(return_value='fake_device_path'))
        self.stubs.Set(self._driver.compute_api, 'instance_volume_attach',
                       mock.Mock(side_effect=Exception))
        self.assertRaises(Exception, self._driver._attach_volume,
                          self._context, self.share, fake_server,
                          availiable_volume)

    def test_attach_volume_error(self):
        fake_server = fake_compute.FakeServer()
        availiable_volume = fake_volume.FakeVolume()
        error_volume = fake_volume.FakeVolume(status='error')
        self.stubs.Set(self._driver, '_get_device_path',
                       mock.Mock(return_value='fake_device_path'))
        self.stubs.Set(self._driver.compute_api, 'instance_volume_attach',
                       mock.Mock())
        self.stubs.Set(self._driver.volume_api, 'get',
                       mock.Mock(return_value=error_volume))
        self.assertRaises(exception.ManilaException,
                          self._driver._attach_volume,
                          self._context, self.share,
                          fake_server, availiable_volume)

    def test_get_volume(self):
        volume = fake_volume.FakeVolume(
                display_name=CONF.volume_name_template % self.share['id'])
        self.stubs.Set(self._driver.volume_api, 'get_all',
                       mock.Mock(return_value=[volume]))
        result = self._driver._get_volume(self._context, self.share['id'])
        self.assertEqual(result, volume)

    def test_get_volume_none(self):
        self.stubs.Set(self._driver.volume_api, 'get_all',
                       mock.Mock(return_value=[]))
        result = self._driver._get_volume(self._context, self.share['id'])
        self.assertEqual(result, None)

    def test_get_volume_error(self):
        volume = fake_volume.FakeVolume(
                display_name=CONF.volume_name_template % self.share['id'])
        self.stubs.Set(self._driver.volume_api, 'get_all',
                       mock.Mock(return_value=[volume, volume]))
        self.assertRaises(exception.ManilaException,
                self._driver._get_volume, self._context, self.share['id'])

    def test_get_volume_snapshot(self):
        volume_snapshot = fake_volume.FakeVolumeSnapshot(display_name=
                CONF.volume_snapshot_name_template % self.snapshot['id'])
        self.stubs.Set(self._driver.volume_api, 'get_all_snapshots',
                       mock.Mock(return_value=[volume_snapshot]))
        result = self._driver._get_volume_snapshot(self._context,
                self.snapshot['id'])
        self.assertEqual(result, volume_snapshot)

    def test_get_volume_snapshot_none(self):
        self.stubs.Set(self._driver.volume_api, 'get_all_snapshots',
                       mock.Mock(return_value=[]))
        result = self._driver._get_volume_snapshot(self._context,
                self.share['id'])
        self.assertEqual(result, None)

    def test_get_volume_snapshot_error(self):
        volume_snapshot = fake_volume.FakeVolumeSnapshot(display_name=
                CONF.volume_snapshot_name_template % self.snapshot['id'])
        self.stubs.Set(self._driver.volume_api, 'get_all_snapshots',
                mock.Mock(return_value=[volume_snapshot, volume_snapshot]))
        self.assertRaises(exception.ManilaException,
            self._driver._get_volume_snapshot, self._context, self.share['id'])

    def test_detach_volume(self):
        fake_server = fake_compute.FakeServer()
        availiable_volume = fake_volume.FakeVolume()
        attached_volume = fake_volume.FakeVolume(status='in-use')
        self.stubs.Set(self._driver, '_get_volume',
                       mock.Mock(return_value=attached_volume))
        self.stubs.Set(self._driver.compute_api, 'instance_volumes_list',
                       mock.Mock(return_value=[attached_volume]))
        self.stubs.Set(self._driver.compute_api, 'instance_volume_detach',
                       mock.Mock())
        self.stubs.Set(self._driver.volume_api, 'get',
                       mock.Mock(return_value=availiable_volume))
        self._driver._detach_volume(self._context, self.share, fake_server)
        self._driver.compute_api.instance_volume_detach.\
                assert_called_once_with(self._context, fake_server['id'],
                                        availiable_volume['id'])
        self._driver.volume_api.get.\
                assert_called_once_with(self._context, availiable_volume['id'])

    def test_detach_volume_detached(self):
        fake_server = fake_compute.FakeServer()
        availiable_volume = fake_volume.FakeVolume()
        attached_volume = fake_volume.FakeVolume(status='in-use')
        self.stubs.Set(self._driver, '_get_volume',
                       mock.Mock(return_value=attached_volume))
        self.stubs.Set(self._driver.compute_api, 'instance_volumes_list',
                       mock.Mock(return_value=[]))
        self.stubs.Set(self._driver.volume_api, 'get',
                       mock.Mock(return_value=availiable_volume))
        self.stubs.Set(self._driver.compute_api, 'instance_volume_detach',
                       mock.Mock())
        self._driver._detach_volume(self._context, self.share, fake_server)
        self.assertFalse(self._driver.volume_api.get.called)
        self.assertFalse(self._driver.compute_api.
                                        instance_volume_detach.called)

    def test_get_device_path_01(self):
        fake_server = fake_compute.FakeServer()
        vol_list = [[], [fake_volume.FakeVolume(device='/dev/vdc')],
                [fake_volume.FakeVolume(device='/dev/vdd')]]
        self.stubs.Set(self._driver.compute_api, 'instance_volumes_list',
                mock.Mock(side_effect=lambda x, y: vol_list.pop()))
        result = self._driver._get_device_path(self._context, fake_server)
        self.assertEqual(result, '/dev/vdb')

    def test_get_device_path_02(self):
        fake_server = fake_compute.FakeServer()
        vol_list = [[fake_volume.FakeVolume(device='/dev/vdb')],
                [fake_volume.FakeVolume(device='/dev/vdb'),
                    fake_volume.FakeVolume(device='/dev/vdd')]]
        self.stubs.Set(self._driver.compute_api, 'instance_volumes_list',
                mock.Mock(side_effect=lambda x, y: vol_list.pop()))
        result = self._driver._get_device_path(self._context, fake_server)
        self.assertEqual(result, '/dev/vdc')

    def test_get_service_instance_name(self):
        result = self._driver._get_service_instance_name(self.share)
        self.assertEqual(result, CONF.service_instance_name_template %
                self.share['share_network_id'])

    def test_get_server_ip(self):
        fake_server = fake_compute.FakeServer(networks=
                {CONF.service_network_name: '10.254.0.1'})
        result = self._driver._get_server_ip(fake_server)
        self.assertEqual(result,
                fake_server['networks'][CONF.service_network_name][0])

    def test_get_server_ip_none(self):
        fake_server = fake_compute.FakeServer()
        result = self._driver._get_server_ip(fake_server)
        self.assertEqual(result, None)

    def test_get_service_instance(self):
        fake_server = fake_compute.FakeServer()
        self.stubs.Set(self._driver.compute_api, 'server_list',
                       mock.Mock(return_value=[]))
        self.stubs.Set(self._driver, '_create_service_instance',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(self._driver, '_get_ssh_pool',
                       mock.Mock(return_value=mock.Mock()))
        result = self._driver._get_service_instance(self._context, self.share)
        self._driver._get_ssh_pool.assert_called_once_with(fake_server)
        self._driver._create_service_instance.assert_called_once()
        self.assertEqual(result, fake_server)

    def test_get_service_instance_existed(self):
        fake_server = fake_compute.FakeServer()
        self.stubs.Set(self._driver.compute_api, 'server_list',
                       mock.Mock(return_value=[fake_server]))
        self.stubs.Set(self._driver, '_get_ssh_pool',
                       mock.Mock(return_value=mock.Mock()))
        result = self._driver._get_service_instance(self._context, self.share)
        self._driver._get_ssh_pool.assert_called_once_with(fake_server)
        self.assertEqual(result, fake_server)

    def test_get_service_instance_existed_non_active(self):
        fake_error_server = fake_compute.FakeServer(status='error')
        fake_new_server = fake_compute.FakeServer(status='error')
        self.stubs.Set(self._driver.compute_api, 'server_delete', mock.Mock())
        self.stubs.Set(self._driver.compute_api, 'server_list',
                       mock.Mock(return_value=[fake_error_server]))
        self.stubs.Set(self._driver, '_create_service_instance',
                       mock.Mock(return_value=fake_new_server))
        self.stubs.Set(self._driver.compute_api, 'server_get',
                       mock.Mock(side_effect=Exception('could not be found')))
        self.stubs.Set(self._driver, '_get_ssh_pool',
                       mock.Mock(return_value=mock.Mock()))
        result = self._driver._get_service_instance(self._context, self.share)
        self._driver.compute_api.server_get.\
                assert_called_once_with(self._context, fake_error_server['id'])
        self._driver.compute_api.server_delete.\
                assert_called_once_with(self._context, fake_error_server['id'])
        self._driver._create_service_instance.assert_called_once()
        self._driver._get_ssh_pool.assert_called_once_with(fake_new_server)
        self.assertEqual(result, fake_new_server)

    def test_get_service_instance_existed_restore(self):
        fake_server = fake_compute.FakeServer(share_network_id='fake_id',
                        ip='fake_ip', ssh_pool='fake_pool', ssh='fake_ssh')
        self._driver.share_networks_servers[self.share['share_network_id']] = \
                fake_server
        self.stubs.Set(self._driver.compute_api, 'server_list',
                       mock.Mock(return_value=[fake_server]))
        self.stubs.Set(self._driver, '_get_ssh_pool',
                       mock.Mock(return_value=mock.Mock()))
        result = self._driver._get_service_instance(self._context, self.share)
        self.assertFalse(self._driver._get_ssh_pool.called)
        self.assertEqual(result, fake_server)

    def test_get_key_create_new(self):
        fake_keypair = fake_compute.FakeKeypair(name=
                                            CONF.manila_service_keypair_name)
        self.stubs.Set(self._driver.compute_api, 'keypair_list',
                       mock.Mock(return_value=[]))
        self.stubs.Set(self._driver.compute_api, 'keypair_import',
                       mock.Mock(return_value=fake_keypair))
        result = self._driver._get_key(self._context)
        self.assertEqual(result, fake_keypair.name)
        self._driver.compute_api.keypair_list.assert_called_once()
        self._driver.compute_api.keypair_import.assert_called_once()

    def test_get_key_exists(self):
        fake_keypair = fake_compute.FakeKeypair(
                                name=CONF.manila_service_keypair_name,
                                public_key='fake_public_key')
        self.stubs.Set(self._driver.compute_api, 'keypair_list',
                       mock.Mock(return_value=[fake_keypair]))
        self.stubs.Set(self._driver.compute_api, 'keypair_import',
                       mock.Mock(return_value=fake_keypair))
        self.stubs.Set(self._driver, '_execute',
                       mock.Mock(return_value=('fake_public_key', '')))
        result = self._driver._get_key(self._context)
        self._driver.compute_api.keypair_list.assert_called_once()
        self.assertFalse(self._driver.compute_api.keypair_import.called)
        self.assertEqual(result, fake_keypair.name)

    def test_get_key_exists_recreate(self):
        fake_keypair = fake_compute.FakeKeypair(
                                name=CONF.manila_service_keypair_name,
                                public_key='fake_public_key1')
        self.stubs.Set(self._driver.compute_api, 'keypair_list',
                       mock.Mock(return_value=[fake_keypair]))
        self.stubs.Set(self._driver.compute_api, 'keypair_import',
                       mock.Mock(return_value=fake_keypair))
        self.stubs.Set(self._driver.compute_api, 'keypair_delete', mock.Mock())
        self.stubs.Set(self._driver, '_execute',
                       mock.Mock(return_value=('fake_public_key2', '')))
        result = self._driver._get_key(self._context)
        self._driver.compute_api.keypair_list.assert_called_once()
        self._driver.compute_api.keypair_delete.assert_called_once()
        self._driver.compute_api.keypair_import.\
                assert_called_once_with(self._context, fake_keypair.name,
                                        'fake_public_key2')
        self.assertEqual(result, fake_keypair.name)

    def test_get_service_image(self):
        fake_image1 = fake_compute.FakeImage(name=CONF.service_image_name)
        fake_image2 = fake_compute.FakeImage(name='another-image')
        self.stubs.Set(self._driver.compute_api, 'image_list',
                       mock.Mock(return_value=[fake_image1, fake_image2]))
        result = self._driver._get_service_image()
        self.assertEqual(result, fake_image1.id)

    def test_get_service_image_not_found(self):
        self.stubs.Set(self._driver.compute_api, 'image_list',
                       mock.Mock(return_value=[]))
        self.assertRaises(exception.ManilaException,
                          self._driver._get_service_image)

    def test_get_service_image_ambiguous(self):
        fake_image = fake_compute.FakeImage(name=CONF.service_image_name)
        self.stubs.Set(self._driver.compute_api, 'image_list',
                       mock.Mock(return_value=[fake_image, fake_image]))
        self.assertRaises(exception.ManilaException,
                          self._driver._get_service_image)

    def test_create_service_instance(self):
        fake_server = fake_compute.FakeServer()
        fake_port = fake_network.FakePort()
        self.stubs.Set(self._driver, '_get_service_image',
                       mock.Mock(return_value='fake_image_id'))
        self.stubs.Set(self._driver, '_get_key',
                       mock.Mock(return_value='fake_key_name'))
        self.stubs.Set(self._driver, '_setup_network_for_instance',
                       mock.Mock(return_value=fake_port))
        self.stubs.Set(self._driver,
                       '_setup_connectivity_with_service_instances',
                       mock.Mock())
        self.stubs.Set(self._driver.compute_api, 'server_create',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(generic.socket, 'socket', mock.Mock())
        result = self._driver._create_service_instance(self._context,
                                        'instance_name', self.share, None)
        self._driver._get_service_image.assert_called_once()
        self._driver._get_key.assert_called_once()
        self._driver._setup_network_for_instance.assert_called_once()
        self._driver._setup_connectivity_with_service_instances.\
                assert_called_once()
        self._driver.compute_api.server_create.assert_called_once_with(
                self._context, 'instance_name', 'fake_image_id',
                CONF.service_instance_flavor_id, 'fake_key_name', None, None,
                nics=[{'port-id': fake_port['id']}])
        generic.socket.socket.assert_called_once()
        self.assertEqual(result, fake_server)

    def test_create_service_instance_error(self):
        fake_server = fake_compute.FakeServer(status='ERROR')
        fake_port = fake_network.FakePort()
        self.stubs.Set(self._driver, '_get_service_image',
                       mock.Mock(return_value='fake_image_id'))
        self.stubs.Set(self._driver, '_get_key',
                       mock.Mock(return_value='fake_key_name'))
        self.stubs.Set(self._driver, '_setup_network_for_instance',
                       mock.Mock(return_value=fake_port))
        self.stubs.Set(self._driver,
                       '_setup_connectivity_with_service_instances',
                       mock.Mock())
        self.stubs.Set(self._driver.compute_api, 'server_create',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(self._driver.compute_api, 'server_get',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(generic.socket, 'socket', mock.Mock())
        self.assertRaises(exception.ManilaException,
                self._driver._create_service_instance, self._context,
                'instance_name', self.share, None)
        self._driver.compute_api.server_create.assert_called_once()
        self.assertFalse(self._driver.compute_api.server_get.called)
        self.assertFalse(generic.socket.socket.called)

    def test_create_service_instance_failed_setup_connectivity(self):
        fake_server = fake_compute.FakeServer(status='ERROR')
        fake_port = fake_network.FakePort()
        self.stubs.Set(self._driver, '_get_service_image',
                       mock.Mock(return_value='fake_image_id'))
        self.stubs.Set(self._driver, '_get_key',
                       mock.Mock(return_value='fake_key_name'))
        self.stubs.Set(self._driver, '_setup_network_for_instance',
                       mock.Mock(return_value=fake_port))
        self.stubs.Set(self._driver,
                       '_setup_connectivity_with_service_instances',
                       mock.Mock(side_effect=Exception))
        self.stubs.Set(self._driver.neutron_api, 'delete_port', mock.Mock())
        self.stubs.Set(self._driver.compute_api, 'server_create',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(self._driver.compute_api, 'server_get',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(generic.socket, 'socket', mock.Mock())
        self.assertRaises(Exception, self._driver._create_service_instance,
                self._context, 'instance_name', self.share, None)
        self._driver.neutron_api.delete_port.\
                assert_called_once_with(fake_port['id'])
        self.assertFalse(self._driver.compute_api.server_create.called)
        self.assertFalse(self._driver.compute_api.server_get.called)
        self.assertFalse(generic.socket.socket.called)

    def test_create_service_instance_no_key_and_password(self):
        self.stubs.Set(self._driver, '_get_service_image',
                       mock.Mock(return_value='fake_image_id'))
        self.stubs.Set(self._driver, '_get_key',
                       mock.Mock(return_value=None))
        self.assertRaises(exception.ManilaException,
                self._driver._create_service_instance, self._context,
                'instance_name', self.share, None)

    def test_setup_network_for_instance(self):
        fake_service_net = fake_network.FakeNetwork(subnets=[])
        fake_service_subnet = fake_network.\
                FakeSubnet(name=self.share['share_network_id'])
        fake_router = fake_network.FakeRouter()
        fake_port = fake_network.FakePort()
        self.stubs.Set(self._driver.neutron_api, 'get_network',
                mock.Mock(return_value=fake_service_net))
        self.stubs.Set(self._driver.neutron_api, 'subnet_create',
                mock.Mock(return_value=fake_service_subnet))
        self.stubs.Set(self._driver.db, 'share_network_get',
                mock.Mock(return_value='fake_share_network'))
        self.stubs.Set(self._driver, '_get_private_router',
                mock.Mock(return_value=fake_router))
        self.stubs.Set(self._driver.neutron_api, 'router_add_interface',
                mock.Mock())
        self.stubs.Set(self._driver.neutron_api, 'create_port',
                mock.Mock(return_value=fake_port))
        self.stubs.Set(self._driver, '_get_cidr_for_subnet',
                mock.Mock(return_value='fake_cidr'))

        result = self._driver._setup_network_for_instance(self._context,
                self.share, None)

        self._driver.neutron_api.get_network.\
                assert_called_once_with(self._driver.service_network_id)
        self._driver._get_private_router.\
                assert_called_once_with('fake_share_network')
        self._driver.neutron_api.router_add_interface.\
                assert_called_once_with('fake_router_id', 'fake_subnet_id')
        self._driver.neutron_api.subnet_create.assert_called_once_with(
                                         self._driver.service_tenant_id,
                                         self._driver.service_network_id,
                                         self.share['share_network_id'],
                                         'fake_cidr')
        self._driver._get_cidr_for_subnet.assert_called_once_with([])
        self.assertEqual(result, fake_port)
