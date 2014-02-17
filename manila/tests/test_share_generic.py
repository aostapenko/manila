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
from manila import volume

from manila.share.configuration import Configuration
from manila.share.drivers import generic
from manila import test
from manila.tests.db import fakes as db_fakes
from manila.tests import fake_compute
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
        self._driver.compute_api = fake_compute.API()
        self._driver.volume_api = fake_volume.API()
        self._driver.share_networks_locks = {}
        self._driver.get_service_instance = mock.Mock()
        self._driver.share_networks_servers = {}
        self._driver.admin_context = self._context
        self._driver.instance_manager = mock.Mock()
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

    def test_do_setup(self):
        self.stubs.Set(volume, 'API', mock.Mock())
        self.stubs.Set(compute, 'API', mock.Mock())
        self.stubs.Set(generic, 'instance', mock.Mock())
        self.stubs.Set(self._driver, '_setup_helpers', mock.Mock())
        self._driver.do_setup(self._context)
        volume.API.assert_called_once()
        compute.API.assert_called_once()
        self._driver._setup_helpers.assert_called_once()

    def test_setup_helpers(self):
        self._driver._helpers = {}
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
        methods = ('get_service_instance', '_allocate_container',
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
        generic._ssh_exec.side_effect = [
               exception.ProcessExecutionError(stderr='already mounted'), None]
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
        generic._ssh_exec.side_effect = exception.ManilaException
        self.stubs.Set(self._driver, '_get_mount_path',
                mock.Mock(return_value='fake_mount_path'))
        self.assertRaises(exception.ManilaException,
                          self._driver._mount_device,
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
                mock.Mock(side_effect=exception.ManilaException))
        self.assertRaises(exception.ManilaException,
                          self._driver._attach_volume,
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

    def test_allocate_container(self):
        fake_vol = fake_volume.FakeVolume()
        self.stubs.Set(self._driver.volume_api, 'create',
                       mock.Mock(return_value=fake_vol))

        result = self._driver._allocate_container(self._context, self.share)
        self.assertEqual(result, fake_vol)
        self._driver.volume_api.create.assert_called_once_with(self._context,
                                self.share['size'],
                                CONF.volume_name_template % self.share['id'],
                                '',
                                snapshot=None)

    def test_allocate_container_with_snaphot(self):
        fake_vol = fake_volume.FakeVolume()
        fake_vol_snap = fake_volume.FakeVolumeSnapshot()
        self.stubs.Set(self._driver, '_get_volume_snapshot',
                       mock.Mock(return_value=fake_vol_snap))
        self.stubs.Set(self._driver.volume_api, 'create',
                       mock.Mock(return_value=fake_vol))

        result = self._driver._allocate_container(self._context,
                                                  self.share,
                                                  self.snapshot)
        self.assertEqual(result, fake_vol)
        self._driver.volume_api.create.assert_called_once_with(self._context,
                                self.share['size'],
                                CONF.volume_name_template % self.share['id'],
                                '',
                                snapshot=fake_vol_snap)

    def test_allocate_container_error(self):
        fake_vol = fake_volume.FakeVolume(status='error')
        self.stubs.Set(self._driver.volume_api, 'create',
                       mock.Mock(return_value=fake_vol))

        self.assertRaises(exception.ManilaException,
                          self._driver._allocate_container,
                          self._context,
                          self.share)

    def test_deallocate_container(self):
        fake_vol = fake_volume.FakeVolume()
        self.stubs.Set(self._driver, '_get_volume',
                       mock.Mock(return_value=fake_vol))
        self.stubs.Set(self._driver.volume_api, 'delete', mock.Mock())
        self.stubs.Set(self._driver.volume_api, 'get', mock.Mock(
               side_effect=exception.VolumeNotFound(volume_id=fake_vol['id'])))

        self._driver._deallocate_container(self._context, self.share)

        self._driver._get_volume.assert_called_once()
        self._driver.volume_api.delete.assert_called_once()
        self._driver.volume_api.get.assert_called_once()

    def test_create_share_from_snapshot(self):
        self._helper_nfs.create_export.return_value = 'fakelocation'
        methods = ('get_service_instance', '_allocate_container',
                '_attach_volume', '_mount_device')
        for method in methods:
            self.stubs.Set(self._driver, method, mock.Mock())
        result = self._driver.create_share_from_snapshot(self._context,
                                           self.share,
                                           self.snapshot)
        for method in methods:
            getattr(self._driver, method).assert_called_once()
        self.assertEqual(result, 'fakelocation')

    def test_delete_share(self):
        fake_server = fake_compute.FakeServer()
        self.stubs.Set(self._driver, 'get_service_instance',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(self._driver, '_unmount_device', mock.Mock())
        self.stubs.Set(self._driver, '_detach_volume', mock.Mock())
        self.stubs.Set(self._driver, '_deallocate_container', mock.Mock())

        self._driver.delete_share(self._context, self.share)

        self._driver.get_service_instance.assert_called_once()
        self._driver._unmount_device.assert_called_once()
        self._driver._detach_volume.assert_called_once()
        self._driver._deallocate_container.assert_called_once()

    def test_create_snapshot(self):
        fake_vol = fake_volume.FakeVolume()
        fake_vol_snap = fake_volume.FakeVolumeSnapshot()
        self.stubs.Set(self._driver, '_get_volume',
                       mock.Mock(return_value=fake_vol))
        self.stubs.Set(self._driver.volume_api, 'create_snapshot_force',
                       mock.Mock(return_value=fake_vol_snap))

        self._driver.create_snapshot(self._context, self.snapshot)

        self._driver._get_volume.assert_called_once()
        self._driver.volume_api.create_snapshot_force.assert_called_once_with(
                     self._context,
                     fake_vol['id'],
                     CONF.volume_snapshot_name_template % self.snapshot['id'],
                     ''
                )

    def test_delete_snapshot(self):
        fake_vol_snap = fake_volume.FakeVolumeSnapshot()
        self.stubs.Set(self._driver, '_get_volume_snapshot',
                       mock.Mock(return_value=fake_vol_snap))
        self.stubs.Set(self._driver.volume_api, 'delete_snapshot', mock.Mock())
        self.stubs.Set(self._driver.volume_api, 'get_snapshot',
                mock.Mock(side_effect=exception.VolumeSnapshotNotFound(
                    snapshot_id=fake_vol_snap['id'])))

        self._driver.delete_snapshot(self._context, fake_vol_snap)

        self._driver._get_volume_snapshot.assert_called_once()
        self._driver.volume_api.delete_snapshot.assert_called_once()
        self._driver.volume_api.get_snapshot.assert_called_once()

    def test_ensure_share(self):
        self._helper_nfs.create_export.return_value = 'fakelocation'
        methods = ('get_service_instance', '_get_volume',
                '_attach_volume', '_mount_device')
        for method in methods:
            self.stubs.Set(self._driver, method, mock.Mock())
        self._driver.ensure_share(self._context, self.share)
        for method in methods:
            getattr(self._driver, method).assert_called_once()

    def test_allow_access(self):
        fake_server = fake_compute.FakeServer()
        access = {'access_type': 'ip', 'access_to': 'fake_dest'}
        self.stubs.Set(self._driver, 'get_service_instance',
                       mock.Mock(return_value=fake_server))
        self._driver.allow_access(self._context, self.share, access)

        self._driver.get_service_instance.assert_called_once()
        self._driver._helpers[self.share['share_proto']].\
                allow_access.assert_called_once_with(fake_server,
                                                     self.share['name'],
                                                     access['access_type'],
                                                     access['access_to'])

    def test_deny_access(self):
        fake_server = fake_compute.FakeServer()
        access = {'access_type': 'ip', 'access_to': 'fake_dest'}
        self.stubs.Set(self._driver, 'get_service_instance',
                       mock.Mock(return_value=fake_server))
        self._driver.deny_access(self._context, self.share, access)

        self._driver.get_service_instance.assert_called_once()
        self._driver._helpers[self.share['share_proto']].\
                deny_access.assert_called_once_with(fake_server,
                                                    self.share['name'],
                                                    access['access_type'],
                                                    access['access_to'])


class NFSHelperTestCase(test.TestCase):
    """Test case for NFS helper of generic driver."""

    def setUp(self):
        super(NFSHelperTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self.stubs)
        self.fake_conf = Configuration(None)
        self.stubs.Set(generic, '_ssh_exec', mock.Mock(return_value=('', '')))
        self._execute = mock.Mock(return_value=('', ''))
        self._helper = generic.NFSHelper(self._execute, self.fake_conf, {})

    def test_create_export(self):
        fake_server = fake_compute.FakeServer(ip='10.254.0.3')
        ret = self._helper.create_export(fake_server, 'volume-00001')
        expected_location = ':'.join([fake_server['ip'],
            os.path.join(CONF.share_mount_path, 'volume-00001')])
        self.assertEqual(ret, expected_location)

    def test_allow_access(self):
        fake_server = fake_compute.FakeServer(ip='10.254.0.3')
        self._helper.allow_access(fake_server, 'volume-00001',
                                  'ip', '10.0.0.2')
        local_path = os.path.join(CONF.share_mount_path, 'volume-00001')
        generic._ssh_exec.assert_has_calls([
            mock.call(fake_server, ['sudo', 'exportfs']),
            mock.call(fake_server, ['sudo', 'exportfs', '-o',
                                    'rw,no_subtree_check',
                                    ':'.join(['10.0.0.2', local_path])])
            ])

    def test_allow_access_no_ip(self):
        self.assertRaises(exception.InvalidShareAccess,
                          self._helper.allow_access, 'fake_server', 'share0',
                          'fake', 'fakerule')

    def test_deny_access(self):
        fake_server = fake_compute.FakeServer(ip='10.254.0.3')
        local_path = os.path.join(CONF.share_mount_path, 'volume-00001')
        self._helper.deny_access(fake_server, 'volume-00001', 'ip', '10.0.0.2')
        export_string = ':'.join(['10.0.0.2', local_path])
        expected_exec = ['sudo', 'exportfs', '-u', export_string]
        generic._ssh_exec.assert_called_once_with(fake_server, expected_exec)


class CIFSHelperTestCase(test.TestCase):
    """Test case for CIFS helper of generic driver."""

    def setUp(self):
        super(CIFSHelperTestCase, self).setUp()
        self.fake_conf = Configuration(None)
        self.stubs.Set(generic, '_ssh_exec', mock.Mock(return_value=('', '')))
        self._execute = mock.Mock(return_value=('', ''))
        self._helper = generic.CIFSHelper(self._execute, self.fake_conf, {})

    def test_create_export(self):
        fake_server = fake_compute.FakeServer(ip='10.254.0.3',
                                    share_network_id='fake_share_network_id')
        self.stubs.Set(self._helper, '_update_config', mock.Mock())
        self.stubs.Set(self._helper, '_write_remote_config', mock.Mock())
        self.stubs.Set(self._helper, '_restart_service', mock.Mock())
        self.stubs.Set(self._helper, '_get_local_config', mock.Mock())
        self.stubs.Set(generic.ConfigParser, 'ConfigParser', mock.Mock())

        ret = self._helper.create_export(fake_server, 'volume-00001',
                                         recreate=True)
        self._helper._get_local_config.\
                assert_called_once_with(fake_server['share_network_id'])
        self._helper._update_config.assert_called_once()
        self._helper._write_remote_config.assert_called_once()
        self._helper._restart_service.assert_called_once()
        expected_location = '//%s/%s' % (fake_server['ip'], 'volume-00001')
        self.assertEqual(ret, expected_location)

    def test_remove_export(self):
        fake_server = fake_compute.FakeServer(ip='10.254.0.3',
                                    share_network_id='fake_share_network_id')
        self.stubs.Set(generic.ConfigParser, 'ConfigParser', mock.Mock())
        self.stubs.Set(self._helper, '_get_local_config', mock.Mock())
        self.stubs.Set(self._helper, '_update_config', mock.Mock())
        self.stubs.Set(self._helper, '_write_remote_config', mock.Mock())
        self._helper.remove_export(fake_server, 'volume-00001')
        self._helper._get_local_config.assert_called_once()
        self._helper._update_config.assert_called_once()
        self._helper._write_remote_config.assert_called_once()
        generic._ssh_exec.assert_called_once_with(fake_server,
                ['sudo', 'smbcontrol', 'all', 'close-share', 'volume-00001'])

    def test_allow_access(self):
        class FakeParser(object):
            def read(self, *args, **kwargs):
                pass

            def get(self, *args, **kwargs):
                return ''

            def set(self, *args, **kwargs):
                pass

        fake_server = fake_compute.FakeServer(ip='10.254.0.3',
                                    share_network_id='fake_share_network_id')
        self.stubs.Set(generic.ConfigParser, 'ConfigParser', FakeParser)
        self.stubs.Set(self._helper, '_get_local_config', mock.Mock())
        self.stubs.Set(self._helper, '_update_config', mock.Mock())
        self.stubs.Set(self._helper, '_write_remote_config', mock.Mock())
        self.stubs.Set(self._helper, '_restart_service', mock.Mock())

        self._helper.allow_access(fake_server, 'volume-00001',
                                  'ip', '10.0.0.2')
        self._helper._get_local_config.assert_called_once()
        self._helper._update_config.assert_called_once()
        self._helper._write_remote_config.assert_called_once()
        self._helper._restart_service.assert_called_once()

    def test_deny_access(self):
        fake_server = fake_compute.FakeServer(ip='10.254.0.3',
                                    share_network_id='fake_share_network_id')
        self.stubs.Set(generic.ConfigParser, 'ConfigParser', mock.Mock())
        self.stubs.Set(self._helper, '_get_local_config', mock.Mock())
        self.stubs.Set(self._helper, '_update_config', mock.Mock())
        self.stubs.Set(self._helper, '_write_remote_config', mock.Mock())
        self.stubs.Set(self._helper, '_restart_service', mock.Mock())

        self._helper.deny_access(fake_server, 'volume-00001',
                                  'ip', '10.0.0.2')
        self._helper._get_local_config.assert_called_once()
        self._helper._update_config.assert_called_once()
        self._helper._write_remote_config.assert_called_once()
        self._helper._restart_service.assert_called_once()
