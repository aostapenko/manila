# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 Mirantis, Inc.
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

import mock

from cinderclient import exceptions as cinder_exception

from manila import context
from manila import exception
from manila import test
from manila.volume import cinder


class FakeCinderClient(object):
    class Volumes(object):
        def get(self, volume_id):
            return {'id': volume_id}

        def list(self, detailed, search_opts={}):
            return [{'id': 'id1'}, {'id': 'id2'}]

        def create(self, *args, **kwargs):
            return {'id': 'created_id'}

        def __getattr__(self, item):
            return None

    def __init__(self):
        self.volumes = self.Volumes()
        self.volume_snapshots = self.volumes


class CinderApiTestCase(test.TestCase):
    def setUp(self):
        super(CinderApiTestCase, self).setUp()

        self.api = cinder.API()
        self.cinderclient = FakeCinderClient()
        self.ctx = context.get_admin_context()
        self.stubs.Set(cinder, 'cinderclient',
                mock.Mock(return_value=self.cinderclient))
        self.stubs.Set(cinder, '_untranslate_volume_summary_view',
                       lambda ctx, vol: vol)
        self.stubs.Set(cinder, '_untranslate_snapshot_summary_view',
                       lambda ctx, snap: snap)

    def test_get(self):
        volume_id = 'volume_id1'
        result = self.api.get(self.ctx, volume_id)
        self.assertEqual(result['id'], volume_id)

    def test_get_failed(self):
        cinder.cinderclient.side_effect = cinder_exception.NotFound(404)
        volume_id = 'volume_id'
        self.assertRaises(exception.VolumeNotFound,
                          self.api.get, self.ctx, volume_id)

    def test_create(self):
        result = self.api.create(self.ctx, 1, '', '')
        self.assertEqual(result['id'], 'created_id')

    def test_create_failed(self):
        cinder.cinderclient.side_effect = cinder_exception.BadRequest(400)
        self.assertRaises(exception.InvalidInput,
                          self.api.create, self.ctx, 1, '', '')

    def test_get_all(self):
        cinder._untranslate_volume_summary_view.return_value = ['id1', 'id2']
        self.assertEqual([{'id': 'id1'}, {'id': 'id2'}],
                         self.api.get_all(self.ctx))

    def test_check_attach_volume_status_error(self):
        volume = {'status': 'error'}
        self.assertRaises(exception.InvalidVolume,
                          self.api.check_attach, self.ctx, volume)

    def test_check_attach_volume_already_attached(self):
        volume = {'status': 'available'}
        volume['attach_status'] = "attached"
        self.assertRaises(exception.InvalidVolume,
                          self.api.check_attach, self.ctx, volume)

    def test_check_attach_availability_zone_differs(self):
        volume = {'status': 'available'}
        volume['attach_status'] = "detached"
        instance = {'availability_zone': 'zone1'}
        volume['availability_zone'] = 'zone2'
        cinder.CONF.set_override('cinder_cross_az_attach', False)
        self.assertRaises(exception.InvalidVolume,
                          self.api.check_attach, self.ctx, volume, instance)
        volume['availability_zone'] = 'zone1'
        self.assertIsNone(self.api.check_attach(self.ctx, volume, instance))
        cinder.CONF.reset()

    def test_check_attach(self):
        volume = {'status': 'available'}
        volume['attach_status'] = "detached"
        volume['availability_zone'] = 'zone1'
        instance = {'availability_zone': 'zone1'}
        cinder.CONF.set_override('cinder_cross_az_attach', False)
        self.assertIsNone(self.api.check_attach(self.ctx, volume, instance))
        cinder.CONF.reset()

    def test_check_detach(self):
        volume = {'status': 'available'}
        self.assertRaises(exception.InvalidVolume,
                          self.api.check_detach, self.ctx, volume)
        volume['status'] = 'non-available'
        self.assertIsNone(self.api.check_detach(self.ctx, volume))

    def test_update(self):
        self.assertRaises(NotImplementedError,
                          self.api.update, self.ctx, '', '')

    def test_reserve_volume(self):
        self.stubs.Set(self.cinderclient.volumes, 'reserve', mock.Mock())
        self.api.reserve_volume(self.ctx, 'id1')
        self.cinderclient.volumes.reserve.assert_called_once_with('id1')

    def test_unreserve_volume(self):
        self.stubs.Set(self.cinderclient.volumes, 'unreserve', mock.Mock())
        self.api.unreserve_volume(self.ctx, 'id1')
        self.cinderclient.volumes.unreserve.assert_called_once_with('id1')

    def test_begin_detaching(self):
        self.stubs.Set(self.cinderclient.volumes, 'begin_detaching',
                       mock.Mock())
        self.api.begin_detaching(self.ctx, 'id1')
        self.cinderclient.volumes.begin_detaching.\
                assert_called_once_with('id1')

    def test_roll_detaching(self):
        self.stubs.Set(self.cinderclient.volumes, 'roll_detaching',
                       mock.Mock())
        self.api.roll_detaching(self.ctx, 'id1')
        self.cinderclient.volumes.roll_detaching.\
                assert_called_once_with('id1')

    def test_attach(self):
        self.stubs.Set(self.cinderclient.volumes, 'attach', mock.Mock())
        self.api.attach(self.ctx, 'id1', 'uuid', 'point')
        self.cinderclient.volumes.attach.assert_called_once_with('id1',
                                                                 'uuid',
                                                                 'point')

    def test_detach(self):
        self.stubs.Set(self.cinderclient.volumes, 'detach', mock.Mock())
        self.api.detach(self.ctx, 'id1')
        self.cinderclient.volumes.detach.assert_called_once_with('id1')

    def test_initialize_connection(self):
        self.stubs.Set(self.cinderclient.volumes, 'initialize_connection',
                       mock.Mock())
        self.api.initialize_connection(self.ctx, 'id1', 'connector')
        self.cinderclient.volumes.initialize_connection.\
            assert_called_once_with('id1', 'connector')

    def test_terminate_connection(self):
        self.stubs.Set(self.cinderclient.volumes, 'terminate_connection',
                       mock.Mock())
        self.api.terminate_connection(self.ctx, 'id1', 'connector')
        self.cinderclient.volumes.terminate_connection.\
            assert_called_once_with('id1', 'connector')

    def test_delete(self):
        self.stubs.Set(self.cinderclient.volumes, 'delete', mock.Mock())
        self.api.delete(self.ctx, 'id1')
        self.cinderclient.volumes.delete.assert_called_once_with('id1')

    def test_get_snapshot(self):
        snapshot_id = 'snapshot_id1'
        result = self.api.get_snapshot(self.ctx, snapshot_id)
        self.assertEqual(result['id'], snapshot_id)

    def test_get_snapshot_failed(self):
        cinder.cinderclient.side_effect = cinder_exception.NotFound(404)
        snapshot_id = 'snapshot_id'
        self.assertRaises(exception.VolumeSnapshotNotFound,
                          self.api.get_snapshot, self.ctx, snapshot_id)

    def test_get_all_snapshots(self):
        cinder._untranslate_snapshot_summary_view.return_value = ['id1', 'id2']
        self.assertEqual([{'id': 'id1'}, {'id': 'id2'}],
                         self.api.get_all_snapshots(self.ctx))

    def test_create_snapshot(self):
        result = self.api.create_snapshot(self.ctx, {'id': 'id1'}, '', '')
        self.assertEqual(result['id'], 'created_id')

    def test_create_force(self):
        result = self.api.create_snapshot_force(self.ctx,
                                                {'id': 'id1'}, '', '')
        self.assertEqual(result['id'], 'created_id')

    def test_delete_snapshot(self):
        self.stubs.Set(self.cinderclient.volume_snapshots,
                       'delete', mock.Mock())
        self.api.delete_snapshot(self.ctx, 'id1')
        self.cinderclient.volume_snapshots.delete.\
                assert_called_once_with('id1')
