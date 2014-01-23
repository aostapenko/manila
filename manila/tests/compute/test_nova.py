#    Copyright 2014 Mirantis Inc.
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

from manila.compute import nova
from manila import context
from manila import exception
from manila import test
from manila.volume import cinder
from novaclient import exceptions as nova_exception
from novaclient.v1_1 import servers as nova_servers


class Volume(object):
    def __init__(self, volume_id):
        self.id = volume_id
        self.display_name = volume_id


class FakeNovaClient(object):
    class Servers(object):
        def get(self, instance_id):
            return {'id': instance_id}

        def list(self, *args, **kwargs):
            return [{'id': 'id1'}, {'id': 'id2'}]

        def create(self, *args, **kwargs):
            return {'id': 'created_id'}

        def __getattr__(self, item):
            return None

    class Volumes(object):
        def get(self, volume_id):
            return Volume(volume_id)

        def list(self, detailed, *args, **kwargs):
            return [{'id': 'id1'}, {'id': 'id2'}]

        def create(self, *args, **kwargs):
            return {'id': 'created_id'}

        def __getattr__(self, item):
            return None

    def __init__(self):
        self.servers = self.Servers()
        self.volumes = self.Volumes()
        self.keypairs = self.servers


class NovaApiTestCase(test.TestCase):
    def setUp(self):
        super(NovaApiTestCase, self).setUp()

        self.api = nova.API()
        self.novaclient = FakeNovaClient()
        self.ctx = context.get_admin_context()
        self.stubs.Set(nova, 'novaclient',
                mock.Mock(return_value=self.novaclient))
        self.stubs.Set(nova, '_untranslate_server_summary_view',
                       lambda server: server)

    def test_server_create(self):
        result = self.api.server_create(self.ctx, 'server_name', 'fake_image',
                'fake_flavor', None, None, None)
        self.assertEqual(result['id'], 'created_id')

    def test_server_delete(self):
        self.stubs.Set(self.novaclient.servers, 'delete', mock.Mock())
        self.api.server_delete(self.ctx, 'id1')
        self.novaclient.servers.delete.assert_called_once_with('id1')

    def test_server_get(self):
        instance_id = 'instance_id1'
        result = self.api.server_get(self.ctx, instance_id)
        self.assertEqual(result['id'], instance_id)

    def test_server_get_failed(self):
        nova.novaclient.side_effect = nova_exception.NotFound(404)
        instance_id = 'instance_id'
        self.assertRaises(exception.InstanceNotFound,
                          self.api.server_get, self.ctx, instance_id)

    def test_server_list(self):
        self.assertEqual([{'id': 'id1'}, {'id': 'id2'}],
                         self.api.server_list(self.ctx))

    def test_server_pause(self):
        self.stubs.Set(self.novaclient.servers, 'pause', mock.Mock())
        self.api.server_pause(self.ctx, 'id1')
        self.novaclient.servers.pause.assert_called_once_with('id1')

    def test_server_unpause(self):
        self.stubs.Set(self.novaclient.servers, 'unpause', mock.Mock())
        self.api.server_unpause(self.ctx, 'id1')
        self.novaclient.servers.unpause.assert_called_once_with('id1')

    def test_server_suspend(self):
        self.stubs.Set(self.novaclient.servers, 'suspend', mock.Mock())
        self.api.server_suspend(self.ctx, 'id1')
        self.novaclient.servers.suspend.assert_called_once_with('id1')

    def test_server_resume(self):
        self.stubs.Set(self.novaclient.servers, 'resume', mock.Mock())
        self.api.server_resume(self.ctx, 'id1')
        self.novaclient.servers.resume.assert_called_once_with('id1')

    def test_server_reboot_hard(self):
        self.stubs.Set(self.novaclient.servers, 'reboot', mock.Mock())
        self.api.server_reboot(self.ctx, 'id1')
        self.novaclient.servers.reboot.assert_called_once_with('id1',
                nova_servers.REBOOT_HARD)

    def test_server_reboot_soft(self):
        self.stubs.Set(self.novaclient.servers, 'reboot', mock.Mock())
        self.api.server_reboot(self.ctx, 'id1', True)
        self.novaclient.servers.reboot.assert_called_once_with('id1',
                nova_servers.REBOOT_SOFT)

    def test_server_rebuild(self):
        self.stubs.Set(self.novaclient.servers, 'rebuild', mock.Mock())
        self.api.server_rebuild(self.ctx, 'id1', 'fake_image')
        self.novaclient.servers.rebuild.assert_called_once_with('id1',
                                                                'fake_image',
                                                                None)

    def test_instance_volume_attach(self):
        self.stubs.Set(self.novaclient.volumes, 'create_server_volume',
                       mock.Mock())
        self.api.instance_volume_attach(self.ctx, 'instance_id',
                                        'vol_id', 'device')
        self.novaclient.volumes.create_server_volume.\
                assert_called_once_with('instance_id', 'vol_id', 'device')

    def test_instance_volume_detach(self):
        self.stubs.Set(self.novaclient.volumes, 'delete_server_volume',
                       mock.Mock())
        self.api.instance_volume_detach(self.ctx, 'instance_id',
                                        'att_id')
        self.novaclient.volumes.delete_server_volume.\
                assert_called_once_with('instance_id', 'att_id')

    def test_instance_volumes_list(self):
        self.stubs.Set(self.novaclient.volumes, 'get_server_volumes',
                       mock.Mock(return_value=[Volume('id1'), Volume('id2')]))
        self.cinderclient = self.novaclient
        self.stubs.Set(cinder, 'cinderclient',
                       mock.Mock(return_value=self.novaclient))
        result = self.api.instance_volumes_list(self.ctx, 'instance_id')
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].id, 'id1')
        self.assertEqual(result[1].id, 'id2')

    def test_server_update(self):
        self.stubs.Set(self.novaclient.servers, 'update', mock.Mock())
        self.api.server_update(self.ctx, 'id1', 'new_name')
        self.novaclient.servers.update.assert_called_once_with('id1',
                                                               name='new_name')

    def test_update_server_volume(self):
        self.stubs.Set(self.novaclient.volumes, 'update_server_volume',
                       mock.Mock())
        self.api.update_server_volume(self.ctx, 'instance_id', 'att_id',
                                      'new_vol_id')
        self.novaclient.volumes.update_server_volume.\
                assert_called_once_with('instance_id', 'att_id', 'new_vol_id')

    def test_keypair_create(self):
        self.stubs.Set(self.novaclient.keypairs, 'create', mock.Mock())
        self.api.keypair_create(self.ctx, 'keypair_name')
        self.novaclient.keypairs.create.assert_called_once_with('keypair_name')

    def test_keypair_import(self):
        self.stubs.Set(self.novaclient.keypairs, 'create', mock.Mock())
        self.api.keypair_import(self.ctx, 'keypair_name', 'fake_pub_key')
        self.novaclient.keypairs.create.\
                assert_called_once_with('keypair_name', 'fake_pub_key')

    def test_keypair_delete(self):
        self.stubs.Set(self.novaclient.keypairs, 'delete', mock.Mock())
        self.api.keypair_delete(self.ctx, 'fake_keypair_id')
        self.novaclient.keypairs.delete.\
                assert_called_once_with('fake_keypair_id')

    def test_keypair_list(self):
        self.assertEqual([{'id': 'id1'}, {'id': 'id2'}],
                         self.api.keypair_list(self.ctx))
