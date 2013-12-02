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

import copy

from manila import context
from manila import db
from manila import exception
from manila import test


class SubnetsDBTestCase(test.TestCase):
    def setUp(self):
        super(SubnetsDBTestCase, self).setUp()
        self.subnet_values = {
                'subnet_id': '0000-0000-0000-0000',
                'project_id': '1',
                'net_id': '1111-1111-1111-1111',
                'port_id': '2222-2222-2222-2222',
                'mac_address': '00:00:00:00:00:00',
                'fixed_ip': '10.0.0.2',
                }
        self.subnet_values_alt = {
                'subnet_id': '0000-0000-0000-0001',
                'project_id': '1',
                'net_id': '1111-1111-1111-1111',
                'port_id': '2222-2222-2222-2220',
                'mac_address': '00:00:00:00:00:01',
                'fixed_ip': '10.0.0.3',
                }

    def test_subnet_add(self):
        result = db.subnet_add(context.get_admin_context(),
                               copy.copy(self.subnet_values))
        for key, value in self.subnet_values.items():
            self.assertEqual(getattr(result, key), value)
        self.assertEqual(result.state, 'inactive')

    def test_subnet_update(self):
        self.subnet_values['mac_address'] = None
        self.subnet_values['port_id'] = None
        db.subnet_add(context.get_admin_context(),
                      copy.copy(self.subnet_values))
        self.subnet_values['mac_address'] = '11:11:11:11:11:11'
        self.subnet_values['port_id'] = '2222-2222-2222-2222'
        result = db.subnet_update(context.get_admin_context(), {
                            'subnet_id': self.subnet_values['subnet_id'],
                            'mac_address': self.subnet_values['mac_address'],
                            'port_id': self.subnet_values['port_id'],
                            'state': 'active',
                            })
        for key, value in self.subnet_values.items():
            self.assertEqual(getattr(result, key), value)
        self.assertEqual(result.state, 'active')

    def test_subnet_add_existing(self):
        db.subnet_add(context.get_admin_context(), self.subnet_values)
        self.assertRaises(exception.SubnetIsAlreadyAdded,
                db.subnet_add, context.get_admin_context(), self.subnet_values)

    def test_subnet_get(self):
        db.subnet_add(context.get_admin_context(),
                      copy.copy(self.subnet_values))
        result = db.subnet_get(context.get_admin_context(),
                               self.subnet_values['subnet_id'])
        for key, value in self.subnet_values.items():
            self.assertEqual(getattr(result, key), value)

    def test_subnet_get_not_existing(self):
        self.assertRaises(exception.SubnetIsNotAdded,
                          db.subnet_get,
                          context.get_admin_context(),
                          'not_existing_id')

    def test_subnet_get_all_by_project(self):
        db.subnet_add(context.get_admin_context(), self.subnet_values)
        db.subnet_add(context.get_admin_context(), self.subnet_values_alt)
        result = db.subnet_get_all_by_project(context.get_admin_context(),
                                              self.subnet_values['project_id'])
        self.assertEqual(len(result), 2)

    def test_subnet_get_all_by_project_empty(self):
        result = db.subnet_get_all_by_project(context.get_admin_context(), '1')
        self.assertEqual(result, [])

    def test_subnet_remove(self):
        db.subnet_add(context.get_admin_context(),
                      copy.copy(self.subnet_values))
        db.subnet_remove(context.get_admin_context(),
                         self.subnet_values['subnet_id'])
        result = db.subnet_get_all_by_project(context.get_admin_context(),
                                              self.subnet_values['project_id'])
        self.assertEqual(result, [])

    def test_subnet_remove_not_existing(self):
        self.assertRaises(exception.SubnetIsNotAdded, db.subnet_remove,
                          context.get_admin_context(), '1')

    def test_subnet_share_associate(self):
        subnet1_ref = db.subnet_add(context.get_admin_context(),
                                    self.subnet_values)
        subnet2_ref = db.subnet_add(context.get_admin_context(),
                                    self.subnet_values_alt)
        share_id = db.share_create(context.get_admin_context(), {}).id
        db.subnet_share_associate(context.get_admin_context(),
                                  subnet1_ref['subnet_id'],
                                  share_id)
        db.subnet_share_associate(context.get_admin_context(),
                                  subnet2_ref['subnet_id'],
                                  share_id)

        share_ref = db.share_get(context.get_admin_context(), share_id)
        self.assertEqual(len(share_ref.subnets), 2)

    def test_subnet_share_associate_associated(self):
        subnet_ref = db.subnet_add(context.get_admin_context(),
                                   self.subnet_values)
        share_id = db.share_create(context.get_admin_context(), {}).id
        db.subnet_share_associate(context.get_admin_context(),
                                  subnet_ref['subnet_id'],
                                  share_id)
        self.assertRaises(exception.SubnetIsAlreadyAssociated,
                         db.subnet_share_associate,
                         context.get_admin_context(),
                         subnet_ref['subnet_id'],
                         share_id)

    def test_subnet_share_deassociate(self):
        subnet_ref = db.subnet_add(context.get_admin_context(),
                                   self.subnet_values)
        share_id = db.share_create(context.get_admin_context(), {}).id
        db.subnet_share_associate(context.get_admin_context(),
                                  subnet_ref['subnet_id'],
                                  share_id)
        db.subnet_share_deassociate(context.get_admin_context(),
                                    subnet_ref['subnet_id'],
                                    share_id)

        share_ref = db.share_get(context.get_admin_context(), share_id)
        self.assertEqual(len(share_ref.subnets), 0)

    def test_subnet_share_deassociate_not_associated(self):
        subnet_ref = db.subnet_add(context.get_admin_context(),
                                   self.subnet_values)
        share_id = db.share_create(context.get_admin_context(), {}).id
        self.assertRaises(exception.SubnetIsNotAssociated,
                          db.subnet_share_deassociate,
                          context.get_admin_context(),
                          subnet_ref.subnet_id,
                          share_id)
