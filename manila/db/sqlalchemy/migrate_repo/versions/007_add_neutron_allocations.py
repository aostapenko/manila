# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Mirantis Inc.
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

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer
from sqlalchemy import MetaData, String, Table

from manila.openstack.common.gettextutils import _
from manila.openstack.common import log as logging

LOG = logging.getLogger(__name__)


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    Table('shares', meta, autoload=True)

    neutron_allocations= Table(
        'neutron_allocations', meta,
        Column('id', Integer, primary_key=True, nullable=False),
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean, default=False),
        Column('subnet_id', String(length=36), nullable=False),
        Column('project_id', String(length=36), nullable=False),
        Column('port_id', String(length=36)),
        Column('net_id', String(length=36), nullable=False),
        Column('fixed_ip', String(length=36), nullable=False),
        Column('mac_address', String(length=36)),
        Column('state', String(length=36)),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )

    alloc_share_assoc = Table(
        'neutron_allocation_share_associations', meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean, default=False),
        Column('neutron_allocation_id', Integer,
               ForeignKey('neutron_allocations.id'),
               primary_key=True),
        Column('share_id', String(length=36),
               ForeignKey('shares.id'),
               primary_key=True),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )
    try:
        neutron_allocations.create()
        alloc_share_assoc.create()
    except Exception:
        LOG.exception(_("Exception while creating table"))
        meta.drop_all(tables=[neutron_allocations, alloc_share_assoc])
        raise


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    neutron_allocations= Table('neutron_allocations', meta, autoload=True)
    alloc_share_assoc = Table('neutron_allocation_share_associations', meta,
                             autoload=True)
    alloc_share_assoc.drop()
    neutron_allocations.drop()
