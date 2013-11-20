# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack Foundation
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

from sqlalchemy import Boolean, Column, DateTime, Integer, ForeignKey
from sqlalchemy import Index, UniqueConstraint, MetaData, String, Table

from manila.db.sqlalchemy import api as db
from manila.openstack.common.gettextutils import _
from manila.openstack.common import log as logging

LOG = logging.getLogger(__name__)


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    shares = Table('shares', meta, autoload=True)

    neutron_subnets = Table('neutron_subnets', meta,
                          Column('id', String(length=36), primary_key=True,
                                 nullable=False),
                          Column('created_at', DateTime),
                          Column('updated_at', DateTime),
                          Column('deleted_at', DateTime),
                          Column('deleted', Boolean),
                          Column('project_id',
                                 String(length=255),
                                 nullable=False),
                          Column('port_id',
                                 String(length=255)),
                          Column('net_id',
                                 String(length=255),
                                 nullable=False),
                          Column('fixed_ip',
                                 String(length=255),
                                 nullable=False),
                          Column('mac_address',
                                 String(length=255)),
                          Column('state',
                                 String(length=255)),
                          mysql_engine='InnoDB',
                          mysql_charset='utf8',
                          )

    subnet_share_assoc = Table('neutron_subnet_share_associations', meta,
                             Column('created_at', DateTime),
                             Column('updated_at', DateTime),
                             Column('deleted_at', DateTime),
                             Column('deleted', Boolean),
                             Column('subnet_id', String(length=36),
                                    ForeignKey('neutron_subnets.id'),
                                    primary_key=True),
                             Column('share_id', String(length=36),
                                    ForeignKey('shares.id'),
                                    primary_key=True),
                             mysql_engine='InnoDB',
                             mysql_charset='utf8',
                             )
    try:
        neutron_subnets.create()
        subnet_share_assoc.create()
    except Exception:
        LOG.exception("Exception while creating table")
        meta.drop_all(tables=[neutron_subnets, subnet_share_assoc])
        raise


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    neutron_subnets = Table('neutron_subnets', meta, autoload=True)
    subnet_share_assoc = Table('neutron_subnet_share_associations', meta,
                             autoload=True)

    subnet_share_assoc.drop()
    neutron_subnets.drop()
