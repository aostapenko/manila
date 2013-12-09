"""manila_init

Revision ID: 42414c438772
Revises: None
Create Date: 2013-12-08 22:55:24.479128

"""

# revision identifiers, used by Alembic.
revision = 'manila_init'
down_revision = None

from alembic import op
from oslo.config import cfg
from sqlalchemy import Boolean, Column, DateTime
from sqlalchemy import Integer, String
from sqlalchemy import ForeignKeyConstraint, PrimaryKeyConstraint

from manila.openstack.common.gettextutils import _
from manila.openstack.common import log as logging

CONF = cfg.CONF

LOG = logging.getLogger(__name__)


def upgrade():
    op.create_table(
        'migrations',
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean),
        Column('id', Integer, nullable=False),
        Column('source_compute', String(length=255)),
        Column('dest_compute', String(length=255)),
        Column('dest_host', String(length=255)),
        Column('status', String(length=255)),
        Column('instance_uuid', String(length=255)),
        Column('old_instance_type_id', Integer),
        Column('new_instance_type_id', Integer),
        PrimaryKeyConstraint('id')
    )

    op.create_table(
        'services',
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean),
        Column('id', Integer, nullable=False),
        Column('host', String(length=255)),
        Column('binary', String(length=255)),
        Column('topic', String(length=255)),
        Column('report_count', Integer, nullable=False),
        Column('disabled', Boolean),
        Column('availability_zone', String(length=255)),
        PrimaryKeyConstraint('id')
    )

    op.create_table(
        'quotas',
        Column('id', Integer, nullable=False),
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean),
        Column('project_id', String(length=255)),
        Column('resource', String(length=255), nullable=False),
        Column('hard_limit', Integer),
        PrimaryKeyConstraint('id')
    )

    op.create_table(
        'quota_classes',
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean),
        Column('id', Integer),
        Column('class_name', String(length=255)),
        Column('resource', String(length=255)),
        Column('hard_limit', Integer, nullable=True),
        PrimaryKeyConstraint('id')
    )

    op.create_table(
        'quota_usages',
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean),
        Column('id', Integer),
        Column('project_id', String(length=255)),
        Column('user_id', String(length=255)),
        Column('resource', String(length=255)),
        Column('in_use', Integer, nullable=False),
        Column('reserved', Integer, nullable=False),
        Column('until_refresh', Integer, nullable=True),
        PrimaryKeyConstraint('id')
    )

    op.create_table(
        'reservations',
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean),
        Column('id', Integer),
        Column('uuid', String(length=36), nullable=False),
        Column('usage_id', Integer, nullable=False),
        Column('project_id', String(length=255)),
        Column('user_id', String(length=255)),
        Column('resource', String(length=255)),
        Column('delta', Integer, nullable=False),
        Column('expire', DateTime),
        PrimaryKeyConstraint('id'),
        ForeignKeyConstraint(['usage_id'], ['quota_usages.id'], )
    )

    op.create_table('shares',
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean),
        Column('id', String(length=36), nullable=False),
        Column('user_id', String(length=255)),
        Column('project_id', String(length=255)),
        Column('host', String(length=255)),
        Column('size', Integer),
        Column('availability_zone', String(length=255)),
        Column('status', String(length=255)),
        Column('scheduled_at', DateTime),
        Column('launched_at', DateTime),
        Column('terminated_at', DateTime),
        Column('display_name', String(length=255)),
        Column('display_description', String(length=255)),
        Column('snapshot_id', String(length=36)),
        Column('share_proto', String(255)),
        Column('export_location', String(255)),
        PrimaryKeyConstraint('id')
    )

    op.create_table('share_access_map',
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean),
        Column('id', String(length=36), nullable=False),
        Column('share_id', String(36), nullable=False),
        Column('access_type', String(255)),
        Column('access_to', String(255)),
        Column('state', String(255)),
        PrimaryKeyConstraint('id'),
        ForeignKeyConstraint(['share_id'], ['shares.id'], )
    )

    op.create_table(
        'share_snapshots',
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean),
        Column('id', String(length=36), nullable=False),
        Column('user_id', String(length=255)),
        Column('project_id', String(length=255)),
        Column('share_id', String(36), nullable=False),
        Column('size', Integer),
        Column('status', String(length=255)),
        Column('progress', String(length=255)),
        Column('display_name', String(length=255)),
        Column('display_description', String(length=255)),
        Column('share_size', Integer),
        Column('share_proto', String(length=255)),
        Column('export_location', String(255)),
        PrimaryKeyConstraint('id'),
        ForeignKeyConstraint(['share_id'], ['shares.id'], )
    )

    op.create_table(
        'project_user_quotas',
        Column('id', Integer, nullable=False),
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Integer),
        Column('user_id', String(length=255), nullable=False),
        Column('project_id', String(length=255), nullable=False),
        Column('resource', String(length=25), nullable=False),
        Column('hard_limit', Integer, nullable=True),
        PrimaryKeyConstraint('id')
    )

    op.create_table(
        'share_metadata',
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean),
        Column('id', Integer, nullable=False),
        Column('share_id', String(length=36), nullable=False),
        Column('key', String(length=255), nullable=False),
        Column('value', String(length=1023), nullable=False),
        PrimaryKeyConstraint('id'),
        ForeignKeyConstraint(['share_id'], ['shares.id'], )
    )


def downgrade(migrate_engine):
    LOG.exception(_('Downgrade from initial Manila install is unsupported.'))
