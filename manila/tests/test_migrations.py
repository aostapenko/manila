# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010-2011 OpenStack, LLC
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

"""
Tests for database migrations. This test case reads the configuration
file test_migrations.conf for database connection settings
to use in the tests. For each connection found in the config file,
the test case runs a series of test cases to ensure that migrations work
properly both upgrading and downgrading, and that no data loss occurs
if possible.
"""

import commands
import ConfigParser
import os
import urlparse
import uuid

from migrate.versioning import repository
import sqlalchemy

import manila.db.migration as migration
import manila.db.sqlalchemy.migrate_repo
from manila.db.sqlalchemy.migration import versioning_api as migration_api
from manila.openstack.common import log as logging
from manila import test

LOG = logging.getLogger('manila.tests.test_migrations')


def _get_connect_string(backend,
                        user="openstack_citest",
                        passwd="openstack_citest",
                        database="openstack_citest"):
    """
    Try to get a connection with a very specific set of values, if we get
    these then we'll run the tests, otherwise they are skipped
    """
    if backend == "postgres":
        backend = "postgresql+psycopg2"

    return ("%(backend)s://%(user)s:%(passwd)s@localhost/%(database)s"
            % locals())


def _is_mysql_avail(**kwargs):
    return _is_backend_avail('mysql', **kwargs)


def _is_backend_avail(backend,
                      user="openstack_citest",
                      passwd="openstack_citest",
                      database="openstack_citest"):
    try:
        if backend == "mysql":
            connect_uri = _get_connect_string("mysql", user=user,
                                              passwd=passwd, database=database)
        elif backend == "postgres":
            connect_uri = _get_connect_string("postgres", user=user,
                                              passwd=passwd, database=database)
        engine = sqlalchemy.create_engine(connect_uri)
        connection = engine.connect()
    except Exception:
        # intentionally catch all to handle exceptions even if we don't
        # have any backend code loaded.
        return False
    else:
        connection.close()
        engine.dispose()
        return True


def _have_mysql():
    present = os.environ.get('NOVA_TEST_MYSQL_PRESENT')
    if present is None:
        return _is_backend_avail('mysql')
    return present.lower() in ('', 'true')


def get_table(engine, name):
    """Returns an sqlalchemy table dynamically from db.

    Needed because the models don't work for us in migrations
    as models will be far out of sync with the current data."""
    metadata = sqlalchemy.schema.MetaData()
    metadata.bind = engine
    return sqlalchemy.Table(name, metadata, autoload=True)


class TestMigrations(test.TestCase):
    """Test sqlalchemy-migrate migrations."""

    DEFAULT_CONFIG_FILE = os.path.join(os.path.dirname(__file__),
                                       'test_migrations.conf')
    # Test machines can set the MANILA_TEST_MIGRATIONS_CONF variable
    # to override the location of the config file for migration testing
    CONFIG_FILE_PATH = os.environ.get('MANILA_TEST_MIGRATIONS_CONF',
                                      DEFAULT_CONFIG_FILE)
    MIGRATE_FILE = manila.db.sqlalchemy.migrate_repo.__file__
    REPOSITORY = repository.Repository(
        os.path.abspath(os.path.dirname(MIGRATE_FILE)))

    def setUp(self):
        super(TestMigrations, self).setUp()

        self.snake_walk = False
        self.test_databases = {}

        # Load test databases from the config file. Only do this
        # once. No need to re-run this on each test...
        LOG.debug('config_path is %s' % TestMigrations.CONFIG_FILE_PATH)
        if not self.test_databases:
            if os.path.exists(TestMigrations.CONFIG_FILE_PATH):
                cp = ConfigParser.RawConfigParser()
                try:
                    cp.read(TestMigrations.CONFIG_FILE_PATH)
                    defaults = cp.defaults()
                    for key, value in defaults.items():
                        self.test_databases[key] = value
                    self.snake_walk = cp.getboolean('walk_style', 'snake_walk')
                except ConfigParser.ParsingError, e:
                    self.fail("Failed to read test_migrations.conf config "
                              "file. Got error: %s" % e)
            else:
                self.fail("Failed to find test_migrations.conf config "
                          "file.")

        self.engines = {}
        for key, value in self.test_databases.items():
            self.engines[key] = sqlalchemy.create_engine(value)

        # We start each test case with a completely blank slate.
        self._reset_databases()

    def tearDown(self):

        # We destroy the test data store between each test case,
        # and recreate it, which ensures that we have no side-effects
        # from the tests
        self._reset_databases()
        super(TestMigrations, self).tearDown()

    def _reset_databases(self):
        def execute_cmd(cmd=None):
            status, output = commands.getstatusoutput(cmd)
            LOG.debug(output)
            self.assertEqual(0, status)
        for key, engine in self.engines.items():
            conn_string = self.test_databases[key]
            conn_pieces = urlparse.urlparse(conn_string)
            engine.dispose()
            if conn_string.startswith('sqlite'):
                # We can just delete the SQLite database, which is
                # the easiest and cleanest solution
                db_path = conn_pieces.path.strip('/')
                if os.path.exists(db_path):
                    os.unlink(db_path)
                # No need to recreate the SQLite DB. SQLite will
                # create it for us if it's not there...
            elif conn_string.startswith('mysql'):
                # We can execute the MySQL client to destroy and re-create
                # the MYSQL database, which is easier and less error-prone
                # than using SQLAlchemy to do this via MetaData...trust me.
                database = conn_pieces.path.strip('/')
                loc_pieces = conn_pieces.netloc.split('@')
                host = loc_pieces[1]
                auth_pieces = loc_pieces[0].split(':')
                user = auth_pieces[0]
                password = ""
                if len(auth_pieces) > 1:
                    if auth_pieces[1].strip():
                        password = "-p\"%s\"" % auth_pieces[1]
                sql = ("drop database if exists %(database)s; "
                       "create database %(database)s;") % locals()
                cmd = ("mysql -u \"%(user)s\" %(password)s -h %(host)s "
                       "-e \"%(sql)s\"") % locals()
                execute_cmd(cmd)
            elif conn_string.startswith('postgresql'):
                database = conn_pieces.path.strip('/')
                loc_pieces = conn_pieces.netloc.split('@')
                host = loc_pieces[1]

                auth_pieces = loc_pieces[0].split(':')
                user = auth_pieces[0]
                password = ""
                if len(auth_pieces) > 1:
                    password = auth_pieces[1].strip()
                # note(krtaylor): File creation problems with tests in
                # venv using .pgpass authentication, changed to
                # PGPASSWORD environment variable which is no longer
                # planned to be deprecated
                os.environ['PGPASSWORD'] = password
                os.environ['PGUSER'] = user
                # note(boris-42): We must create and drop database, we can't
                # drop database which we have connected to, so for such
                # operations there is a special database template1.
                sqlcmd = ("psql -w -U %(user)s -h %(host)s -c"
                          " '%(sql)s' -d template1")
                sql = ("drop database if exists %(database)s;") % locals()
                droptable = sqlcmd % locals()
                execute_cmd(droptable)
                sql = ("create database %(database)s;") % locals()
                createtable = sqlcmd % locals()
                execute_cmd(createtable)
                os.unsetenv('PGPASSWORD')
                os.unsetenv('PGUSER')

    def test_walk_versions(self):
        """
        Walks all version scripts for each tested database, ensuring
        that there are no errors in the version scripts for each engine
        """
        for key, engine in self.engines.items():
            self._walk_versions(engine, self.snake_walk)

    def test_mysql_connect_fail(self):
        """
        Test that we can trigger a mysql connection failure and we fail
        gracefully to ensure we don't break people without mysql
        """
        if _is_mysql_avail(user="openstack_cifail"):
            self.fail("Shouldn't have connected")

    @test.skip_unless(_have_mysql(), "mysql not available")
    def test_mysql_innodb(self):
        """
        Test that table creation on mysql only builds InnoDB tables
        """
        # add this to the global lists to make reset work with it, it's removed
        # automaticaly in tearDown so no need to clean it up here.
        connect_string = _get_connect_string('mysql')
        engine = sqlalchemy.create_engine(connect_string)
        self.engines["mysqlcitest"] = engine
        self.test_databases["mysqlcitest"] = connect_string

        # build a fully populated mysql database with all the tables
        self._reset_databases()
        self._walk_versions(engine, False, False)

        uri = _get_connect_string('mysql', database="information_schema")
        connection = sqlalchemy.create_engine(uri).connect()

        # sanity check
        total = connection.execute("SELECT count(*) "
                                   "from information_schema.TABLES "
                                   "where TABLE_SCHEMA='openstack_citest'")
        self.assertTrue(total.scalar() > 0, "No tables found. Wrong schema?")

        noninnodb = connection.execute("SELECT count(*) "
                                       "from information_schema.TABLES "
                                       "where TABLE_SCHEMA='openstack_citest' "
                                       "and ENGINE!='InnoDB' "
                                       "and TABLE_NAME!='migrate_version'")
        count = noninnodb.scalar()
        self.assertEqual(count, 0, "%d non InnoDB tables created" % count)

    def test_postgresql_connect_fail(self):
        """
        Test that we can trigger a postgres connection failure and we fail
        gracefully to ensure we don't break people without postgres
        """
        if _is_backend_avail('postgres', user="openstack_cifail"):
            self.fail("Shouldn't have connected")

    @test.skip_unless(_is_backend_avail('postgres'),
                      "postgresql not available")
    def test_postgresql_opportunistically(self):
        # add this to the global lists to make reset work with it, it's removed
        # automatically in tearDown so no need to clean it up here.
        connect_string = _get_connect_string("postgres")
        engine = sqlalchemy.create_engine(connect_string)
        self.engines["postgresqlcitest"] = engine
        self.test_databases["postgresqlcitest"] = connect_string

        # build a fully populated postgresql database with all the tables
        self._reset_databases()
        self._walk_versions(engine, False, False)

    def _walk_versions(self, engine=None, snake_walk=False, downgrade=True):
        # Determine latest version script from the repo, then
        # upgrade from 1 through to the latest, with no data
        # in the databases. This just checks that the schema itself
        # upgrades successfully.

        # Place the database under version control
        migration_api.version_control(engine,
                                      TestMigrations.REPOSITORY,
                                      migration.INIT_VERSION)
        self.assertEqual(migration.INIT_VERSION,
                         migration_api.db_version(engine,
                                                  TestMigrations.REPOSITORY))

        migration_api.upgrade(engine, TestMigrations.REPOSITORY,
                              migration.INIT_VERSION + 1)

        LOG.debug('latest version is %s' % TestMigrations.REPOSITORY.latest)

        for version in xrange(migration.INIT_VERSION + 2,
                              TestMigrations.REPOSITORY.latest + 1):
            # upgrade -> downgrade -> upgrade
            self._migrate_up(engine, version, with_data=True)
            if snake_walk:
                self._migrate_down(engine, version - 1)
                self._migrate_up(engine, version)

        if downgrade:
            # Now walk it back down to 0 from the latest, testing
            # the downgrade paths.
            for version in reversed(
                xrange(migration.INIT_VERSION + 1,
                       TestMigrations.REPOSITORY.latest)):
                # downgrade -> upgrade -> downgrade
                self._migrate_down(engine, version)
                if snake_walk:
                    self._migrate_up(engine, version + 1)
                    self._migrate_down(engine, version)

    def _migrate_down(self, engine, version):
        migration_api.downgrade(engine,
                                TestMigrations.REPOSITORY,
                                version)
        self.assertEqual(version,
                         migration_api.db_version(engine,
                                                  TestMigrations.REPOSITORY))

    def _migrate_up(self, engine, version, with_data=False):
        """migrate up to a new version of the db.

        We allow for data insertion and post checks at every
        migration version with special _prerun_### and
        _check_### functions in the main test.
        """
        # NOTE(sdague): try block is here because it's impossible to debug
        # where a failed data migration happens otherwise
        try:
            if with_data:
                data = None
                prerun = getattr(self, "_prerun_%3.3d" % version, None)
                if prerun:
                    data = prerun(engine)

            migration_api.upgrade(engine,
                                  TestMigrations.REPOSITORY,
                                  version)
            self.assertEqual(
                version,
                migration_api.db_version(engine,
                                         TestMigrations.REPOSITORY))

            if with_data:
                check = getattr(self, "_check_%3.3d" % version, None)
                if check:
                    check(engine, data)
        except Exception:
            LOG.error("Failed to migrate to version %s on engine %s" %
                      (version, engine))
            raise

    def test_migration_006(self):
        """Test adding share_metadata table works correctly."""
        for (key, engine) in self.engines.items():
            migration_api.version_control(engine,
                                          TestMigrations.REPOSITORY,
                                          migration.INIT_VERSION)
            migration_api.upgrade(engine, TestMigrations.REPOSITORY, 5)
            metadata = sqlalchemy.schema.MetaData()
            metadata.bind = engine

            migration_api.upgrade(engine, TestMigrations.REPOSITORY, 6)

            self.assertTrue(engine.dialect.has_table(engine.connect(),
                                                     "share_metadata"))
            share_metadata = sqlalchemy.Table('share_metadata',
                                                    metadata,
                                                    autoload=True)

            self.assertIsInstance(share_metadata.c.created_at.type,
                                  sqlalchemy.types.DATETIME)
            self.assertIsInstance(share_metadata.c.updated_at.type,
                                  sqlalchemy.types.DATETIME)
            self.assertIsInstance(share_metadata.c.deleted_at.type,
                                  sqlalchemy.types.DATETIME)
            self.assertIsInstance(share_metadata.c.deleted.type,
                                  sqlalchemy.types.BOOLEAN)
            self.assertIsInstance(share_metadata.c.id.type,
                                  sqlalchemy.types.INTEGER)
            self.assertIsInstance(share_metadata.c.share_id.type,
                                  sqlalchemy.types.VARCHAR)
            self.assertIsInstance(share_metadata.c.key.type,
                                  sqlalchemy.types.VARCHAR)
            self.assertIsInstance(share_metadata.c.value.type,
                                  sqlalchemy.types.VARCHAR)

            migration_api.downgrade(engine, TestMigrations.REPOSITORY, 5)

            self.assertFalse(engine.dialect.has_table(engine.connect(),
                                                      "share_metadata"))

    def test_migration_007(self):
        """Test adding subnets table works correctly."""
        for (key, engine) in self.engines.items():
            migration_api.version_control(engine,
                                          TestMigrations.REPOSITORY,
                                          migration.INIT_VERSION)
            migration_api.upgrade(engine, TestMigrations.REPOSITORY, 6)
            metadata = sqlalchemy.schema.MetaData()
            metadata.bind = engine

            migration_api.upgrade(engine, TestMigrations.REPOSITORY, 7)

            self.assertTrue(engine.dialect.has_table(engine.connect(),
                                    "neutron_subnets"))
            self.assertTrue(engine.dialect.has_table(engine.connect(),
                                    "neutron_subnet_share_associations"))

            subnets = sqlalchemy.Table('neutron_subnets',
                                       metadata, autoload=True)

            self.assertIsInstance(subnets.c.created_at.type,
                                  sqlalchemy.types.DATETIME)
            self.assertIsInstance(subnets.c.updated_at.type,
                                  sqlalchemy.types.DATETIME)
            self.assertIsInstance(subnets.c.deleted_at.type,
                                  sqlalchemy.types.DATETIME)
            self.assertIsInstance(subnets.c.deleted.type,
                                  sqlalchemy.types.BOOLEAN)
            self.assertIsInstance(subnets.c.id.type,
                                  sqlalchemy.types.INTEGER)
            self.assertIsInstance(subnets.c.net_id.type,
                                  sqlalchemy.types.VARCHAR)
            self.assertIsInstance(subnets.c.subnet_id.type,
                                  sqlalchemy.types.VARCHAR)
            self.assertIsInstance(subnets.c.port_id.type,
                                  sqlalchemy.types.VARCHAR)
            self.assertIsInstance(subnets.c.mac_address.type,
                                  sqlalchemy.types.VARCHAR)
            self.assertIsInstance(subnets.c.fixed_ip.type,
                                  sqlalchemy.types.VARCHAR)
            self.assertIsInstance(subnets.c.state.type,
                                  sqlalchemy.types.VARCHAR)

            subnet_assoc = sqlalchemy.\
                            Table('neutron_subnet_share_associations',
                                  metadata, autoload=True)

            self.assertIsInstance(subnet_assoc.c.created_at.type,
                                  sqlalchemy.types.DATETIME)
            self.assertIsInstance(subnet_assoc.c.updated_at.type,
                                  sqlalchemy.types.DATETIME)
            self.assertIsInstance(subnet_assoc.c.deleted_at.type,
                                  sqlalchemy.types.DATETIME)
            self.assertIsInstance(subnet_assoc.c.deleted.type,
                                  sqlalchemy.types.BOOLEAN)
            self.assertIsInstance(subnet_assoc.c.subnet_id.type,
                                  sqlalchemy.types.INTEGER)
            self.assertIsInstance(subnet_assoc.c.share_id.type,
                                  sqlalchemy.types.VARCHAR)

            migration_api.downgrade(engine, TestMigrations.REPOSITORY, 6)

            self.assertFalse(engine.dialect.has_table(engine.connect(),
                                     "neutron_subnets"))
            self.assertFalse(engine.dialect.has_table(engine.connect(),
                                     "neutron_subnet_share_associations"))
