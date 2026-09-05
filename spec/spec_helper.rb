# spec/spec_helper.rb
#
# frozen_string_literal: true

# Boots the whole app against a scratch SQLite database: Rodauth's tables
# built from the rodauth-tools templates (the same shape as production) plus
# the migrated admin tables. ENV must be set before lib/rodauth_admin loads,
# because RodauthAdmin::Auth's table_guard connects at class-definition time.
#
# Two modes:
#
#   default (local, and the `test` CI job) — a scratch SQLite file plays all
#     three credentials, and this file builds and migrates it.
#   pre-provisioned (the `test-postgres` CI job) — ADMIN_DATABASE_URL is
#     already set in ENV, pointing at a real PostgreSQL authdb that CI built,
#     migrated and granted with three genuinely different roles. Nothing is
#     built here; the schema steps below are skipped when the schema exists,
#     which is also what makes a re-run against the same database work.

require 'fileutils'
require 'securerandom'
require 'tmpdir'
require 'uri'

ENV['RACK_ENV'] = 'test'
ENV['AUTH_SECRET'] = "test-hmac-secret-#{'x' * 48}"
ENV['RODAUTH_ADMIN_SESSION_SECRET'] = SecureRandom.hex(64)
ENV.delete('ARGON2_SECRET')

PROVISIONED_DATABASE = !ENV['ADMIN_DATABASE_URL'].to_s.strip.empty?

# The suite's `before` hook DELETEs every account table through the migrator
# credential, which in the provisioned mode is the schema owner. RACK_ENV=test
# is not a guard: it is set two lines up, unconditionally, by this very file.
# So the database has to name itself as disposable — or the operator has to
# say so explicitly, once, in the environment.
SCRATCH_DATABASE_NAME = /(^|_)(test|ci|scratch)($|_)/
DESTRUCTIVE_OVERRIDE = 'RODAUTH_ADMIN_ALLOW_DESTRUCTIVE_SPECS'

def scratch_database!(url)
  return if ENV[DESTRUCTIVE_OVERRIDE] == '1'

  # An unparseable URL (a password with unescaped punctuation, say) is not a
  # licence to proceed: no name means no proof, so the refusal stands.
  name = begin
    URI.parse(url).path.to_s.split('/').last.to_s
  rescue URI::InvalidURIError
    ''
  end
  return if name.match?(SCRATCH_DATABASE_NAME)

  abort <<~REFUSAL
    Refusing to run the specs against ADMIN_DATABASE_URL database #{name.inspect}.

    This suite truncates every account table (accounts and every account_*
    child) plus admin_operators before each example, through the migrator
    credential. It is only ever safe against a scratch database.

    Name the database so it says so (matching #{SCRATCH_DATABASE_NAME.source},
    e.g. onetime_authdb_ci), or set #{DESTRUCTIVE_OVERRIDE}=1 if you have
    genuinely decided this database is disposable.
  REFUSAL
end

if PROVISIONED_DATABASE
  scratch_database!(ENV.fetch('ADMIN_DATABASE_URL'))
  SCRATCH_DIR = nil
  # A caller who sets only ADMIN_DATABASE_URL gets the single-credential
  # behaviour it had before; the Postgres lane sets all three.
  ENV['ADMIN_DATABASE_URL_RO'] ||= ENV.fetch('ADMIN_DATABASE_URL')
  ENV['ADMIN_DATABASE_URL_MIGRATIONS'] ||= ENV.fetch('ADMIN_DATABASE_URL')
else
  SCRATCH_DIR = File.join(Dir.tmpdir, "rodauth-admin-spec-#{Process.pid}")
  FileUtils.mkdir_p(SCRATCH_DIR)
  # One SQLite file plays all three roles (docs/design/database-credentials.md).
  ENV['ADMIN_DATABASE_URL'] = "sqlite://#{SCRATCH_DIR}/authdb.sqlite3"
  ENV['ADMIN_DATABASE_URL_RO'] = ENV.fetch('ADMIN_DATABASE_URL')
  ENV['ADMIN_DATABASE_URL_MIGRATIONS'] = ENV.fetch('ADMIN_DATABASE_URL')
end

require 'rack/test'
require 'rotp'
require 'argon2'

require_relative '../lib/rodauth_admin'
require_relative '../lib/rodauth_admin/authdb_schema'
require_relative '../lib/rodauth_admin/allowlist'
require_relative '../lib/rodauth_admin/audit'

# Both steps are idempotent: build! refuses to rebuild over an existing
# accounts table and Sequel::Migrator is a no-op when already at the latest
# version, so a pre-provisioned database falls straight through.
migrator = RodauthAdmin::Database.migrator
RodauthAdmin::AuthdbSchema.build!(migrator) unless migrator.table_exists?(:accounts)
RodauthAdmin::Database.migrate_admin!
RodauthAdmin.boot!

module SpecSupport
  TEST_ARGON2_COST = { t_cost: 1, m_cost: 5, p_cost: 1 }.freeze

  module_function

  # Fixture setup and teardown are schema-owner work, not runtime work, so
  # they go through the migrator whenever it is a genuinely different
  # credential. Under the real PostgreSQL grants the app role cannot do what
  # a fixture needs: `accounts` is SELECT-only for it, it has no access at
  # all to account_password_hashes, and account_otp_keys has no DELETE grant
  # (db/grants/postgres/rodauth_admin_roles.sql) — which is exactly the
  # privilege boundary the specs exist to keep intact, so the fixtures must
  # not be the thing that widens it. On SQLite all three URLs are the same
  # file, the comparison is false, and this stays Database.app as before.
  FIXTURE_DB = if RodauthAdmin::Env.database_url == RodauthAdmin::Env.database_url_migrations
                 RodauthAdmin::Database.app
               else
                 RodauthAdmin::Database.migrator
               end

  def authdb = FIXTURE_DB
  def admin_db = FIXTURE_DB

  # A Verified production-shaped account with an argon2id password hash in
  # the separate account_password_hashes table, exactly as the tenant app
  # stores it.
  def create_account(email:, password:, status_id: 2, external_id: nil)
    id = authdb[:accounts].insert(email: email, status_id: status_id, external_id: external_id)
    hash = Argon2::Password.new(**TEST_ARGON2_COST).create(password)
    authdb[:account_password_hashes].insert(id: id, password_hash: hash)
    id
  end

  # Every child of accounts first, then accounts. A hand-kept list is enough
  # on SQLite (foreign keys are not enforced there by default), but
  # PostgreSQL rejects the delete from accounts if any table the list forgot
  # still references it — so ask the database instead of maintaining a list.
  # account_statuses is reference data, never a child.
  ACCOUNT_CHILD_TABLES = FIXTURE_DB.tables.select { |t| t.to_s.start_with?('account_') }
                                   .reject { |t| t == :account_statuses }.freeze

  def wipe!
    ACCOUNT_CHILD_TABLES.each { |t| authdb[t].delete }
    authdb[:accounts].delete
    admin_db[:admin_operators].delete
    # admin_actions is append-only by trigger; leave it and assert on deltas.
  end

  def actions(action = nil)
    ds = admin_db[:admin_actions].order(:id)
    ds = ds.where(action: action) if action
    ds.all
  end
end

RSpec.configure do |config|
  config.include Rack::Test::Methods
  config.include SpecSupport
  config.before { SpecSupport.wipe! }
  config.after(:suite) do
    RodauthAdmin::Database.reset!
    FileUtils.rm_rf(SCRATCH_DIR) if SCRATCH_DIR
  end
end
