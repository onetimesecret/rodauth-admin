# spec/spec_helper.rb
#
# frozen_string_literal: true

# Boots the whole app against a scratch SQLite database: Rodauth's tables
# built from the rodauth-tools templates (the same shape as production) plus
# the migrated admin tables. ENV must be set before lib/rodauth_admin loads,
# because RodauthAdmin::Auth's table_guard connects at class-definition time.
#
# Two modes, chosen by SpecMode.provisioned_database? from the environment as
# inherited — before this file sets RACK_ENV:
#
#   default (local, and the `test` CI job) — a scratch SQLite file plays all
#     three credentials, and this file builds and migrates it. Any
#     ADMIN_DATABASE_URL* inherited from the shell is IGNORED and overwritten.
#   pre-provisioned (the `test-postgres` CI job) — the caller set RACK_ENV=test
#     *and* ADMIN_DATABASE_URL, pointing at a real PostgreSQL authdb that CI
#     built, migrated and granted with three genuinely different roles.
#     Nothing is built here; the schema steps below are skipped when the
#     schema exists, which is also what makes a re-run work.
#
# The RACK_ENV=test condition is what keeps a developer shell out of the
# provisioned path: direnv exports the real local ADMIN_DATABASE_URL with
# RACK_ENV=development, and treating that as "provisioned" made `rake test`
# die in the scratch guard. Saying `RACK_ENV=test ADMIN_DATABASE_URL=... rspec`
# is the deliberate act that opts in — and the scratch guard still has to pass.

require 'fileutils'
require 'securerandom'
require 'tmpdir'
require 'uri'

require 'simplecov'
SimpleCov.start do
  enable_coverage :line
  cover 'lib/**/*.rb'
  skip '/spec/'
  skip '/try/'
end
SimpleCov.at_exit do
  result = SimpleCov.result
  result.format!
  covered = result.covered_lines
  total = covered + result.missed_lines
  # One grep-able line for the CI job summary; no minimum threshold.
  $stdout.puts format('Coverage: %<pct>.1f%% (%<covered>d/%<total>d lines)',
                      pct: result.covered_percent, covered: covered, total: total)
end

require_relative 'support/spec_mode'
PROVISIONED_DATABASE = SpecMode.provisioned_database?(ENV)

ENV['RACK_ENV'] = 'test'
ENV['AUTH_SECRET'] = "test-hmac-secret-#{'x' * 48}"
ENV['RODAUTH_ADMIN_SESSION_SECRET'] = SecureRandom.hex(64)
ENV.delete('ARGON2_SECRET')

# RACK_ENV=test is not a guard: it is set two lines up, unconditionally, by
# this very file. So the database has to name itself as disposable — or the
# operator has to say so explicitly, once, in the environment. The rule and
# the name-check are in spec/support/scratch_guard.rb, pure over strings.
require_relative 'support/scratch_guard'

if PROVISIONED_DATABASE
  # A caller who sets only ADMIN_DATABASE_URL gets the single-credential
  # behaviour it had before; the Postgres lane sets all three.
  ENV['ADMIN_DATABASE_URL_RO'] ||= ENV.fetch('ADMIN_DATABASE_URL')
  ENV['ADMIN_DATABASE_URL_MIGRATIONS'] ||= ENV.fetch('ADMIN_DATABASE_URL')
  SCRATCH_DIR = nil
else
  SCRATCH_DIR = File.join(Dir.tmpdir, "rodauth-admin-spec-#{Process.pid}")
  FileUtils.mkdir_p(SCRATCH_DIR)
  # One SQLite file plays all three roles (docs/design/database-credentials.md).
  ENV['ADMIN_DATABASE_URL'] = "sqlite://#{SCRATCH_DIR}/authdb.sqlite3"
  ENV['ADMIN_DATABASE_URL_RO'] = ENV.fetch('ADMIN_DATABASE_URL')
  ENV['ADMIN_DATABASE_URL_MIGRATIONS'] = ENV.fetch('ADMIN_DATABASE_URL')
end

# The override turns the guard off wholesale, so it says so, loudly, every
# time. bin/ci strips it unless the caller set it on the command line of a
# RACK_ENV=test invocation.
if ScratchGuard.override?(ENV)
  warn <<~BANNER
    ****************************************************************
    #{ScratchGuard::DESTRUCTIVE_OVERRIDE}=1 is set.

    The scratch-database guard is DISABLED for this run. This suite
    truncates every account table and runs DDL through the migrator
    credential, against whatever ADMIN_DATABASE_URL* point at:

      ADMIN_DATABASE_URL             #{ENV.fetch('ADMIN_DATABASE_URL', '(unset)')}
      ADMIN_DATABASE_URL_RO          #{ENV.fetch('ADMIN_DATABASE_URL_RO', '(unset)')}
      ADMIN_DATABASE_URL_MIGRATIONS  #{ENV.fetch('ADMIN_DATABASE_URL_MIGRATIONS', '(unset)')}

    If you did not mean to set this, stop now and unset it.
    ****************************************************************
  BANNER
end

# Before anything connects: every URL the suite can write through, not just
# the app one. The destructive statements run through the migrator.
offenders = ScratchGuard.offenders(ENV, scratch_dir: SCRATCH_DIR)
abort ScratchGuard.refusal(*offenders.first) unless offenders.empty?

require 'rack/lint'
require 'rack/test'
require 'rotp'
require 'argon2'

require_relative '../lib/rodauth_admin'
require_relative '../lib/rodauth_admin/authdb_schema'
require_relative '../lib/rodauth_admin/allowlist'
require_relative '../lib/rodauth_admin/audit'

# The string check above proves the configuration; this proves the
# connection. Sequel resolves a URL into opts[:database], and that is what
# the DELETEs and the DDL actually land in.
def assert_scratch_connection!(label, db)
  name = ScratchGuard.violation(db.opts[:database], scratch_dir: SCRATCH_DIR)
  abort ScratchGuard.refusal("the #{label} connection", name) if name
end

migrator = RodauthAdmin::Database.migrator
assert_scratch_connection!('migrator', migrator)
assert_scratch_connection!('app', RodauthAdmin::Database.app)

# Both steps are idempotent: build! refuses to rebuild over an existing
# accounts table and Sequel::Migrator is a no-op when already at the latest
# version, so a pre-provisioned database falls straight through.
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

  # Every spec drives the app through Rack::Lint, so a Rack 3 protocol
  # violation (a frozen-string body, a bad header name, a non-Integer status)
  # fails a spec here rather than surprising a real server. Lint is test-only
  # on purpose: config.ru runs the app bare.
  LINTED_APP = Rack::Lint.new(RodauthAdmin::App)

  def app = LINTED_APP

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
