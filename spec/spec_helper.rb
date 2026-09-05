# spec/spec_helper.rb
#
# frozen_string_literal: true

# Boots the whole app against a scratch SQLite database: Rodauth's tables
# built from the rodauth-tools templates (the same shape as production) plus
# the migrated admin tables. ENV must be set before lib/rodauth_admin loads,
# because RodauthAdmin::Auth's table_guard connects at class-definition time.

require 'fileutils'
require 'securerandom'
require 'tmpdir'

ENV['RACK_ENV'] = 'test'
ENV['AUTH_SECRET'] = "test-hmac-secret-#{'x' * 48}"
ENV['RODAUTH_ADMIN_SESSION_SECRET'] = SecureRandom.hex(64)
ENV.delete('ARGON2_SECRET')

SCRATCH_DIR = File.join(Dir.tmpdir, "rodauth-admin-spec-#{Process.pid}")
FileUtils.mkdir_p(SCRATCH_DIR)
# One SQLite file plays all three roles (docs/design/database-credentials.md).
ENV['ADMIN_DATABASE_URL'] = "sqlite://#{SCRATCH_DIR}/authdb.sqlite3"
ENV['ADMIN_DATABASE_URL_RO'] = ENV.fetch('ADMIN_DATABASE_URL')
ENV['ADMIN_DATABASE_URL_MIGRATIONS'] = ENV.fetch('ADMIN_DATABASE_URL')

require 'rack/test'
require 'rotp'
require 'argon2'

require_relative '../lib/rodauth_admin'
require_relative '../lib/rodauth_admin/authdb_schema'
require_relative '../lib/rodauth_admin/allowlist'
require_relative '../lib/rodauth_admin/audit'

RodauthAdmin::AuthdbSchema.build!(RodauthAdmin::Database.migrator)
RodauthAdmin::Database.migrate_admin!
RodauthAdmin.boot!

module SpecSupport
  TEST_ARGON2_COST = { t_cost: 1, m_cost: 5, p_cost: 1 }.freeze

  module_function

  def authdb = RodauthAdmin::Database.app
  def admin_db = RodauthAdmin::Database.app

  # A Verified production-shaped account with an argon2id password hash in
  # the separate account_password_hashes table, exactly as the tenant app
  # stores it.
  def create_account(email:, password:, status_id: 2, external_id: nil)
    id = authdb[:accounts].insert(email: email, status_id: status_id, external_id: external_id)
    hash = Argon2::Password.new(**TEST_ARGON2_COST).create(password)
    authdb[:account_password_hashes].insert(id: id, password_hash: hash)
    id
  end

  def wipe!
    %i[account_otp_keys account_lockouts account_login_failures account_authentication_audit_logs
       account_password_hashes accounts].each { |t| authdb[t].delete }
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
    FileUtils.rm_rf(SCRATCH_DIR)
  end
end
