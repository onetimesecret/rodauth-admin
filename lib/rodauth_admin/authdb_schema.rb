# lib/rodauth_admin/authdb_schema.rb
#
# frozen_string_literal: true

require 'sequel'
require 'rodauth/tools'

module RodauthAdmin
  # The production authdb schema, expressed as the rodauth-tools feature
  # list it was generated from plus the handful of columns the tenant app
  # added on top. Used for two things:
  #
  #   1. Building a local development / test authdb (`rake authdb:dev`,
  #      spec_helper) that has the same shape as production, without
  #      copying the tenant app's migrations.
  #   2. Documentation: this list IS the capability surface (CHARTER §3).
  #
  # Production itself is never touched by this module. Its schema is
  # validated at boot by table_guard in RodauthAdmin::Auth.
  #
  # Source of truth for the feature list: onetimesecret/onetimesecret
  # apps/web/auth/config.rb and migrations/001_initial.rb (2026-09-04).
  module AuthdbSchema
    # Order matters: base first (every other table has an FK to accounts).
    PRODUCTION_FEATURES = %i[
      base
      audit_logging
      reset_password
      jwt_refresh
      verify_account
      verify_login_change
      remember
      lockout
      email_auth
      password_expiration
      account_expiration
      single_session
      active_sessions
      webauthn
      otp
      otp_unlock
      recovery_codes
      sms_codes
      disallow_password_reuse
    ].freeze

    TABLE_PREFIX = 'account'

    module_function

    # Create every production authdb table in +db+. Idempotent guard: refuses
    # to run against a database that already has an accounts table.
    def build!(db)
      if db.table_exists?(:accounts)
        raise ConfigurationError,
              'authdb already has an accounts table; refusing to rebuild'
      end

      generator = Rodauth::Tools::Migration.new(features: PRODUCTION_FEATURES, prefix: TABLE_PREFIX, db: db)
      generator.execute_create_tables(db)
      apply_production_deltas!(db)
      db
    end

    # What the tenant app's 001_initial.rb / 006 / 008 migrations add beyond
    # the rodauth-tools templates.
    def apply_production_deltas!(db)
      db.alter_table(:accounts) do
        # The Redis<->SQL join key: accounts.external_id == Customer.extid
        add_column :external_id, String, null: true
        add_index :external_id, unique: true
        add_column :created_at, DateTime, null: false, default: Sequel::CURRENT_TIMESTAMP
        add_column :updated_at, DateTime, null: false, default: Sequel::CURRENT_TIMESTAMP
      end

      db.alter_table(:account_password_hashes) do
        add_column :created_at, DateTime, null: false, default: Sequel::CURRENT_TIMESTAMP
      end

      # Present in production's migration but never written: Rodauth deletes a
      # recovery code on use. Kept for shape parity; do not build stats on it.
      db.alter_table(:account_recovery_codes) do
        add_column :used_at, DateTime
      end

      # 006_omniauth_identities + 008_issuer_scoped_identities
      db.create_table(:account_identities) do
        primary_key :id, type: :Bignum
        foreign_key :account_id, :accounts, null: false, type: :Bignum, on_delete: :cascade
        String :provider, null: false
        String :uid, null: false
        String :issuer, null: false, default: ''
        unique %i[provider issuer uid]
        index :account_id
      end
      db
    end

    # Every table build! creates, in creation order.
    def tables
      Rodauth::TemplateInspector.all_tables_for_features(PRODUCTION_FEATURES, table_prefix: TABLE_PREFIX) +
        [:account_identities]
    end
  end
end
