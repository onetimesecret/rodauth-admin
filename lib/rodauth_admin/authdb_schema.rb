# lib/rodauth_admin/authdb_schema.rb
#
# frozen_string_literal: true

require 'sequel'
require 'rodauth/migrations'
require 'rodauth/tools'

require_relative 'env'

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

    # Create every production authdb table in +db+. Two guards, both before
    # any DDL: never in production (this module builds development and test
    # databases; production's schema is owned by the tenant app's
    # migrations), and never over an existing accounts table.
    #
    # The refusal lives here rather than only in the Rakefile because the
    # rake task is not the only caller — spec_helper builds through this
    # method too — and a guard that a second caller can walk around is not
    # a guard. The Rakefile keeps its abort as the friendly CLI message.
    def build!(db)
      raise ConfigurationError, 'refusing to build an authdb with RACK_ENV=production' if Env.production?

      if db.table_exists?(:accounts)
        raise ConfigurationError,
              'authdb already has an accounts table; refusing to rebuild'
      end

      generator = Rodauth::Tools::Migration.new(features: PRODUCTION_FEATURES, prefix: TABLE_PREFIX, db: db)
      if db.database_type == :postgres
        execute_create_tables_postgres(db, generator)
      else
        generator.execute_create_tables(db)
      end
      apply_production_deltas!(db)
      apply_password_functions!(db)
      db
    end

    # rodauth-tools 0.4.1's base.erb emits account_password_hashes — whose
    # primary key is a foreign key to accounts — BEFORE accounts itself.
    # SQLite accepts that (foreign keys are not enforced at CREATE time), so
    # the bug is invisible on the default local path; PostgreSQL rejects it
    # with `relation "accounts" does not exist`. Nothing else in the template
    # set references account_password_hashes (account_previous_password_hashes
    # keys off accounts), so moving that one block to the end is enough and
    # leaves the resulting schema identical.
    #
    # The eval mirrors what the gem's own execute_create_tables does, for the
    # same reason it does it: the input is a Sequel migration DSL string
    # generated from the gem's ERB templates. Guarded so that a template
    # change upstream stops the build rather than silently skipping the move.
    PG_DEFERRED_BLOCK = <<~RUBY
      create_table(:account_password_hashes) do
        foreign_key :id, :accounts, primary_key: true, type: :Bignum
        String :password_hash, null: false
      end
    RUBY

    def execute_create_tables_postgres(db, generator)
      code = generator.generate
      unless code.include?(PG_DEFERRED_BLOCK)
        raise ConfigurationError,
              'rodauth-tools base.erb no longer emits the expected ' \
              'account_password_hashes block; re-check the PostgreSQL table order'
      end

      code = "#{code.sub(PG_DEFERRED_BLOCK, '')}\n#{PG_DEFERRED_BLOCK}"

      require 'sequel/extensions/migration'
      migration = Sequel.migration do
        up do
          # rubocop:disable-next Security/Eval
          eval(code, binding, __FILE__, __LINE__)
        end
      end
      migration.apply(db, :up)
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

    # PostgreSQL only. Production's authdb has the two SECURITY DEFINER
    # password functions (tenant app migration 003) and Rodauth *uses them
    # by default* on PostgreSQL: `use_database_authentication_functions?`
    # is true for :postgres, so `password_match?` calls
    # rodauth_valid_password_hash rather than reading the hash table
    # (rodauth 2.47.0 lib/rodauth/features/base.rb:826, :501). Without them
    # a PostgreSQL authdb built from the templates cannot verify a password
    # at all, and the EXECUTE grants in
    # db/grants/postgres/rodauth_admin_roles.sql would have no target.
    #
    # Rodauth ships the generator: argon2: true makes get_salt return the
    # argon2 parameter+salt prefix instead of bcrypt's 29 bytes, which
    # matches production's hand-written function.
    # SQLite has no equivalent and needs none: there Rodauth reads
    # account_password_hashes directly.
    def apply_password_functions!(db)
      return db unless db.database_type == :postgres

      Rodauth.create_database_authentication_functions(db, argon2: true)
      # The whole point of SECURITY DEFINER is that only the login role may
      # call them; PUBLIC EXECUTE would let the read-only role brute-force
      # password hashes it is deliberately denied SELECT on.
      ['rodauth_get_salt(int8)', 'rodauth_valid_password_hash(int8, text)'].each do |sig|
        db.run("REVOKE ALL ON FUNCTION #{sig} FROM PUBLIC")
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
