# lib/rodauth_admin/database.rb
#
# frozen_string_literal: true

require 'sequel'
require 'timeout'

require_relative 'env'

module RodauthAdmin
  # Sequel connections, one per credential (docs/design/database-credentials.md):
  #
  #   app        runtime user. The ONLY connection Rodauth uses, and the one
  #              the allowlist and admin_actions are written through.
  #   readonly   read-only user; every admin query (Phase 2+).
  #   migrator   the tenant app's existing migration user. Offline only:
  #              rake db:migrate and rake authdb:dev. Never touched by the
  #              running app.
  #
  # Every connection points at the same database: the admin's tables live
  # beside Rodauth's, prefixed admin_, and are migrated by the same
  # migrator with their own schema_info table.
  module Database
    ADMIN_MIGRATIONS_DIR = File.expand_path('../../db/migrate', __dir__)
    ADMIN_TABLES = %i[admin_operators admin_actions].freeze
    # The tenant app's migrations own :schema_info in this database.
    ADMIN_SCHEMA_TABLE = :admin_schema_info

    # What "the authdb is unreachable" actually looks like, and nothing
    # else. Read paths degrade to an explanatory panel on these (Stats,
    # AccountList) — so the list must stay narrow: a NoMethodError or a
    # NameError caught here would be reported to an incident responder as
    # "the database is down", which is the worst possible time to be lied
    # to. Sequel::DatabaseConnectionError and Sequel::PoolTimeout are
    # subclasses of Sequel::DatabaseError today; both are named so a
    # future reparenting cannot silently narrow this.
    UNAVAILABLE_ERRORS = [
      Sequel::DatabaseError,
      Sequel::DatabaseConnectionError,
      Sequel::PoolTimeout,
      IOError,
      SystemCallError,
      Timeout::Error
    ].freeze

    # The one-line "why" a read path is showing a degraded panel. First line
    # only: a PostgreSQL connection error's message is a paragraph.
    def self.failure_reason(error)
      "#{error.class}: #{error.message.to_s.lines.first.to_s.strip}"
    end

    MUTEX = Mutex.new
    private_constant :MUTEX

    class << self
      def app
        connection(:app) { connect(Env.database_url, name: 'app') }
      end

      def readonly
        connection(:readonly) { connect(Env.database_url_ro, name: 'readonly') }
      end

      def migrator
        connection(:migrator) { connect(Env.database_url_migrations, name: 'migrator') }
      end

      # Disconnect and forget every connection (tests, credential rotation).
      def reset!
        MUTEX.synchronize do
          connections.each_value(&:disconnect)
          connections.clear
        end
      end

      # Run the admin migrations with the migrator credential. Offline only.
      def migrate_admin!(db = migrator)
        Sequel.extension :migration
        Sequel::Migrator.run(db, ADMIN_MIGRATIONS_DIR, table: ADMIN_SCHEMA_TABLE)
        db
      end

      def check_admin_schema!(db = app)
        missing = ADMIN_TABLES.reject { |t| db.table_exists?(t) }
        return true if missing.empty?

        raise ConfigurationError,
              "database is missing #{missing.join(', ')}; " \
              'run `bundle exec rake db:migrate` with ADMIN_DATABASE_URL_MIGRATIONS set'
      end

      private

      # rubocop:disable ThreadSafety/ClassInstanceVariable -- guarded by MUTEX
      def connections
        @connections ||= {}
      end
      # rubocop:enable ThreadSafety/ClassInstanceVariable

      def connection(key)
        MUTEX.synchronize { connections[key] ||= yield }
      end

      def connect(url, name:)
        opts = { test: false }
        # In-memory SQLite is per-connection; a pool would give each thread
        # its own empty database.
        opts[:max_connections] = 1 if url.include?(':memory:')
        db = Sequel.connect(url, **opts)
        db.extension :date_arithmetic
        db.loggers << SemanticLogger["Sequel(#{name})"] if Env.development? && defined?(SemanticLogger)
        db
      end
    end
  end
end
