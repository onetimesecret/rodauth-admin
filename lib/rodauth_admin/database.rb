# lib/rodauth_admin/database.rb
#
# frozen_string_literal: true

require 'sequel'
require 'timeout'

require_relative 'env'

# One timezone on both sides of every timestamp, set once, before any
# connection exists.
#
# Rodauth writes account_lockouts.deadline with the DATABASE clock
# (CURRENT_TIMESTAMP + interval, into a `timestamp without time zone`
# column; set_deadline_values? is false on PostgreSQL). The admin only ever
# reads those columns. With no timezone configured Sequel literalises a Ruby
# Time in the app process's local wall clock and parses a fetched timestamp
# back the same way, so an app container on TZ=America/New_York compares
# 08:00 against a deadline the database wrote as 12:00 UTC and shows expired
# lockouts as active for four hours.
#
# UTC on both sides removes the dependency on the host's TZ entirely:
# database_timezone says "timestamps coming out of the database are UTC"
# (the tenant app runs PostgreSQL with the default TimeZone=UTC), and
# application_timezone says "convert them to UTC Time objects, and
# literalise Ruby Times as UTC on the way in".
Sequel.database_timezone = :utc
Sequel.application_timezone = :utc

module RodauthAdmin
  # Sequel connections, one per credential (docs/design/database-credentials.md):
  #
  #   app        runtime user. The ONLY connection Rodauth uses, and the one
  #              the allowlist and admin_actions are written through.
  #   readonly   read-only user; every admin query (Phase 2+).
  #   verbs      mutation user; the Phase 4 verbs, and the admin_actions row
  #              each one commits in the SAME transaction on this SAME
  #              connection. Deliberately not the readonly role widened.
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

      def verbs
        connection(:verbs) { connect(Env.database_url_verbs, name: 'verbs') }
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

      # Everything a connection needs beyond the URL, in one place so that a
      # database built in-process (the tryouts, spec fixtures) behaves like
      # the ones the app opens.
      def configure!(db)
        db.extension :date_arithmetic
        # SQLite's CURRENT_TIMESTAMP is UTC, but Sequel's SQLite adapter
        # wraps it in datetime(..., 'localtime') unless told otherwise —
        # which would put the app host's TZ back into `deadline > now` on
        # the SQLite lane only. Timestamps are stored as UTC strings here
        # (Sequel.application_timezone above), so ask for UTC.
        db.current_timestamp_utc = true if db.respond_to?(:current_timestamp_utc=)
        # PostgreSQL compares a `timestamp without time zone` (which is what
        # account_lockouts.deadline is) against CURRENT_TIMESTAMP by casting
        # the latter through the SESSION's TimeZone. Production runs UTC, but
        # a session that inherits a local zone would silently shift every
        # deadline comparison, so pin it rather than inherit it.
        db.pool.after_connect = proc { |c| c.exec("SET TIME ZONE 'UTC'") } if db.database_type == :postgres
        db
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
        db = configure!(Sequel.connect(url, **opts))
        db.loggers << SemanticLogger["Sequel(#{name})"] if Env.development? && defined?(SemanticLogger)
        db
      end
    end
  end
end
