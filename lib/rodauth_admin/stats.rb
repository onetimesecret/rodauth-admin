# lib/rodauth_admin/stats.rb
#
# frozen_string_literal: true

require 'sequel'

require_relative 'database'

module RodauthAdmin
  # Aggregate authdb visibility (CHARTER §6 phase 2). Read-only: every stat
  # is its own cheap, indexed COUNT run through the SELECT-only credential,
  # and no row is ever loaded.
  #
  # Degradation contract: the authdb blinking must never 500 an admin
  # screen, so #call rescues database errors and returns a Result with
  # available: false and every count nil.
  module Stats
    # customer_count comes from the Familia/Redis side, which v1 deliberately
    # does not talk to: CHARTER §4 forbids cross-service calls and §7 leaves
    # the Redis-side read open. So the seam ships as a pluggable callable
    # returning Integer or nil, wired to NullSource. When a later phase picks
    # a source (read-only Redis, or a stats endpoint on the tenant app), it
    # sets Stats.customer_count_source and the drift stat lights up with no
    # other change here.
    module NullSource
      def self.call = nil
    end

    # @!attribute status_breakdown
    #   [Array<Hash>] one frozen {id:, name:, count:} per account_statuses
    #   row, ordered by id. Labels are read from the table, never hardcoded:
    #   the 1/2/3 mapping is positional seed data and a future status
    #   addition must not mislabel.
    # @!attribute active_session_keys
    #   [Integer] rows in account_active_session_keys. The name is
    #   deliberate: Rodauth retains rows until its inactivity cleanup runs,
    #   so this is "active session keys", not "users online".
    # @!attribute recovery_code_rows
    #   [Integer] rows in account_recovery_codes. Production's used_at is
    #   always NULL because Rodauth deletes a code on use (db/README.md
    #   "Known drift"), so the unused-code stat is simply the row count.
    Result = Data.define(
      :available, :reason, :computed_at,
      :total_accounts, :status_breakdown,
      :mfa_otp_accounts, :mfa_webauthn_accounts,
      :active_lockouts, :active_session_keys, :recovery_code_rows,
      :orphaned_accounts, :customer_count, :customer_count_delta
    )

    CACHE_MUTEX = Mutex.new
    private_constant :CACHE_MUTEX

    class << self
      def customer_count_source
        CACHE_MUTEX.synchronize { customer_source }
      end

      def customer_count_source=(source)
        CACHE_MUTEX.synchronize { store_customer_source(source || NullSource) }
      end

      # @return [Result] never raises
      def call(db: Database.readonly, now: Time.now)
        compute(db, now)
      # Sequel::DatabaseError covers query failures and
      # Sequel::DatabaseConnectionError connection ones, but a dead socket
      # can surface as plain IOError/SystemCallError too, so the net is
      # StandardError: a stats board must never 500.
      rescue StandardError => e
        RodauthAdmin.logger.warn('authdb stats unavailable', e)
        unavailable("#{e.class}: #{e.message.to_s.lines.first.to_s.strip}", now)
      end

      # A brief process-local memo: the stats board is nine counts against
      # ~200k rows and must not be recomputed on every nav render. An
      # unavailable result is never cached, so the next request retries.
      def cached(ttl: 60, db: Database.readonly, now: Time.now)
        CACHE_MUTEX.synchronize do
          hit = read_cache
          return hit[:result] if hit && hit[:result].available && (now - hit[:at]) < ttl

          result = call(db: db, now: now)
          store_cache(result, now) if result.available
          result
        end
      end

      def reset_cache!
        CACHE_MUTEX.synchronize { clear_cache }
        nil
      end

      private

      # rubocop:disable ThreadSafety/ClassInstanceVariable -- guarded by CACHE_MUTEX
      def read_cache = @cache
      def customer_source = (@customer_source ||= NullSource)
      def store_customer_source(source) = @customer_source = source

      def store_cache(result, now)
        @cache = { result: result, at: now }
      end

      def clear_cache
        @cache = nil
      end
      # rubocop:enable ThreadSafety/ClassInstanceVariable

      def compute(db, now)
        Result.new(
          available: true, reason: nil, computed_at: now,
          status_breakdown: status_breakdown(db),
          **account_counts(db), **feature_counts(db, now)
        ).freeze
      end

      def account_counts(db)
        total = db[:accounts].count
        customers = customer_source.call
        {
          total_accounts: total,
          # A seq scan at 200k rows, which is acceptable at this size. If
          # accounts grows, add a partial index on (external_id) WHERE
          # external_id IS NULL rather than pre-building one now.
          orphaned_accounts: db[:accounts].where(external_id: nil).count,
          customer_count: customers,
          customer_count_delta: customers && (total - customers)
        }
      end

      def feature_counts(db, now)
        {
          mfa_otp_accounts: db[:account_otp_keys].count,
          mfa_webauthn_accounts: db[:account_webauthn_keys].distinct.select(:account_id).count,
          # Lockout rows linger: Rodauth does not eagerly delete expired
          # ones, so every "locked now" read filters on deadline.
          active_lockouts: db[:account_lockouts].where { deadline > now }.count,
          active_session_keys: db[:account_active_session_keys].count,
          recovery_code_rows: db[:account_recovery_codes].count
        }
      end

      def status_breakdown(db)
        counts = db[:accounts].group_and_count(:status_id).to_hash(:status_id, :count)
        db[:account_statuses].order(:id).select_map(%i[id name]).map do |id, name|
          { id: id, name: name, count: counts.fetch(id, 0) }.freeze
        end.freeze
      end

      def unavailable(reason, now)
        Result.new(
          available: false, reason: reason, computed_at: now,
          total_accounts: nil, status_breakdown: nil,
          mfa_otp_accounts: nil, mfa_webauthn_accounts: nil,
          active_lockouts: nil, active_session_keys: nil, recovery_code_rows: nil,
          orphaned_accounts: nil, customer_count: nil, customer_count_delta: nil
        ).freeze
      end
    end
  end
end
