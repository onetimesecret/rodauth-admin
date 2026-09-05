# lib/rodauth_admin/account_list.rb
#
# frozen_string_literal: true

require 'sequel'

require_relative 'database'

module RodauthAdmin
  # The two state-filtered account lists of CHARTER §6 phase 2: who is
  # locked out right now (C-1), and which accounts have no Redis-side
  # customer to link to (orphans).
  #
  # Read-only, paginated, and closed: +filter+ is a strict whitelist and the
  # ordering is fixed per filter, so no caller input is ever interpolated
  # into SQL. Database errors degrade to available: false rather than
  # raising; the one deliberate raise is InvalidFilter, which is a
  # programming/param error, not an outage.
  module AccountList
    FILTERS = %i[locked orphaned].freeze
    PER_PAGE_DEFAULT = 25
    PER_PAGE_MAX = 100

    class InvalidFilter < ArgumentError; end

    # The columns every row carries, whatever the filter.
    ROW_COLUMNS = [
      Sequel[:accounts][:id], Sequel[:accounts][:email], Sequel[:accounts][:status_id],
      Sequel[:accounts][:external_id], Sequel[:account_statuses][:name].as(:status)
    ].freeze

    LOCKOUT_DEADLINE = Sequel[:account_lockouts][:deadline]
    LOCKED_COLUMNS = [
      LOCKOUT_DEADLINE.as(:lockout_deadline),
      Sequel[:account_login_failures][:number].as(:login_failures)
    ].freeze

    # The two outcomes of the database-touching half of a call, split out so
    # the degradation rescue can wrap the query and nothing else.
    Page = Data.define(:total, :page, :records)
    QueryFailure = Data.define(:filter, :page, :per_page, :reason)

    Row = Data.define(
      :id, :email, :status_id, :status, :external_id, :created_at,
      :lockout_deadline, :login_failures
    )

    Result = Data.define(:available, :reason, :filter, :page, :per_page, :total, :rows) do
      def pages
        return nil unless available

        [(total.to_f / per_page).ceil, 1].max
      end

      def next_page
        page + 1 if available && pages && page < pages
      end

      def prev_page
        page - 1 if available && page > 1
      end
    end

    class << self
      # @param filter [Symbol, String] one of FILTERS
      # @raise [InvalidFilter] for anything else
      # @return [Result] never raises for database reasons
      def call(filter:, page: 1, per_page: PER_PAGE_DEFAULT, db: Database.readonly, now: Time.now)
        filter   = normalize_filter(filter)
        per_page = clamp(per_page, PER_PAGE_DEFAULT, 1, PER_PAGE_MAX)
        page     = [coerce(page, 1), 1].max

        outcome = query(filter, page, per_page, db, now)
        return unavailable(outcome) if outcome.is_a?(QueryFailure)

        # Row building is deliberately outside the query rescue: a bug in
        # build_row is a bug, and must not be reported as an outage.
        rows = outcome.records.map { |r| build_row(filter, r) }.freeze
        Result.new(available: true, reason: nil, filter: filter, page: outcome.page,
                   per_page: per_page, total: outcome.total, rows: rows).freeze
      end

      private

      def normalize_filter(filter)
        sym = filter.respond_to?(:to_sym) ? filter.to_sym : nil
        return sym if FILTERS.include?(sym)

        raise InvalidFilter, "unknown filter #{filter.inspect}; expected one of #{FILTERS.join(', ')}"
      end

      def coerce(value, default) = Integer(value, exception: false) || default

      def clamp(value, default, min, max) = coerce(value, default).clamp(min, max)

      # Everything that touches the database, and only that. Same net as
      # Stats.call: a blinking authdb is an explanatory state, never a 500 —
      # and never a mislabelled bug.
      def query(filter, page, per_page, db, now)
        base = filter == :locked ? locked_dataset(db, now) : orphaned_dataset(db)
        total = base.count
        page = clamp_page(page, total, per_page)
        Page.new(total: total, page: page, records: base.limit(per_page, (page - 1) * per_page).all)
      rescue *Database::UNAVAILABLE_ERRORS => e
        RodauthAdmin.logger.warn('authdb account list unavailable', e)
        QueryFailure.new(filter: filter, page: page, per_page: per_page,
                         reason: Database.failure_reason(e))
      end

      # An out-of-range page shows the last page rather than an empty table
      # with a "previous" link into nothing: ?page=999999 is a stale
      # bookmark or a shrunken list, not an error worth a screen.
      def clamp_page(page, total, per_page)
        total.zero? ? page : page.clamp(1, [(total.to_f / per_page).ceil, 1].max)
      end

      # Lockout rows linger after they expire (Rodauth does not delete them
      # eagerly), so deadline is filtered on every read. BooleanExpression
      # rather than `deadline > now`: the rubocop Yoda cop misreads a Sequel
      # comparison as a reversed Ruby one.
      def locked_dataset(db, now)
        locked_joins(db)
          .where(Sequel::SQL::BooleanExpression.new(:>, LOCKOUT_DEADLINE, now))
          .order(LOCKOUT_DEADLINE, Sequel[:accounts][:id])
          .select(*account_columns(db), *LOCKED_COLUMNS)
      end

      def locked_joins(db)
        db[:accounts]
          .join(:account_lockouts, id: :id)
          .left_join(:account_login_failures, id: Sequel[:accounts][:id])
          .left_join(:account_statuses, id: Sequel[:accounts][:status_id])
      end

      # WHERE external_id IS NULL is a seq scan at 200k rows; acceptable at
      # this size. Add a partial index if accounts grows.
      def orphaned_dataset(db)
        db[:accounts]
          .left_join(:account_statuses, id: Sequel[:accounts][:status_id])
          .where(Sequel[:accounts][:external_id] => nil)
          .order(Sequel[:accounts][:id])
          .select(*account_columns(db))
      end

      # created_at is conditional: production's accounts has timestamps
      # (authdb_schema.rb), a bare rodauth-tools table does not.
      def account_columns(db)
        return ROW_COLUMNS unless db[:accounts].columns.include?(:created_at)

        ROW_COLUMNS + [Sequel[:accounts][:created_at]]
      end

      def build_row(filter, row)
        locked = filter == :locked
        Row.new(
          id: row[:id], email: row[:email], status_id: row[:status_id], status: row[:status],
          external_id: row[:external_id], created_at: row[:created_at],
          lockout_deadline: locked ? row[:lockout_deadline] : nil,
          login_failures: locked ? (row[:login_failures] || 0) : nil
        ).freeze
      end

      def unavailable(failure)
        Result.new(available: false, reason: failure.reason, filter: failure.filter,
                   page: failure.page, per_page: failure.per_page, total: nil, rows: [].freeze).freeze
      end
    end
  end
end
