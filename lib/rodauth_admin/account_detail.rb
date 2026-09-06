# lib/rodauth_admin/account_detail.rb
#
# frozen_string_literal: true

require 'sequel'

require_relative 'database'

module RodauthAdmin
  # The one per-account page of CHARTER §6 phase 3, read-only: identity and
  # status, lockout, MFA inventory, sessions, refresh tokens, pending
  # tokens, SSO identities, password history, and a paginated
  # authentication timeline.
  #
  # Two rules run through every query here.
  #
  # 1. Explicit columns, always. `SELECT *` on accounts would pull
  #    password_hash (rodauth-tools builds keep it on the accounts table),
  #    and on the key tables it would pull the bearer secrets themselves.
  #    Nothing in this file may ever select accounts.password_hash,
  #    account_previous_password_hashes.password_hash,
  #    account_otp_keys.key, account_recovery_codes.code,
  #    account_webauthn_keys.public_key, or the `key` column of any of the
  #    lockout / reset / verification / login-change / email-auth /
  #    jwt-refresh tables. The column lists in this file are the ONLY thing
  #    keeping accounts.password_hash (rodauth-tools builds put it there) out
  #    of the app: the read-only PostgreSQL role holds a table-wide
  #    `GRANT SELECT ON accounts`, so PostgreSQL will not stop a slip either
  #    — it only column-scopes account_previous_password_hashes. That is why
  #    every dataset here selects named columns, and why the lists below are
  #    constants rather than inline.
  #
  # 2. Not found is not an outage. A missing account is a normal answer
  #    (found: false, available: true); only Database::UNAVAILABLE_ERRORS
  #    degrade the result to available: false, exactly as in Stats and
  #    AccountList. Anything else — a NoMethodError in this file — is a bug
  #    and propagates.
  # rubocop:disable Metrics/ModuleLength -- eight sections of one screen; splitting
  # them across files would scatter the column whitelists this module exists to hold.
  module AccountDetail
    PER_PAGE_DEFAULT = 25
    PER_PAGE_MAX = 100

    # Sessions are listed, not counted, and an account can accumulate a lot
    # of session-key rows (Rodauth retains them until its inactivity cleanup
    # runs). The page shows the most recently used SESSION_CAP and reports
    # the true total beside them, so a pathological account cannot render a
    # multi-thousand-row table into an admin's browser.
    SESSION_CAP = 50
    # Refresh tokens accumulate the same way (Rodauth keeps a row per issued
    # token until its deadline is swept), so they are capped and totalled on
    # the same terms as sessions.
    REFRESH_TOKEN_CAP = 50
    # A session_id is a bearer-ish identifier; the page shows a prefix long
    # enough to correlate two rows and short enough to be useless if the
    # screenshot leaks.
    SESSION_ID_PREFIX = 8

    # See Stats::DB_CLOCK: every `deadline > now` comparison defaults to the
    # database's own clock, because the database is what wrote the deadline.
    DB_CLOCK = Sequel::CURRENT_TIMESTAMP

    ACCOUNT_COLUMNS = [
      Sequel[:accounts][:id], Sequel[:accounts][:email], Sequel[:accounts][:status_id],
      Sequel[:accounts][:external_id], Sequel[:account_statuses][:name].as(:status)
    ].freeze
    # created_at/updated_at are the tenant app's addition (authdb_schema.rb);
    # a bare rodauth-tools accounts table has neither, so they are probed.
    ACCOUNT_TIMESTAMPS = %i[created_at updated_at].freeze

    # Pending token types, in render order. Each entry names the table, the
    # columns to select from it, and the deadline column that carries its
    # expiry — verification is the odd one out: Rodauth stores requested_at
    # there, not a deadline, so "expired?" is not computable for it and
    # stays nil. The column lists are spelled out rather than discovered
    # because discovery itself is a leak: Sequel's Dataset#columns runs
    # `SELECT * ... LIMIT 0`, which on PostgreSQL needs SELECT on every
    # column of the table — including the `key` the read-only role is
    # deliberately denied.
    PENDING_TOKENS = [
      { type: :password_reset, table: :account_password_reset_keys,
        columns: %i[deadline email_last_sent], deadline: :deadline },
      { type: :verification, table: :account_verification_keys,
        columns: %i[requested_at email_last_sent], deadline: nil },
      { type: :login_change, table: :account_login_change_keys,
        columns: %i[login deadline], deadline: :deadline },
      { type: :email_auth, table: :account_email_auth_keys,
        columns: %i[deadline email_last_sent], deadline: :deadline }
    ].freeze

    Account = Data.define(:id, :email, :status_id, :status, :external_id, :created_at, :updated_at)
    Lockout = Data.define(:present, :locked, :deadline, :email_last_sent, :login_failures)
    Otp = Data.define(:present, :last_use, :num_failures)
    OtpUnlock = Data.define(:present, :num_successes, :next_auth_attempt_after)
    WebauthnKey = Data.define(:webauthn_id, :sign_count, :last_use)
    Mfa = Data.define(:otp, :otp_unlock, :recovery_code_rows, :webauthn_keys)
    Session = Data.define(:session_id, :created_at, :last_use)
    Sessions = Data.define(:total, :capped, :rows)
    RefreshToken = Data.define(:id, :deadline, :expired)
    RefreshTokens = Data.define(:total, :capped, :rows)
    PendingToken = Data.define(:type, :present, :deadline, :requested_at, :expired, :email_last_sent, :login)
    Identity = Data.define(:id, :provider, :issuer, :uid)
    Password = Data.define(:changed_at, :age_days, :previous_hash_count)

    # @!attribute available
    #   [Boolean] false only when the authdb was unreachable. Check this
    #   first: every section is nil when it is false.
    # @!attribute found
    #   [Boolean] false when the authdb answered and has no such account.
    #   available: true, reason: nil, every section nil.
    Result = Data.define(
      :available, :reason, :found, :id,
      :account, :lockout, :mfa, :sessions, :refresh_tokens,
      :pending_tokens, :identities, :password
    )

    TimelineRow = Data.define(:id, :at, :message, :metadata)

    # Same pagination shape as AccountList::Result, so the view helpers are
    # shared verbatim.
    Timeline = Data.define(:available, :reason, :account_id, :page, :per_page, :total, :rows) do
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

    # The database-touching half of a call, split out so the degradation
    # rescue wraps the queries and nothing else.
    Page = Data.define(:total, :page, :records)
    QueryFailure = Data.define(:reason, :page)
    private_constant :Page, :QueryFailure

    # rubocop:disable Metrics/ClassLength -- see the module note above.
    class << self
      # @param id [Integer, String] the accounts.id
      # @param now [Time, nil] the clock for every expiry comparison;
      #   defaults to the database's own (DB_CLOCK)
      # @return [Result] never raises for database reasons
      def find(id:, db: Database.readonly, now: nil)
        account_id = Integer(id, exception: false)
        return not_found(id) if account_id.nil?

        sections = sections(account_id, db, now || DB_CLOCK)
        return unavailable(account_id, sections.reason) if sections.is_a?(QueryFailure)
        return not_found(account_id) if sections.nil?

        Result.new(available: true, reason: nil, found: true, id: account_id, **sections).freeze
      end

      # Resolve an operator's typed query to an account id.
      #
      # Match order is exact email, then exact external_id: an email is what
      # an operator types, an external_id is what the colonel console deep
      # links with, and the two value spaces do not overlap. No LIKE and no
      # wildcards — this is a jump box, not a search engine, and a
      # prefix search over 200k rows is both a seq scan and a way to page
      # through the user table by guessing.
      #
      # The email match is tried case-sensitively first so it uses the
      # unique index, then once more folded through LOWER(). The fallback is
      # a seq scan, but it only runs for a mixed-case paste that already
      # missed, never on the hot path. Ruby's String#downcase and SQL's
      # lower() do not agree on every non-ASCII codepoint, so the folded pass
      # is an ASCII-email convenience, not a Unicode-correct match; an address
      # that only differs outside ASCII has to be pasted exactly.
      #
      # @return [Integer, nil] nil for an empty query, no match, or an
      #   unreachable authdb (a lookup that cannot answer is not a match)
      def lookup(query, db: Database.readonly)
        q = query.to_s.strip
        return nil if q.empty?

        accounts = db[:accounts]
        accounts.where(email: q).get(:id) ||
          accounts.where(Sequel.function(:lower, :email) => q.downcase).get(:id) ||
          accounts.where(external_id: q).get(:id)
      rescue *Database::UNAVAILABLE_ERRORS => e
        RodauthAdmin.logger.warn('authdb account lookup unavailable', e)
        nil
      end

      # @return [Timeline] never raises for database reasons
      # `now:` is accepted (and unused) so the three entry points share one
      # call shape; a timeline row has no expiry to compare against.
      def timeline(id:, page: 1, per_page: PER_PAGE_DEFAULT, db: Database.readonly, now: nil) # rubocop:disable Lint/UnusedMethodArgument
        account_id = Integer(id, exception: false)
        per_page   = clamp(per_page, PER_PAGE_DEFAULT, 1, PER_PAGE_MAX)
        page       = [coerce(page, 1), 1].max
        return empty_timeline(account_id, page, per_page) if account_id.nil?

        build_timeline(account_id, per_page, timeline_page(account_id, page, per_page, db))
      end

      private

      def coerce(value, default) = Integer(value, exception: false) || default

      def clamp(value, default, min, max) = coerce(value, default).clamp(min, max)

      # Everything that touches the database for #find, and only that.
      # Returns nil for "no such account", a QueryFailure for an outage, and
      # a keyword hash of sections otherwise. The section builders run inside
      # this rescue, so the separation is by exception class, not by call
      # site: only Database::UNAVAILABLE_ERRORS degrade the page, and a bug
      # in a builder (NoMethodError, TypeError) propagates as itself.
      # Honestly: a query-shape error does not. A column missing on an older
      # authdb raises Sequel::DatabaseError and is reported as unavailable,
      # the same trade Phase 2's query blocks make.
      def sections(id, db, now)
        account = account_row(db, id)
        return nil if account.nil?

        {
          account: build_account(account),
          lockout: lockout(db, id, now),
          mfa: mfa(db, id),
          sessions: sessions(db, id),
          refresh_tokens: refresh_tokens(db, id, now),
          pending_tokens: pending_tokens(db, id, now),
          identities: identities(db, id),
          password: password(db, id, now)
        }
      rescue *Database::UNAVAILABLE_ERRORS => e
        RodauthAdmin.logger.warn('authdb account detail unavailable', e)
        QueryFailure.new(reason: Database.failure_reason(e), page: nil)
      end

      def account_row(db, id)
        db[:accounts]
          .left_join(:account_statuses, id: Sequel[:accounts][:status_id])
          .where(Sequel[:accounts][:id] => id)
          .select(*account_columns(db))
          .first
      end

      # db.schema, not db[:accounts].columns: the latter probes with
      # `SELECT * ... LIMIT 0`, and a `SELECT *` on accounts is exactly what
      # this file refuses to issue — password_hash lives on that table on
      # rodauth-tools builds, and the read-only role's table-wide
      # `GRANT SELECT ON accounts` would happily return it (AccountList does
      # run .columns on this role today; that is a probe, not a page). Only
      # the explicit column list keeps the hash out. db.schema reads the
      # catalog (PRAGMA on SQLite) and touches no row at all.
      def account_columns(db)
        present = db.schema(:accounts).map(&:first)
        ACCOUNT_COLUMNS + ACCOUNT_TIMESTAMPS.select { |c| present.include?(c) }
                                            .map { |c| Sequel[:accounts][c] }
      end

      def build_account(row)
        Account.new(
          id: row[:id], email: row[:email], status_id: row[:status_id], status: row[:status],
          external_id: row[:external_id], created_at: row[:created_at], updated_at: row[:updated_at]
        ).freeze
      end

      # Lockout rows linger after they expire (Rodauth does not delete them
      # eagerly), so `present` and `locked` are two different facts: a row
      # with a past deadline means "not locked, an expired lockout row is
      # still sitting there", which is exactly what an operator asking "why
      # can't they log in?" needs to be told.
      def lockout(db, id, now)
        row = db[:account_lockouts].where(id: id)
                                   .select(:deadline, :email_last_sent, live(:deadline, now))
                                   .first
        Lockout.new(
          present: !row.nil?, locked: live?(row),
          login_failures: db[:account_login_failures].where(id: id).get(:number) || 0,
          **fields(row, :deadline, :email_last_sent)
        ).freeze
      end

      def mfa(db, id)
        Mfa.new(
          otp: otp(db, id), otp_unlock: otp_unlock(db, id),
          # Rodauth deletes a recovery code on use, so used_at is always
          # NULL in production (db/README.md "Known drift"): the row count
          # IS the unused-code count, and the view labels it "(rows)".
          recovery_code_rows: db[:account_recovery_codes].where(id: id).count,
          webauthn_keys: webauthn_keys(db, id)
        ).freeze
      end

      def otp(db, id)
        row = db[:account_otp_keys].where(id: id).select(:last_use, :num_failures).first
        Otp.new(present: !row.nil?, **fields(row, :last_use, :num_failures)).freeze
      end

      def otp_unlock(db, id)
        row = db[:account_otp_unlocks].where(id: id)
                                      .select(:num_successes, :next_auth_attempt_after).first
        OtpUnlock.new(present: !row.nil?, **fields(row, :num_successes, :next_auth_attempt_after)).freeze
      end

      def webauthn_keys(db, id)
        db[:account_webauthn_keys].where(account_id: id)
                                  .order(Sequel.desc(:last_use), :webauthn_id)
                                  .select(:webauthn_id, :sign_count, :last_use)
                                  .map do |row|
          WebauthnKey.new(webauthn_id: row[:webauthn_id], sign_count: row[:sign_count],
                          last_use: row[:last_use]).freeze
        end.freeze
      end

      def sessions(db, id)
        base = db[:account_active_session_keys].where(account_id: id)
        rows = session_rows(base)
        total = base.count
        Sessions.new(total: total, capped: total > rows.length, rows: rows).freeze
      end

      def session_rows(base)
        base.order(Sequel.desc(:last_use), :session_id)
            .select(:session_id, :created_at, :last_use)
            .limit(SESSION_CAP)
            .map do |row|
              Session.new(session_id: truncate_session_id(row[:session_id]),
                          **fields(row, :created_at, :last_use)).freeze
            end.freeze
      end

      # The full session_id never leaves this method.
      def truncate_session_id(value)
        s = value.to_s
        s.length > SESSION_ID_PREFIX ? "#{s[0, SESSION_ID_PREFIX]}…" : s
      end

      def refresh_tokens(db, id, now)
        base = db[:account_jwt_refresh_keys].where(account_id: id)
        rows = refresh_token_rows(base, now)
        total = base.count
        RefreshTokens.new(total: total, capped: total > rows.length, rows: rows).freeze
      end

      def refresh_token_rows(base, now)
        base.order(Sequel.desc(:deadline), :id)
            .select(:id, :deadline, live(:deadline, now))
            .limit(REFRESH_TOKEN_CAP)
            .map do |row|
              RefreshToken.new(expired: !live?(row), **fields(row, :id, :deadline)).freeze
            end.freeze
      end

      # Always one row per token type, present or not, so the view renders a
      # fixed table rather than an inference from absence.
      def pending_tokens(db, id, now)
        PENDING_TOKENS.map { |spec| pending_token(db, id, now, spec) }.freeze
      end

      PENDING_COLUMNS = %i[deadline requested_at email_last_sent login].freeze
      private_constant :PENDING_COLUMNS

      def pending_token(db, id, now, spec)
        row = pending_token_row(db, id, now, spec)
        PendingToken.new(
          type: spec[:type], present: !row.nil?,
          # nil, not false: verification keys carry requested_at and no
          # deadline, so "is it expired?" has no answer here.
          expired: row && spec[:deadline] ? !live?(row) : nil,
          **fields(row, *PENDING_COLUMNS)
        ).freeze
      end

      def pending_token_row(db, id, now, spec)
        select = spec[:columns].dup
        select << live(spec[:deadline], now) if spec[:deadline]
        db[spec[:table]].where(id: id).select(*select).first
      end

      def identities(db, id)
        db[:account_identities].where(account_id: id)
                               .order(:provider, :issuer, :uid)
                               .select(:id, :provider, :issuer, :uid)
                               .map do |row|
          Identity.new(id: row[:id], provider: row[:provider], issuer: row[:issuer], uid: row[:uid]).freeze
        end.freeze
      end

      def password(db, id, now)
        changed_at = db[:account_password_change_times].where(id: id).get(:changed_at)
        Password.new(
          changed_at: changed_at, age_days: age_days(changed_at, now),
          # Sequel collapses this to COUNT(*), which needs no column
          # privilege at all; the select names the two columns the
          # read-only role is granted so the intent survives a refactor
          # that turns the count into a fetch. password_hash is never named.
          previous_hash_count: previous_hash_count(db, id)
        ).freeze
      end

      def previous_hash_count(db, id)
        db[:account_previous_password_hashes].where(account_id: id).select(:id, :account_id).count
      end

      # Only computable against a Ruby clock and a Ruby Time. `now` is a SQL
      # expression by default and SQLite can hand back a String for a
      # timestamp, so both are handled by returning nil rather than guessing.
      def age_days(changed_at, now)
        return nil unless changed_at.is_a?(Time)

        wall = now.is_a?(Time) ? now : Time.now
        ((wall - changed_at) / 86_400).floor
      end

      # `deadline > now` as a selected boolean, so the comparison happens
      # inside the database against the database's clock. BooleanExpression
      # rather than the infix form: the rubocop Yoda cop misreads a Sequel
      # comparison as a reversed Ruby one.
      def live(column, now)
        Sequel::SQL::BooleanExpression.new(:>, Sequel[column], now).as(:live)
      end

      # A row's selected columns as Data keywords, nil across the board when
      # the row is absent — every section renders "nothing here" the same way.
      def fields(row, *keys) = keys.to_h { |k| [k, row && row[k]] }

      # The `live` boolean of a fetched row: PostgreSQL returns true/false,
      # SQLite 1/0, and an absent row is not live.
      def live?(row) = !row.nil? && [true, 1].include?(row[:live])

      def timeline_page(id, page, per_page, db)
        base = timeline_dataset(db, id)
        total = base.count
        page = clamp_page(page, total, per_page)
        Page.new(total: total, page: page, records: base.limit(per_page, (page - 1) * per_page).all)
      rescue *Database::UNAVAILABLE_ERRORS => e
        RodauthAdmin.logger.warn('authdb account timeline unavailable', e)
        QueryFailure.new(reason: Database.failure_reason(e), page: page)
      end

      def timeline_dataset(db, id)
        db[:account_authentication_audit_logs]
          .where(account_id: id)
          .order(Sequel.desc(:at), Sequel.desc(:id))
          .select(:id, :at, :message, :metadata)
      end

      def build_timeline(id, per_page, outcome)
        return unavailable_timeline(id, outcome.page, per_page, outcome.reason) if outcome.is_a?(QueryFailure)

        rows = outcome.records.map { |r| timeline_row(r) }.freeze
        Timeline.new(available: true, reason: nil, account_id: id, page: outcome.page,
                     per_page: per_page, total: outcome.total, rows: rows).freeze
      end

      # An out-of-range page shows the last page rather than an empty table
      # with a "previous" link into nothing (AccountList.clamp_page).
      def clamp_page(page, total, per_page)
        total.zero? ? page : page.clamp(1, [(total.to_f / per_page).ceil, 1].max)
      end

      # metadata is a JSON string written by Rodauth. It is passed through
      # verbatim: parsing it here would only move the escaping problem into
      # the view, which renders it as text.
      def timeline_row(row)
        TimelineRow.new(id: row[:id], at: row[:at], message: row[:message],
                        metadata: row[:metadata].nil? ? nil : row[:metadata].to_s).freeze
      end

      def not_found(id)
        Result.new(available: true, reason: nil, found: false, id: Integer(id, exception: false),
                   **nil_sections).freeze
      end

      def unavailable(id, reason)
        Result.new(available: false, reason: reason, found: false, id: id, **nil_sections).freeze
      end

      def nil_sections
        { account: nil, lockout: nil, mfa: nil, sessions: nil, refresh_tokens: nil,
          pending_tokens: nil, identities: nil, password: nil }
      end

      def empty_timeline(id, page, per_page)
        Timeline.new(available: true, reason: nil, account_id: id, page: page,
                     per_page: per_page, total: 0, rows: [].freeze).freeze
      end

      def unavailable_timeline(id, page, per_page, reason)
        Timeline.new(available: false, reason: reason, account_id: id, page: page,
                     per_page: per_page, total: nil, rows: [].freeze).freeze
      end
    end
    # rubocop:enable Metrics/ClassLength
  end
  # rubocop:enable Metrics/ModuleLength
end
