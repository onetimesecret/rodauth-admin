# lib/rodauth_admin/verbs.rb
#
# frozen_string_literal: true

require 'securerandom'
require 'sequel'

require_relative 'audit'
require_relative 'account_detail'
require_relative 'database'

module RodauthAdmin
  # The mutating half of the tool (CHARTER §3, §6 phase 4), in support-pain
  # order: clear lockout, force a password reset, expire tokens, disable
  # MFA, regenerate recovery codes, revoke sessions, revoke refresh keys,
  # unlink an SSO identity.
  #
  # Four rules run through every verb here.
  #
  # 1. One transaction, one connection, both halves. The mutation and its
  #    admin_actions row commit together on Database.verbs — the third
  #    runtime credential (docs/design/database-credentials.md), which holds
  #    exactly the DML the table below needs plus INSERT on admin_actions.
  #    A verb that deleted rows and failed to record why would be the one
  #    failure mode this tool exists to prevent, so the audit row is written
  #    inside the same `db.transaction` block, never after it.
  #
  # 2. Reason first, before anything. Audit::BlankReason is raised on the
  #    way in, not by Audit.record on the way out, so a blank reason cannot
  #    reach a DELETE even in a hypothetical caller that swallows the error.
  #
  # 3. Deletes, never reads-then-deletes. `dataset.delete` returns the row
  #    count, so "how many did we clear?" is the mutation's own answer and
  #    there is no window between counting and deleting. A verb with nothing
  #    to delete still runs and records zeroes: "we tried, there was
  #    nothing" is a different fact from "we never tried".
  #
  # 4. Secrets stay out of the audit trail. Regenerated recovery codes are
  #    returned to the caller for one render and never written to metadata;
  #    an identity's uid is not recorded either (it is frequently an email).
  #
  # Errors, not degradation: unlike the read side, a verb on an unreachable
  # authdb raises. The web layer catches and renders the degraded panel. A
  # mutation that silently reports "unavailable" would be indistinguishable
  # from one that half-ran.
  # rubocop:disable Metrics/ModuleLength -- eight verbs, one shared transaction
  # body, and the table lists they mutate; splitting them would separate a verb
  # from the audit contract it is only correct alongside.
  module Verbs
    # An id that no account row matches, or an identity that does not belong
    # to the named account. Not an outage, and not something to retry.
    class NotFound < RodauthAdmin::Error; end

    # Refused because the target is the operator's own account. Operators
    # manage their own MFA in the tenant app; an admin tool that can strip
    # its own operator's second factor is a privilege-escalation path with a
    # reason field attached.
    class SelfTarget < RodauthAdmin::Error; end

    # Refused because the account has no OTP key and no WebAuthn key.
    # Recovery codes are a backup for a second factor; minting them for an
    # account that has none creates a password-only login path that looks
    # like MFA.
    class NoSecondFactor < RodauthAdmin::Error; end

    # The tenant app sets recovery_codes_limit to 4
    # (onetimesecret apps/web/auth/config/features/mfa.rb, 2026-09-05);
    # Rodauth's own default is 16. Regenerating must mint the number the
    # tenant's UI promises, so this tracks the tenant, not the gem.
    RECOVERY_CODES_LIMIT = 4

    # Rodauth mints a recovery code with new_recovery_code -> random_key ->
    # SecureRandom.urlsafe_base64(32) (rodauth 2.47.0 features/recovery_codes.rb:245,
    # base.rb:754). Codes are stored verbatim in account_recovery_codes.code
    # — the column is the credential — so the format has to match exactly or
    # the tenant app will not accept what the operator hands the customer.
    RECOVERY_CODE_BYTES = 32

    # force_password_reset backdates account_password_change_times.changed_at
    # rather than subtracting the tenant's require_password_change_after from
    # now: a fixed far-past timestamp is expired under any window the tenant
    # ever configures, and is obvious in the row as "an operator did this"
    # rather than looking like a real password change.
    EXPIRED_CHANGED_AT = Time.at(0).utc.freeze

    # Slug (URL) => verb method, in charter order. The web layer routes off
    # this constant so a verb cannot exist without a slug or vice versa.
    # unlink_identity is deliberately absent: it is nested under an identity
    # id (/accounts/:id/identities/:identity_id/unlink) and takes an extra
    # argument, so it does not fit the one-shape-fits-all POST.
    SLUGS = {
      'clear-lockout' => :clear_lockout,
      'force-password-reset' => :force_password_reset,
      'expire-tokens' => :expire_tokens,
      'disable-mfa' => :disable_mfa,
      'regenerate-recovery-codes' => :regenerate_recovery_codes,
      'revoke-sessions' => :revoke_sessions,
      'revoke-refresh-keys' => :revoke_refresh_keys
    }.freeze

    # Verbs refused on the operator's own account.
    SELF_REFUSED = %i[disable_mfa regenerate_recovery_codes].freeze

    # Who is acting. account_id is the actor's row in this same authdb (the
    # operator logs in through it), and is what SelfTarget compares against.
    Actor = Data.define(:email, :account_id, :ip, :user_agent) do
      def self.build(email:, account_id: nil, ip: nil, user_agent: nil)
        new(email: email, account_id: account_id, ip: ip, user_agent: user_agent).freeze
      end
    end

    # @!attribute counts
    #   [Hash{Symbol=>Integer}] rows deleted (or written) per table, frozen.
    # @!attribute metadata
    #   [Hash] exactly what was recorded in admin_actions.metadata. Never
    #   contains a recovery code, a key, or an identity uid.
    # @!attribute codes
    #   [Array<String>, nil] plaintext recovery codes, regenerate only,
    #   for a single render. Not recoverable afterwards.
    Result = Data.define(:action, :account_id, :target, :counts, :metadata, :codes) do
      def total = counts.values.sum
    end

    # What each verb would touch right now, for the confirm pages.
    # @!attribute counts
    #   [Hash{Symbol=>Hash}] verb method name => the same counts shape the
    #   verb returns. nil when the account was not found or not readable.
    Preview = Data.define(:available, :reason, :found, :account_id, :counts, :identities)

    # Tables each verb clears, in delete order. Every name and column here
    # was checked against AuthdbSchema's build (lib/rodauth_admin/authdb_schema.rb):
    # the per-account key is `id` on the single-row-per-account tables and
    # `account_id` on the multi-row ones.
    BY_ACCOUNT_ID = %i[
      account_lockouts account_login_failures account_password_reset_keys
      account_verification_keys account_login_change_keys account_email_auth_keys
      account_otp_keys account_otp_unlocks account_recovery_codes account_webauthn_user_ids
    ].freeze

    LOCKOUT_TABLES = %i[account_lockouts account_login_failures].freeze
    TOKEN_TABLES = %i[
      account_password_reset_keys account_verification_keys
      account_login_change_keys account_email_auth_keys
    ].freeze
    MFA_TABLES = %i[
      account_otp_keys account_otp_unlocks account_recovery_codes
      account_webauthn_keys account_webauthn_user_ids
    ].freeze

    # rubocop:disable Metrics/ClassLength -- see the module note above.
    class << self
      # Rodauth's own unlock_account is exactly this pair of deletes
      # (remove_lockout_metadata, rodauth 2.47.0 features/lockout.rb:292),
      # so an operator clearing a lockout leaves the account in the state a
      # successful login would have left it in — no more, no less.
      def clear_lockout(id:, actor:, reason:, db: Database.verbs)
        run(:clear_lockout, id: id, actor: actor, reason: reason, db: db) do |account_id, conn|
          # Read before the delete purely so the flash and the audit row can
          # say "and 4 failures"; the count of *rows* is what counts carries.
          failures = conn[:account_login_failures].where(id: account_id).get(:number)
          [delete_all(conn, LOCKOUT_TABLES, account_id), { login_failure_number: failures || 0 }]
        end
      end

      # Backdates the password so the tenant app's password_expiration
      # feature demands a new one at next login, and drops any outstanding
      # reset key so a stale emailed link cannot be used to set the password
      # back before the operator's customer ever sees the prompt.
      #
      # KNOWN GAP (verified 2026-09-05): the tenant app does not currently
      # `enable :password_expiration` (apps/web/auth/config/features/*.rb) —
      # the table exists, nothing reads it. Until it is enabled this verb
      # records intent and kills reset keys, but does not by itself force a
      # change at login. It is written this way rather than as something
      # stronger because the alternative (closing the account, nulling the
      # hash) is not reversible by the customer.
      def force_password_reset(id:, actor:, reason:, db: Database.verbs)
        run(:force_password_reset, id: id, actor: actor, reason: reason, db: db) do |account_id, conn|
          reset_keys = conn[:account_password_reset_keys].where(id: account_id).delete
          [{ account_password_change_times: backdate_password(conn, account_id),
             account_password_reset_keys: reset_keys },
           { changed_at: EXPIRED_CHANGED_AT.iso8601, password_reset_keys_deleted: reset_keys }]
        end
      end

      # Every emailed bearer link the account has outstanding.
      def expire_tokens(id:, actor:, reason:, db: Database.verbs)
        run(:expire_tokens, id: id, actor: actor, reason: reason, db: db) do |account_id, conn|
          counts = delete_all(conn, TOKEN_TABLES, account_id)
          [counts, counts]
        end
      end

      # Strips every second factor. Refused on self (SELF_REFUSED).
      def disable_mfa(id:, actor:, reason:, db: Database.verbs)
        run(:disable_mfa, id: id, actor: actor, reason: reason, db: db) do |account_id, conn|
          counts = delete_all(conn, MFA_TABLES, account_id)
          [counts, counts]
        end
      end

      # Replaces the account's recovery codes wholesale and returns the new
      # plaintext ONCE, in the result. Nothing here writes a code anywhere
      # but account_recovery_codes.
      #
      # Refused on self, and refused when the account has no OTP key and no
      # WebAuthn key. The second-factor check runs inside the transaction so
      # it cannot race a concurrent disable_mfa.
      def regenerate_recovery_codes(id:, actor:, reason:, db: Database.verbs, limit: RECOVERY_CODES_LIMIT)
        codes = nil
        result = run(:regenerate_recovery_codes, id: id, actor: actor, reason: reason, db: db) do |account_id, conn|
          unless second_factor?(conn, account_id)
            raise NoSecondFactor, "account #{account_id} has no OTP or WebAuthn key"
          end

          deleted = conn[:account_recovery_codes].where(id: account_id).delete
          codes = mint_recovery_codes(conn, account_id, limit)
          [{ account_recovery_codes: codes.length },
           { deleted: deleted, generated: codes.length }] # never the codes themselves
        end
        result.with(codes: codes.freeze)
      end

      # active_sessions: every SQL session row. The tenant app checks this
      # table on each request, so the customer is signed out everywhere.
      def revoke_sessions(id:, actor:, reason:, db: Database.verbs)
        run(:revoke_sessions, id: id, actor: actor, reason: reason, db: db) do |account_id, conn|
          deleted = conn[:account_active_session_keys].where(account_id: account_id).delete
          counts = { account_active_session_keys: deleted }
          [counts, counts]
        end
      end

      # jwt_refresh: every outstanding refresh token. Access tokens already
      # issued live until they expire on their own; nothing in the database
      # can recall them.
      def revoke_refresh_keys(id:, actor:, reason:, db: Database.verbs)
        run(:revoke_refresh_keys, id: id, actor: actor, reason: reason, db: db) do |account_id, conn|
          deleted = conn[:account_jwt_refresh_keys].where(account_id: account_id).delete
          counts = { account_jwt_refresh_keys: deleted }
          [counts, counts]
        end
      end

      # Unlinks one SSO identity. The DELETE is scoped by both ids, so an
      # identity id belonging to another account deletes nothing and raises
      # NotFound rather than unlinking a stranger's login. provider and
      # issuer go into metadata; uid does not — for most providers it is the
      # customer's email address.
      def unlink_identity(id:, identity_id:, actor:, reason:, db: Database.verbs)
        run(:unlink_identity, id: id, actor: actor, reason: reason, db: db) do |account_id, conn|
          row = conn[:account_identities].where(id: identity_id, account_id: account_id)
                                         .select(:id, :provider, :issuer).first
          raise NotFound, "identity #{identity_id} is not on account #{account_id}" if row.nil?

          deleted = conn[:account_identities].where(id: row[:id], account_id: account_id).delete
          raise NotFound, "identity #{identity_id} is not on account #{account_id}" if deleted.zero?

          [{ account_identities: deleted },
           { identity_id: row[:id], provider: row[:provider], issuer: row[:issuer] }]
        end
      end

      # The counts every verb would touch right now, for the confirm pages.
      # Read-only, on the read-only credential, and degrading exactly like
      # the rest of the read side: this is a preview, and an unreachable
      # authdb here must not look like "there is nothing to do". It reuses
      # AccountDetail.find rather than re-listing the tables, so the confirm
      # page and the account page can never disagree.
      #
      # These are estimates by construction — a row can appear or vanish
      # between the GET and the POST. The verb's own returned counts are the
      # truth; this is what the operator is told they are about to do.
      def preview(id:, db: Database.readonly)
        detail = AccountDetail.find(id: id, db: db)
        return unavailable_preview(detail) unless detail.available
        return not_found_preview(detail.id) unless detail.found

        Preview.new(available: true, reason: nil, found: true, account_id: detail.id,
                    counts: preview_counts(detail).freeze, identities: detail.identities).freeze
      end

      private

      # The shared body of every verb: validate, resolve, refuse, mutate and
      # record in one transaction. The block returns [counts, metadata] and
      # runs with the transaction's connection.
      def run(action, id:, actor:, reason:, db:)
        reason = check_reason(action, reason)
        account_id = coerce_id(id)
        account = nil
        counts = nil
        metadata = nil

        db.transaction do
          account = account_row(db, account_id)
          raise NotFound, "no account #{account_id}" if account.nil?

          refuse_self(action, account_id, actor)
          counts, metadata = yield(account_id, db)
          record(action, account, actor, reason, counts, metadata, db)
        end

        Result.new(action: action, account_id: account_id, target: account[:email],
                   counts: counts.freeze, metadata: metadata.freeze, codes: nil).freeze
      end

      # Raised here, before the transaction opens, so no verb can reach a
      # DELETE without one. Audit.record would raise the same error, but
      # only after the rows were gone.
      def check_reason(action, reason)
        text = reason.to_s.strip
        raise Audit::BlankReason, "#{action} requires a reason" if text.empty?

        text
      end

      def coerce_id(id)
        Integer(id, exception: false) or raise NotFound, "not an account id: #{id.inspect}"
      end

      # Named columns, as everywhere else: `SELECT *` on accounts would pull
      # password_hash on a rodauth-tools build, and the verbs role holds a
      # table-wide GRANT SELECT that would not stop it.
      def account_row(db, account_id)
        db[:accounts].where(id: account_id).select(:id, :email).first
      end

      def refuse_self(action, account_id, actor)
        return unless SELF_REFUSED.include?(action)
        return unless actor.account_id && Integer(actor.account_id, exception: false) == account_id

        raise SelfTarget, "#{action} is refused on the operator's own account"
      end

      # rubocop:disable Metrics/ParameterLists -- the audit contract, spelled out.
      def record(action, account, actor, reason, counts, metadata, db)
        Audit.record(
          db: db, action: action.to_s, reason: reason,
          actor: actor.email, actor_account_id: actor.account_id,
          target_account_id: account[:id], target: account[:email],
          ip: actor.ip, user_agent: actor.user_agent,
          metadata: metadata.merge(counts: counts)
        )
      end
      # rubocop:enable Metrics/ParameterLists

      def delete_all(db, tables, account_id)
        tables.to_h { |t| [t, db[t].where(account_key(t) => account_id).delete] }
      end

      # account_webauthn_keys keys off account_id; the other MFA and token
      # tables use `id` as both primary key and foreign key to accounts
      # (verified against AuthdbSchema.build!'s output, 2026-09-05).
      def account_key(table) = BY_ACCOUNT_ID.include?(table) ? :id : :account_id

      # UPSERT without relying on a dialect: the row is one-per-account and
      # this runs inside the verb's transaction, so update-then-insert has
      # no window a concurrent writer could use to duplicate it.
      def backdate_password(db, account_id)
        ds = db[:account_password_change_times].where(id: account_id)
        return 1 if ds.update(changed_at: EXPIRED_CHANGED_AT) == 1

        db[:account_password_change_times].insert(id: account_id, changed_at: EXPIRED_CHANGED_AT)
        1
      end

      def second_factor?(db, account_id)
        !db[:account_otp_keys].where(id: account_id).empty? ||
          !db[:account_webauthn_keys].where(account_id: account_id).empty?
      end

      # Rodauth's own format and length; see RECOVERY_CODE_BYTES.
      def mint_recovery_codes(db, account_id, limit)
        Array.new(limit) { SecureRandom.urlsafe_base64(RECOVERY_CODE_BYTES) }.each do |code|
          db[:account_recovery_codes].insert(id: account_id, code: code)
        end
      end

      def preview_counts(detail)
        lockout = detail.lockout
        mfa = detail.mfa
        {
          clear_lockout: lockout_preview(lockout),
          force_password_reset: { account_password_change_times: 1,
                                  account_password_reset_keys: pending(detail, :password_reset) },
          expire_tokens: token_preview(detail),
          disable_mfa: mfa_preview(mfa),
          regenerate_recovery_codes: { account_recovery_codes: mfa.recovery_code_rows,
                                       second_factor: second_factor_present?(mfa) },
          revoke_sessions: { account_active_session_keys: detail.sessions.total },
          revoke_refresh_keys: { account_jwt_refresh_keys: detail.refresh_tokens.total },
          unlink_identity: { account_identities: detail.identities.length }
        }
      end

      def lockout_preview(lockout)
        { account_lockouts: lockout.present ? 1 : 0,
          account_login_failures: lockout.login_failures.positive? ? 1 : 0,
          login_failure_number: lockout.login_failures }
      end

      def token_preview(detail)
        { account_password_reset_keys: pending(detail, :password_reset),
          account_verification_keys: pending(detail, :verification),
          account_login_change_keys: pending(detail, :login_change),
          account_email_auth_keys: pending(detail, :email_auth) }
      end

      def mfa_preview(mfa)
        { account_otp_keys: mfa.otp.present ? 1 : 0,
          account_otp_unlocks: mfa.otp_unlock.present ? 1 : 0,
          account_recovery_codes: mfa.recovery_code_rows,
          account_webauthn_keys: mfa.webauthn_keys.length,
          # AccountDetail does not read account_webauthn_user_ids (there is
          # nothing on it worth showing); it is one row per account and is
          # deleted with the keys, so the preview says so rather than lying
          # by omission.
          account_webauthn_user_ids: mfa.webauthn_keys.empty? ? 0 : 1 }
      end

      def second_factor_present?(mfa) = mfa.otp.present || !mfa.webauthn_keys.empty?

      def pending(detail, type)
        detail.pending_tokens.find { |t| t.type == type }&.present ? 1 : 0
      end

      def unavailable_preview(detail)
        Preview.new(available: false, reason: detail.reason, found: false,
                    account_id: detail.id, counts: nil, identities: nil).freeze
      end

      def not_found_preview(account_id)
        Preview.new(available: true, reason: nil, found: false,
                    account_id: account_id, counts: nil, identities: nil).freeze
      end
    end
    # rubocop:enable Metrics/ClassLength
  end
  # rubocop:enable Metrics/ModuleLength
end
