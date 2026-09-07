# lib/rodauth_admin/audit.rb
#
# frozen_string_literal: true

require 'json'

require_relative 'database'

module RodauthAdmin
  # Writer for the admin_actions table: append-only, reason required.
  #
  # Two audit trails, not one (CHARTER §3): Rodauth's own
  # account_authentication_audit_logs records auth *events* and is display
  # data; this table records what an operator *did*, including signing in.
  module Audit
    TABLE = :admin_actions

    # Session-lifecycle actions are recorded without an operator-supplied
    # reason. Everything else must say why.
    SESSION_ACTIONS = %w[login login_denied logout two_factor_auth otp_setup session_revoked].freeze
    SESSION_REASON = 'session'

    # A refusal is recorded under the verb's own name with this suffix
    # ('disable_mfa_refused'). Refusals are the tool's own answer, not an
    # operator's, so they are exempt from the reason requirement by the same
    # mechanism as SESSION_ACTIONS: a refused verb that could not be written
    # down for want of a reason would leave the interesting half of the
    # trail -- who tried what on whom -- unrecorded. In practice Verbs
    # already has the operator's reason by then and passes it through; this
    # is the floor, not the usual case.
    REFUSAL_SUFFIX = '_refused'
    REFUSAL_REASON = 'refused'

    class BlankReason < ArgumentError; end

    module_function

    # @param action [String] short verb, e.g. 'login', 'operator_add', 'clear_lockout'
    # @param actor [String] operator email, or 'cli:<os user>' for rake tasks
    # @param actor_account_id [Integer, nil] authdb accounts.id of the actor
    # @param reason [String, nil] required unless action is in SESSION_ACTIONS
    # @param target_account_id [Integer, nil] authdb accounts.id acted on
    # @param target [String, nil] display handle for the target (email/extid)
    # @param metadata [Hash, nil] anything else worth keeping, stored as JSON
    # rubocop:disable-next Metrics/ParameterLists
    def record(action:, actor:, reason: nil, actor_account_id: nil, target_account_id: nil, target: nil,
               ip: nil, user_agent: nil, metadata: nil, db: Database.app)
      action = action.to_s
      reason = reason.to_s.strip
      reason = default_reason(action) || raise(BlankReason, "#{action} requires a reason") if reason.empty?

      db[TABLE].insert(
        at: Sequel::CURRENT_TIMESTAMP,
        action: action,
        actor: actor.to_s,
        actor_account_id: actor_account_id,
        target_account_id: target_account_id,
        target: target,
        reason: reason,
        ip: ip,
        user_agent: user_agent&.slice(0, 512),
        metadata: metadata && JSON.generate(metadata)
      )
    end

    def recent(limit: 50, db: Database.app)
      db[TABLE].reverse(:at, :id).limit(limit).all
    end

    # The stand-in reason for the two kinds of row an operator does not
    # author, or nil when the action must carry one.
    def default_reason(action)
      return SESSION_REASON if SESSION_ACTIONS.include?(action)
      return REFUSAL_REASON if action.end_with?(REFUSAL_SUFFIX)

      nil
    end
  end
end
