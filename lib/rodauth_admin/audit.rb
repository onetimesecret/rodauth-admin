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
    SESSION_ACTIONS = %w[login login_denied logout two_factor_auth].freeze
    SESSION_REASON = 'session'

    class BlankReason < ArgumentError; end

    module_function

    # @param action [String] short verb, e.g. 'login', 'operator_add', 'clear_lockout'
    # @param actor [String] operator email, or 'cli:<os user>' for rake tasks
    # @param actor_account_id [Integer, nil] authdb accounts.id of the actor
    # @param reason [String, nil] required unless action is in SESSION_ACTIONS
    # @param target_account_id [Integer, nil] authdb accounts.id acted on
    # @param target [String, nil] display handle for the target (email/extid)
    # @param metadata [Hash, nil] anything else worth keeping, stored as JSON
    # rubocop:disable Metrics/ParameterLists
    def record(action:, actor:, reason: nil, actor_account_id: nil, target_account_id: nil, target: nil,
               ip: nil, user_agent: nil, metadata: nil, db: Database.app)
      action = action.to_s
      reason = reason.to_s.strip
      if reason.empty?
        raise BlankReason, "#{action} requires a reason" unless SESSION_ACTIONS.include?(action)

        reason = SESSION_REASON
      end

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
    # rubocop:enable Metrics/ParameterLists

    def recent(limit: 50, db: Database.app)
      db[TABLE].reverse(:at, :id).limit(limit).all
    end
  end
end
