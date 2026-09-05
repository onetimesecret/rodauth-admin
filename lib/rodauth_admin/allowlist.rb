# lib/rodauth_admin/allowlist.rb
#
# frozen_string_literal: true

require_relative 'database'
require_relative 'audit'

module RodauthAdmin
  # The operator allowlist: the only identity-shaped thing this codebase
  # owns. A row admits a production Rodauth account (by accounts.id) to the
  # admin; removing the row is offboarding. Every change is an admin action.
  module Allowlist
    TABLE = :admin_operators

    module_function

    def allowed?(account_id, db: Database.app)
      return false if account_id.nil?

      !db[TABLE].where(account_id: account_id).empty?
    end

    def list(db: Database.app)
      db[TABLE].order(:created_at).all
    end

    class AmbiguousEmail < Error; end

    # Resolve a (normalized) email to an accounts.id: the authdb first, the
    # allowlist's display copy only if the authdb has no such address.
    # @raise [AmbiguousEmail] if the address now belongs to a different
    #   account in the authdb than the one it was allowlisted under
    # @return [Integer, nil]
    def account_id_for_email(email, authdb:, db: Database.app)
      current = authdb[:accounts].where(email: email).get(:id)
      listed  = db[TABLE].where(Sequel.function(:lower, :email) => email).get(:account_id)
      if current && listed && current != listed
        raise AmbiguousEmail,
              "#{email} is account #{current} in the authdb but was allowlisted as account #{listed}"
      end

      current || listed
    end

    # @return [Integer] the new admin_operators row id
    def add!(account_id:, email:, actor:, reason:, db: Database.app, actor_account_id: nil) # rubocop:disable Metrics/ParameterLists
      db.transaction do
        row_id = db[TABLE].insert(account_id: account_id, email: email, added_by: actor,
                                  created_at: Sequel::CURRENT_TIMESTAMP)
        Audit.record(
          db: db, action: 'operator_add', actor: actor, actor_account_id: actor_account_id,
          target_account_id: account_id, target: email, reason: reason
        )
        row_id
      end
    end

    # @return [Hash, nil] the removed row, or nil if the account was not an operator
    def remove!(account_id:, actor:, reason:, db: Database.app, actor_account_id: nil)
      db.transaction do
        row = db[TABLE].where(account_id: account_id).first
        next nil unless row

        db[TABLE].where(account_id: account_id).delete
        Audit.record(
          db: db, action: 'operator_remove', actor: actor, actor_account_id: actor_account_id,
          target_account_id: account_id, target: row[:email], reason: reason
        )
        row
      end
    end
  end
end
