# try/authdb_schema_try.rb
#
# frozen_string_literal: true

# The local authdb is generated from rodauth-tools' migration templates for
# the feature set production enables, plus the columns the tenant app added.
# These checks pin the shape against the capability table in CHARTER §3.

require 'sequel'
require_relative '../lib/rodauth_admin/env'
require_relative '../lib/rodauth_admin/authdb_schema'

@db = Sequel.sqlite
RodauthAdmin::AuthdbSchema.build!(@db)

## Every table in the capability table exists
expected = %i[
  accounts account_statuses account_password_hashes
  account_login_failures account_lockouts
  account_otp_keys account_recovery_codes account_otp_unlocks
  account_webauthn_keys account_webauthn_user_ids
  account_active_session_keys account_jwt_refresh_keys
  account_password_reset_keys account_verification_keys account_login_change_keys account_email_auth_keys
  account_identities
  account_password_change_times account_previous_password_hashes
  account_authentication_audit_logs
]
expected - @db.tables
#=> []

## Statuses are seeded positionally (1 Unverified / 2 Verified / 3 Closed)
@db[:account_statuses].order(:id).select_map(:name)
#=> ["Unverified", "Verified", "Closed"]

## The Redis<->SQL join key is present and unique
@db.indexes(:accounts).values.any? { |ix| ix[:columns] == [:external_id] && ix[:unique] }
#=> true

## Accounts carry production's timestamps
(%i[created_at updated_at] - @db.schema(:accounts).map(&:first)).empty?
#=> true

## account_identities is issuer-scoped (migration 008)
@db.indexes(:account_identities).values.any? { |ix| ix[:columns] == %i[provider issuer uid] && ix[:unique] }
#=> true

## Refuses to build over an existing schema
begin
  RodauthAdmin::AuthdbSchema.build!(@db)
rescue RodauthAdmin::ConfigurationError => e
  e.message.include?('refusing')
end
#=> true

## tables lists what build! created (order: templates first, then deltas)
RodauthAdmin::AuthdbSchema.tables.last
#=> :account_identities
