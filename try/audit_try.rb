# try/audit_try.rb
#
# frozen_string_literal: true

# admin_actions: append-only, reason required. The database enforces the
# first, the writer enforces the second.

require 'sequel'
ENV['RACK_ENV'] = 'test'
require_relative '../lib/rodauth_admin'
require_relative '../lib/rodauth_admin/audit'
require_relative '../lib/rodauth_admin/allowlist'

@db = Sequel.sqlite
RodauthAdmin::Database.migrate_admin!(@db)

## Migrations create both admin tables
(RodauthAdmin::Database::ADMIN_TABLES - @db.tables).empty?
#=> true

## A mutation-shaped action without a reason is refused
begin
  RodauthAdmin::Audit.record(db: @db, action: 'clear_lockout', actor: 'op@example.com', target_account_id: 42)
rescue RodauthAdmin::Audit::BlankReason
  :refused
end
#=> :refused

## Session actions get the fixed 'session' reason
RodauthAdmin::Audit.record(db: @db, action: 'login', actor: 'op@example.com', actor_account_id: 7)
@db[:admin_actions].first[:reason]
#=> "session"

## A reason is stored trimmed; metadata is JSON text
RodauthAdmin::Audit.record(db: @db, action: 'clear_lockout', actor: 'op@example.com', actor_account_id: 7,
                           target_account_id: 42, target: 'user@example.com', reason: '  ticket #123 ',
                           metadata: { ticket: 123 })
row = @db[:admin_actions].order(:id).last
[row[:reason], row[:metadata]]
#=> ["ticket #123", "{\"ticket\":123}"]

## Rows cannot be updated
begin
  @db[:admin_actions].update(reason: 'rewritten history')
rescue Sequel::DatabaseError => e
  e.message.include?('append-only')
end
#=> true

## Rows cannot be deleted
begin
  @db[:admin_actions].delete
rescue Sequel::DatabaseError => e
  e.message.include?('append-only')
end
#=> true

## Allowlist add and remove are themselves admin actions
RodauthAdmin::Allowlist.add!(db: @db, account_id: 42, email: 'user@example.com', actor: 'cli:d', reason: 'onboarding')
RodauthAdmin::Allowlist.remove!(db: @db, account_id: 42, actor: 'cli:d', reason: 'offboarding')
@db[:admin_actions].order(:id).select_map(:action).last(2)
#=> ["operator_add", "operator_remove"]

## Removing an unknown operator is a no-op that returns nil
RodauthAdmin::Allowlist.remove!(db: @db, account_id: 999, actor: 'cli:d', reason: 'nobody')
#=> nil

## otp_setup is a session-lifecycle action: no operator-supplied reason
RodauthAdmin::Audit.record(db: @db, action: 'otp_setup', actor: 'op@example.com', actor_account_id: 7)
@db[:admin_actions].order(:id).last[:reason]
#=> "session"

## account_id_for_email resolves through the authdb first (current address wins)
@authdb = Sequel.sqlite
@authdb.create_table(:accounts) do
  primary_key :id
  String :email
end
@authdb[:accounts].insert(id: 42, email: 'renamed@example.com')
RodauthAdmin::Allowlist.add!(db: @db, account_id: 42, email: 'old@example.com', actor: 'cli:d', reason: 'onboarding')
RodauthAdmin::Allowlist.account_id_for_email('renamed@example.com', authdb: @authdb, db: @db)
#=> 42

## ...and falls back to the allowlist display copy, case-insensitively, for an account the authdb no longer has
RodauthAdmin::Allowlist.account_id_for_email('old@example.com', authdb: @authdb, db: @db)
#=> 42

## An address known to neither resolves to nil
RodauthAdmin::Allowlist.account_id_for_email('nobody@example.com', authdb: @authdb, db: @db)
#=> nil

## An address reassigned in the authdb to a different account is refused, not guessed
@authdb[:accounts].insert(id: 43, email: 'old@example.com')
begin
  RodauthAdmin::Allowlist.account_id_for_email('old@example.com', authdb: @authdb, db: @db)
rescue RodauthAdmin::Allowlist::AmbiguousEmail => e
  e.message
end
#=> "old@example.com is account 43 in the authdb but was allowlisted as account 42"
