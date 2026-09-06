# try/account_detail_try.rb
#
# frozen_string_literal: true

# The read-only per-account view: every section of a populated account, an
# account with nothing, an unknown id, lookup by email / external_id,
# expiry against both an explicit clock and the database's own, timeline
# ordering and pagination, the session cap, and a degradation path that
# never raises.

require 'sequel'
ENV['RACK_ENV'] = 'test'
require_relative '../lib/rodauth_admin'
require_relative '../lib/rodauth_admin/authdb_schema'
require_relative '../lib/rodauth_admin/account_detail'

@db = RodauthAdmin::Database.configure!(Sequel.sqlite)
RodauthAdmin::AuthdbSchema.build!(@db)
@now = Time.now.utc

# @full has something in every section; @bare has an account row and
# nothing else.
@full = @db[:accounts].insert(email: 'Full@Example.com', status_id: 2, external_id: 'cust-full')
@bare = @db[:accounts].insert(email: 'bare@example.com', status_id: 1, external_id: nil)

# A live lockout with a failure count, and an expired one on @bare's peer.
@db[:account_lockouts].insert(id: @full, key: 'lk', deadline: @now + 3600, email_last_sent: @now - 60)
@db[:account_login_failures].insert(id: @full, number: 3)

@db[:account_otp_keys].insert(id: @full, key: 'secret', num_failures: 2, last_use: @now - 120)
@db[:account_otp_unlocks].insert(id: @full, num_successes: 1, next_auth_attempt_after: @now + 300)
@db[:account_recovery_codes].insert(id: @full, code: 'c1')
@db[:account_recovery_codes].insert(id: @full, code: 'c2')
@db[:account_webauthn_keys].insert(account_id: @full, webauthn_id: 'wk-1', public_key: 'pk',
                                   sign_count: 7, last_use: @now - 60)

@db[:account_active_session_keys].insert(account_id: @full, session_id: 'abcdefghijklmnop',
                                         created_at: @now - 600, last_use: @now - 60)

@db[:account_jwt_refresh_keys].insert(account_id: @full, key: 'rk1', deadline: @now + 3600)
@db[:account_jwt_refresh_keys].insert(account_id: @full, key: 'rk2', deadline: @now - 3600)

@db[:account_password_reset_keys].insert(id: @full, key: 'prk', deadline: @now + 900,
                                         email_last_sent: @now - 30)
@db[:account_verification_keys].insert(id: @full, key: 'vk', requested_at: @now - 3600,
                                       email_last_sent: @now - 3000)
@db[:account_login_change_keys].insert(id: @full, key: 'lck', login: 'new@example.com',
                                       deadline: @now - 900)

@db[:account_identities].insert(account_id: @full, provider: 'google', issuer: '', uid: 'g-1')
@db[:account_identities].insert(account_id: @full, provider: 'entra_id', issuer: 'tenant-a', uid: 'e-1')

@db[:account_password_change_times].insert(id: @full, changed_at: @now - (86_400 * 10))
@db[:account_previous_password_hashes].insert(account_id: @full, password_hash: 'h1')
@db[:account_previous_password_hashes].insert(account_id: @full, password_hash: 'h2')

30.times do |i|
  @db[:account_authentication_audit_logs].insert(account_id: @full, at: @now - (i * 60),
                                                 message: "event-#{i}", metadata: '{"ip":"127.0.0.1"}')
end

# A db whose every query fails, standing in for an unreachable authdb
# (try/stats_try.rb uses the same double).
class BrokenDb
  class BrokenDataset
    def method_missing(*) = raise(Sequel::DatabaseError, 'authdb is down')
    def respond_to_missing?(*) = true
  end

  def [](_table) = BrokenDataset.new
end
@broken = BrokenDb.new

## A found account carries identity and status
r = RodauthAdmin::AccountDetail.find(id: @full, db: @db, now: @now)
a = r.account
[r.available, r.found, r.id, a.email, a.status_id, a.status, a.external_id, a.created_at.is_a?(Time)]
#=> [true, true, @full, 'Full@Example.com', 2, 'Verified', 'cust-full', true]

## The result and its sections are frozen
r = RodauthAdmin::AccountDetail.find(id: @full, db: @db, now: @now)
[r.frozen?, r.account.frozen?, r.mfa.frozen?, r.identities.first.frozen?, r.pending_tokens.first.frozen?]
#=> [true, true, true, true, true]

## A live lockout reads as locked, with its failure count
l = RodauthAdmin::AccountDetail.find(id: @full, db: @db, now: @now).lockout
[l.present, l.locked, l.login_failures, l.deadline.is_a?(Time), l.email_last_sent.is_a?(Time)]
#=> [true, true, 3, true, true]

## An expired lockout row lingers: present, not locked
l = RodauthAdmin::AccountDetail.find(id: @full, db: @db, now: @now + 7200).lockout
[l.present, l.locked]
#=> [true, false]

## The MFA inventory: TOTP, unlock state, recovery-code rows, passkeys
m = RodauthAdmin::AccountDetail.find(id: @full, db: @db, now: @now).mfa
k = m.webauthn_keys.first
[m.otp.present, m.otp.num_failures, m.otp.last_use.is_a?(Time), m.otp_unlock.present,
 m.otp_unlock.num_successes, m.recovery_code_rows, m.webauthn_keys.length, k.webauthn_id, k.sign_count]
#=> [true, 2, true, true, 1, 2, 1, 'wk-1', 7]

## Session ids are truncated to a prefix, never shown whole
s = RodauthAdmin::AccountDetail.find(id: @full, db: @db, now: @now).sessions
[s.total, s.capped, s.rows.length, s.rows.first.session_id, s.rows.first.last_use.is_a?(Time)]
#=> [1, false, 1, "abcdefgh…", true]

## Refresh tokens carry their own expiry verdict
t = RodauthAdmin::AccountDetail.find(id: @full, db: @db, now: @now).refresh_tokens
[t.total, t.rows.map(&:expired)]
#=> [2, [false, true]]

## Pending tokens are one fixed row per type, expired computed per deadline
p = RodauthAdmin::AccountDetail.find(id: @full, db: @db, now: @now).pending_tokens
p.map { |x| [x.type, x.present, x.expired] }
#=> [[:password_reset, true, false], [:verification, true, nil], [:login_change, true, true], [:email_auth, false, nil]]

## The login-change token carries the requested new login
p = RodauthAdmin::AccountDetail.find(id: @full, db: @db, now: @now).pending_tokens
row = p.find { |x| x.type == :login_change }
[row.login, row.deadline.is_a?(Time)]
#=> ['new@example.com', true]

## The verification token carries requested_at, and no expiry verdict
row = RodauthAdmin::AccountDetail.find(id: @full, db: @db, now: @now)
                                 .pending_tokens.find { |x| x.type == :verification }
[row.requested_at.is_a?(Time), row.deadline, row.expired, row.email_last_sent.is_a?(Time)]
#=> [true, nil, nil, true]

## SSO identities are listed, ordered by provider
RodauthAdmin::AccountDetail.find(id: @full, db: @db, now: @now)
                           .identities.map { |i| [i.provider, i.issuer, i.uid] }
#=> [['entra_id', 'tenant-a', 'e-1'], ['google', '', 'g-1']]

## Password age is computed against the given clock; reuse history is counted
pw = RodauthAdmin::AccountDetail.find(id: @full, db: @db, now: @now).password
[pw.changed_at.is_a?(Time), pw.age_days, pw.previous_hash_count]
#=> [true, 10, 2]

## An account with nothing attached is found, with every section empty
r = RodauthAdmin::AccountDetail.find(id: @bare, db: @db, now: @now)
[r.found, r.account.email, r.lockout.present, r.lockout.login_failures,
 r.mfa.otp.present, r.mfa.recovery_code_rows, r.mfa.webauthn_keys,
 r.sessions.total, r.sessions.rows, r.refresh_tokens.total, r.identities,
 r.pending_tokens.map(&:present), r.password.changed_at, r.password.previous_hash_count]
#=> [true, 'bare@example.com', false, 0, false, 0, [], 0, [], 0, [], [false, false, false, false], nil, 0]

## An unknown id is found: false, not an outage
r = RodauthAdmin::AccountDetail.find(id: 999_999, db: @db, now: @now)
[r.available, r.reason, r.found, r.id, r.account, r.mfa]
#=> [true, nil, false, 999_999, nil, nil]

## A non-numeric id is the same not-found answer, never a raise
r = RodauthAdmin::AccountDetail.find(id: 'nope', db: @db, now: @now)
[r.available, r.found, r.id]
#=> [true, false, nil]

## Lookup matches an exact email
RodauthAdmin::AccountDetail.lookup('Full@Example.com', db: @db)
#=> @full

## Lookup folds case when the exact match misses
RodauthAdmin::AccountDetail.lookup('full@EXAMPLE.com', db: @db)
#=> @full

## Lookup matches an external_id (the colonel deep link)
RodauthAdmin::AccountDetail.lookup('cust-full', db: @db)
#=> @full

## Lookup strips surrounding whitespace
RodauthAdmin::AccountDetail.lookup("  cust-full \n", db: @db)
#=> @full

## An empty or blank query matches nothing
[RodauthAdmin::AccountDetail.lookup('', db: @db),
 RodauthAdmin::AccountDetail.lookup('   ', db: @db),
 RodauthAdmin::AccountDetail.lookup(nil, db: @db)]
#=> [nil, nil, nil]

## No wildcards: a prefix is not a match
[RodauthAdmin::AccountDetail.lookup('cust-%', db: @db),
 RodauthAdmin::AccountDetail.lookup('full@', db: @db),
 RodauthAdmin::AccountDetail.lookup('missing@example.com', db: @db)]
#=> [nil, nil, nil]

## Lookup against an unreachable authdb answers nil rather than raising
RodauthAdmin::AccountDetail.lookup('cust-full', db: @broken)
#=> nil

## The timeline is newest first and paginated at the default size
t = RodauthAdmin::AccountDetail.timeline(id: @full, db: @db)
[t.available, t.total, t.per_page, t.page, t.rows.length, t.rows.first.message, t.rows.last.message,
 t.pages, t.next_page, t.prev_page]
#=> [true, 30, 25, 1, 25, 'event-0', 'event-24', 2, 2, nil]

## Page two carries the remainder
t = RodauthAdmin::AccountDetail.timeline(id: @full, page: 2, db: @db)
[t.page, t.rows.length, t.rows.first.message, t.next_page, t.prev_page]
#=> [2, 5, 'event-25', nil, 1]

## metadata comes through as the raw JSON string, unparsed
RodauthAdmin::AccountDetail.timeline(id: @full, db: @db).rows.first.metadata
#=> '{"ip":"127.0.0.1"}'

## per_page is clamped to the maximum, and a junk value falls back
[RodauthAdmin::AccountDetail.timeline(id: @full, per_page: 1000, db: @db).per_page,
 RodauthAdmin::AccountDetail.timeline(id: @full, per_page: 0, db: @db).per_page,
 RodauthAdmin::AccountDetail.timeline(id: @full, per_page: 'lots', db: @db).per_page]
#=> [100, 1, 25]

## An out-of-range page shows the last page rather than an empty table
t = RodauthAdmin::AccountDetail.timeline(id: @full, page: 999_999, db: @db)
[t.page, t.rows.length]
#=> [2, 5]

## An account with no timeline rows is an empty page, still available
t = RodauthAdmin::AccountDetail.timeline(id: @bare, db: @db)
[t.available, t.total, t.rows, t.pages, t.next_page]
#=> [true, 0, [], 1, nil]

## The session list is capped, and reports the true total beside it
@capped = @db[:accounts].insert(email: 'capped@example.com', status_id: 2)
60.times do |i|
  @db[:account_active_session_keys].insert(account_id: @capped, session_id: format('sess-%04d', i),
                                           created_at: @now, last_use: @now - i)
end
s = RodauthAdmin::AccountDetail.find(id: @capped, db: @db, now: @now).sessions
[s.total, s.capped, s.rows.length, s.rows.first.session_id]
#=> [60, true, 50, "sess-000…"]

## With the default `now:`, a deadline the DATABASE wrote in the future is locked
@clock = @db[:accounts].insert(email: 'clock@example.com', status_id: 2)
@db[:account_lockouts].insert(id: @clock, key: 'ck',
                              deadline: Sequel.date_add(Sequel::CURRENT_TIMESTAMP, minutes: 5))
l = RodauthAdmin::AccountDetail.find(id: @clock, db: @db).lockout
[l.present, l.locked]
#=> [true, true]

## ... and one the database wrote in the past is present but not locked
@db[:account_lockouts].where(id: @clock)
                      .update(deadline: Sequel.date_add(Sequel::CURRENT_TIMESTAMP, minutes: -5))
l = RodauthAdmin::AccountDetail.find(id: @clock, db: @db).lockout
[l.present, l.locked]
#=> [true, false]

## The default clock also decides refresh-token expiry
@db[:account_jwt_refresh_keys].insert(account_id: @clock, key: 'ck1',
                                      deadline: Sequel.date_add(Sequel::CURRENT_TIMESTAMP, minutes: 5))
@db[:account_jwt_refresh_keys].insert(account_id: @clock, key: 'ck2',
                                      deadline: Sequel.date_add(Sequel::CURRENT_TIMESTAMP, minutes: -5))
RodauthAdmin::AccountDetail.find(id: @clock, db: @db).refresh_tokens.rows.map(&:expired)
#=> [false, true]

## An unreachable authdb degrades find instead of raising
r = RodauthAdmin::AccountDetail.find(id: @full, db: @broken, now: @now)
[r.available, r.found, r.id, r.account, r.sessions, r.reason.include?('authdb is down')]
#=> [false, false, @full, nil, nil, true]

## ... and degrades the timeline the same way
t = RodauthAdmin::AccountDetail.timeline(id: @full, page: 3, db: @broken)
[t.available, t.total, t.rows, t.pages, t.next_page, t.reason.include?('authdb is down')]
#=> [false, nil, [], nil, nil, true]

## A bug in the query layer is not "the authdb is unreachable": it propagates
class BuggyDb
  def [](_table) = raise(NoMethodError, 'undefined method for nil')
end
begin
  RodauthAdmin::AccountDetail.find(id: @full, db: BuggyDb.new, now: @now)
rescue NoMethodError
  :propagated
end
#=> :propagated
