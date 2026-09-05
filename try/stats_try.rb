# try/stats_try.rb
#
# frozen_string_literal: true

# Aggregate authdb visibility: nine cheap counts, status labels read from
# the table, expired lockouts excluded, brief caching, and a degradation
# path that never raises.

require 'sequel'
ENV['RACK_ENV'] = 'test'
require_relative '../lib/rodauth_admin'
require_relative '../lib/rodauth_admin/authdb_schema'
require_relative '../lib/rodauth_admin/stats'

@db = Sequel.sqlite
RodauthAdmin::AuthdbSchema.build!(@db)
@now = Time.now

# Two verified accounts (one orphaned), one unverified, one closed.
@a1 = @db[:accounts].insert(email: 'a1@example.com', status_id: 2, external_id: 'cust1')
@a2 = @db[:accounts].insert(email: 'a2@example.com', status_id: 2, external_id: nil)
@a3 = @db[:accounts].insert(email: 'a3@example.com', status_id: 1, external_id: nil)
@a4 = @db[:accounts].insert(email: 'a4@example.com', status_id: 3, external_id: 'cust4')

@db[:account_otp_keys].insert(id: @a1, key: 'k')
@db[:account_webauthn_keys].insert(account_id: @a1, webauthn_id: 'w1', public_key: 'p', sign_count: 0)
@db[:account_webauthn_keys].insert(account_id: @a1, webauthn_id: 'w2', public_key: 'p', sign_count: 0)
@db[:account_active_session_keys].insert(account_id: @a1, session_id: 's1')
@db[:account_recovery_codes].insert(id: @a1, code: 'c1')
@db[:account_recovery_codes].insert(id: @a1, code: 'c2')
# One live lockout and one that expired an hour ago: only the live one counts.
@db[:account_lockouts].insert(id: @a2, key: 'lk2', deadline: @now + 3600)
@db[:account_lockouts].insert(id: @a3, key: 'lk3', deadline: @now - 3600)

# A db whose every query fails, standing in for an unreachable authdb.
class BrokenDb
  class BrokenDataset
    def method_missing(*) = raise(Sequel::DatabaseError, 'authdb is down')
    def respond_to_missing?(*) = true
  end

  def [](_table) = BrokenDataset.new
end
@broken = BrokenDb.new

## Totals and the derived counts
r = RodauthAdmin::Stats.call(db: @db, now: @now)
[r.available, r.total_accounts, r.mfa_otp_accounts, r.mfa_webauthn_accounts,
 r.active_session_keys, r.recovery_code_rows, r.orphaned_accounts]
#=> [true, 4, 1, 1, 1, 2, 2]

## Expired lockouts do not count as active
RodauthAdmin::Stats.call(db: @db, now: @now).active_lockouts
#=> 1

## Status labels come from account_statuses, with zero-count rows kept
RodauthAdmin::Stats.call(db: @db, now: @now).status_breakdown.map { |s| [s[:id], s[:name], s[:count]] }
#=> [[1, "Unverified", 1], [2, "Verified", 2], [3, "Closed", 1]]

## The Result and its breakdown rows are frozen
r = RodauthAdmin::Stats.call(db: @db, now: @now)
[r.frozen?, r.status_breakdown.frozen?, r.status_breakdown.first.frozen?]
#=> [true, true, true]

## v1 ships the null customer-count source, so drift is nil
r = RodauthAdmin::Stats.call(db: @db, now: @now)
[r.customer_count, r.customer_count_delta]
#=> [nil, nil]

## A pluggable source lights up the drift stat
RodauthAdmin::Stats.customer_count_source = -> { 6 }
r = RodauthAdmin::Stats.call(db: @db, now: @now)
RodauthAdmin::Stats.customer_count_source = nil
[r.customer_count, r.customer_count_delta, RodauthAdmin::Stats.customer_count_source]
#=> [6, -2, RodauthAdmin::Stats::NullSource]

## An unreachable authdb degrades instead of raising
r = RodauthAdmin::Stats.call(db: @broken, now: @now)
[r.available, r.total_accounts, r.status_breakdown, r.reason.include?('authdb is down')]
#=> [false, nil, nil, true]

## Within the ttl, cached returns the memo (a new account is not seen)
RodauthAdmin::Stats.reset_cache!
first = RodauthAdmin::Stats.cached(ttl: 60, db: @db, now: @now)
@db[:accounts].insert(email: 'a5@example.com', status_id: 2, external_id: 'cust5')
second = RodauthAdmin::Stats.cached(ttl: 60, db: @db, now: @now + 30)
[first.total_accounts, second.total_accounts, second.equal?(first)]
#=> [4, 4, true]

## Past the ttl it recomputes
RodauthAdmin::Stats.cached(ttl: 60, db: @db, now: @now + 61).total_accounts
#=> 5

## An unavailable result is not cached, so the next call retries
RodauthAdmin::Stats.reset_cache!
down = RodauthAdmin::Stats.cached(ttl: 60, db: @broken, now: @now)
back = RodauthAdmin::Stats.cached(ttl: 60, db: @db, now: @now)
[down.available, back.available, back.total_accounts]
#=> [false, true, 5]

## A bug in the query layer is not "the authdb is unreachable": it propagates
class BuggyDb
  def [](_table) = raise(NoMethodError, 'undefined method for nil')
end
begin
  RodauthAdmin::Stats.call(db: BuggyDb.new, now: @now)
rescue NoMethodError
  :propagated
end
#=> :propagated

## Accounts whose status_id has no account_statuses row become one residual row
# Production's accounts.status_id has no foreign key to account_statuses, so
# this state is reachable there; SQLite needs foreign_keys off to model it.
@unconstrained = Sequel.connect('sqlite:/', max_connections: 1)
RodauthAdmin::AuthdbSchema.build!(@unconstrained)
@unconstrained.run('PRAGMA foreign_keys = OFF')
@unconstrained[:accounts].insert(email: 'ok@example.com', status_id: 2)
@unconstrained[:accounts].insert(email: 'ghost@example.com', status_id: 99)
@unconstrained[:accounts].insert(email: 'ghost2@example.com', status_id: 98)
r = RodauthAdmin::Stats.call(db: @unconstrained, now: @now)
[r.status_breakdown.last, r.status_breakdown.sum { |s| s[:count] } == r.total_accounts]
#=> [{ id: nil, name: 'unknown', count: 2 }, true]

## With every status known, no residual row is appended
RodauthAdmin::Stats.call(db: @db, now: @now).status_breakdown.map { |s| s[:id] }
#=> [1, 2, 3]

## A slow query does not hold the cache lock: other threads keep reading
class SlowDb
  def initialize(inner) = @inner = inner

  def [](table)
    sleep 0.3
    @inner[table]
  end
end
RodauthAdmin::Stats.reset_cache!
warm = RodauthAdmin::Stats.cached(ttl: 300, db: @db, now: @now)
slow = Thread.new { RodauthAdmin::Stats.cached(ttl: 0, db: SlowDb.new(@db), now: @now) }
sleep 0.05
started = Time.now
source = RodauthAdmin::Stats.customer_count_source
hit = RodauthAdmin::Stats.cached(ttl: 300, db: @db, now: @now)
elapsed = Time.now - started
slow.join
[source, hit.equal?(warm), elapsed < 0.2]
#=> [RodauthAdmin::Stats::NullSource, true, true]
