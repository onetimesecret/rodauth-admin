# try/account_list_try.rb
#
# frozen_string_literal: true

# The locked and orphaned lists: strict filter whitelist, fixed ordering,
# capped pagination, expired lockouts excluded, and graceful degradation.

require 'sequel'
ENV['RACK_ENV'] = 'test'
require_relative '../lib/rodauth_admin'
require_relative '../lib/rodauth_admin/authdb_schema'
require_relative '../lib/rodauth_admin/account_list'

@db = Sequel.sqlite
RodauthAdmin::AuthdbSchema.build!(@db)
@now = Time.now

# Three locked accounts (one lockout already expired) and three orphans.
@ids = (1..5).map do |i|
  @db[:accounts].insert(email: "u#{i}@example.com", status_id: i == 1 ? 1 : 2,
                        external_id: i <= 2 ? "cust#{i}" : nil)
end
@db[:account_lockouts].insert(id: @ids[0], key: 'k0', deadline: @now + 7200)
@db[:account_lockouts].insert(id: @ids[1], key: 'k1', deadline: @now + 3600)
@db[:account_lockouts].insert(id: @ids[2], key: 'k2', deadline: @now - 60)
@db[:account_login_failures].insert(id: @ids[0], number: 5)

# A db whose every query fails, standing in for an unreachable authdb.
class BrokenDb
  class BrokenDataset
    def method_missing(*) = raise(Sequel::DatabaseError, 'authdb is down')
    def respond_to_missing?(*) = true
  end

  def [](_table) = BrokenDataset.new
end
@broken = BrokenDb.new

## locked: only live lockouts, ordered by deadline then id
r = RodauthAdmin::AccountList.call(filter: :locked, db: @db, now: @now)
[r.available, r.total, r.rows.map(&:email)]
#=> [true, 2, ["u2@example.com", "u1@example.com"]]

## A locked row carries the status label, deadline, failure count and join key
row = RodauthAdmin::AccountList.call(filter: 'locked', db: @db, now: @now).rows.last
[row.email, row.status_id, row.status, row.external_id, row.login_failures, !row.created_at.nil?]
#=> ["u1@example.com", 1, "Unverified", "cust1", 5, true]

## A locked account with no login-failure row reports zero, not nil
RodauthAdmin::AccountList.call(filter: :locked, db: @db, now: @now).rows.first.login_failures
#=> 0

## Lockout deadline is present on locked rows
RodauthAdmin::AccountList.call(filter: :locked, db: @db, now: @now).rows.first.lockout_deadline.nil?
#=> false

## orphaned: external_id IS NULL, id ascending, lockout fields nil
r = RodauthAdmin::AccountList.call(filter: :orphaned, db: @db, now: @now)
[r.total, r.rows.map(&:email), r.rows.first.lockout_deadline, r.rows.first.login_failures]
#=> [3, ["u3@example.com", "u4@example.com", "u5@example.com"], nil, nil]

## Result and rows are frozen
r = RodauthAdmin::AccountList.call(filter: :orphaned, db: @db, now: @now)
[r.frozen?, r.rows.frozen?, r.rows.first.frozen?]
#=> [true, true, true]

## Pagination: page 2 of the orphan list, with page/next/prev helpers
r = RodauthAdmin::AccountList.call(filter: :orphaned, page: 2, per_page: 2, db: @db, now: @now)
[r.total, r.pages, r.page, r.rows.map(&:email), r.next_page, r.prev_page]
#=> [3, 2, 2, ["u5@example.com"], nil, 1]

## First page reports a next page and no previous one
r = RodauthAdmin::AccountList.call(filter: :orphaned, page: 1, per_page: 2, db: @db, now: @now)
[r.next_page, r.prev_page]
#=> [2, nil]

## per_page is clamped to PER_PAGE_MAX and page floors at 1
r = RodauthAdmin::AccountList.call(filter: :orphaned, page: 0, per_page: 1000, db: @db, now: @now)
[r.per_page, r.page]
#=> [100, 1]

## Garbage page/per_page fall back to the defaults
r = RodauthAdmin::AccountList.call(filter: :orphaned, page: 'x', per_page: 'y', db: @db, now: @now)
[r.page, r.per_page]
#=> [1, 25]

## An unknown filter is refused
begin
  RodauthAdmin::AccountList.call(filter: 'x', db: @db, now: @now)
rescue RodauthAdmin::AccountList::InvalidFilter
  :refused
end
#=> :refused

## A SQL-ish filter is refused, not interpolated
begin
  RodauthAdmin::AccountList.call(filter: 'locked; DROP TABLE accounts--', db: @db, now: @now)
rescue RodauthAdmin::AccountList::InvalidFilter => e
  [:refused, e.is_a?(ArgumentError), @db.table_exists?(:accounts)]
end
#=> [:refused, true, true]

## An unreachable authdb degrades instead of raising
r = RodauthAdmin::AccountList.call(filter: :locked, db: @broken, now: @now)
[r.available, r.total, r.rows, r.pages, r.next_page, r.reason.include?('authdb is down')]
#=> [false, nil, [], nil, nil, true]

## A bug in row building is not "the authdb is unreachable": it propagates
class BuggyDb
  def [](_table) = raise(NoMethodError, 'undefined method for nil')
end
begin
  RodauthAdmin::AccountList.call(filter: :orphaned, db: BuggyDb.new, now: @now)
rescue NoMethodError
  :propagated
end
#=> :propagated

## A page past the end clamps to the last page rather than rendering nothing
r = RodauthAdmin::AccountList.call(filter: :orphaned, page: 999_999, per_page: 2, db: @db, now: @now)
[r.page, r.pages, r.rows.map(&:email), r.next_page, r.prev_page]
#=> [2, 2, ["u5@example.com"], nil, 1]

## An empty list keeps page 1 rather than clamping to zero
r = RodauthAdmin::AccountList.call(filter: :locked, page: 5, db: @db, now: @now + 86_400)
[r.total, r.page, r.pages]
#=> [0, 5, 1]

## per_page: 0 clamps to 1 rather than dividing by zero
r = RodauthAdmin::AccountList.call(filter: :orphaned, per_page: 0, db: @db, now: @now)
[r.per_page, r.rows.size, r.pages]
#=> [1, 1, 3]

## An Array filter (Rack's ?filter[]=locked) is refused, not crashed on
begin
  RodauthAdmin::AccountList.call(filter: ['locked'], db: @db, now: @now)
rescue RodauthAdmin::AccountList::InvalidFilter
  :refused
end
#=> :refused
