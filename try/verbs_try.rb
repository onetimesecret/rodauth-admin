# try/verbs_try.rb
#
# frozen_string_literal: true

# The mutating verbs: every happy path with its row counts, the four
# refusals (unknown account, own account, a fellow operator, no second
# factor) and the admin_actions row each refusal leaves behind, a blank reason
# refused before any write, the admin_actions row each verb leaves behind,
# the guarantee that a recovery code never reaches metadata, and a failing
# insert rolling the audit row back with the mutation.

require 'delegate'
require 'json'
require 'securerandom'
require 'sequel'
ENV['RACK_ENV'] = 'test'
require_relative '../lib/rodauth_admin'
require_relative '../lib/rodauth_admin/authdb_schema'
require_relative '../lib/rodauth_admin/verbs'

V = RodauthAdmin::Verbs

@db = RodauthAdmin::Database.configure!(Sequel.sqlite)
RodauthAdmin::AuthdbSchema.build!(@db)
RodauthAdmin::Database.migrate_admin!(@db)
@now = Time.now.utc

@actor = V::Actor.build(email: 'op@example.com', account_id: nil, ip: '10.0.0.1', user_agent: 'try')

# A fresh, fully-populated account per test: the verbs delete, so sharing
# one fixture across tests would make each test depend on the last.
def seed(db, now, email: nil, mfa: true)
  id = db[:accounts].insert(email: email || "a#{SecureRandom.hex(6)}@example.com", status_id: 2)
  seed_lockout(db, now, id)
  seed_sessions(db, now, id)
  seed_tokens(db, now, id)
  seed_mfa(db, id) if mfa
  id
end

def seed_lockout(db, now, id)
  db[:account_lockouts].insert(id: id, key: 'lk', deadline: now + 3600)
  db[:account_login_failures].insert(id: id, number: 4)
end

def seed_sessions(db, now, id)
  db[:account_active_session_keys].insert(account_id: id, session_id: 's1', created_at: now, last_use: now)
  db[:account_active_session_keys].insert(account_id: id, session_id: 's2', created_at: now, last_use: now)
  db[:account_jwt_refresh_keys].insert(account_id: id, key: 'rk', deadline: now + 3600)
  db[:account_remember_keys].insert(id: id, key: 'rm', deadline: now + (14 * 86_400))
  db[:account_identities].insert(account_id: id, provider: 'google', issuer: '', uid: "g-#{id}")
end

def seed_tokens(db, now, id)
  db[:account_password_reset_keys].insert(id: id, key: 'prk', deadline: now + 900)
  db[:account_verification_keys].insert(id: id, key: 'vk', requested_at: now)
  db[:account_login_change_keys].insert(id: id, key: 'lck', login: 'n@example.com', deadline: now + 900)
  db[:account_email_auth_keys].insert(id: id, key: 'eak', deadline: now + 900)
end

def seed_mfa(db, id)
  db[:account_otp_keys].insert(id: id, key: 'otp', num_failures: 0)
  db[:account_otp_unlocks].insert(id: id, num_successes: 1)
  db[:account_recovery_codes].insert(id: id, code: 'old-1')
  db[:account_webauthn_keys].insert(account_id: id, webauthn_id: 'wk', public_key: 'pk', sign_count: 1)
  db[:account_webauthn_user_ids].insert(id: id, webauthn_id: 'wuid')
end

def last_action(db)
  db[:admin_actions].reverse(:id).first
end

## clear_lockout deletes exactly what Rodauth's unlock_account deletes
id = seed(@db, @now)
r = V.clear_lockout(id: id, actor: @actor, reason: 'customer called', db: @db)
[r.action, r.counts, r.metadata[:login_failure_number], @db[:account_lockouts].where(id: id).count,
 @db[:account_login_failures].where(id: id).count]
#=> [:clear_lockout, { account_lockouts: 1, account_login_failures: 1 }, 4, 0, 0]

## clear_lockout on an account with no lockout still runs and records zeroes
@nolock = @db[:accounts].insert(email: 'nolock@example.com', status_id: 2)
r = V.clear_lockout(id: @nolock, actor: @actor, reason: 'nothing there', db: @db)
[r.counts, r.total, last_action(@db)[:action], last_action(@db)[:target_account_id]]
#=> [{ account_lockouts: 0, account_login_failures: 0 }, 0, 'clear_lockout', @nolock]

## The audit row carries actor, reason, ip and the counts as metadata
id = seed(@db, @now)
V.clear_lockout(id: id, actor: @actor, reason: 'because', db: @db)
row = last_action(@db)
[row[:actor], row[:reason], row[:ip], row[:user_agent], JSON.parse(row[:metadata])['counts']]
#=> ['op@example.com', 'because', '10.0.0.1', 'try', { 'account_lockouts' => 1, 'account_login_failures' => 1 }]

## force_password_reset backdates the change time and kills the reset key
id = seed(@db, @now)
r = V.force_password_reset(id: id, actor: @actor, reason: 'suspected compromise', db: @db)
changed = @db[:account_password_change_times].where(id: id).get(:changed_at)
[r.counts, changed.to_i, @db[:account_password_reset_keys].where(id: id).count]
#=> [{ account_password_change_times: 1, account_password_reset_keys: 1 }, 0, 0]

## force_password_reset updates an existing change-time row rather than duplicating it
id = seed(@db, @now)
@db[:account_password_change_times].insert(id: id, changed_at: @now)
V.force_password_reset(id: id, actor: @actor, reason: 'again', db: @db)
[@db[:account_password_change_times].where(id: id).count,
 @db[:account_password_change_times].where(id: id).get(:changed_at).to_i]
#=> [1, 0]

## expire_tokens clears all four emailed-link tables
id = seed(@db, @now)
r = V.expire_tokens(id: id, actor: @actor, reason: 'links leaked', db: @db)
[r.counts.keys == V::TOKEN_TABLES, r.counts.values, r.total, @db[:account_email_auth_keys].where(id: id).count]
#=> [true, [1, 1, 1, 1], 4, 0]

## disable_mfa clears every second-factor table
id = seed(@db, @now)
r = V.disable_mfa(id: id, actor: @actor, reason: 'lost phone', db: @db)
[r.counts.keys == V::MFA_TABLES, r.counts.values, @db[:account_webauthn_keys].where(account_id: id).count,
 @db[:account_webauthn_user_ids].where(id: id).count]
#=> [true, [1, 1, 1, 1, 1], 0, 0]

## disable_mfa is refused on the operator's own account
id = seed(@db, @now)
self_actor = V::Actor.build(email: 'op@example.com', account_id: id)
before = @db[:admin_actions].count
begin
  V.disable_mfa(id: id, actor: self_actor, reason: 'mine', db: @db)
rescue V::SelfTarget => e
  [e.class, @db[:account_otp_keys].where(id: id).count, @db[:admin_actions].count - before]
end
#=> [RodauthAdmin::Verbs::SelfTarget, 1, 1]

## A refused self-target is recorded as disable_mfa_refused, with the reason
row = last_action(@db)
[row[:action], row[:reason], JSON.parse(row[:metadata])['refusal'], row[:target_account_id] == id]
#=> ['disable_mfa_refused', 'mine', 'self_target', true]

## disable_mfa is refused on ANOTHER operator's account, and recorded
@op_id = seed(@db, @now)
@db[:admin_operators].insert(account_id: @op_id, email: 'colleague@example.com', added_by: 'try',
                             created_at: Sequel::CURRENT_TIMESTAMP)
before = @db[:admin_actions].count
begin
  V.disable_mfa(id: @op_id, actor: @actor, reason: 'they asked nicely', db: @db)
rescue V::OperatorTarget => e
  row = last_action(@db)
  [e.class, @db[:account_otp_keys].where(id: @op_id).count, @db[:admin_actions].count - before,
   row[:action], JSON.parse(row[:metadata])['refusal'], row[:target_account_id]]
end
#=> [RodauthAdmin::Verbs::OperatorTarget, 1, 1, 'disable_mfa_refused', 'operator_target', @op_id]

## A verb that is not in SELF_REFUSED is fine on an operator's account
r = V.clear_lockout(id: @op_id, actor: @actor, reason: 'colleague locked out', db: @db)
[r.counts, last_action(@db)[:action]]
#=> [{ account_lockouts: 1, account_login_failures: 1 }, 'clear_lockout']

## regenerate_recovery_codes returns the tenant's limit of fresh codes
id = seed(@db, @now)
r = V.regenerate_recovery_codes(id: id, actor: @actor, reason: 'used them all', db: @db)
stored = @db[:account_recovery_codes].where(id: id).select_map(:code)
[r.counts, r.codes.length, r.codes.uniq.length, stored.sort == r.codes.sort, stored.include?('old-1')]
#=> [{ account_recovery_codes: 4 }, 4, 4, true, false]

## Fresh codes are Rodauth's own format: urlsafe_base64(32)
id = seed(@db, @now)
r = V.regenerate_recovery_codes(id: id, actor: @actor, reason: 'rotate', db: @db)
r.codes.all? { |c| c.match?(/\A[A-Za-z0-9_-]{43}\z/) }
#=> true

## A recovery code never reaches the audit trail
id = seed(@db, @now)
r = V.regenerate_recovery_codes(id: id, actor: @actor, reason: 'rotate', db: @db)
row = last_action(@db)
meta = JSON.parse(row[:metadata])
[r.metadata, r.codes.any? { |c| row.values.join(' ').include?(c) }, meta['generated']]
#=> [{ deleted: 1, generated: 4 }, false, 4]

## regenerate_recovery_codes is refused when there is no second factor
id = seed(@db, @now, mfa: false)
before = @db[:admin_actions].count
begin
  V.regenerate_recovery_codes(id: id, actor: @actor, reason: 'why not', db: @db)
rescue V::NoSecondFactor => e
  row = last_action(@db)
  [e.class, @db[:account_recovery_codes].where(id: id).count, @db[:admin_actions].count - before,
   row[:action], JSON.parse(row[:metadata])['refusal']]
end
#=> [RodauthAdmin::Verbs::NoSecondFactor, 0, 1, 'regenerate_recovery_codes_refused', 'no_second_factor']

## A WebAuthn key alone is a second factor
id = seed(@db, @now, mfa: false)
@db[:account_webauthn_keys].insert(account_id: id, webauthn_id: 'wk', public_key: 'pk', sign_count: 0)
V.regenerate_recovery_codes(id: id, actor: @actor, reason: 'webauthn only', db: @db).codes.length
#=> 4

## regenerate_recovery_codes is refused on the operator's own account
id = seed(@db, @now)
begin
  V.regenerate_recovery_codes(id: id, actor: V::Actor.build(email: 'op@example.com', account_id: id),
                              reason: 'mine', db: @db)
rescue V::SelfTarget => e
  [e.class, @db[:account_recovery_codes].where(id: id).select_map(:code), last_action(@db)[:action]]
end
#=> [RodauthAdmin::Verbs::SelfTarget, ['old-1'], 'regenerate_recovery_codes_refused']

## revoke_sessions deletes every active session row AND the remember-me token
id = seed(@db, @now)
r = V.revoke_sessions(id: id, actor: @actor, reason: 'stolen laptop', db: @db)
[r.counts, @db[:account_active_session_keys].where(account_id: id).count,
 @db[:account_remember_keys].where(id: id).count]
#=> [{ account_active_session_keys: 2, account_remember_keys: 1 }, 0, 0]

## revoke_sessions on an account with no remember cookie still runs and records zeroes
id = @db[:accounts].insert(email: "norm#{SecureRandom.hex(4)}@example.com", status_id: 2)
r = V.revoke_sessions(id: id, actor: @actor, reason: 'nothing there', db: @db)
[r.counts, r.total]
#=> [{ account_active_session_keys: 0, account_remember_keys: 0 }, 0]

## revoke_refresh_keys deletes every refresh token
id = seed(@db, @now)
r = V.revoke_refresh_keys(id: id, actor: @actor, reason: 'token leak', db: @db)
[r.counts, @db[:account_jwt_refresh_keys].where(account_id: id).count]
#=> [{ account_jwt_refresh_keys: 1 }, 0]

## unlink_identity records provider and issuer, never the uid
id = seed(@db, @now)
iid = @db[:account_identities].where(account_id: id).get(:id)
r = V.unlink_identity(id: id, identity_id: iid, actor: @actor, reason: 'wrong tenant', db: @db)
[r.counts, r.metadata[:provider], r.metadata.key?(:uid),
 JSON.parse(last_action(@db)[:metadata]).key?('uid'), @db[:account_identities].where(id: iid).count]
#=> [{ account_identities: 1 }, 'google', false, false, 0]

## unlink_identity refuses an identity that belongs to another account
mine = seed(@db, @now)
theirs = seed(@db, @now)
iid = @db[:account_identities].where(account_id: theirs).get(:id)
before = @db[:admin_actions].count
begin
  V.unlink_identity(id: mine, identity_id: iid, actor: @actor, reason: 'oops', db: @db)
rescue V::NotFound => e
  [e.class, @db[:account_identities].where(id: iid).count, @db[:admin_actions].count - before]
end
#=> [RodauthAdmin::Verbs::NotFound, 1, 0]

## Every verb raises NotFound on an id no account has
missing = @db[:accounts].max(:id) + 1000
V::SLUGS.values.map do |verb|
  V.public_send(verb, id: missing, actor: @actor, reason: 'r', db: @db)
rescue V::NotFound
  :not_found
end.uniq
#=> [:not_found]

## A non-numeric id is NotFound, not a crash
begin
  V.clear_lockout(id: 'wat', actor: @actor, reason: 'r', db: @db)
rescue V::NotFound => e
  e.class
end
#=> RodauthAdmin::Verbs::NotFound

## A blank reason is refused before anything is deleted
id = seed(@db, @now)
before = @db[:admin_actions].count
errors = ['', '   ', nil].map do |reason|
  V.clear_lockout(id: id, actor: @actor, reason: reason, db: @db)
rescue RodauthAdmin::Audit::BlankReason
  :refused
end
[errors, @db[:account_lockouts].where(id: id).count, @db[:admin_actions].count - before]
#=> [%i[refused refused refused], 1, 0]

## A failure inside the transaction rolls back the deletes AND the audit row
id = seed(@db, @now)
before_actions = @db[:admin_actions].count
before_sessions = @db[:account_active_session_keys].where(account_id: id).count
# A db whose admin_actions insert fails, everything else real: exactly the
# "mutation succeeded, audit row did not" case the transaction exists for.
class AuditBreaker < SimpleDelegator
  def [](table)
    return BrokenInsert.new(__getobj__[table]) if table == :admin_actions

    __getobj__[table]
  end
end

class BrokenInsert < SimpleDelegator
  def insert(*) = raise(Sequel::DatabaseError, 'admin_actions is read-only')
end
wrapped = AuditBreaker.new(@db)
begin
  V.revoke_sessions(id: id, actor: @actor, reason: 'will fail', db: wrapped)
rescue Sequel::DatabaseError
  [@db[:account_active_session_keys].where(account_id: id).count, before_sessions,
   @db[:admin_actions].count - before_actions]
end
#=> [2, 2, 0]

## preview reports what each verb would touch, without touching anything
@pid = seed(@db, @now)
@preview = V.preview(id: @pid, db: @db)
[@preview.available, @preview.found, @preview.account_id, @preview.identities.length,
 @db[:account_lockouts].where(id: @pid).count]
#=> [true, true, @pid, 1, 1]

## preview counts what each verb would touch
@preview.counts[:clear_lockout]
#=> { account_lockouts: 1, account_login_failures: 1, login_failure_number: 4 }

## preview counts the remember-me token beside the session keys
@preview.counts[:revoke_sessions]
#=> { account_active_session_keys: 2, account_remember_keys: 1 }

## preview reports the MFA inventory and whether a second factor exists at all
[@preview.counts[:disable_mfa][:account_webauthn_keys], @preview.counts[:disable_mfa][:account_webauthn_user_ids],
 @preview.counts[:regenerate_recovery_codes]]
#=> [1, 1, { account_recovery_codes: 1, second_factor: true }]

## preview of an unknown account is found: false, not an outage
p = V.preview(id: @db[:accounts].max(:id) + 1000, db: @db)
[p.available, p.found, p.counts]
#=> [true, false, nil]

## preview degrades rather than raising when the authdb is unreachable
class BrokenDb
  class BrokenDataset
    def method_missing(*) = raise(Sequel::DatabaseError, 'authdb is down')
    def respond_to_missing?(*) = true
  end

  def [](_table) = BrokenDataset.new
  def schema(_table) = raise(Sequel::DatabaseError, 'authdb is down')
end
p = V.preview(id: 1, db: BrokenDb.new)
[p.available, p.found, p.counts, p.reason.include?('authdb is down')]
#=> [false, false, nil, true]

## SLUGS maps every URL slug to a public verb, and every verb answers
[V::SLUGS.length, V::SLUGS.all? { |slug, m| slug.tr('-', '_').to_sym == m && V.respond_to?(m) },
 V::SLUGS.keys.first, V::SLUGS.keys.last]
#=> [7, true, 'clear-lockout', 'revoke-refresh-keys']

## Results are frozen, including the one carrying the codes
id = seed(@db, @now)
r = V.revoke_sessions(id: id, actor: @actor, reason: 'freeze', db: @db)
g = V.regenerate_recovery_codes(id: seed(@db, @now), actor: @actor, reason: 'freeze', db: @db)
[r.frozen?, r.counts.frozen?, r.target.is_a?(String), g.frozen?, g.codes.frozen?, g.counts.frozen?]
#=> [true, true, true, true, true, true]

## unlink_identity coerces the identity id: an Array is NotFound, not `id IN (...)`
id = seed(@db, @now)
iid = @db[:account_identities].where(account_id: id).get(:id)
begin
  V.unlink_identity(id: id, identity_id: [iid], actor: @actor, reason: 'array', db: @db)
rescue V::NotFound => e
  [e.class, @db[:account_identities].where(id: iid).count]
end
#=> [RodauthAdmin::Verbs::NotFound, 1]
