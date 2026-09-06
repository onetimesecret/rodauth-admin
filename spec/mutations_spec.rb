# spec/mutations_spec.rb
#
# frozen_string_literal: true

require_relative 'spec_helper'
require_relative 'support/front_door_helpers'

# Phase 4 exit criterion: an operator signs in, opens a verb's confirm page,
# types a reason, and the row is gone AND recorded — in that order, through
# the whole guard chain (docs/design/mutations.md). The verb module's own
# behaviour is covered by try/verbs_try.rb; what is tested here is the
# request: the guards, the statuses, the flash and what reaches the page.
RSpec.describe RodauthAdmin::App do
  include FrontDoorHelpers

  let(:email) { 'operator@example.com' }
  let(:password) { 'correct horse battery staple' }
  let!(:account_id) { create_account(email: email, password: password, external_id: 'extid-op-1') }
  let(:now) { Time.now }

  # The customer whose account the operator is fixing. Given one of
  # everything so each verb has something to remove.
  let(:target) { create_account(email: 'customer@example.com', password: password, external_id: 'extid-c-1') }

  def stock_target!(id = target)
    authdb[:account_lockouts].insert(id: id, key: 'lk', deadline: now + 3600)
    authdb[:account_login_failures].insert(id: id, number: 4)
    authdb[:account_password_reset_keys].insert(id: id, key: 'prk', deadline: now + 900)
    authdb[:account_email_auth_keys].insert(id: id, key: 'eak', deadline: now + 900)
    authdb[:account_otp_keys].insert(id: id, key: 'otp', num_failures: 0)
    authdb[:account_recovery_codes].insert(id: id, code: 'old-1')
    authdb[:account_active_session_keys].insert(account_id: id, session_id: 's1', created_at: now, last_use: now)
    authdb[:account_jwt_refresh_keys].insert(account_id: id, key: 'rk', deadline: now + 900)
    authdb[:account_identities].insert(account_id: id, provider: 'google', issuer: '', uid: 'g-1')
    id
  end

  def verb_path(id, slug) = "/accounts/#{id}/#{slug}"

  # A GET, then the POST it hands the token to — the same two requests a
  # browser makes, which is also what keeps the CSRF token path-scoped.
  def run_verb!(id, slug, reason: 'ticket 4412: customer called, verified')
    form_post verb_path(id, slug), reason: reason
  end

  before { @otp_secret = sign_in_operator! }

  describe 'the confirm page' do
    it 'shows the live counts and a reason box for every verb' do
      stock_target!
      RodauthAdmin::Verbs::SLUGS.each_key do |slug|
        get verb_path(target, slug)
        expect(last_response.status).to eq(200), "#{slug}: #{last_response.status}"
        expect(last_response.body).to include('name="reason"'), slug
        expect(last_response.body).to include('name="_csrf"'), slug
      end
    end

    it 'names the tenant-side gaps on the two verbs that have them' do
      stock_target!
      get verb_path(target, 'force-password-reset')
      expect(last_response.body).to include('password_expiration')
      get verb_path(target, 'revoke-refresh-keys')
      expect(last_response.body).to include('jwt_refresh')
    end

    it 'does not list the failure counter as a table it would empty' do
      stock_target!
      get verb_path(target, 'clear-lockout')
      expect(last_response.body).to include('<code>account_login_failures</code>')
      expect(last_response.body).not_to include('<code>login_failure_number</code>')
      expect(last_response.body).to include('counter currently stands at 4')
    end

    it 'says so when there is nothing to remove, and still offers the button' do
      get verb_path(target, 'clear-lockout')
      expect(last_response.body).to include('nothing to remove')
      expect(last_response.body).to include('type="submit"')
    end

    it 'is a 404 for an unknown account and for an unknown slug' do
      get verb_path(999_999, 'clear-lockout')
      expect(last_response.status).to eq(404)
      get verb_path(target, 'reticulate-splines')
      expect(last_response.status).to eq(404)
    end
  end

  describe 'executing a verb' do
    it 'clears the lockout, records the operator as actor, and flashes the counts' do
      stock_target!
      run_verb!(target, 'clear-lockout')
      expect(last_response).to be_redirect
      expect(last_response.location).to end_with("/accounts/#{target}")
      expect(authdb[:account_lockouts].where(id: target).count).to eq(0)
      expect(authdb[:account_login_failures].where(id: target).count).to eq(0)

      row = actions('clear_lockout').last
      expect(row[:actor]).to eq(email)
      expect(row[:actor_account_id]).to eq(account_id)
      expect(row[:target_account_id]).to eq(target)
      expect(row[:reason]).to include('4412')

      get "/accounts/#{target}"
      expect(last_response.body).to include('account_lockouts 1')
    end

    it 'expires every pending token' do
      stock_target!
      run_verb!(target, 'expire-tokens')
      expect(last_response).to be_redirect
      expect(authdb[:account_password_reset_keys].where(id: target).count).to eq(0)
      expect(authdb[:account_email_auth_keys].where(id: target).count).to eq(0)
    end

    it 'revokes sessions and refresh keys' do
      stock_target!
      run_verb!(target, 'revoke-sessions')
      run_verb!(target, 'revoke-refresh-keys')
      expect(authdb[:account_active_session_keys].where(account_id: target).count).to eq(0)
      expect(authdb[:account_jwt_refresh_keys].where(account_id: target).count).to eq(0)
      expect(actions.map { |a| a[:action] }).to include('revoke_sessions', 'revoke_refresh_keys')
    end

    it 'backdates the password change time and drops the reset key' do
      stock_target!
      run_verb!(target, 'force-password-reset')
      expect(authdb[:account_password_change_times].where(id: target).get(:changed_at).to_i).to eq(0)
      expect(authdb[:account_password_reset_keys].where(id: target).count).to eq(0)
    end

    it 'refuses a blank reason with a 422 and changes nothing' do
      stock_target!
      before = actions.size
      run_verb!(target, 'clear-lockout', reason: '   ')
      expect(last_response.status).to eq(422)
      expect(last_response.body).to include('A reason is required')
      expect(authdb[:account_lockouts].where(id: target).count).to eq(1)
      expect(actions.size).to eq(before)
    end

    # The account is deleted between the confirm page and the POST, which
    # is the only way to reach the POST's own NotFound with a valid,
    # path-scoped CSRF token — and is exactly the race the verb layer
    # raises NotFound for.
    it 'is a 404 when the account has gone between the confirm page and the POST' do
      doomed = create_account(email: 'doomed@example.com', password: password)
      before = actions.size
      get verb_path(doomed, 'clear-lockout')
      token = hidden_field(last_response.body, '_csrf')
      authdb[:account_password_hashes].where(id: doomed).delete
      authdb[:accounts].where(id: doomed).delete
      post verb_path(doomed, 'clear-lockout'), reason: 'nobody', _csrf: token
      expect(last_response.status).to eq(404)
      expect(actions.size).to eq(before)
    end

    it 'rejects a POST with no CSRF token and mutates nothing' do
      stock_target!
      post verb_path(target, 'clear-lockout'), reason: 'forged'
      expect(last_response).to be_redirect
      expect(last_response.location).to end_with('/login')
      expect(authdb[:account_lockouts].where(id: target).count).to eq(1)
    end
  end

  # COPY is the operator-facing prose for every verb, and the dispatch reads
  # the slug straight out of it. A verb added to one and not the other is a
  # page with no words or words with no page, both of which only show up on
  # the request itself.
  describe 'the verb table' do
    it 'has copy for exactly the verbs that exist' do
      expect(RodauthAdmin::VerbRoutes::COPY.keys)
        .to eq(RodauthAdmin::Verbs::SLUGS.keys + [RodauthAdmin::VerbRoutes::UNLINK_SLUG])
    end
  end

  describe 'disabling MFA' do
    it 'removes every second factor, records it, and flashes the counts' do
      stock_target!
      authdb[:account_otp_unlocks].insert(id: target, num_successes: 1)
      run_verb!(target, 'disable-mfa')
      expect(last_response).to be_redirect

      expect(authdb[:account_otp_keys].where(id: target).count).to eq(0)
      expect(authdb[:account_otp_unlocks].where(id: target).count).to eq(0)
      expect(authdb[:account_recovery_codes].where(id: target).count).to eq(0)

      row = actions('disable_mfa').last
      expect(row[:target_account_id]).to eq(target)
      expect(row[:reason]).to include('4412')

      get "/accounts/#{target}"
      expect(last_response.body).to include('account_otp_keys 1')
    end
  end

  # The half of the verb that bites today: the tenant app does not consult
  # account_active_session_keys, but it does honour a remember-me cookie.
  describe 'revoking sessions' do
    it 'deletes the remember-me token as well as the session keys' do
      stock_target!
      authdb[:account_remember_keys].insert(id: target, key: 'rm', deadline: now + (14 * 86_400))
      run_verb!(target, 'revoke-sessions')
      expect(authdb[:account_remember_keys].where(id: target).count).to eq(0)
      expect(authdb[:account_active_session_keys].where(account_id: target).count).to eq(0)
    end

    it 'says on the confirm page that an open browser session is not ended' do
      get verb_path(target, 'revoke-sessions')
      expect(last_response.body).to include('check_active_session')
      expect(last_response.body).to include('remember-me')
    end
  end

  describe 'the operator-target refusal' do
    # A second operator with a second factor of their own. A method rather
    # than a `let` so the group stays under the memoized-helper limit; it is
    # called once per example either way.
    def colleague!
      id = create_account(email: 'colleague@example.com', password: password)
      allowlist!(id, 'colleague@example.com')
      authdb[:account_otp_keys].insert(id: id, key: 'otp', num_failures: 0)
      id
    end

    it 'refuses disable-mfa on a fellow operator with a 403 and records the attempt' do
      colleague = colleague!
      run_verb!(colleague, 'disable-mfa')
      expect(last_response.status).to eq(403)
      expect(last_response.body).to include('another operator')
      expect(authdb[:account_otp_keys].where(id: colleague).count).to eq(1)

      row = actions('disable_mfa_refused').last
      expect(row[:target_account_id]).to eq(colleague)
      expect(row[:metadata].to_s).to include('operator_target')
    end

    it 'hides both refused verbs on a fellow operator\'s account page' do
      get "/accounts/#{colleague!}"
      expect(last_response.body).not_to include('disable-mfa')
      expect(last_response.body).not_to include('regenerate-recovery-codes')
      expect(last_response.body).to include('clear-lockout'), 'the other verbs stay'
    end
  end

  describe 'the self-target refusal' do
    it 'refuses disable-mfa on the operator\'s own account with a 403' do
      run_verb!(account_id, 'disable-mfa')
      expect(last_response.status).to eq(403)
      expect(last_response.body).to include('your own account')
      expect(authdb[:account_otp_keys].where(id: account_id).count).to eq(1)

      row = actions('disable_mfa_refused').last
      expect(row[:target_account_id]).to eq(account_id)
      expect(row[:metadata].to_s).to include('self_target')
    end

    it 'hides both refused verbs on the operator\'s own account page' do
      get "/accounts/#{account_id}"
      expect(last_response.body).not_to include('disable-mfa')
      expect(last_response.body).not_to include('regenerate-recovery-codes')
      expect(last_response.body).to include('clear-lockout'), 'the other verbs stay'
    end
  end

  describe 'regenerating recovery codes' do
    it 'renders the new codes once and they are the rows now in the authdb' do
      stock_target!
      run_verb!(target, 'regenerate-recovery-codes')
      expect(last_response.status).to eq(200)

      stored = authdb[:account_recovery_codes].where(id: target).select_map(:code)
      expect(stored.size).to eq(RodauthAdmin::Verbs::RECOVERY_CODES_LIMIT)
      expect(stored).not_to include('old-1')
      expect(stored).to all(satisfy { |code| last_response.body.include?(code) })

      metadata = actions('regenerate_recovery_codes').last[:metadata].to_s
      expect(stored).to all(satisfy { |code| !metadata.include?(code) })
    end

    it 'does not show them again on a reload of the account page' do
      stock_target!
      run_verb!(target, 'regenerate-recovery-codes')
      codes = authdb[:account_recovery_codes].where(id: target).select_map(:code)
      get "/accounts/#{target}"
      expect(codes).to all(satisfy { |code| !last_response.body.include?(code) })
    end

    it 'refuses with a 422 when the account has no second factor' do
      authdb[:account_recovery_codes].insert(id: target, code: 'old-1')
      run_verb!(target, 'regenerate-recovery-codes')
      expect(last_response.status).to eq(422)
      expect(last_response.body).to include('no TOTP or WebAuthn key')
      expect(authdb[:account_recovery_codes].where(id: target).select_map(:code)).to eq(['old-1'])
    end
  end

  describe 'unlinking an SSO identity' do
    def identity_path
      stock_target!
      "/accounts/#{target}/identities/#{authdb[:account_identities].where(account_id: target).get(:id)}/unlink"
    end

    it 'unlinks it and records provider and issuer but never the uid' do
      form_post identity_path, reason: 'ticket 9: customer left the SSO tenant'
      expect(last_response).to be_redirect
      expect(authdb[:account_identities].where(account_id: target).count).to eq(0)
      metadata = actions('unlink_identity').last[:metadata].to_s
      expect(metadata).to include('google')
      expect(metadata).not_to include('g-1')
    end

    # The confirm page refuses first (the identity is not on this account),
    # and a POST straight at the URL never gets a token for it either.
    it 'is a 404 for an identity that belongs to somebody else' do
      other = create_account(email: 'other@example.com', password: password)
      authdb[:account_identities].insert(account_id: other, provider: 'entra_id', issuer: 'i', uid: 'x-1')
      theirs = authdb[:account_identities].where(account_id: other).get(:id)
      path = "/accounts/#{target}/identities/#{theirs}/unlink"

      get path
      expect(last_response.status).to eq(404)
      post path, reason: 'wrong account', _csrf: 'not a token for this path'
      expect(last_response).to be_redirect
      expect(authdb[:account_identities].where(id: theirs).count).to eq(1)
    end

    # The route is exact: the confirm page is not rendered under a longer path.
    it 'is a 404 for anything past /unlink' do
      get "#{identity_path}/extra"
      expect(last_response.status).to eq(404)
    end
  end

  # The freshness window is the one guard with no visible form field, so it
  # is tested by moving the clock rather than by touching the constant: what
  # must hold is that an OLD stamp is stale, not that a small constant is.
  describe 'the MFA-freshness step-up' do
    def in_the_future
      travelled = Time.now + RodauthAdmin::Auth::MFA_FRESH_SECONDS + 60
      allow(Time).to receive(:now).and_return(travelled)
      yield
    ensure
      allow(Time).to receive(:now).and_call_original
    end

    it 'bounces a stale confirm GET to /otp-auth and comes back to it afterwards' do
      stock_target!
      path = verb_path(target, 'clear-lockout')
      in_the_future { get path }
      expect(last_response).to be_redirect
      expect(last_response.location).to end_with('/otp-auth')

      # Rodauth refuses a code from a time step it has already accepted, so
      # backdate last_use exactly as the front-door spec does.
      authdb[:account_otp_keys].where(id: account_id).update(last_use: Time.now - 120)
      form_post '/otp-auth', otp: ROTP::TOTP.new(@otp_secret).now
      expect(last_response.location).to end_with(path), 'the step-up must return to the requested page'

      get path
      expect(last_response.status).to eq(200)
    end

    it 'sends a stale POST back to the confirm page instead of executing it' do
      stock_target!
      path = verb_path(target, 'clear-lockout')
      get path
      token = hidden_field(last_response.body, '_csrf')
      in_the_future { post path, reason: 'stale', _csrf: token }
      expect(last_response).to be_redirect
      expect(last_response.location).to end_with(path)
      expect(authdb[:account_lockouts].where(id: target).count).to eq(1)
    end
  end

  describe 'a logged-out request' do
    it 'never reaches a verb, by GET or by POST' do
      stock_target!
      get verb_path(target, 'clear-lockout')
      token = hidden_field(last_response.body, '_csrf')
      form_post '/logout'
      before = actions.size

      get verb_path(target, 'clear-lockout')
      expect(last_response.location).to end_with('/login')
      post verb_path(target, 'clear-lockout'), reason: 'signed out', _csrf: token
      expect(last_response).to be_redirect
      expect(authdb[:account_lockouts].where(id: target).count).to eq(1)
      expect(actions.size - before).to be <= 1, 'only the logout row, if that'
    end
  end
end
