# spec/account_detail_spec.rb
#
# frozen_string_literal: true

require_relative 'spec_helper'
require_relative 'support/front_door_helpers'

# Phase 3 (CHARTER §6): the per-account page and the lookup that reaches it,
# as an operator meets them. The query layer has its own tryouts; what is
# asserted here is the screen — every section heading, the load-bearing
# footnotes, the 404-vs-degraded split, the lookup redirect, and above all
# what never reaches the HTML: no OTP key, no recovery code, no password
# hash, no full session id.
RSpec.describe RodauthAdmin::App do
  include FrontDoorHelpers

  let(:email) { 'operator@example.com' }
  let(:password) { 'correct horse battery staple' }
  # Referenced only through FrontDoorHelpers#allowlist!'s default argument,
  # which the cop cannot see; without it there is no operator to sign in as.
  let!(:account_id) { create_account(email: email, password: password, external_id: 'extid-op-1') } # rubocop:disable RSpec/LetSetup

  # Distinctive fixture values for the columns this page must never select.
  # Asserting on these strings is how "we did not render the secret" stays
  # true after a refactor: a `SELECT *` slipping into the query layer would
  # put one of them on the page.
  let(:secrets) do
    %w[SECRET-otp-key-xyz SECRET-recovery-code SECRET-lockout-key SECRET-webauthn-pubkey
       SECRET-refresh-key SECRET-reset-key SECRET-previous-hash]
  end

  let(:session_id) { 'abcdefgh-THE-REST-IS-SECRET' }

  # An account with a row in every Phase 3 table, shaped like the tryouts'
  # fixtures. Deadlines are Time.now ± an hour, as in the Phase 2 spec.
  def seed_full!(now = Time.now)
    id = create_account(email: 'subject@example.com', password: password, external_id: 'extid-subject')

    authdb[:account_lockouts].insert(id: id, key: 'SECRET-lockout-key', deadline: now + 3600,
                                     email_last_sent: now - 60)
    authdb[:account_login_failures].insert(id: id, number: 4)

    authdb[:account_otp_keys].insert(id: id, key: 'SECRET-otp-key-xyz', num_failures: 2, last_use: now)
    authdb[:account_otp_unlocks].insert(id: id, num_successes: 1, next_auth_attempt_after: now + 3600)
    authdb[:account_recovery_codes].insert(id: id, code: 'SECRET-recovery-code')
    authdb[:account_webauthn_keys].insert(account_id: id, webauthn_id: 'wk-1',
                                          public_key: 'SECRET-webauthn-pubkey', sign_count: 7, last_use: now)

    authdb[:account_active_session_keys].insert(account_id: id, session_id: session_id,
                                                created_at: now - 600, last_use: now)

    authdb[:account_jwt_refresh_keys].insert(account_id: id, key: 'SECRET-refresh-key', deadline: now + 3600)
    authdb[:account_jwt_refresh_keys].insert(account_id: id, key: 'SECRET-refresh-key-2', deadline: now - 3600)

    authdb[:account_password_reset_keys].insert(id: id, key: 'SECRET-reset-key', deadline: now + 3600,
                                                email_last_sent: now - 30)
    authdb[:account_verification_keys].insert(id: id, key: 'vk', requested_at: now - 3600,
                                              email_last_sent: now - 3000)
    authdb[:account_login_change_keys].insert(id: id, key: 'lck', login: 'new@example.com', deadline: now - 3600)
    authdb[:account_email_auth_keys].insert(id: id, key: 'eak', deadline: now + 3600, email_last_sent: now - 10)

    authdb[:account_identities].insert(account_id: id, provider: 'google', issuer: '', uid: 'g-1')
    authdb[:account_identities].insert(account_id: id, provider: 'entra_id', issuer: 'tenant-a', uid: 'e-1')

    authdb[:account_password_change_times].insert(id: id, changed_at: now - (86_400 * 10))
    authdb[:account_previous_password_hashes].insert(account_id: id, password_hash: 'SECRET-previous-hash')

    3.times do |i|
      authdb[:account_authentication_audit_logs].insert(account_id: id, at: now - (i * 60),
                                                        message: "event-#{i}", metadata: '{"ip":"127.0.0.1"}')
    end
    id
  end

  def bare_account!
    create_account(email: 'bare@example.com', password: password, external_id: nil)
  end

  def unavailable_detail
    RodauthAdmin::AccountDetail::Result.new(
      available: false, reason: 'Sequel::DatabaseConnectionError: could not connect', found: false, id: 1,
      account: nil, lockout: nil, mfa: nil, sessions: nil, refresh_tokens: nil,
      pending_tokens: nil, identities: nil, password: nil
    )
  end

  describe 'the account page' do
    it 'renders every section of a fully seeded account' do
      id = seed_full!
      sign_in_operator!
      get "/accounts/#{id}"
      expect(last_response.status).to eq(200)
      body = last_response.body

      expect(body).to include('Identity &amp; status', 'Lockout', 'MFA inventory', 'Sessions',
                              'API refresh tokens', 'Pending tokens', 'SSO identities', 'Password',
                              'Auth timeline')
      expect(body).to include('subject@example.com', 'extid-subject')
      expect(body).to include('Verified')
      expect(body).to include('entra_id', 'tenant-a', 'g-1')
      expect(body).to include('10 days ago')
    end

    it 'carries the load-bearing footnotes' do
      id = seed_full!
      sign_in_operator!
      get "/accounts/#{id}"
      body = last_response.body

      expect(body).to include('Active session keys, not users online')
      expect(body).to include('Unused recovery codes (rows)')
      expect(body).to include('used_at'), 'the recovery-code drift caveat must be on the page'
      expect(body).to include('never the hashes')
    end

    # The whole point of the column whitelists in the query layer.
    it 'never renders a key, a code or a password hash' do
      id = seed_full!
      sign_in_operator!
      get "/accounts/#{id}"
      secrets.each { |secret| expect(last_response.body).not_to include(secret) }
    end

    it 'truncates the session id and never renders the full one' do
      id = seed_full!
      sign_in_operator!
      get "/accounts/#{id}"
      expect(last_response.body).to include('abcdefgh')
      expect(last_response.body).not_to include(session_id)
      expect(last_response.body).not_to include('THE-REST-IS-SECRET')
    end

    it 'renders an empty state for every section of an account with nothing' do
      id = bare_account!
      sign_in_operator!
      get "/accounts/#{id}"
      expect(last_response.status).to eq(200)
      body = last_response.body

      expect(body).to include('Not locked, no lockout row.')
      expect(body).to include('not enrolled')
      expect(body).to include('No WebAuthn keys.')
      expect(body).to include('No active session keys.')
      expect(body).to include('No JWT refresh tokens.')
      expect(body).to include('No SSO identities.')
      expect(body).to include('No authentication events recorded.')
    end

    it 'shows a live lockout as locked until its deadline' do
      id = seed_full!
      sign_in_operator!
      get "/accounts/#{id}"
      expect(last_response.body).to include('Locked until')
      expect(last_response.body).to match(/\d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC/)
    end

    it 'says an expired lockout row lingers rather than calling the account locked' do
      id = bare_account!
      authdb[:account_lockouts].insert(id: id, key: 'k', deadline: Time.now - 3600)
      sign_in_operator!
      get "/accounts/#{id}"
      expect(last_response.body).to include('An expired lockout row lingers here')
      expect(last_response.body).not_to include('Locked until')
    end

    it 'marks pending tokens expired or live, and leaves verification without an answer' do
      id = seed_full!
      sign_in_operator!
      get "/accounts/#{id}"
      body = last_response.body

      expect(body).to include('password_reset', 'verification', 'login_change', 'email_auth')
      expect(body).to include('live', 'expired')
      expect(body).to include('new@example.com'), 'the login-change target is the point of that row'
      expect(body).to include('no answer for it')
    end

    it 'deep-links the external id to the colonel console when one is configured' do
      allow(RodauthAdmin::Env).to receive(:colonel_console_url).and_return('https://console.example.com')
      id = seed_full!
      sign_in_operator!
      get "/accounts/#{id}"
      expect(last_response.body).to include('href="https://console.example.com/colonel/customers/extid-subject"')
    end

    it 'renders the degraded panel, still 200, when the authdb is unreachable' do
      sign_in_operator!
      allow(RodauthAdmin::AccountDetail).to receive(:find).and_return(unavailable_detail)
      get '/accounts/1'
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include('This account is unavailable')
      expect(last_response.body).to include('Sequel::DatabaseConnectionError: could not connect')
      expect(last_response.body).to include('not a statement about whether the account exists')
    end

    it 'answers an unknown id with its own 404 page' do
      sign_in_operator!
      get '/accounts/987654'
      expect(last_response.status).to eq(404)
      expect(last_response.body).to include('No account matches')
      expect(last_response.body).to include('987654')
    end

    # A non-integer segment matches no route at all; the plugin's page is
    # the right answer there, and a 500 is not.
    it 'answers a non-integer id with a 404 rather than a 500' do
      sign_in_operator!
      get '/accounts/abc'
      expect(last_response.status).to eq(404)
    end

    # The Integer segment must not swallow the Phase 2 list, nor vice versa.
    it 'leaves the filtered list route intact' do
      sign_in_operator!
      get '/accounts?filter=locked'
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include('Locked accounts')
    end
  end

  describe 'the timeline' do
    it 'orders newest first and paginates, preserving per_page' do
      id = seed_full!
      sign_in_operator!
      get "/accounts/#{id}?per_page=1"
      expect(last_response.body).to include('page 1 of 3', 'total 3')
      expect(last_response.body).to include('event-0')
      expect(last_response.body).not_to include('event-1')
      expect(last_response.body).to include("href=\"/accounts/#{id}?page=2&amp;per_page=1\"")

      get "/accounts/#{id}?page=2&per_page=1"
      expect(last_response.body).to include('event-1')
      expect(last_response.body).to include("href=\"/accounts/#{id}?page=1&amp;per_page=1\"")
    end

    it 'clamps a page past the end and a per_page past the cap' do
      id = seed_full!
      sign_in_operator!
      get "/accounts/#{id}?page=999999&per_page=1"
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include('page 3 of 3')

      get "/accounts/#{id}?per_page=1000"
      expect(last_response.body).to include('100 per page')
    end

    it 'renders metadata as escaped text, never as markup' do
      id = bare_account!
      authdb[:account_authentication_audit_logs].insert(account_id: id, at: Time.now, message: 'login',
                                                        metadata: '{"ua":"<script>alert(1)</script>"}')
      sign_in_operator!
      get "/accounts/#{id}"
      expect(last_response.body).to include('&lt;script&gt;')
      expect(last_response.body).not_to include('<script>alert(1)</script>')
    end
  end

  describe 'the lookup' do
    it 'renders the form when no query is given' do
      sign_in_operator!
      get '/account'
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include('Email or external id')
      expect(last_response.body).to include('Exact match only')
    end

    it 'redirects an email to that account page' do
      id = seed_full!
      sign_in_operator!
      get '/account?q=subject@example.com'
      expect(last_response.status).to eq(302)
      expect(last_response.location).to end_with("/accounts/#{id}")
    end

    it 'redirects an external id to that account page' do
      id = seed_full!
      sign_in_operator!
      get '/account?q=extid-subject'
      expect(last_response.location).to end_with("/accounts/#{id}")
    end

    it 'folds case on the email' do
      id = seed_full!
      sign_in_operator!
      get '/account?q=SUBJECT@Example.COM'
      expect(last_response.location).to end_with("/accounts/#{id}")
    end

    it 'answers a query nothing matches with a 404' do
      sign_in_operator!
      get '/account?q=nobody@example.com'
      expect(last_response.status).to eq(404)
      expect(last_response.body).to include('No account matches')
      expect(last_response.body).to include('nobody@example.com')
    end

    # The query is operator input rendered back into HTML.
    it 'html-escapes the query it reflects back' do
      sign_in_operator!
      get '/account?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'
      expect(last_response.status).to eq(404)
      expect(last_response.body).to include('&lt;script&gt;')
      expect(last_response.body).not_to include('<script>alert(1)</script>')
    end

    # Rack turns ?q[]=x into an Array, which is no kind of email.
    it 'treats an array query as no query rather than a 500' do
      sign_in_operator!
      get '/account?q[]=subject@example.com'
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include('Exact match only')
    end

    it 'offers the lookup form in the nav once signed in' do
      sign_in_operator!
      get '/'
      expect(last_response.body).to include('<form method="get" action="/account">')
    end
  end

  describe 'the locked list' do
    it 'links each email to its account page' do
      id = bare_account!
      authdb[:account_lockouts].insert(id: id, key: 'k', deadline: Time.now + 3600)
      sign_in_operator!
      get '/accounts?filter=locked'
      expect(last_response.body).to include("href=\"/accounts/#{id}\">bare@example.com</a>")
    end
  end

  describe 'the gate' do
    it 'sends an anonymous request to the login form' do
      get '/accounts/1'
      expect(last_response).to be_redirect
      expect(last_response.location).to end_with('/login')
    end

    it 'sends an anonymous lookup to the login form' do
      get '/account?q=x'
      expect(last_response).to be_redirect
      expect(last_response.location).to end_with('/login')
    end

    it 'requires the second factor before the account page' do
      allowlist!
      login!
      get '/accounts/1'
      expect(last_response).to be_redirect
      expect(last_response.location).to end_with('/otp-setup')
    end
  end
end
