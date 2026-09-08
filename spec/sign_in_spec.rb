# spec/sign_in_spec.rb
#
# frozen_string_literal: true

require_relative 'spec_helper'
require_relative 'support/sign_in_helpers'

# Phase 1 exit criterion: an operator signs in with their production account,
# completes TOTP, is allowlisted, and gets in. Everything else
# here is the set of ways in that must stay shut.
RSpec.describe RodauthAdmin::App do
  include SignInHelpers

  let(:email) { 'operator@example.com' }
  let(:password) { 'correct horse battery staple' }
  let!(:account_id) { create_account(email: email, password: password, external_id: 'extid-op-1') }

  it 'redirects anonymous requests to the login form' do
    get '/'
    expect(last_response).to be_redirect
    expect(last_response.location).to end_with('/login')
  end

  it 'answers the liveness probe without authentication' do
    get '/healthz'
    expect(last_response.status).to eq(200)
    body = JSON.parse(last_response.body)
    expect(body['status']).to eq('ok')
    expect(body['checks']).to eq('app' => 'ok', 'readonly' => 'ok', 'verbs' => 'ok')
  end

  it 'turns away a valid production account that is not allowlisted, and records it' do
    login!
    expect(last_response).to be_redirect
    expect(last_response.location).to end_with('/login')
    get '/login'
    expect(last_response.body).to include('not an operator')

    denied = actions('login_denied').last
    expect(denied[:actor]).to eq(email)
    expect(denied[:actor_account_id]).to eq(account_id)
    expect(denied[:reason]).to eq('session')

    get '/'
    expect(last_response).to be_redirect
    expect(last_response.location).to end_with('/login'), 'session must be torn down'
  end

  it 'rejects a wrong password without touching the admin audit trail' do
    allowlist!
    before = actions.size
    login!(email, 'nope')
    expect(last_response.status).to eq(401)
    expect(actions.size).to eq(before)
  end

  # Lockout is not enabled on the admin instance (CHARTER §4, revision 5): the
  # counters belong to the tenant app, and a wrong password here must not
  # move the operator's production account towards a lockout.
  it 'does not count a wrong password against the shared identity' do
    allowlist!
    5.times { login!(email, 'wrong') }
    expect(authdb[:account_login_failures].where(id: account_id).count).to eq(0)
    expect(authdb[:account_lockouts].where(id: account_id).count).to eq(0)

    messages = authdb[:account_authentication_audit_logs].where(account_id: account_id).select_map(:message)
    expect(messages.count('rodauth-admin: login_failure')).to eq(5), 'the failures still reach the auth log'
  end

  it 'refuses unverified accounts even when allowlisted' do
    unverified = create_account(email: 'new@example.com', password: password, status_id: 1)
    RodauthAdmin::Allowlist.add!(account_id: unverified, email: 'new@example.com', actor: 'spec', reason: 'fixture')
    before = actions.size
    login!('new@example.com')
    expect(last_response.status).to eq(403)
    expect(actions.size).to eq(before)
  end

  it 'requires TOTP setup before an allowlisted operator sees anything' do
    allowlist!
    login!
    expect(last_response).to be_redirect
    expect(actions('login').last[:actor]).to eq(email)

    get '/'
    expect(last_response).to be_redirect
    expect(last_response.location).to end_with('/otp-setup')

    complete_otp_setup!
    get '/'
    expect(last_response.status).to eq(200)
    expect(last_response.body).to include('Auth stats')
    expect(last_response.body).to include(email)
    expect(last_response.body).to include('extid-op-1')
  end

  it 'writes the OTP key to the production-shaped table, HMAC-protected, and tags the auth log' do
    allowlist!
    login!
    secret = complete_otp_setup!

    stored = authdb[:account_otp_keys].where(id: account_id).get(:key)
    expect(stored).not_to be_nil
    expect(stored).not_to eq(secret), 'otp_keys_use_hmac? must be on, matching the tenant app'

    enrolled = actions('otp_setup').last
    expect(enrolled[:actor]).to eq(email), 'enrolling TOTP on a production account is an admin action'
    expect(enrolled[:actor_account_id]).to eq(account_id)

    messages = authdb[:account_authentication_audit_logs].where(account_id: account_id).select_map(:message)
    expect(messages).to include('rodauth-admin: login')
    expect(messages).to all(start_with('rodauth-admin: '))
  end

  it 'asks for the code on the next sign-in and records both factors' do
    allowlist!
    login!
    secret = complete_otp_setup!
    form_post '/logout'
    expect(actions('logout').last[:actor]).to eq(email)

    # Rodauth refuses a code from a time step already used (setup consumed
    # the current one) and checks that against the database clock, so
    # Timecop cannot help: backdate the stored last_use instead.
    authdb[:account_otp_keys].where(id: account_id).update(last_use: Time.now - 120)

    login!
    expect(last_response).to be_redirect
    # app.rb calls require_authentication and require_two_factor_setup, not
    # require_two_factor_authenticated; it does not need to. rodauth 2.47.0's
    # two_factor_base overrides require_authentication to call
    # require_two_factor_authenticated whenever the session is
    # two_factor_partially_authenticated? (features/two_factor_base.rb:132),
    # so an account with TOTP enrolled cannot reach a read screen on a
    # password alone. This is the example that holds that true.
    get '/'
    expect(last_response).to be_redirect
    expect(last_response.location).to end_with('/otp-auth'), 'password alone must not complete the sign-in'
    get "/accounts/#{account_id}"
    expect(last_response.location).to end_with('/otp-auth'), 'nor any other read screen'

    form_post '/otp-auth', otp: ROTP::TOTP.new(secret).now
    expect(last_response).to be_redirect
    expect(actions('two_factor_auth').last[:actor_account_id]).to eq(account_id)

    get '/'
    expect(last_response.status).to eq(200)
  end

  it 'ends the session on the next request after the allowlist row is removed' do
    allowlist!
    login!
    complete_otp_setup!
    get '/'
    expect(last_response.status).to eq(200)

    RodauthAdmin::Allowlist.remove!(account_id: account_id, actor: 'spec', reason: 'offboarding')
    get '/'
    expect(last_response).to be_redirect
    expect(last_response.location).to end_with('/login')
    expect(actions('operator_remove').last[:target]).to eq(email)
  end

  it 'does not route otp-disable: MFA is removed in the tenant app, never here' do
    allowlist!
    login!
    complete_otp_setup!
    get '/'
    expect(last_response.status).to eq(200)

    # otp-disable, and two_factor_base's multifactor-disable (removes every
    # second factor) and multifactor-manage (links to it).
    paths = %w[/otp-disable /multifactor-disable /multifactor-manage]
    paths.each do |path|
      get path
      expect(last_response.status).to eq(404), "GET #{path} must not be routed"
    end
    # A tokenless POST ends at the CSRF handler (session cleared), so the
    # last POST's status is all that can be asserted; the key is what matters.
    paths.each { |path| post path, password: password } # rubocop:disable Style/CombinableLoops
    expect(last_response.status).not_to eq(200)
    expect(authdb[:account_otp_keys].where(id: account_id).count).to eq(1)
  end

  it 'shuts Rodauth routes too once the allowlist row is removed' do
    allowlist!
    login!
    RodauthAdmin::Allowlist.remove!(account_id: account_id, actor: 'spec', reason: 'offboarding')

    get '/otp-setup'
    expect(last_response).to be_redirect
    expect(last_response.location).to end_with('/login'), 'de-provisioned operator must not reach otp-setup'
    expect(authdb[:account_otp_keys].where(id: account_id).count).to eq(0)

    get '/login'
    expect(last_response.body).to include('no longer an operator')
  end

  it 'ends the session when the tenant account is closed' do
    allowlist!
    login!
    complete_otp_setup!
    get '/'
    expect(last_response.status).to eq(200)

    authdb[:accounts].where(id: account_id).update(status_id: 3)
    get '/'
    expect(last_response).to be_redirect
    expect(last_response.location).to end_with('/login'), 'a closed tenant account is not an operator'
    expect(RodauthAdmin::Allowlist.allowed?(account_id)).to be(true), 'the allowlist row is not touched'
  end

  it 'shuts Rodauth routes too once the tenant account is closed, and records the revocation' do
    allowlist!
    login!
    authdb[:accounts].where(id: account_id).update(status_id: 3)

    get '/otp-setup'
    expect(last_response).to be_redirect
    expect(last_response.location).to end_with('/login'), 'a closed account must not reach otp-setup'
    expect(authdb[:account_otp_keys].where(id: account_id).count).to eq(0)

    revoked = actions('session_revoked').last
    expect(revoked[:actor_account_id]).to eq(account_id)
    expect(revoked[:reason]).to eq('session')
  end

  it 'ends the session, without a 500, when the tenant account is deleted' do
    allowlist!
    login!
    complete_otp_setup!

    authdb[:account_authentication_audit_logs].where(account_id: account_id).delete
    %i[account_otp_keys account_login_failures account_lockouts account_password_hashes accounts].each do |t|
      authdb[t].where(id: account_id).delete
    end
    get '/'
    expect(last_response).to be_redirect
    expect(last_response.location).to end_with('/login')
  end

  it 'sends a stale form back to the login page instead of a 500' do
    allowlist!
    before = actions('login').size
    post '/login', login: email, password: password, _csrf: 'stale-token-from-an-expired-session'
    expect(last_response).to be_redirect
    expect(last_response.location).to end_with('/login')
    expect(actions('login').size).to eq(before), 'the login must not go through'

    get '/login'
    expect(last_response.body).to include('session expired')
    get '/'
    expect(last_response).to be_redirect, 'no session was established'
  end

  it 'records a login whose User-Agent is longer than 255 bytes' do
    allowlist!
    header 'User-Agent', "Mozilla/5.0 #{'x' * 600}"
    login!
    expect(last_response).to be_redirect
    row = actions('login').last
    expect(row[:actor]).to eq(email)
    expect(row[:user_agent].bytesize).to eq(512)
  end

  # The other half of the same decision: a tenant-side lockout (anyone
  # hammering the public login) must not shut the operator out of the
  # console that clears it.
  it 'admits an operator whose tenant account is locked out' do
    allowlist!
    authdb[:account_login_failures].insert(id: account_id, number: 5)
    authdb[:account_lockouts].insert(id: account_id, key: 'k', deadline: Time.now + 3600)
    login!
    expect(last_response).to be_redirect
    expect(last_response.location).not_to end_with('/login')
    get '/otp-setup'
    expect(last_response.status).to eq(200), 'the session was established'
  end
end
