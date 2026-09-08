# spec/support/sign_in_helpers.rb
#
# frozen_string_literal: true

# Signing in — password, TOTP, allowlist — is the precondition of every
# screen this app has, so the steps live here rather than in the spec that
# happens to test the sign-in itself.
module SignInHelpers
  def allowlist!(id = account_id, addr = email)
    RodauthAdmin::Allowlist.add!(account_id: id, email: addr, actor: 'spec', reason: 'test fixture')
  end

  # Roda's route_csrf plugin issues per-path tokens; a real browser gets one
  # from the rendered form, so the specs do the same.
  def hidden_field(body, name)
    body[/name="#{name}"[^>]*value="([^"]+)"/, 1] || body[/value="([^"]+)"[^>]*name="#{name}"/, 1]
  end

  def form_post(path, params = {})
    get path
    token = hidden_field(last_response.body, '_csrf')
    expect(token).not_to be_nil, "no CSRF token on GET #{path} (status #{last_response.status})"
    post path, params.merge(_csrf: token)
  end

  def login!(login = email, passwd = password)
    form_post '/login', login: login, password: passwd
  end

  # Rodauth's otp-setup form carries the provisioning secret (what the
  # authenticator app gets from the QR) and, with otp_keys_use_hmac?, the
  # raw secret that is what actually lands in account_otp_keys. Codes are
  # computed from the provisioning secret. Returns it for later sign-ins.
  def complete_otp_setup!
    get '/otp-setup'
    expect(last_response.status).to eq(200)
    body = last_response.body
    secret = hidden_field(body, 'otp_secret')
    raw = hidden_field(body, 'otp_raw_secret')
    token = hidden_field(body, '_csrf')
    expect(secret).not_to be_nil
    params = { otp_secret: secret, otp: ROTP::TOTP.new(secret).now, password: password, _csrf: token }
    params[:otp_raw_secret] = raw if raw
    post '/otp-setup', params
    expect(last_response).to be_redirect, "otp-setup failed: #{last_response.status}"
    secret
  end

  # The whole sign-in in one line, for specs that are about what comes after it.
  def sign_in_operator!
    allowlist!
    login!
    complete_otp_setup!
  end
end
