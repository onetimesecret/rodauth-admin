# spec/secrets_spec.rb
#
# frozen_string_literal: true

require 'json'
require 'open3'
require 'rbconfig'

require_relative 'spec_helper'
require_relative 'support/sign_in_helpers'

# The production secrets, proven to reach Rodauth. spec_helper deletes
# ARGON2_SECRET and sets one AUTH_SECRET for the whole run, so the peppered
# password path and HMAC rotation are otherwise never exercised: if either
# were wired wrong, every operator would be locked out and the first sign
# would be the deploy. Each case boots the app in a child process
# (support/boot_probe.rb) with the secrets it is about, against this run's
# database.
RSpec.describe RodauthAdmin::Auth do
  include SignInHelpers

  let(:email) { 'operator@example.com' }
  let(:password) { 'correct horse battery staple' }

  # Everything the child needs from this process, and no secret it is not
  # given explicitly: the probe must boot from what the case says.
  def probe(**vars)
    env = { 'RACK_ENV' => 'test', 'ARGON2_SECRET' => nil, 'AUTH_SECRET' => nil, 'AUTH_OLD_SECRET' => nil }
    vars.each { |k, v| env[k.to_s.upcase] = v }
    out, status = Open3.capture2e(env, RbConfig.ruby, File.expand_path('support/boot_probe.rb', __dir__))
    line = out.lines.grep(/\APROBE /).last
    expect(line).not_to be_nil, "boot probe failed (#{status}):\n#{out}"
    JSON.parse(line.delete_prefix('PROBE '))
  end

  def signed_in_past_password?(result)
    result['login']['status'] == 302 && !result['login']['location'].end_with?('/login')
  end

  describe 'ARGON2_SECRET' do
    let(:pepper) { 'argon2-pepper-for-the-spec' }

    # A Verified account whose hash was made with the pepper, as the tenant
    # app writes it in production.
    before do
      id = authdb[:accounts].insert(email: email, status_id: 2, external_id: 'extid-pepper')
      hash = Argon2::Password.new(**SpecSupport::TEST_ARGON2_COST, secret: pepper).create(password)
      authdb[:account_password_hashes].insert(id: id, password_hash: hash)
      allowlist!(id)
    end

    it 'verifies a peppered production hash when the pepper is set' do
      result = probe(argon2_secret: pepper, probe_login: email, probe_password: password)
      expect(signed_in_past_password?(result)).to be(true), result.inspect
    end

    it 'refuses the same hash without the pepper' do
      result = probe(probe_login: email, probe_password: password)
      expect(result['login']['status']).to eq(401), result.inspect
    end
  end

  describe 'AUTH_OLD_SECRET' do
    let(:account_id) { create_account(email: email, password: password, external_id: 'extid-rotate') }

    # Enrol TOTP in this process, under this run's AUTH_SECRET, then sign
    # out and free the current time step for the child's code.
    def enrol!
      allowlist!
      login!
      secret = complete_otp_setup!
      form_post '/logout'
      authdb[:account_otp_keys].where(id: account_id).update(last_use: Time.now - 120)
      secret
    end

    it 'still verifies a TOTP key enrolled under the previous secret after a rotation' do
      code = ROTP::TOTP.new(enrol!).now
      enrolled_under = RodauthAdmin::Env.auth_secret
      rotated_to = "rotated-hmac-secret-#{'y' * 44}"

      # The new secret alone does not match the stored key: that is what
      # makes the rotation case below prove something.
      alone = probe(auth_secret: rotated_to, probe_login: email, probe_password: password, probe_otp: code)
      expect(alone['otp']['status']).to eq(401), alone.inspect
      expect(alone['home']).not_to eq(200)

      rotated = probe(auth_secret: rotated_to, auth_old_secret: enrolled_under,
                      probe_login: email, probe_password: password, probe_otp: code)
      expect(rotated['otp']['status']).to eq(302), rotated.inspect
      expect(rotated['home']).to eq(200), rotated.inspect
    end
  end
end
