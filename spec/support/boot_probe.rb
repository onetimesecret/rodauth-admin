# spec/support/boot_probe.rb
#
# frozen_string_literal: true

# Boots the app in a fresh process against whatever secrets ENV holds, signs
# in once, and prints what happened as one JSON line. spec/secrets_spec.rb
# runs it: ARGON2_SECRET and AUTH_SECRET / AUTH_OLD_SECRET are read once, at
# class-definition time, so the only honest way to test that they reach
# Rodauth is to boot with them set.
#
# Input (ENV): PROBE_LOGIN, PROBE_PASSWORD, and optionally PROBE_OTP, a code
# to submit at /otp-auth once the password is accepted. The database URLs
# and RACK_ENV come from the parent, which has already built the schema.

require 'json'
require 'rack/test'

require_relative '../../lib/rodauth_admin'

SemanticLogger.add_appender(io: $stderr, level: :warn)
RodauthAdmin.boot!

# The smallest Rack::Test driver that gets through route_csrf.
class BootProbe
  include Rack::Test::Methods

  def app = RodauthAdmin::App

  # The nav's lookup form carries its own token for /account, and comes
  # first; the one wanted is in the page's own form (as in SignInHelpers).
  def form_post(path, params)
    get path
    token = last_response.body.sub(%r{<nav>.*?</nav>}m, '')[/name="_csrf"[^>]*value="([^"]+)"/, 1]
    post path, params.merge(_csrf: token)
    { 'status' => last_response.status, 'location' => last_response.location }
  end

  def run
    result = { 'login' => form_post('/login', login: ENV.fetch('PROBE_LOGIN'),
                                              password: ENV.fetch('PROBE_PASSWORD')) }
    result['otp'] = form_post('/otp-auth', otp: ENV.fetch('PROBE_OTP')) if ENV['PROBE_OTP']
    get '/'
    result['home'] = last_response.status
    result
  end
end

# The parent reads this line; it is the probe's whole output contract.
puts "PROBE #{JSON.generate(BootProbe.new.run)}" # rubocop:disable RSpec/Output
