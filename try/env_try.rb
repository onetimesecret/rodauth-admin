# try/env_try.rb
#
# frozen_string_literal: true

# RodauthAdmin::Env: every boot-time safety check. The suite always runs
# with RACK_ENV=test, so the production branches are exercised only here,
# each case against an ENV built from nothing and with the memoized
# secrets forgotten.

require_relative '../lib/rodauth_admin'

@keys = %w[
  RACK_ENV ADMIN_DATABASE_URL ADMIN_DATABASE_URL_RO ADMIN_DATABASE_URL_VERBS
  RODAUTH_ADMIN_SESSION_SECRET AUTH_SECRET AUTH_OLD_SECRET RODAUTH_ADMIN_HOST COLONEL_CONSOLE_URL
].freeze
@memos = %i[@session_secret @auth_secret @auth_old_secret].freeze
@saved = ENV.to_h.slice(*@keys)
@saved_memos = @memos.to_h { |iv| [iv, RodauthAdmin::Env.instance_variable_get(iv)] }

@prod = {
  'RACK_ENV' => 'production',
  'ADMIN_DATABASE_URL' => 'postgresql://app@db/authdb',
  'ADMIN_DATABASE_URL_RO' => 'postgresql://ro@db/authdb',
  'ADMIN_DATABASE_URL_VERBS' => 'postgresql://verbs@db/authdb',
  'RODAUTH_ADMIN_SESSION_SECRET' => 's' * 64,
  'AUTH_SECRET' => 'tenant-hmac-secret',
  'RODAUTH_ADMIN_HOST' => 'admin.example.com'
}.freeze

# Runs the block against exactly +vars+, then puts the caller's ENV and
# memos back: the try stage shares one process across files.
@with_env = lambda do |vars, &blk|
  @keys.each { |k| ENV.delete(k) }
  vars.each { |k, v| ENV[k] = v }
  @memos.each { |iv| RodauthAdmin::Env.instance_variable_set(iv, nil) }
  blk.call
ensure
  @keys.each { |k| ENV.delete(k) }
  @saved.each { |k, v| ENV[k] = v }
  @saved_memos.each { |iv, v| RodauthAdmin::Env.instance_variable_set(iv, v) }
end

# :ok, or the ConfigurationError message.
@outcome = lambda do |vars, &blk|
  @with_env.call(vars) do
    blk.call
    :ok
  rescue RodauthAdmin::ConfigurationError => e
    e.message
  end
end

## An unset RACK_ENV is production: fail closed
@with_env.call({}) { RodauthAdmin::Env.production? }
#=> true

## A complete production environment validates
@outcome.call(@prod) { RodauthAdmin::Env.validate! }
#=> :ok

## validate! refuses production without any one of the required values
required = @prod.keys - ['RACK_ENV']
required.reject { |key| @outcome.call(@prod.except(key)) { RodauthAdmin::Env.validate! }.include?(key) }
#=> []

## A blank value counts as missing
@outcome.call(@prod.merge('AUTH_SECRET' => '   ')) { RodauthAdmin::Env.validate! }
#=> 'AUTH_SECRET (the tenant app HMAC secret) is required in production'

## The session secret must be at least 64 bytes, in any environment
[63, 64].map { |n| @outcome.call(@prod.merge('RODAUTH_ADMIN_SESSION_SECRET' => 's' * n)) { RodauthAdmin::Env.session_secret } }
#=> ['RODAUTH_ADMIN_SESSION_SECRET must be >= 64 bytes', :ok]

## ...and the length check applies outside production too
@outcome.call({ 'RACK_ENV' => 'test', 'RODAUTH_ADMIN_SESSION_SECRET' => 'short' }) { RodauthAdmin::Env.session_secret }
#=> 'RODAUTH_ADMIN_SESSION_SECRET must be >= 64 bytes'

## Outside production a missing session secret is generated, 64 random bytes as hex
@with_env.call({ 'RACK_ENV' => 'test' }) { RodauthAdmin::Env.session_secret.size }
#=> 128

## Outside production a missing database URL falls back to the dev SQLite file
@with_env.call({ 'RACK_ENV' => 'development' }) { RodauthAdmin::Env.database_url }
#=> RodauthAdmin::Env::DEV_DATABASE_URL

## The HMAC secrets are removed from ENV once read, and the value is kept
@with_env.call(@prod.merge('AUTH_OLD_SECRET' => 'previous')) do
  [RodauthAdmin::Env.auth_secret, RodauthAdmin::Env.auth_old_secret,
   ENV.key?('AUTH_SECRET'), ENV.key?('AUTH_OLD_SECRET'), RodauthAdmin::Env.auth_secret]
end
#=> ['tenant-hmac-secret', 'previous', false, false, 'tenant-hmac-secret']

## Outside production a missing AUTH_SECRET is generated rather than raised
@with_env.call({ 'RACK_ENV' => 'test' }) { RodauthAdmin::Env.auth_secret.size }
#=> 64

## No AUTH_OLD_SECRET means no rotation
@with_env.call(@prod) { RodauthAdmin::Env.auth_old_secret }
#=> nil

## The colonel console URL loses trailing slashes, and blank means unset
[' https://ops.example.com/// ', '', nil].map do |url|
  @with_env.call(url ? { 'COLONEL_CONSOLE_URL' => url } : {}) { RodauthAdmin::Env.colonel_console_url }
end
#=> ['https://ops.example.com', nil, nil]
