# try/env_try.rb
#
# frozen_string_literal: true

# The bind address is the single source of truth for the session cookie's
# Secure flag: loopback (the ADR-0001 SSH-tunnel deployment) relaxes it so the
# cookie survives the plain-http tunnel; every other bind keeps it. See
# RodauthAdmin::Env#secure_cookie?.

ENV['RACK_ENV'] = 'test'
require_relative '../lib/rodauth_admin/env'

E = RodauthAdmin::Env

# Set ENV for the block, restore exactly afterwards (nil means "was unset").
def with_env(vars)
  saved = vars.keys.to_h { |k| [k, ENV.fetch(k, nil)] }
  vars.each { |k, v| v.nil? ? ENV.delete(k) : (ENV[k] = v) }
  yield
ensure
  saved.each { |k, v| v.nil? ? ENV.delete(k) : (ENV[k] = v) }
end

## Unset bind defaults to loopback
with_env('RODAUTH_ADMIN_BIND' => nil) { [E.bind_address, E.loopback_bind?] }
#=> ["127.0.0.1", true]

## IPv6 loopback and the "localhost" literal are loopback
[with_env('RODAUTH_ADMIN_BIND' => '::1') { E.loopback_bind? },
 with_env('RODAUTH_ADMIN_BIND' => 'localhost') { E.loopback_bind? }]
#=> [true, true]

## 0.0.0.0 (all interfaces) and a routable address are not loopback
[with_env('RODAUTH_ADMIN_BIND' => '0.0.0.0') { E.loopback_bind? },
 with_env('RODAUTH_ADMIN_BIND' => '10.0.0.5') { E.loopback_bind? }]
#=> [false, false]

## An unclassifiable hostname fails safe: not loopback, so Secure stays on
with_env('RODAUTH_ADMIN_BIND' => 'admin.internal') { E.loopback_bind? }
#=> false

## Production keeps Secure on a public bind, relaxes it on loopback
[with_env('RACK_ENV' => 'production', 'RODAUTH_ADMIN_BIND' => '0.0.0.0') { E.secure_cookie? },
 with_env('RACK_ENV' => 'production', 'RODAUTH_ADMIN_BIND' => '127.0.0.1') { E.secure_cookie? }]
#=> [true, false]

## Outside production the cookie is never Secure, whatever the bind
with_env('RACK_ENV' => 'development', 'RODAUTH_ADMIN_BIND' => '0.0.0.0') { E.secure_cookie? }
#=> false
