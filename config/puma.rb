# config/puma.rb
#
# frozen_string_literal: true

require_relative '../lib/rodauth_admin/env'

# The bind address is the single source of truth: it opens the socket here and
# decides the session cookie's Secure flag (RodauthAdmin::Env#secure_cookie?).
# Binding to loopback is the ADR-0001 SSH-tunnel deployment and the only thing
# that relaxes Secure, so the socket and the cookie can never disagree. Set
# RODAUTH_ADMIN_BIND to a public address only behind real TLS.
bind "tcp://#{RodauthAdmin::Env.bind_address}:#{ENV.fetch('PORT', '9292')}"
