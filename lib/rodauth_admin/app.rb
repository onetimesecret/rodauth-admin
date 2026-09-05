# lib/rodauth_admin/app.rb
#
# frozen_string_literal: true

require 'roda'
require 'json'

require_relative 'env'
require_relative 'database'
require_relative 'allowlist'
require_relative 'auth'

module RodauthAdmin
  class App < Roda
    VIEWS_DIR = File.expand_path('../../views', __dir__)

    # Its own cookie, its own TTL: shared identity is not shared session.
    SESSION_MAX_SECONDS = 8 * 3600
    SESSION_MAX_IDLE_SECONDS = 30 * 60

    plugin :render, views: VIEWS_DIR, layout: 'layout', escape: true
    plugin :sessions,
           secret: Env.session_secret,
           key: 'rodauth_admin.session',
           max_seconds: SESSION_MAX_SECONDS,
           max_idle_seconds: SESSION_MAX_IDLE_SECONDS,
           cookie_options: { secure: Env.production?, httponly: true, same_site: :strict }
    plugin :flash
    plugin :route_csrf
    plugin :halt
    plugin :rodauth, auth_class: RodauthAdmin::Auth

    plugin :not_found do
      view(content: '<h1>Not found</h1>')
    end

    plugin :error_handler do |e|
      RodauthAdmin.logger.error 'Unhandled error', exception: e
      response.status = 500
      view(content: '<h1>Something went wrong</h1><p>The error has been logged.</p>')
    end

    route do |r|
      # Public, unauthenticated: is the process up, can it see its stores?
      # No account data, no table names — a liveness probe, not a status page.
      r.get 'healthz' do
        response['content-type'] = 'application/json'
        JSON.generate(health)
      end

      r.rodauth
      check_csrf!

      # Password first, then a second factor: every operator, every session.
      rodauth.require_authentication
      rodauth.require_two_factor_setup

      # Re-checked on every request so removing an allowlist row ends the
      # session on the operator's next click, not at cookie expiry.
      unless Allowlist.allowed?(rodauth.session_value)
        rodauth.clear_session
        flash['error'] = 'This account is no longer an operator of Rodauth Admin.'
        r.redirect '/login'
      end

      r.root do
        @account = rodauth.account_from_session
        view 'index'
      end
    end

    private

    def health
      checks = {
        app: probe { Database.app.test_connection },
        readonly: probe { Database.readonly.test_connection }
      }
      ok = checks.values.all?('ok')
      response.status = ok ? 200 : 503
      { status: ok ? 'ok' : 'degraded', checks: checks }
    end

    def probe
      yield ? 'ok' : 'failed'
    rescue StandardError => e
      RodauthAdmin.logger.warn 'health probe failed', exception: e
      'unreachable'
    end
  end
end
