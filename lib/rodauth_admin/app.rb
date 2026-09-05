# lib/rodauth_admin/app.rb
#
# frozen_string_literal: true

require 'roda'
require 'json'

require_relative 'env'
require_relative 'database'
require_relative 'allowlist'
require_relative 'audit'
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
    # A CSRF failure here is almost always a form submitted after the
    # session expired (30 min idle / 8 h max), so the token no longer
    # verifies. Send the operator back to the login form with an
    # explanation rather than the generic 500 the default (:raise) produces.
    # Clearing the session first also makes a genuinely forged POST inert.
    plugin :route_csrf do |r|
      clear_session
      flash['error'] = 'That form was submitted after your session expired. Please sign in again.'
      r.redirect '/login'
    end
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

      # Re-checked on every request, BEFORE Rodauth's own routes, so that
      # removing an allowlist row or closing the tenant account ends the
      # session on the operator's next click (including a click on
      # /otp-setup or /otp-auth), not at cookie expiry.
      revoke_session!(r) if rodauth.logged_in? && !operator_session?

      r.rodauth
      check_csrf!

      # Password first, then a second factor: every operator, every session.
      rodauth.require_authentication
      rodauth.require_two_factor_setup

      r.root do
        @account = rodauth.account_from_session or revoke_session!(r)
        view 'index'
      end
    end

    private

    # The signed-in identity is still a Verified authdb account AND still
    # on the allowlist. Both are re-read from the database; neither is
    # cached in the session.
    def operator_session?
      rodauth.session_account_open? && Allowlist.allowed?(rodauth.session_value)
    end

    # Tear down a session whose identity is no longer an operator. This is
    # the only way such a session ends (the logout route is behind the same
    # gate), so it is recorded; the email may be gone, hence the id fallback.
    def revoke_session!(req)
      id = rodauth.session_value
      Audit.record(action: 'session_revoked', actor: "account:#{id}", actor_account_id: id,
                   ip: req.ip, user_agent: req.user_agent)
      rodauth.clear_session
      flash['error'] = 'This account is no longer an operator of Rodauth Admin.'
      req.redirect '/login'
    end

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
