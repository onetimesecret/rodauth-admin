# lib/rodauth_admin/app.rb
#
# frozen_string_literal: true

require 'roda'
require 'json'
require 'erb'

require_relative 'env'
require_relative 'database'
require_relative 'allowlist'
require_relative 'audit'
require_relative 'auth'
require_relative 'stats'
require_relative 'account_list'

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

      # Read-only screens: no Audit.record here. The audit trail is for
      # mutations (CHARTER §4); the sign-in that opened this session is
      # already recorded.
      r.root do
        @account = rodauth.account_from_session or revoke_session!(r)
        @stats = Stats.cached
        view 'index'
      end

      r.get 'accounts' do
        @list = AccountList.call(filter: r.params['filter'],
                                 page: r.params['page'] || 1,
                                 per_page: r.params['per_page'] || AccountList::PER_PAGE_DEFAULT)
        view 'accounts'
      rescue AccountList::InvalidFilter => e
        # A missing or mistyped filter is a 400, not a redirect to a default
        # list: a typo in an operator's URL should be loud, and silently
        # showing a different list than the one asked for is worse.
        response.status = 400
        @reason = e.message
        view 'accounts_filter'
      end
    end

    private

    # A deep link to the tenant colonel console (CHARTER §4 seam 1), which
    # exists only when both halves are configured: an unset console URL or an
    # orphan row renders as plain text instead.
    def colonel_customer_url(external_id)
      base = Env.colonel_console_url
      return nil if base.nil? || external_id.nil? || external_id.to_s.empty?

      # external_id is authdb data, not a constant: url_encode keeps a value
      # containing '/', '?' or '#' inside the path segment it belongs to
      # instead of letting it rewrite the link's target.
      "#{base}/colonel/customers/#{ERB::Util.url_encode(external_id)}"
    end

    # "12 (3%)" — the denominator is total_accounts, which can be zero on an
    # empty authdb.
    def percent_of(count, total)
      return '—' if count.nil?
      return count.to_s if total.nil? || total.zero?

      "#{count} (#{((count.to_f / total) * 100).round(1)}%)"
    end

    # Every timestamp reaching a view is UTC by construction: database.rb
    # sets Sequel.database_timezone/application_timezone to :utc, so a
    # fetched `timestamp without time zone` is parsed as UTC rather than
    # relabelled from the app host's local wall clock. getutc is kept as the
    # explicit assertion of that — a Time from anywhere else (Time.now for
    # computed_at) is converted rather than mislabelled "UTC".
    def utc_time(time)
      return '—' if time.nil?
      return time.getutc.strftime('%Y-%m-%d %H:%M:%S UTC') if time.respond_to?(:getutc)

      # SQLite can hand back a bare string for a column it has no type for.
      "#{time} UTC"
    end

    # Preserves filter and per_page across pagination; page is the only
    # thing a prev/next link changes.
    def accounts_path(filter, page, per_page)
      "/accounts?filter=#{filter}&page=#{page}&per_page=#{per_page}"
    end

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
