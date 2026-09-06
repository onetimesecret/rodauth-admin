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
require_relative 'account_detail'
require_relative 'verb_routes'

module RodauthAdmin
  # rubocop:disable Metrics/ClassLength -- one routing tree plus the view
  # helpers it needs; splitting the helpers out would put the templates'
  # vocabulary in a different file from the routes that render them.
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

    # The mutation verbs' routes and view helpers (CHARTER §6 phase 4).
    # Included after the plugins so their instance methods are already in
    # place; nothing here overrides a plugin method.
    include RodauthAdmin::VerbRoutes

    plugin :not_found do
      view(content: '<h1>Not found</h1>')
    end

    plugin :error_handler do |e|
      RodauthAdmin.logger.error 'Unhandled error', exception: e
      response.status = 500
      view(content: '<h1>Something went wrong</h1><p>The error has been logged.</p>')
    end

    route do |r| # rubocop:disable Metrics/BlockLength -- the routing tree is one expression by design
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

      # The per-account page. Two "no page" outcomes, kept apart on
      # purpose: an id nobody has is a 404 (the operator mistyped, or the
      # account was deleted), while an authdb that cannot answer is a 200
      # carrying the degraded panel — the same split every other screen
      # makes, because "we looked and there is nothing" and "we could not
      # look" are different answers to an operator.
      r.get 'accounts', Integer do |id|
        @detail = AccountDetail.find(id: id)
        if !@detail.available
          view 'account'
        elsif !@detail.found
          missing(id.to_s)
        else
          @timeline = AccountDetail.timeline(id: id,
                                             page: r.params['page'] || 1,
                                             per_page: r.params['per_page'] || AccountDetail::PER_PAGE_DEFAULT)
          view 'account'
        end
      end

      # Everything that changes something (CHARTER §6 phase 4). Reached
      # only after the read-only GET above has declined the path: it
      # matches /accounts/:id exactly, so a bare account page never gets
      # here and a verb slug never reaches it.
      r.on 'accounts', Integer do |id|
        verb_routes(r, id)
      end

      # The lookup, and the inbound deep link from the colonel console
      # (/account?q=<external_id>). A single hit redirects rather than
      # rendering, so the operator lands on the canonical /accounts/<id>
      # URL and can bookmark or share it. Three other outcomes are kept
      # apart: several matches disambiguate on their own page, a miss is now
      # genuinely a miss (the authdb answered and has nothing), and an
      # unreachable authdb is the degraded panel, never a 404.
      r.get 'account' do
        q = r.params['q']
        # ?q[]=x arrives as an Array. Nothing but a String can be an email
        # or an external_id, so it is the empty query, not a 500.
        q = nil unless q.is_a?(String)
        next view 'lookup' if q.nil? || q.strip.empty?

        resolve_lookup(r, q)
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

    def account_path(id)
      "/accounts/#{Integer(id)}"
    end

    # The timeline is the only paginated thing on the account page, so its
    # links carry per_page and nothing else.
    def timeline_path(id, page, per_page)
      "#{account_path(id)}?page=#{page}&per_page=#{per_page}"
    end

    # One query, four answers. The order matters: an unreachable authdb is
    # checked before the match list, because an empty list there means
    # "nothing was asked", not "nothing exists".
    def resolve_lookup(req, query)
      @query = query
      @lookup = AccountDetail.lookup(query)
      return view 'lookup_matches' unless @lookup.available
      return missing(nil, query) if @lookup.matches.empty?
      return req.redirect(account_path(@lookup.matches.first.id)) if @lookup.matches.length == 1

      view 'lookup_matches'
    end

    # The 404 both dead ends share: our own page, through the layout, so
    # the operator gets the id or the query they asked for back (escaped by
    # the render plugin) instead of the plugin's bare "Not found".
    def missing(id, query = nil)
      response.status = 404
      @missing_id = id
      @query = query
      view 'account_missing'
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
        readonly: probe { Database.readonly.test_connection },
        verbs: probe { Database.verbs.test_connection }
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
  # rubocop:enable Metrics/ClassLength
end
