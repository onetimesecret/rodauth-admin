# spec/aggregate_visibility_spec.rb
#
# frozen_string_literal: true

require_relative 'spec_helper'
require_relative 'support/front_door_helpers'

# Phase 2 (CHARTER §6): the stats board and the two state-filtered lists, as
# an operator actually meets them — signed in, second factor complete,
# allowlisted. The query layer has its own tryouts; what is asserted here is
# the screens: the labels the inherited spec's risks section insists on, the
# links, the pagination, the 400 on a bad filter, and that a blinking authdb
# degrades rather than 500s.
RSpec.describe RodauthAdmin::App do
  include FrontDoorHelpers

  def app = RodauthAdmin::App

  let(:email) { 'operator@example.com' }
  let(:password) { 'correct horse battery staple' }
  let!(:account_id) { create_account(email: email, password: password, external_id: 'extid-op-1') }

  # spec_helper's wipe! derives its child-table list from the database, so
  # the tables seeded below are already truncated before each example; the
  # explicit sweep keeps this spec's fixtures self-contained anyway.
  def seeded_tables
    %i[account_lockouts account_login_failures account_otp_keys
       account_webauthn_keys account_active_session_keys account_recovery_codes]
  end

  before do
    seeded_tables.each { |t| authdb[t].delete }
    RodauthAdmin::Stats.reset_cache!
  end

  after { RodauthAdmin::Stats.reset_cache! }

  # Stats are memoized for 60s process-wide, so every assertion about them
  # has to ask for a freshly computed board.
  def visit_stats
    RodauthAdmin::Stats.reset_cache!
    get '/'
  end

  def lock!(id, deadline)
    authdb[:account_lockouts].insert(id: id, key: "lockkey-#{id}", deadline: deadline)
  end

  # A locked account, an *expired* lockout that must never show up, an
  # orphan, and one row in each MFA / session / recovery table.
  def seed_authdb!
    locked = create_account(email: 'locked@example.com', password: password, external_id: 'extid-locked')
    expired = create_account(email: 'expired@example.com', password: password, external_id: 'extid-expired')
    orphan = create_account(email: 'orphan@example.com', password: password, external_id: nil)

    lock!(locked, Time.now + 3600)
    lock!(expired, Time.now - 3600)
    authdb[:account_login_failures].insert(id: locked, number: 4)

    authdb[:account_otp_keys].insert(id: orphan, key: 'otpkey', num_failures: 0, last_use: Time.now)
    authdb[:account_webauthn_keys].insert(account_id: orphan, webauthn_id: 'wid', public_key: 'pk',
                                          sign_count: 0, last_use: Time.now)
    authdb[:account_active_session_keys].insert(account_id: orphan, session_id: 'sid',
                                                created_at: Time.now, last_use: Time.now)
    authdb[:account_recovery_codes].insert(id: orphan, code: 'rc-1')

    { locked: locked, expired: expired, orphan: orphan }
  end

  describe 'the stats board' do
    before { seed_authdb! }

    it 'renders every stat with the labels the risks section requires' do
      sign_in_operator!
      visit_stats
      expect(last_response.status).to eq(200)
      body = last_response.body

      expect(body).to include('Total accounts', 'Active lockouts', 'Orphaned accounts',
                              'Active session keys', 'Unused recovery codes (rows)',
                              'MFA adoption', 'Status breakdown', 'Customer-count drift')
      expect(body).to include('not users online'), 'the session-key caveat must be on the page'
      expect(body).to include('used_at'), 'the recovery-code drift caveat must be on the page'
      expect(body).to match(/as of \d\d:\d\d:\d\d UTC \(cached &le;60s\)/)
    end

    it 'counts what was seeded, and excludes the expired lockout' do
      sign_in_operator!
      visit_stats
      stats = RodauthAdmin::Stats.cached

      expect(stats.total_accounts).to eq(4)
      expect(stats.active_lockouts).to eq(1), 'the expired lockout row must not count'
      expect(stats.orphaned_accounts).to eq(1)
      expect(stats.active_session_keys).to eq(1)
      expect(stats.recovery_code_rows).to eq(1)
      expect(stats.mfa_webauthn_accounts).to eq(1)
      # The seeded key plus the operator's own enrollment.
      expect(stats.mfa_otp_accounts).to eq(2)
      expect(last_response.body).to include('Verified')
    end

    it 'links the lockout and orphan counts to their lists' do
      sign_in_operator!
      visit_stats
      expect(last_response.body).to include('href="/accounts?filter=locked"',
                                            'href="/accounts?filter=orphaned"')
    end

    it 'says the customer-count drift is not configured, and points at the charter' do
      sign_in_operator!
      visit_stats
      expect(last_response.body).to include('not configured')
      expect(last_response.body).to include('CHARTER &sect;7')
    end

    it 'renders an explanatory panel, still 200, when the authdb is unreachable' do
      sign_in_operator!
      allow(RodauthAdmin::Stats).to receive(:cached).and_return(unavailable_stats)
      get '/'
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include('Stats are unavailable')
      expect(last_response.body).to include('The authdb is unreachable or the read-only credential is')
      expect(last_response.body).to include('Sequel::DatabaseConnectionError: could not connect')
    end
  end

  describe 'the locked list' do
    before { seed_authdb! }

    it 'shows the locked account with its deadline and failure count, and not the expired one' do
      sign_in_operator!
      get '/accounts?filter=locked'
      expect(last_response.status).to eq(200)
      body = last_response.body

      expect(body).to include('Locked accounts')
      expect(body).to include('locked@example.com')
      expect(body).not_to include('expired@example.com')
      expect(body).to include('Login failures')
      expect(body).to include('<td>4</td>')
      expect(body).to match(/\d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC/), 'the lockout deadline must be rendered'
    end

    it 'renders the external id as plain text when no colonel console is configured' do
      allow(RodauthAdmin::Env).to receive(:colonel_console_url).and_return(nil)
      sign_in_operator!
      get '/accounts?filter=locked'
      expect(last_response.body).to include('extid-locked')
      expect(last_response.body).not_to include('/colonel/customers/')
    end

    it 'deep-links the external id when the colonel console is configured' do
      allow(RodauthAdmin::Env).to receive(:colonel_console_url).and_return('https://console.example.com')
      sign_in_operator!
      get '/accounts?filter=locked'
      expect(last_response.body).to include('href="https://console.example.com/colonel/customers/extid-locked"')
    end

    # external_id is authdb data. A value carrying '/' or '?' would otherwise
    # rewrite the link's path or start a query string on the colonel console.
    it 'url-escapes an external id that could rewrite the link target' do
      allow(RodauthAdmin::Env).to receive(:colonel_console_url).and_return('https://console.example.com')
      weird = create_account(email: 'weird@example.com', password: password,
                             external_id: 'a/b?c')
      lock!(weird, Time.now + 3600)
      sign_in_operator!
      get '/accounts?filter=locked'
      expect(last_response.body).to include('href="https://console.example.com/colonel/customers/a%2Fb%3Fc"')
      expect(last_response.body).not_to include('customers/a/b?c')
    end
  end

  describe 'the orphaned list' do
    before { seed_authdb! }

    it 'shows accounts with no external id, rendered inline as a dash' do
      allow(RodauthAdmin::Env).to receive(:colonel_console_url).and_return('https://console.example.com')
      sign_in_operator!
      get '/accounts?filter=orphaned'
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include('Orphaned accounts')
      expect(last_response.body).to include('orphan@example.com')
      expect(last_response.body).not_to include('locked@example.com')
      expect(last_response.body).not_to include('/colonel/customers/'), 'an orphan has nothing to link to'
    end

    it 'renders an empty state rather than an empty table' do
      # Give the orphans an external_id rather than deleting them: the row
      # has children, and adoption is what actually empties this list.
      authdb[:accounts].where(external_id: nil).select_map(:id).each do |id|
        authdb[:accounts].where(id: id).update(external_id: "extid-adopted-#{id}")
      end
      sign_in_operator!
      get '/accounts?filter=orphaned'
      expect(last_response.body).to include('Every account is linked to a customer record.')
    end

    it 'paginates, preserving the filter and per_page in the links' do
      3.times { |i| create_account(email: "extra#{i}@example.com", password: password, external_id: nil) }
      sign_in_operator!
      get '/accounts?filter=orphaned&per_page=1'
      expect(last_response.body).to include('page 1 of 4', 'total 4')
      expect(last_response.body).to include('href="/accounts?filter=orphaned&amp;page=2&amp;per_page=1"')
      expect(last_response.body).not_to include('previous')

      get '/accounts?filter=orphaned&page=2&per_page=1'
      expect(last_response.body).to include('page 2 of 4')
      expect(last_response.body).to include('href="/accounts?filter=orphaned&amp;page=1&amp;per_page=1"')
    end

    # A stale bookmark or a list that shrank: show the last page, not an
    # empty table with a "previous" link into nothing.
    it 'clamps a page past the end to the last page' do
      3.times { |i| create_account(email: "far#{i}@example.com", password: password, external_id: nil) }
      sign_in_operator!
      get '/accounts?filter=orphaned&page=999999&per_page=1'
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include('page 4 of 4')
      expect(last_response.body).not_to include('next &rarr;')
    end

    it 'clamps per_page to the cap, visibly' do
      sign_in_operator!
      get '/accounts?filter=orphaned&per_page=1000'
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include('100 per page')
    end

    it 'renders an explanatory panel, still 200, when the authdb is unreachable' do
      sign_in_operator!
      allow(RodauthAdmin::AccountList).to receive(:call).and_return(unavailable_list)
      get '/accounts?filter=orphaned'
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include('This list is unavailable')
      expect(last_response.body).to include('The authdb is unreachable or the read-only credential is')
    end
  end

  describe 'the filter whitelist' do
    it 'refuses an unknown filter with a 400 that names the valid ones' do
      sign_in_operator!
      get '/accounts?filter=x'
      expect(last_response.status).to eq(400)
      expect(last_response.body).to include('locked', 'orphaned')
      expect(last_response.body).to include('Unknown account filter')
    end

    # Rack turns ?filter[]=locked into an Array, which has no #to_sym: the
    # whitelist must refuse it as a filter rather than 500 on the coercion.
    it 'refuses an array filter with a 400 rather than a 500' do
      sign_in_operator!
      get '/accounts?filter[]=locked'
      expect(last_response.status).to eq(400)
      expect(last_response.body).to include('Unknown account filter')
    end

    # The refused filter is echoed back to the operator, so it is operator
    # input rendered into HTML — escaped, always.
    it 'html-escapes the filter it reflects back' do
      sign_in_operator!
      get '/accounts?filter=%3Cb%3Ex'
      expect(last_response.status).to eq(400)
      expect(last_response.body).to include('&lt;b&gt;x')
      expect(last_response.body).not_to include('<b>x')
    end

    it 'refuses a missing filter the same way, rather than guessing a default' do
      sign_in_operator!
      get '/accounts'
      expect(last_response.status).to eq(400)
      expect(last_response.body).to include('Unknown account filter')
    end
  end

  describe 'the gate' do
    it 'sends an anonymous request to the login form' do
      get '/accounts?filter=locked'
      expect(last_response).to be_redirect
      expect(last_response.location).to end_with('/login')
    end

    it 'requires the second factor before the list' do
      allowlist!
      login!
      get '/accounts?filter=locked'
      expect(last_response).to be_redirect
      expect(last_response.location).to end_with('/otp-setup')
    end

    it 'revokes the session of an operator removed from the allowlist' do
      sign_in_operator!
      get '/accounts?filter=locked'
      expect(last_response.status).to eq(200)

      RodauthAdmin::Allowlist.remove!(account_id: account_id, actor: 'spec', reason: 'offboarding')
      get '/accounts?filter=locked'
      expect(last_response).to be_redirect
      expect(last_response.location).to end_with('/login')
      expect(actions('session_revoked').last[:actor_account_id]).to eq(account_id)
    end
  end

  def unavailable_stats
    RodauthAdmin::Stats::Result.new(
      available: false, reason: 'Sequel::DatabaseConnectionError: could not connect', computed_at: Time.now,
      total_accounts: nil, status_breakdown: nil, mfa_otp_accounts: nil, mfa_webauthn_accounts: nil,
      active_lockouts: nil, active_session_keys: nil, recovery_code_rows: nil,
      orphaned_accounts: nil, customer_count: nil, customer_count_delta: nil
    )
  end

  def unavailable_list
    RodauthAdmin::AccountList::Result.new(
      available: false, reason: 'Sequel::DatabaseConnectionError: could not connect',
      filter: :orphaned, page: 1, per_page: 25, total: nil, rows: []
    )
  end
end
