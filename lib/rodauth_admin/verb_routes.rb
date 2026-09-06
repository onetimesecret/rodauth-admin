# lib/rodauth_admin/verb_routes.rb
#
# frozen_string_literal: true

require_relative 'allowlist'
require_relative 'audit'
require_relative 'database'
require_relative 'verbs'

module RodauthAdmin
  # The web half of the mutation verbs (CHARTER §3, §6 phase 4), included
  # into App. It lives in its own file because it is the only part of the
  # routing tree with a guard chain of its own; app.rb stays the map of the
  # read-only screens.
  #
  # Every verb is the same two requests, so this is one dispatch rather than
  # seven pairs of routes:
  #
  #   GET  /accounts/:id/<slug>   what would happen, live counts, reason box
  #   POST /accounts/:id/<slug>   do it, record it, flash the counts
  #
  # plus the one nested route, /accounts/:id/identities/:identity_id/unlink,
  # which needs the identity id and so cannot share the slug shape.
  #
  # The guard chain, in the order a request meets it (docs/design/mutations.md):
  # allowlisted operator session (app.rb, before Rodauth's own routes) →
  # require_authentication → require_two_factor_setup → MFA-fresh (here) →
  # CSRF (app.rb, check_csrf!) → reason (Verbs, before the transaction).
  #
  # The verb copy is a Hash and the template is one file. Seven templates
  # would drift apart sentence by sentence, and the differences between
  # these pages are three sentences each.
  # rubocop:disable Metrics/ModuleLength -- most of the length is the COPY
  # table: eight verbs' worth of operator-facing prose, which belongs beside
  # the dispatch that renders it rather than in a ninth file.
  module VerbRoutes
    # unlink_identity is not in Verbs::SLUGS (it is nested and takes an
    # extra argument), so the web layer names it here.
    UNLINK_SLUG = 'unlink-identity'
    UNLINK_VERB = :unlink_identity

    # title:  the page heading and the button
    # does:   what the mutation does, present tense, one sentence
    # note:   a standing caveat about the tenant app, or nil. These are
    #         facts verified against the tenant config on 2026-09-05, not
    #         warnings: the button is shown either way, because "this did
    #         less than you think" is worse discovered afterwards.
    # empty:  what "there is nothing here" means for this verb
    COPY = {
      'clear-lockout' => {
        title: 'Clear lockout',
        does: 'Deletes the account lockout and its login-failure counter, exactly as a successful ' \
              'login would. The customer can sign in again immediately with their existing password.',
        note: nil,
        empty: 'This account is not locked and has no failure counter: nothing to remove. The action is still recorded.'
      },
      'force-password-reset' => {
        title: 'Force password reset',
        does: 'Backdates the recorded password-change time to 1970 and deletes any outstanding ' \
              'password-reset key, so an emailed reset link already in flight stops working.',
        note: 'The tenant app does not currently enable the password_expiration feature, so this ' \
              'invalidates outstanding reset links and backdates the password-change time, but it will ' \
              'only force a new password at login once the tenant enables that feature.',
        empty: 'There is no outstanding reset key; the change time is backdated regardless.'
      },
      'expire-tokens' => {
        title: 'Expire pending tokens',
        does: 'Deletes every outstanding emailed link the account has: password reset, account ' \
              'verification, login change and email auth.',
        note: nil,
        empty: 'There are no pending tokens: nothing to remove. The action is still recorded.'
      },
      'disable-mfa' => {
        title: 'Disable MFA',
        does: 'Deletes the TOTP key, the OTP unlock row, every unused recovery code and every ' \
              'WebAuthn key. The customer signs in with their password alone until they enrol again.',
        note: 'Refused on your own account and on any other operator\'s: operators change their own MFA in ' \
              'the tenant app, or are offboarded from the allowlist.',
        empty: 'This account has no second factor on file: nothing to remove. The action is still recorded.'
      },
      'regenerate-recovery-codes' => {
        title: 'Regenerate recovery codes',
        does: 'Deletes the account\'s existing recovery codes and mints a fresh set. The new codes ' \
              'are shown once, on the next page, and are not recoverable afterwards.',
        note: 'Refused on your own account and on any other operator\'s, and refused when the account has ' \
              'no TOTP or WebAuthn key ' \
              '— recovery codes without a second factor are a password-only login path that looks like MFA.',
        empty: 'This account has no recovery codes on file; a fresh set is minted regardless.'
      },
      'revoke-sessions' => {
        title: 'Revoke sessions',
        does: 'Deletes the account\'s Rodauth session-key rows and every remember-me token, so a saved ' \
              '"keep me signed in" cookie stops working immediately.',
        note: 'The tenant app does not currently consult the session-key table (it checks its own session ' \
              'store), so a browser window that is already open is NOT signed out by this. The remember-me ' \
              'deletion takes effect now; the session-key rows will bite once the tenant enforces ' \
              'check_active_session.',
        empty: 'There are no session keys and no remember-me tokens: nothing to remove. The action is still recorded.'
      },
      'revoke-refresh-keys' => {
        title: 'Revoke API refresh tokens',
        does: 'Deletes every outstanding JWT refresh token. Access tokens already issued live until ' \
              'they expire on their own; nothing in the database can recall them.',
        note: 'The tenant app does not currently enable jwt_refresh, so this normally finds nothing.',
        empty: 'There are no refresh tokens: nothing to remove. The action is still recorded.'
      },
      UNLINK_SLUG => {
        title: 'Unlink SSO identity',
        does: 'Deletes this one linked identity. The customer can no longer sign in through that ' \
              'provider until they link it again.',
        note: nil,
        empty: 'Nothing to remove.'
      }
    }.freeze

    # What the confirm page is re-rendered with when the verb layer refuses:
    # the status the refusal deserves, and the sentence explaining it.
    SELF_REFUSAL = { status: 403,
                     message: 'Refused: this is your own account. Operators change their own MFA and ' \
                              'recovery codes in the tenant app.' }.freeze
    OPERATOR_REFUSAL = { status: 403,
                         message: 'Refused: this account belongs to another operator of this tool. Another ' \
                                  'operator\'s second factor is not a support ticket — they change it in the ' \
                                  'tenant app, or they are offboarded from the allowlist.' }.freeze
    NO_FACTOR_REFUSAL = { status: 422,
                          message: 'Refused: this account has no TOTP or WebAuthn key, so recovery codes ' \
                                   'would be a password-only login path that looks like MFA.' }.freeze
    # preview's counts carry two keys that are not table row counts:
    # login_failure_number (the counter's value, which is an Integer and so
    # cannot be told apart by type) and second_factor (a boolean). Filtering
    # by key rather than by type is what keeps the clear-lockout confirm page
    # from listing "login_failure_number 4" as a table it is about to empty.
    NON_TABLE_KEYS = %i[login_failure_number second_factor].freeze

    BLANK_REASON_REFUSAL = { status: 422,
                             message: 'A reason is required. Every mutation is recorded with one.' }.freeze

    # Mounted under `r.on 'accounts', Integer` in app.rb, after the read-only
    # GET, which matches /accounts/:id exactly and so never reaches here.
    def verb_routes(req, id)
      req.on 'identities', Integer, 'unlink' do |identity_id|
        req.get { verb_confirm(req, id, UNLINK_SLUG, identity_id: identity_id) }
        req.post { verb_execute(req, id, UNLINK_SLUG, identity_id: identity_id) }
      end

      req.is String do |slug|
        # An unknown slug falls out of the block with no response, which
        # Roda finishes as a 404 through the not_found plugin — the same
        # answer a mistyped URL gets anywhere else in this app.
        next unless Verbs::SLUGS.key?(slug)

        req.get { verb_confirm(req, id, slug) }
        req.post { verb_execute(req, id, slug) }
      end
    end

    private

    # The confirm page. The step-up happens here, on the GET, because that
    # is the only request Rodauth can send back to afterwards.
    def verb_confirm(req, id, slug, identity_id: nil, refusal: nil)
      rodauth.require_fresh_mfa!
      @preview = Verbs.preview(id: id)
      return missing(id.to_s) if @preview.available && !@preview.found

      @identity = find_identity(@preview, identity_id) if identity_id
      return missing(id.to_s) if identity_id && @preview.available && @identity.nil?

      render_verb(req, id, slug, refusal: refusal)
    end

    # rubocop:disable Metrics/AbcSize -- one rescue per refusal the verb layer
    # can raise; each maps to a different status and a different sentence,
    # and collapsing them would lose the sentence.
    def verb_execute(req, id, slug, identity_id: nil)
      unless rodauth.mfa_fresh?
        flash['error'] = 'Your second factor is no longer fresh. Confirm the code and try again.'
        req.redirect verb_path(id, slug, identity_id)
      end

      result = run_verb(req, id, slug, identity_id)
      return show_codes(req, id, result) if result.codes

      flash['notice'] = verb_flash(result)
      req.redirect account_path(id)
    rescue Verbs::NotFound
      missing(id.to_s)
    rescue Verbs::SelfTarget
      verb_confirm(req, id, slug, identity_id: identity_id, refusal: SELF_REFUSAL)
    rescue Verbs::OperatorTarget
      verb_confirm(req, id, slug, identity_id: identity_id, refusal: OPERATOR_REFUSAL)
    rescue Verbs::NoSecondFactor
      verb_confirm(req, id, slug, identity_id: identity_id, refusal: NO_FACTOR_REFUSAL)
    rescue Audit::BlankReason
      verb_confirm(req, id, slug, identity_id: identity_id, refusal: BLANK_REASON_REFUSAL)
    end
    # rubocop:enable Metrics/AbcSize

    def run_verb(req, id, slug, identity_id)
      args = { id: id, actor: verb_actor(req), reason: req.params['reason'] }
      args[:identity_id] = identity_id if identity_id
      Verbs.public_send(verb_method(slug), **args)
    end

    def verb_method(slug) = slug == UNLINK_SLUG ? UNLINK_VERB : Verbs::SLUGS.fetch(slug)

    # The operator, read from the session on every request: who they are is
    # never carried in the form.
    def verb_actor(req)
      account = rodauth.account_from_session
      Verbs::Actor.build(email: account && account[:email], account_id: rodauth.session_value,
                         ip: req.ip, user_agent: req.user_agent)
    end

    # The one-time codes page. No redirect: a redirect would put the codes
    # in a flash, and a flash is a cookie.
    def show_codes(_req, id, result)
      @account_id = id
      @codes = result.codes
      @target = result.target
      view 'verb_codes'
    end

    # "Clear lockout on a@b: 2 rows (account_lockouts 1, account_login_failures 1)."
    def verb_flash(result)
      slug = COPY.keys.find { |s| verb_method(s) == result.action }
      pairs = result.counts.map { |table, n| "#{table} #{n}" }.join(', ')
      "#{COPY.dig(slug, :title) || result.action} on #{result.target}: #{result.total} rows (#{pairs})."
    end

    def render_verb(_req, id, slug, refusal: nil)
      @account_id = id
      @slug = slug
      @copy = COPY.fetch(slug)
      @error = refusal && refusal[:message]
      @counts = preview_counts_for(slug)
      @self_target = mfa_verb?(slug) && rodauth.session_value == id
      @operator_target = mfa_verb?(slug) && !@self_target && operator_account?(id)
      response.status = refusal[:status] if refusal
      view 'verb'
    end

    # The two verbs refused on an operator's account, whether the operator is
    # the one signed in (SelfTarget) or a colleague (OperatorTarget).
    def mfa_verb?(slug) = Verbs::SELF_REFUSED.include?(verb_method(slug))

    # Is this account an operator of this tool? Read on the read-only
    # credential, like everything else the pages display, and failing CLOSED:
    # an authdb that cannot answer hides the two buttons rather than offering
    # a button the verb layer will refuse anyway (it re-reads the same table
    # inside the transaction, which is the check that counts).
    def operator_account?(account_id)
      Allowlist.allowed?(account_id, db: Database.readonly)
    rescue Sequel::Error
      true
    end

    # For unlink the preview counts every identity on the account; that page
    # is about the one named in the URL.
    def preview_counts_for(slug)
      return nil unless @preview.available
      return { account_identities: 1 } if slug == UNLINK_SLUG

      @preview.counts[verb_method(slug)]
    end

    def find_identity(preview, identity_id)
      return nil unless preview.available && preview.identities

      preview.identities.find { |i| i.id == identity_id }
    end

    # The one place a verb URL is written.
    def verb_path(id, slug, identity_id = nil)
      return "#{account_path(id)}/identities/#{Integer(identity_id)}/unlink" if slug == UNLINK_SLUG

      "#{account_path(id)}/#{slug}"
    end

    def verb_row_counts(counts)
      (counts || {}).except(*NON_TABLE_KEYS)
    end

    def nothing_to_do?(counts)
      rows = verb_row_counts(counts)
      !rows.empty? && rows.values.sum.zero?
    end
  end
  # rubocop:enable Metrics/ModuleLength
end
