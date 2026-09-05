# lib/rodauth_admin/auth.rb
#
# frozen_string_literal: true

require 'rodauth'
require 'rodauth/tools'

require_relative 'env'
require_relative 'database'
require_relative 'allowlist'
require_relative 'audit'

module RodauthAdmin
  # The admin's own front door, over the operator's existing production
  # identity (CHARTER §4). This Rodauth instance authenticates against the
  # production accounts table through the login-scoped credential and
  # enables only what a sign-in needs:
  #
  #   login / logout   password against account_password_hashes (argon2 +
  #                    ARGON2_SECRET pepper, bcrypt for legacy hashes)
  #   otp              TOTP second factor; required for every operator
  #                    (RodauthAdmin::App calls require_two_factor_setup).
  #                    Enrolment (otp-setup) writes the production key table
  #                    and is recorded in admin_actions; otp-disable,
  #                    multifactor-disable and multifactor-manage are routed
  #                    off (operators disable MFA in the tenant app)
  #   lockout          same counters as the tenant app; lockout couples both
  #                    ways, by design
  #   audit_logging    writes production's auth-event log, tagged so the two
  #                    apps' events are distinguishable
  #
  # Deliberately NOT enabled: create_account, verify_account, reset_password,
  # change_password, close_account, remember, active_sessions (see charter),
  # recovery_codes (the tenant app owns recovery; the admin door is TOTP only),
  # webauthn (Phase 1 keeps one second factor; revisit when an operator
  # without TOTP shows up).
  class Auth < Rodauth::Auth
    configure do
      enable :login, :logout, :otp, :lockout, :audit_logging, :argon2,
             :external_identity, :table_guard

      # The runtime credential; the ONLY one Rodauth touches. Block form
      # defers the connection to first use so tests can point ENV at a
      # scratch database first.
      db { RodauthAdmin::Database.app }

      # --- schema validation (rodauth-tools) --------------------------------
      table_guard_mode :raise
      external_identity_column :external_id
      external_identity_check_columns true

      # --- secrets shared with the tenant app --------------------------------
      # OTP keys (and lockout unlock keys) are HMAC'd with the tenant app's
      # AUTH_SECRET. Env.auth_secret requires it in production and removes
      # it from ENV once read.
      hmac_secret RodauthAdmin::Env.auth_secret
      hmac_old_secret RodauthAdmin::Env.auth_old_secret if RodauthAdmin::Env.auth_old_secret
      argon2_secret ENV.fetch('ARGON2_SECRET', nil) if ENV.fetch('ARGON2_SECRET', nil)
      # Fresh hashes are never written here (no password changes), but the
      # cost must be valid for argon2 verification paths.
      password_hash_cost(RodauthAdmin::Env.test? ? { t_cost: 1, m_cost: 5,
                                                     p_cost: 1 } : { t_cost: 2, m_cost: 16, p_cost: 1 })

      # --- identity --------------------------------------------------------
      login_column :email
      login_label 'Email'
      normalize_login { |login| login.to_s.unicode_normalize(:nfc).strip.downcase }
      # Only Verified accounts (status 2) may pass the door.
      skip_status_checks? false

      # --- lockout (mirrors tenant app) --------------------------------------
      max_invalid_logins 5
      # The admin door never sends email. Unlock happens through the tenant
      # app's own unlock flow (same table, same HMAC'd key) or, from Phase 4,
      # an operator's clear-lockout verb. Both lockout routes are disabled
      # and the mail gem is not loaded.
      unlock_account_request_route nil
      unlock_account_route nil
      require_mail? false

      # --- TOTP --------------------------------------------------------------
      otp_issuer RodauthAdmin::Env.otp_issuer
      otp_keys_use_hmac? true
      otp_auth_failures_limit 7
      # No "remember this device" and no partial-auth grace: every session
      # starts with password + code.
      two_factor_auth_return_to_requested_location? true
      # enable :otp routes otp-auth, otp-setup AND otp-disable. The last one
      # would strip TOTP from the shared production identity through the
      # admin door (and the runtime role is denied DELETE on
      # account_otp_keys, db/grants/postgres/rodauth_admin_roles.sql).
      otp_disable_route nil
      # two_factor_base (pulled in by otp) routes multifactor-manage and
      # multifactor-disable as well; the latter removes EVERY second factor
      # from the account. Same reasoning, same answer.
      two_factor_disable_route nil
      two_factor_manage_route nil

      # --- audit_logging: tag every row so production's log can tell the
      # two apps apart -------------------------------------------------------
      audit_log_message_default { |action| "rodauth-admin: #{action}" }
      audit_log_metadata_default do
        { app: 'rodauth-admin', ip: request.ip, user_agent: request.user_agent.to_s[0, 256] }
      end

      # --- routing / sessions -----------------------------------------------
      domain RodauthAdmin::Env.public_host
      already_logged_in { redirect '/' }
      login_redirect '/'
      logout_redirect '/login'
      require_login_redirect '/login'
      two_factor_need_setup_redirect '/otp-setup'
      two_factor_auth_required_redirect '/otp-auth'
      two_factor_auth_redirect '/'
      otp_setup_redirect '/'
      login_return_to_requested_location? true

      # --- allowlist gate + admin_actions ------------------------------------
      #
      # after_login runs inside Rodauth's login transaction, after the
      # session is populated. A non-allowlisted but otherwise valid login
      # is recorded, the session is torn down, and the request ends at the
      # login form with an explanation. Nothing about the tenant account is
      # changed; production's audit log still gets its 'login' row, which
      # is correct: the password was right.
      after_login do
        if RodauthAdmin::Allowlist.allowed?(account_id)
          RodauthAdmin::Audit.record(
            action: 'login', actor: account[:email], actor_account_id: account_id,
            ip: request.ip, user_agent: request.user_agent
          )
        else
          RodauthAdmin::Audit.record(
            action: 'login_denied', actor: account[:email], actor_account_id: account_id,
            ip: request.ip, user_agent: request.user_agent
          )
          clear_session
          set_redirect_error_status 403
          set_redirect_error_flash 'This account is not an operator of Rodauth Admin.'
          redirect login_path
        end
      end

      # Enrolling TOTP writes the production account_otp_keys row: an
      # operator did something to the shared identity, so it is an admin
      # action, not just a Rodauth auth-log event.
      after_otp_setup do
        RodauthAdmin::Audit.record(
          action: 'otp_setup', actor: account[:email], actor_account_id: account_id,
          ip: request.ip, user_agent: request.user_agent
        )
      end

      after_two_factor_authentication do
        RodauthAdmin::Audit.record(
          action: 'two_factor_auth', actor: account[:email], actor_account_id: account_id,
          ip: request.ip, user_agent: request.user_agent
        )
      end

      # The session is gone by after_logout, so record here. Read the email
      # directly rather than via account_from_session: that memoizes
      # @account, and audit_logging would then write production's logout
      # row twice (once in before_logout, once in after_logout).
      before_logout do
        id = session_value
        next unless id

        email = db[accounts_table].where(account_id_column => id).get(login_column)
        RodauthAdmin::Audit.record(
          action: 'logout', actor: email || "account:#{id}", actor_account_id: id,
          ip: request.ip, user_agent: request.user_agent
        )
      end
    end

    # Is the signed-in account still a Verified row in the authdb? A closed
    # (status 3) or deleted tenant account must lose admin access on its
    # next request, not at cookie expiry. Deliberately does not go through
    # account_from_session: that memoizes @account, and audit_logging would
    # then write production's logout row twice (see before_logout).
    def session_account_open?
      id = session_value
      return false unless id

      !account_ds(id).where(account_session_status_filter).empty?
    end
  end
end
