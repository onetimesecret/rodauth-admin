-- db/grants/postgres/rodauth_admin_roles.sql
--
-- Rodauth Admin's two runtime credentials on the existing authdb, following
-- the tenant app's own pattern (initialize_auth_db.sql): a runtime user with
-- DML only, and the migrator (ots_migrator) owning every table. There is no
-- admin-specific migration user; `rake db:migrate` runs offline with
-- ADMIN_DATABASE_URL_MIGRATIONS set to the existing migrator's URL.
-- See docs/design/database-credentials.md.
--
--   rodauth_admin_app  runtime user (ADMIN_DATABASE_URL). The ONLY role the
--                      login door connects with: writes exactly what a
--                      Rodauth sign-in with login + lockout + otp +
--                      audit_logging touches, plus DML on the admin's own
--                      tables (admin_operators, admin_actions).
--   rodauth_admin_ro   read-only user (ADMIN_DATABASE_URL_RO). Every admin
--                      query. Phase 4 widens it to UPDATE/DELETE on the
--                      token and key tables, in a reviewed change to this
--                      file and nowhere else.
--
-- Neither role can CREATE, ALTER, DROP or TRUNCATE anything.
--
-- Run as a superuser or as ots_migrator (the database owner) AFTER
-- `rake db:migrate` has created the admin tables. The database name and the
-- two passwords are psql variables rather than placeholders to edit: they
-- are values, not SQL, so passing them keeps a password containing '/', '&'
-- or a quote from being mangled or from ending up in the file.
--
--   psql -d postgres -v ON_ERROR_STOP=1 \
--        -v dbname=onetime_authdb \
--        -v app_pw="$APP_ROLE_PASSWORD" -v ro_pw="$RO_ROLE_PASSWORD" \
--        -f db/grants/postgres/rodauth_admin_roles.sql
--
-- This file is the grant list; review changes to it like code.

CREATE ROLE rodauth_admin_app LOGIN PASSWORD :'app_pw';
CREATE ROLE rodauth_admin_ro  LOGIN PASSWORD :'ro_pw';

GRANT CONNECT ON DATABASE :"dbname" TO rodauth_admin_app, rodauth_admin_ro;

\c :"dbname"

GRANT USAGE ON SCHEMA public TO rodauth_admin_app, rodauth_admin_ro;

-- ============================================================================
-- rodauth_admin_app: the login door + the admin's own tables
-- ============================================================================

-- Account lookup by email, status check, external_id (read only)
GRANT SELECT ON accounts, account_statuses TO rodauth_admin_app;

-- Password verification. When the rodauth_get_salt / rodauth_valid_password_hash
-- SECURITY DEFINER functions exist (tenant app migration 003), Rodauth uses
-- them and the role needs no direct access to the hash table. The direct
-- SELECT below is the fallback for databases without the functions; drop it
-- once the functions are confirmed present.
-- SECURITY DEFINER functions execute as their owner, so PUBLIC EXECUTE would
-- hand every role in the database an oracle over the hash table both runtime
-- roles are deliberately denied SELECT on. Revoke first, then grant to the
-- one role that needs it.
-- Guarded with to_regprocedure: on an authdb without the functions, a bare
-- REVOKE aborts the script half-applied, which is the one outcome a
-- privilege file must never produce. Skipping is correct there — with no
-- functions there is no oracle to revoke and Rodauth falls back to the hash
-- table (see the commented GRANT below).
DO $$
BEGIN
  IF to_regprocedure('rodauth_get_salt(bigint)') IS NOT NULL THEN
    REVOKE ALL ON FUNCTION rodauth_get_salt(bigint) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION rodauth_get_salt(bigint) TO rodauth_admin_app;
  ELSE
    RAISE NOTICE 'rodauth_get_salt(bigint) not present; skipping its grants';
  END IF;

  IF to_regprocedure('rodauth_valid_password_hash(bigint, text)') IS NOT NULL THEN
    REVOKE ALL ON FUNCTION rodauth_valid_password_hash(bigint, text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION rodauth_valid_password_hash(bigint, text) TO rodauth_admin_app;
  ELSE
    RAISE NOTICE 'rodauth_valid_password_hash(bigint, text) not present; skipping its grants';
  END IF;
END
$$;
-- GRANT SELECT ON account_password_hashes TO rodauth_admin_app;  -- fallback only

-- lockout feature: failure counters and lockout rows
GRANT SELECT, INSERT, UPDATE, DELETE ON account_login_failures, account_lockouts TO rodauth_admin_app;

-- otp feature: last_use / num_failures on every successful or failed code;
-- INSERT when an operator enrols TOTP through the admin door; DELETE is
-- deliberately withheld (operators disable MFA in the tenant app, not here).
GRANT SELECT, INSERT, UPDATE ON account_otp_keys TO rodauth_admin_app;

-- audit_logging feature: one row per auth event, tagged 'rodauth-admin'
GRANT SELECT, INSERT ON account_authentication_audit_logs TO rodauth_admin_app;
GRANT USAGE, SELECT ON SEQUENCE account_authentication_audit_logs_id_seq TO rodauth_admin_app;

-- The admin's own tables (created by ots_migrator via rake db:migrate).
-- admin_actions is append-only: INSERT and SELECT, and the trigger from
-- db/migrate/002_admin_actions.rb rejects UPDATE/DELETE even for the owner.
GRANT SELECT, INSERT, UPDATE, DELETE ON admin_operators TO rodauth_admin_app;
GRANT USAGE, SELECT ON SEQUENCE admin_operators_id_seq TO rodauth_admin_app;
GRANT SELECT, INSERT ON admin_actions TO rodauth_admin_app;
GRANT USAGE, SELECT ON SEQUENCE admin_actions_id_seq TO rodauth_admin_app;
GRANT SELECT ON admin_schema_info TO rodauth_admin_app;

-- ============================================================================
-- rodauth_admin_ro: every admin query (CHARTER §3 capability table)
-- ============================================================================
--
-- Phase 2 (aggregate visibility) reads exactly these eight, and every stat
-- and filtered list on the board fails closed without them. Removing one is
-- removing a screen, so they are called out separately from the rest of the
-- capability surface:
--
--   accounts                     status breakdown, orphan list (external_id
--                                IS NULL), the id every other count joins on
--   account_statuses             status id -> name; never trust the ordinal
--   account_otp_keys             MFA adoption
--   account_webauthn_keys        MFA adoption (passkeys)
--   account_lockouts             active lockouts (always with deadline > now)
--   account_login_failures       failure counts beside the lockout list
--   account_active_session_keys  active session keys (NOT "users online")
--   account_recovery_codes       unused recovery codes; a row count, since
--                                Rodauth deletes a code on use (db/README.md)
--
-- spec/grants_spec.rb asserts all eight are readable by this role, and that
-- writes are refused, whenever the suite runs against PostgreSQL.
--
-- Phase 3 (account detail) reads the remaining tables below. They were
-- granted here from Phase 1, but they are now in use: removing one is again
-- removing a section of the per-account page, so they get the same treatment:
--
--   account_otp_unlocks                MFA panel: TOTP unlock state
--                                      (num_successes, next_auth_attempt_after)
--   account_webauthn_user_ids          the account's WebAuthn user handle,
--                                      beside the passkey list
--   account_jwt_refresh_keys           API refresh tokens: id + deadline,
--                                      count and expiry; never the key
--   account_password_reset_keys        pending tokens: reset requested?
--                                      deadline, email_last_sent
--   account_verification_keys          pending tokens: unverified account,
--                                      requested_at, email_last_sent
--   account_login_change_keys          pending tokens: pending new login,
--                                      deadline
--   account_email_auth_keys            pending tokens: email-auth link,
--                                      deadline, email_last_sent
--   account_identities                 SSO identities (provider, issuer, uid)
--   account_password_change_times      password age (changed_at)
--   account_authentication_audit_logs  the paginated auth-event timeline
--
-- spec/grants_spec.rb asserts these ten as well, as a separate example, so a
-- regression names the phase whose screens went dark. Note that no GRANT
-- changed for Phase 3: the list below was already the whole CHARTER §3
-- surface. account_previous_password_hashes stays column-scoped (id,
-- account_id) and is only ever COUNTed -- the hashes are never a capability.

GRANT SELECT ON
  accounts,
  account_statuses,
  account_login_failures,
  account_lockouts,
  account_otp_keys,
  account_recovery_codes,
  account_otp_unlocks,
  account_webauthn_keys,
  account_webauthn_user_ids,
  account_active_session_keys,
  account_jwt_refresh_keys,
  account_password_reset_keys,
  account_verification_keys,
  account_login_change_keys,
  account_email_auth_keys,
  account_identities,
  account_password_change_times,
  account_authentication_audit_logs,
  admin_operators,
  admin_actions
TO rodauth_admin_ro;

-- Password reuse history: the COUNT is a capability, the hashes never are.
GRANT SELECT (id, account_id) ON account_previous_password_hashes TO rodauth_admin_ro;

-- Never: account_password_hashes, account_remember_keys, account_session_keys,
-- account_sms_codes. Not in the capability table, so not readable.

-- ============================================================================
-- Verification
-- ============================================================================
--
-- SELECT grantee, table_name, string_agg(privilege_type, ',' ORDER BY privilege_type)
--   FROM information_schema.role_table_grants
--  WHERE grantee IN ('rodauth_admin_app', 'rodauth_admin_ro')
--  GROUP BY 1, 2 ORDER BY 1, 2;
--
-- SELECT grantee, table_name, column_name
--   FROM information_schema.column_privileges
--  WHERE grantee = 'rodauth_admin_ro' AND table_name = 'account_previous_password_hashes';
