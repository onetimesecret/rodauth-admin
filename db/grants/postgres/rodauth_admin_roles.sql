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
-- `rake db:migrate` has created the admin tables. Replace CHANGE_ME first.
-- This file is the grant list; review changes to it like code.

CREATE ROLE rodauth_admin_app LOGIN PASSWORD 'CHANGE_ME_APP_ROLE_PASSWORD';
CREATE ROLE rodauth_admin_ro  LOGIN PASSWORD 'CHANGE_ME_RO_ROLE_PASSWORD';

GRANT CONNECT ON DATABASE onetime_authdb TO rodauth_admin_app, rodauth_admin_ro;

\c onetime_authdb

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
GRANT EXECUTE ON FUNCTION rodauth_get_salt(bigint) TO rodauth_admin_app;
GRANT EXECUTE ON FUNCTION rodauth_valid_password_hash(bigint, text) TO rodauth_admin_app;
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
