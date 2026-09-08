-- db/grants/postgres/rodauth_admin_roles.sql
--
-- Rodauth Admin's three runtime credentials on the existing authdb, following
-- the tenant app's own pattern (initialize_auth_db.sql): a runtime user with
-- DML only, and the migrator (ots_migrator) owning every table. There is no
-- admin-specific migration user; `rake db:migrate` runs offline with
-- ADMIN_DATABASE_URL_MIGRATIONS set to the existing migrator's URL.
-- See docs/design/database-credentials.md.
--
--   rodauth_admin_app  runtime user (ADMIN_DATABASE_URL). The ONLY role the
--                      admin sign-in connects with: writes exactly what a
--                      Rodauth sign-in with login + lockout + otp +
--                      audit_logging touches, plus DML on the admin's own
--                      tables (admin_operators, admin_actions).
--   rodauth_admin_ro   read-only user (ADMIN_DATABASE_URL_RO). Every admin
--                      query. SELECT only, permanently: Phase 4 was going to
--                      widen this role to UPDATE/DELETE and deliberately did
--                      not (see below).
--   rodauth_admin_verbs  mutation user (ADMIN_DATABASE_URL_VERBS). The Phase 4
--                      verbs (CHARTER §6 item 4) and the admin_actions row
--                      each one commits in the same transaction. DELETE on
--                      the token, key and session tables; nothing else.
--
-- Phase 4 revision (2026-09-05). CHARTER §4 said Phase 4 would widen
-- rodauth_admin_ro to UPDATE/DELETE on the token and key tables. It does not:
-- a role named _ro that can DELETE is a trap for whoever reads the connection
-- string during an incident, and every read screen would then be running with
-- delete privilege for the sake of a handful of POSTs. A third role costs one
-- URL and buys a real boundary, so the verbs got their own.
--
-- No role can CREATE, ALTER, DROP or TRUNCATE anything. On PostgreSQL 15+
-- that is unconditional. On 14 and earlier it holds for every object here
-- but not for the schema itself: those versions grant CREATE on schema
-- public to PUBLIC, and this file deliberately does not revoke it (see the
-- note below GRANT USAGE ON SCHEMA).
--
-- Run as a superuser or as ots_migrator (the database owner) AFTER
-- `rake db:migrate` has created the admin tables. The database name and the
-- role passwords are psql variables rather than placeholders to edit: they
-- are values, not SQL, so passing them keeps a password containing '/', '&'
-- or a quote from being mangled or from ending up in the file.
--
--   psql -d postgres -v ON_ERROR_STOP=1 \
--        -v dbname=onetime_authdb \
--        -v app_pw="$APP_ROLE_PASSWORD" -v ro_pw="$RO_ROLE_PASSWORD" \
--        -v verbs_pw="$VERBS_ROLE_PASSWORD" \
--        -f db/grants/postgres/rodauth_admin_roles.sql
--
-- The file is idempotent, and re-running it is the upgrade path: an existing
-- deployment picks up a role or a grant added in a later phase by applying
-- the whole file again with the same invocation. GRANT is idempotent by
-- nature (granting a privilege a role already holds is a no-op), the two
-- REVOKEs are inside a guarded DO block, and the three CREATE ROLE statements
-- below are guarded so that a role which already exists is left exactly as
-- it is -- password included -- with a NOTICE. Nothing here ever ALTERs a
-- role: a password is rotated by an explicit ALTER ROLE, not as a side
-- effect of re-applying grants, and since roles are cluster-wide a re-run
-- against one database must not silently reset a credential every other
-- database on the cluster shares. Pass the passwords on every run anyway: a
-- role that turns out to be missing is created with them, and one that
-- exists never reads them (psql does not expand variables in a skipped \if
-- branch). The guard uses \gset and \if, which are psql (client-side)
-- features since PostgreSQL 10; the server version does not matter for them.
--
-- This file is the grant list; review changes to it like code.

-- Roles are cluster-wide, so pg_roles is consulted on the maintenance
-- database before \c. psql variables are not interpolated inside a
-- dollar-quoted DO body, which is why this is \gset + \if rather than a
-- DO block: the password has to reach CREATE ROLE as :'app_pw'.
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rodauth_admin_app') AS create_app \gset
\if :create_app
CREATE ROLE rodauth_admin_app LOGIN PASSWORD :'app_pw';
\else
\echo 'NOTICE: role rodauth_admin_app already exists; leaving it (and its password) as it is'
\endif

SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rodauth_admin_ro') AS create_ro \gset
\if :create_ro
CREATE ROLE rodauth_admin_ro LOGIN PASSWORD :'ro_pw';
\else
\echo 'NOTICE: role rodauth_admin_ro already exists; leaving it (and its password) as it is'
\endif

SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rodauth_admin_verbs') AS create_verbs \gset
\if :create_verbs
CREATE ROLE rodauth_admin_verbs LOGIN PASSWORD :'verbs_pw';
\else
\echo 'NOTICE: role rodauth_admin_verbs already exists; leaving it (and its password) as it is'
\endif

GRANT CONNECT ON DATABASE :"dbname" TO rodauth_admin_app, rodauth_admin_ro, rodauth_admin_verbs;

\c :"dbname"

GRANT USAGE ON SCHEMA public TO rodauth_admin_app, rodauth_admin_ro, rodauth_admin_verbs;

-- PostgreSQL 14 and earlier grant CREATE on schema public to PUBLIC by
-- default, so on those versions each of these three roles can create its own
-- tables (and functions) in the schema it has USAGE on. 15+ revoked that
-- upstream. This file deliberately does NOT run
-- `REVOKE CREATE ON SCHEMA public FROM PUBLIC;` to close it on <= 14:
--
--   - it is a database-wide change, not a change to these three roles. A
--     privilege held through PUBLIC cannot be revoked from one role, so the
--     only way to take it from rodauth_admin_* is to take it from every role
--     in the database, including the tenant's own migrator. On <= 14
--     ots_migrator typically holds CREATE on public through PUBLIC alone
--     (owning every table is not owning the schema, which usually stays with
--     the superuser that created the database), and the tenant's next
--     `rake db:migrate` would then fail with "permission denied for schema
--     public";
--   - it needs the schema owner or a superuser. Run as ots_migrator per the
--     header, it errors with "must be owner of schema public" and under
--     ON_ERROR_STOP the file stops there, half-applied.
--
-- So on <= 14 that grant is the database owner's decision, made outside this
-- file. If the owner wants it: first confirm the tenant migrator will keep
-- CREATE (it owns the schema, or `GRANT CREATE ON SCHEMA public TO
-- ots_migrator;`), then, as the schema owner or a superuser, run
-- `REVOKE CREATE ON SCHEMA public FROM PUBLIC;` on the database.

-- ============================================================================
-- rodauth_admin_app: the sign-in + the admin's own tables
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
-- INSERT when an operator enrols TOTP through the admin; DELETE is
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
-- spec/grants_spec.rb asserts these nine as well, as a separate example, so a
-- regression names the phase whose screens went dark. Note that no GRANT
-- changed for Phase 3: the list below was already the whole CHARTER §3
-- surface. account_previous_password_hashes stays column-scoped (id,
-- account_id) and is only ever COUNTed -- the hashes are never a capability.

-- account_webauthn_user_ids is granted because CHARTER §3 lists it, but no
-- screen reads it yet: no phase asserts it, and nothing breaks if it is
-- unreadable today.
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

-- Remember-me tokens: same precedent, same shape. The revoke-sessions
-- confirm page states how many "keep me signed in" cookies the verb is about
-- to invalidate, which is a capability; the token in `key` is a credential
-- and stays unreadable. `deadline` is granted because it is the only thing
-- that makes the count meaningful (an expired row signs nobody in).
GRANT SELECT (id, deadline) ON account_remember_keys TO rodauth_admin_ro;

-- Never: account_password_hashes, account_session_keys, account_sms_codes,
-- and account_remember_keys.key. Not in the capability table, so not
-- readable.

-- ============================================================================
-- rodauth_admin_verbs: the Phase 4 mutations (CHARTER §6 item 4)
-- ============================================================================
--
-- One role per verb table, and the audit row on the same connection so that
-- the mutation and its admin_actions entry commit or roll back together
-- (docs/design/database-credentials.md). The verbs and what they touch:
--
--   clear_lockout               DELETE account_lockouts, account_login_failures
--   force_password_reset        UPSERT account_password_change_times,
--                               DELETE account_password_reset_keys
--   expire_tokens               DELETE account_password_reset_keys,
--                               account_verification_keys,
--                               account_login_change_keys,
--                               account_email_auth_keys
--   disable_mfa                 DELETE account_otp_keys, account_otp_unlocks,
--                               account_recovery_codes,
--                               account_webauthn_keys,
--                               account_webauthn_user_ids
--   regenerate_recovery_codes   DELETE + INSERT account_recovery_codes
--   revoke_sessions             DELETE account_active_session_keys,
--                               account_remember_keys
--   revoke_refresh_keys         DELETE account_jwt_refresh_keys
--   unlink_identity             DELETE account_identities
--
-- SELECT accompanies every mutation: a verb reads the rows it is about to
-- remove so the confirm page and the audit metadata can state the counts.
-- account_statuses is NOT in the list: the verbs never read a status name
-- (the confirm pages come from the read-only role's preview), and a grant
-- nothing exercises is a grant nobody notices going stale.
-- admin_operators IS in it: disable_mfa and regenerate_recovery_codes refuse
-- on a fellow operator's account, and that check reads this table inside the
-- verb's own transaction.

GRANT SELECT ON
  accounts,
  account_lockouts,
  account_login_failures,
  account_password_reset_keys,
  account_verification_keys,
  account_login_change_keys,
  account_email_auth_keys,
  account_otp_keys,
  account_otp_unlocks,
  account_recovery_codes,
  account_webauthn_keys,
  account_webauthn_user_ids,
  account_active_session_keys,
  account_jwt_refresh_keys,
  account_identities,
  account_password_change_times,
  admin_operators
TO rodauth_admin_verbs;

-- The deletes. UPDATE is granted nowhere here: every verb but
-- force_password_reset removes rows, and a verb that could UPDATE
-- account_otp_keys could quietly re-key an operator's second factor.
GRANT DELETE ON
  account_lockouts,
  account_login_failures,
  account_password_reset_keys,
  account_verification_keys,
  account_login_change_keys,
  account_email_auth_keys,
  account_otp_keys,
  account_otp_unlocks,
  account_recovery_codes,
  account_webauthn_keys,
  account_webauthn_user_ids,
  account_active_session_keys,
  account_jwt_refresh_keys,
  account_identities,
  account_remember_keys
TO rodauth_admin_verbs;

-- revoke_sessions clears remember-me tokens as well as session keys: the
-- tenant app does not consult account_active_session_keys today, so the
-- remember cookie is the half of "sign this customer out" that bites. The
-- SELECT is column-scoped (`key` stays unreadable, as for every role here)
-- and is not optional: PostgreSQL needs SELECT on the columns a DELETE's
-- WHERE clause names, and this one is `WHERE id = ?`.
GRANT SELECT (id, deadline) ON account_remember_keys TO rodauth_admin_verbs;

-- regenerate_recovery_codes writes the replacement codes.
GRANT INSERT ON account_recovery_codes TO rodauth_admin_verbs;

-- force_password_reset upserts changed_at to a far-past timestamp so the
-- tenant app's password_expiration feature demands a new password at the
-- next login. An account that has never changed its password has no row,
-- hence INSERT as well as UPDATE.
GRANT INSERT, UPDATE ON account_password_change_times TO rodauth_admin_verbs;

-- The audit row, written in the verb's own transaction. Append-only here as
-- everywhere: INSERT and SELECT, no UPDATE, no DELETE.
GRANT SELECT, INSERT ON admin_actions TO rodauth_admin_verbs;
GRANT USAGE, SELECT ON SEQUENCE admin_actions_id_seq TO rodauth_admin_verbs;

-- Never, for this role: account_password_hashes (a verb that could touch it
-- would be setting passwords, which this tool does not do — force_password_reset
-- expires the password, it does not change it), account_previous_password_hashes,
-- account_remember_keys.key (the token itself; the role deletes those rows
-- without ever being able to read one), account_session_keys, account_sms_codes,
-- account_authentication_audit_logs (Rodauth's own log is evidence; the admin
-- appends to admin_actions instead), admin_operators beyond SELECT, and
-- accounts beyond SELECT (status changes are the tenant app's job).

-- ============================================================================
-- Verification
-- ============================================================================
--
-- SELECT grantee, table_name, string_agg(privilege_type, ',' ORDER BY privilege_type)
--   FROM information_schema.role_table_grants
--  WHERE grantee IN ('rodauth_admin_app', 'rodauth_admin_ro', 'rodauth_admin_verbs')
--  GROUP BY 1, 2 ORDER BY 1, 2;
--
-- SELECT grantee, table_name, column_name
--   FROM information_schema.column_privileges
--  WHERE grantee = 'rodauth_admin_ro' AND table_name = 'account_previous_password_hashes';
