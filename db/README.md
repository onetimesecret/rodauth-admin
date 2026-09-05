# Database

Rodauth Admin uses one database, the tenant app's authdb, through three
credentials. The model is spelled out in
[`docs/design/database-credentials.md`](../docs/design/database-credentials.md).

| ENV | Role | Purpose |
|---|---|---|
| `ADMIN_DATABASE_URL` | `rodauth_admin_app` | runtime: the Rodauth login door plus the admin tables |
| `ADMIN_DATABASE_URL_RO` | `rodauth_admin_ro` | runtime: every admin query, SELECT only |
| `ADMIN_DATABASE_URL_MIGRATIONS` | `ots_migrator` (existing) | offline: `rake db:migrate`, `rake authdb:dev` |

No code in the running application runs DDL. Ever.

## Rodauth's tables

Owned by the tenant app and its migrations. The schema is described in
`lib/rodauth_admin/authdb_schema.rb` as the rodauth-tools feature list
production was generated from, plus the columns the tenant app added on top
(`external_id`, timestamps, `account_identities`). That description is used
to:

- **validate production at boot.** `RodauthAdmin::Auth` enables
  `table_guard` in `:raise` mode, so a missing table for any enabled login
  feature stops the process before it serves a request.
- **build a local authdb** for development and tests from the gem's ERB
  templates: `bundle exec rake authdb:dev` (SQLite at `data/authdb.sqlite3`).
  Never point that task at production; it refuses to run with
  `RACK_ENV=production` and against a database that already has `accounts`.

Two secrets are shared with the tenant app because the identity is shared:
`AUTH_SECRET` (OTP keys are HMAC'd with it) and `ARGON2_SECRET` (password
pepper). See `.env.example`.

## The admin's tables

Two tables in the same database, prefixed `admin_`, migrated from
`db/migrate/` by the existing migrator with their own bookkeeping table
`admin_schema_info`:

- `admin_operators` — the allowlist. `account_id` is `accounts.id`.
- `admin_actions` — append-only audit trail with a required `reason`.
  Append-only is enforced by triggers (SQLite and PostgreSQL) and, on
  PostgreSQL, by the runtime role having INSERT and SELECT only.
  The PostgreSQL trigger uses `EXECUTE FUNCTION`, so the migration needs
  PostgreSQL 11 or newer.

```bash
ADMIN_DATABASE_URL_MIGRATIONS=postgresql://ots_migrator:...@authdb/onetime_authdb \
  bundle exec rake db:migrate
psql -U postgres -f db/grants/postgres/rodauth_admin_roles.sql   # after editing CHANGE_ME
```

## Known drift between the inherited spec and production

`10-aggregate-visibility.md` counts `account_recovery_codes WHERE used_at IS
NULL`. The column exists in production's migration but Rodauth deletes a
recovery code on use, so `used_at` is always NULL and the stat is simply the
row count. Phase 2 should label it "unused recovery codes (rows)".
