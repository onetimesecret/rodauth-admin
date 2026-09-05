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
# The grant file takes the database name and the two role passwords as psql
# variables, so nothing in it has to be edited and a password containing
# '/', '&' or a quote survives intact.
psql -U postgres -v ON_ERROR_STOP=1 \
     -v dbname=onetime_authdb \
     -v app_pw="$APP_ROLE_PASSWORD" -v ro_pw="$RO_ROLE_PASSWORD" \
     -f db/grants/postgres/rodauth_admin_roles.sql
```

## CI

`docs/design/database-credentials.md` says the specs prove behaviour, the
grant file proves privilege, and a Postgres CI lane is the place to prove
both together. That lane is `test-postgres` in
`.github/workflows/ci.yml`. Against a `postgres:16` service container it:

1. creates `onetime_authdb_ci` as the superuser (standing in for
   `ots_migrator` — the only credential in the job that runs DDL);
2. builds Rodauth's tables with `rake authdb:dev`, which on PostgreSQL also
   creates the two SECURITY DEFINER password functions production has;
3. runs `rake db:migrate` for the admin tables and their trigger;
4. applies `db/grants/postgres/rodauth_admin_roles.sql` verbatim, passing
   the database name and the two passwords as psql variables exactly as the
   command above does — the file is reviewed like code, so it is executed
   like code, and no text substitution touches it;
5. runs the whole suite with `ADMIN_DATABASE_URL` as `rodauth_admin_app`,
   `ADMIN_DATABASE_URL_RO` as `rodauth_admin_ro`, and
   `ADMIN_DATABASE_URL_MIGRATIONS` as the superuser.

What that proves, and nothing else does:

- the grants are **sufficient** — the front-door specs sign in, enrol TOTP,
  lock out and write `admin_actions` as `rodauth_admin_app` with no privilege
  it was not deliberately given, through the password functions rather than
  the hash table;
- the grants are **restrictive** — `spec/grants_spec.rb` asserts
  `rodauth_admin_ro` can read every Phase 2 table, cannot see a password
  hash, cannot call the password functions, and cannot write; and that
  `rodauth_admin_app` cannot UPDATE or DELETE `admin_actions`;
- the **trigger** is the second lock — the same spec shows the migrator that
  owns `admin_actions` is refused too, which no grant can express.

On SQLite there are no roles and the grant file is inert, so
`spec/grants_spec.rb` skips cleanly and the default lane stays fast.

The CI database is named `onetime_authdb_ci`, not `onetime_authdb`, because
`spec/spec_helper.rb` refuses to run at all against a database that does not
look disposable — the suite truncates every account table before each
example, and does it through the *migrator* credential, so the name must
match `(^|_)(test|ci|scratch)($|_)` (or `RODAUTH_ADMIN_ALLOW_DESTRUCTIVE_SPECS=1`
must be set deliberately).

The check (`spec/support/scratch_guard.rb`, unit-tested by
`try/scratch_guard_try.rb`) covers **all three** URLs — `ADMIN_DATABASE_URL`,
`ADMIN_DATABASE_URL_RO` and `ADMIN_DATABASE_URL_MIGRATIONS` — before anything
connects, and re-checks the resolved `opts[:database]` of the connections
afterwards. Copying the migrator URL from the tenant app's existing
environment (as the section above suggests) while pointing the app URL at a
`_ci` database is therefore refused, not silently obeyed: the destructive
statements run through the migrator.

## Known drift between the inherited spec and production

`10-aggregate-visibility.md` counts `account_recovery_codes WHERE used_at IS
NULL`. The column exists in production's migration but Rodauth deletes a
recovery code on use, so `used_at` is always NULL and the stat is simply the
row count. Phase 2 should label it "unused recovery codes (rows)".
