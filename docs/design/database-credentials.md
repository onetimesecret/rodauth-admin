# Design: database credentials

Decided 2026-09-04. Refines CHARTER §4 ("two credentials, not one").

## The model

Rodauth Admin follows the same two-user pattern the tenant app already
runs for Rodauth: a runtime user with DML only, and a migration user that
owns the schema and is used only offline.

| Credential | ENV | Postgres role | Used by | Can |
|---|---|---|---|---|
| **app** (runtime) | `ADMIN_DATABASE_URL` | `rodauth_admin_app` (new) | the Rodauth login door; allowlist and `admin_actions` writes | SELECT on accounts and statuses; INSERT/UPDATE/DELETE on exactly the tables a sign-in touches (login failures, lockouts, OTP keys, auth audit log); DML on `admin_operators`; INSERT+SELECT on `admin_actions` |
| **read-only** | `ADMIN_DATABASE_URL_RO` | `rodauth_admin_ro` (new) | every admin query, Phase 2 onward | SELECT on the CHARTER §3 capability tables and the admin tables; column-level SELECT on password history (never the hashes) |
| **migrator** | `ADMIN_DATABASE_URL_MIGRATIONS` | `ots_migrator` (the tenant app's **existing** migration user) | `rake db:migrate`, `rake authdb:dev` | DDL. Owns every table, Rodauth's and the admin's |

All three point at the **same database**, the authdb. The admin's own
tables (`admin_operators`, `admin_actions`) live beside Rodauth's, prefixed
`admin_`, with their own migration bookkeeping table `admin_schema_info` so
they never collide with the tenant app's `schema_info`.

## Why

- **No additional migration user.** Migrations only run offline, by a
  person, with the migrator URL exported for that shell. The existing
  migrator already owns the database; giving it the admin tables too is
  one grant file fewer and one credential fewer to keep.
- **One runtime user for both the login path and the admin tables.** The
  login path needs writes on Rodauth's tables anyway (CHARTER §4); a
  separate runtime user for the two small admin tables would be a second
  credential with no security boundary behind it. The boundary that
  matters is between *runtime DML* and *DDL*, and between *writing* and
  *reading*, and both are kept.
- **A separate read-only user is kept.** Every admin screen from Phase 2
  reads through it. Phase 4 widens it to UPDATE/DELETE on token and key
  tables in a reviewed change to the grant file, and the login door's
  credential never grows.
- **Same database, not a second one.** The admin tables reference
  `accounts.id`; keeping them in the authdb makes that a real foreign key
  candidate later, keeps backups and failover in one place, and lets the
  existing migrator do the DDL.

## Consequences

- The running app never sees the migrator URL. `Env.validate!` does not
  require it; `Database.migrator` connects lazily and only from rake tasks.
- Append-only on `admin_actions` is enforced twice: a trigger that rejects
  UPDATE/DELETE for everyone including the owner, and the runtime role
  having no UPDATE/DELETE grant on it.
- SQLite in development uses one file for all three URLs. The grant
  boundaries exist only on PostgreSQL; the specs prove behaviour, the grant
  file proves privilege, and a Postgres CI lane is the place to prove both
  together.
- Rotating `rodauth_admin_app`'s password signs nobody out (sessions are
  cookie-encrypted with `RODAUTH_ADMIN_SESSION_SECRET`), but the process
  must be restarted with the new URL.

## Files

- `db/grants/postgres/rodauth_admin_roles.sql` — the two runtime roles and
  every grant. Run after `rake db:migrate` as the migrator or a superuser.
- `db/migrate/` — the admin tables, run by the migrator.
- `lib/rodauth_admin/env.rb`, `lib/rodauth_admin/database.rb` — the three
  connections.
