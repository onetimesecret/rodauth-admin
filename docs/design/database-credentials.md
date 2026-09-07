# Design: database credentials

Decided 2026-09-04. Refines CHARTER §4 ("two credentials, not one").

## The model

Rodauth Admin follows the same two-user pattern the tenant app already
runs for Rodauth: runtime users with DML only, and a migration user that
owns the schema and is used only offline. Phase 4 added a third runtime
user for the mutations rather than widening the read-only one.

| Credential | ENV | Postgres role | Used by | Can |
|---|---|---|---|---|
| **app** (runtime) | `ADMIN_DATABASE_URL` | `rodauth_admin_app` (new) | the Rodauth login door; allowlist and `admin_actions` writes | SELECT on accounts and statuses; INSERT/UPDATE/DELETE on exactly the tables a sign-in touches (login failures, lockouts, OTP keys, auth audit log); DML on `admin_operators`; INSERT+SELECT on `admin_actions` |
| **read-only** | `ADMIN_DATABASE_URL_RO` | `rodauth_admin_ro` (new) | every admin query, Phase 2 onward | SELECT on the CHARTER §3 capability tables and the admin tables; column-level SELECT on password history (never the hashes) |
| **verbs** (runtime) | `ADMIN_DATABASE_URL_VERBS` | `rodauth_admin_verbs` (new, Phase 4) | the Phase 4 mutation verbs and the `admin_actions` row each commits with | SELECT on `accounts`, `account_statuses` and every table it mutates; DELETE on the lockout, failure, token, MFA, session, refresh-key and identity tables; INSERT on `account_recovery_codes`; INSERT+UPDATE on `account_password_change_times`; INSERT+SELECT on `admin_actions` |
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
- **A separate read-only user is kept, and stays read-only.** Every admin
  screen from Phase 2 reads through it, and the login door's credential
  never grows.

### Phase 4 revision (2026-09-05): a third runtime credential, not a wider `_ro`

CHARTER §4 and the first version of this document said Phase 4 would widen
`rodauth_admin_ro` to UPDATE/DELETE on the token and key tables. It did not.
A role named `_ro` that can DELETE is a trap: the next person to read the
connection string during an incident will believe the name, and every read
screen — the stats board, the lists, the account page, all of which run on
that role continuously — would have been holding delete privilege for the
sake of seven POST handlers. The alternative costs one environment variable
and one CREATE ROLE, and buys a boundary that is true by construction:
`rodauth_admin_verbs` can delete exactly the fourteen tables the verbs name
and nothing else, `rodauth_admin_ro` remains SELECT-only, and
`spec/grants_spec.rb` asserts both directions on the PostgreSQL lane.

The verbs role also holds INSERT+SELECT on `admin_actions` because the audit
row is written in the **same transaction on the same connection** as the
mutation: either the change and its reason both land, or neither does.
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
- The verbs credential is the only runtime role that can remove account
  data, and `healthz` probes it alongside `app` and `readonly` so a
  misconfigured URL is visible before an operator needs a verb rather than
  during.
- SQLite in development uses one file for all four URLs. The grant
  boundaries exist only on PostgreSQL; the specs prove behaviour, the grant
  file proves privilege, and a Postgres CI lane is the place to prove both
  together.
- Rotating `rodauth_admin_app`'s password signs nobody out (sessions are
  cookie-encrypted with `RODAUTH_ADMIN_SESSION_SECRET`), but the process
  must be restarted with the new URL.

## Files

- `db/grants/postgres/rodauth_admin_roles.sql` — the three runtime roles and
  every grant. Run after `rake db:migrate` as the migrator or a superuser.
- `db/migrate/` — the admin tables, run by the migrator.
- `lib/rodauth_admin/env.rb`, `lib/rodauth_admin/database.rb` — the four
  connections (`app`, `readonly`, `verbs`, `migrator`).
