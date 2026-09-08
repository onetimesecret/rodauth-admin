# Rodauth Admin

Standalone admin application for the Rodauth (`full`-mode) authentication
store behind [Onetime Secret](https://github.com/onetimesecret/onetimesecret):
the ~200k-account SQL authdb that the colonel console cannot see or touch.

**Status:** Phase 1 (bootstrap), Phase 2 (aggregate visibility) and Phase 3
(account detail) done; **Phase 4 (mutations) is in progress on this branch.**
The front door works end to end against a local authdb, the read-only stats
board and the locked / orphaned lists are in, and so is the account detail
page: a `/account?q=<email or external_id>` lookup and an `/accounts/<id>`
page showing status, lockout, MFA inventory, sessions, API refresh tokens,
pending tokens, SSO identities, password age and the paginated auth-event
timeline. Phase 4 adds the mutation verbs on top of it — clear lockout,
force password reset, expire pending tokens, disable MFA, regenerate
recovery codes, revoke sessions, revoke API refresh tokens and unlink an SSO
identity — each one a confirm page and a POST, guarded by a reason, an
`admin_actions` row written in the same transaction, its own database
credential, and an **MFA-fresh session**: a second factor older than fifteen
minutes is stepped up through `/otp-auth` before a verb page will open, and
a stale POST is sent back to its confirm page instead of executing
([`docs/design/mutations.md`](docs/design/mutations.md)). Two verbs
(disable MFA, regenerate recovery codes) are refused on the operator's own
account. A quality phase on top adds
the checks: `bin/ci`, git hooks, five CI jobs and a branch rule
([`docs/design/quality-gates.md`](docs/design/quality-gates.md)). Deploy
target and production grants are not yet applied.

## Read first

- [`docs/CHARTER.md`](docs/CHARTER.md) — why this is its own codebase, what it
  owns, architecture, five-phase plan, open questions. Revision 4 records the
  Phase 4 decision to give the mutations their own database credential;
  revision 2 resolved operator identity: operators sign in with their
  **production** account, gated by an allowlist.
- [`docs/design/database-credentials.md`](docs/design/database-credentials.md)
  — one database, four credentials: runtime, read-only, mutations, and the
  tenant app's existing migrator. [`db/README.md`](db/README.md) has the
  operational side.
- [`docs/design/mutations.md`](docs/design/mutations.md) — the mutation
  verbs: the guard chain per request, the transaction-with-audit rule, the
  self-target rule, the two tenant-side dependencies, and what is
  deliberately not a verb.
- [`docs/decisions/`](docs/decisions/) — ADRs; 0001 is why this is a
  standalone process behind an SSH tunnel, never a mount in the tenant app.
- [`docs/design/quality-gates.md`](docs/design/quality-gates.md) — what runs
  where: editor, pre-commit, pre-push, CI, branch rule; and what is
  deliberately not gated.
- [`docs/specs/inherited/`](docs/specs/inherited/) — verbatim copies of the
  main-repo specs this grew out of, read through the charter's §5 ledger.

## Ground rules (from the charter)

- Own front door, shared identity: operators authenticate here directly with
  their existing production Rodauth account. TOTP required, every session.
- Allowlist decides who may enter. Removing the row is offboarding.
- Own audit trail: `admin_actions`, append-only, reason required, written
  from the first sign-in.
- Three runtime credentials: an app role that writes exactly what a Rodauth
  sign-in touches plus the admin's own two tables, a SELECT-only role for
  every query, and a verbs role that can delete exactly the tables the Phase 4
  mutations name. DDL only offline, through the tenant app's existing
  migrator.
- No mutation without its guards: reason required, MFA-fresh session,
  `admin_actions` row, and the mutation credential — never the read-only one
  (`docs/design/database-credentials.md`, Phase 4 revision).
- Three integration seams with the main repo, no more.

## Layout

```
config.ru                    rack entry point
config/puma.rb                the server bind; loopback both listens and relaxes the cookie
bin/setup                    bundle install + install the git hooks
bin/ci                       the single definition of "the checks" (lint, try, rspec, audit)
.pre-commit-config.yaml      pre-commit hooks; pre-push runs bin/ci
lib/rodauth_admin.rb         boot: env validation, admin schema check, app load
lib/rodauth_admin/
  env.rb                     every ENV read; unset RACK_ENV means production
  database.rb                app / readonly / verbs / migrator connections
  auth.rb                    the Rodauth instance (login, otp, lockout, audit_logging)
  app.rb                     the Roda app: healthz, rodauth routes, allowlist gate, stats board, account lists
  allowlist.rb               admin_operators reads and audited writes
  audit.rb                   admin_actions writer
  stats.rb                   aggregate authdb counts, briefly cached, degrades to unavailable
  account_list.rb            the locked / orphaned account lists, filtered and paginated
  account_detail.rb          the per-account read side
  verbs.rb                   the Phase 4 mutations: reason required, audited in the same transaction
  verb_routes.rb             the verbs' confirm/execute routes, the MFA-fresh guard and the per-verb copy
  authdb_schema.rb           production authdb shape as a rodauth-tools feature list
db/migrate/                  the admin tables (Sequel migrations, own bookkeeping table)
db/grants/postgres/          the three runtime roles and every grant
views/                       layout, stats board, account lists; Rodauth renders its own forms
try/, spec/                  tryouts (units) and RSpec (front-door flows)
docs/design/                 database-credentials.md, mutations.md, quality-gates.md
```

## Local development

```bash
bin/setup                       # bundle install + install the git hooks
cp .env.example .env            # then edit; RACK_ENV=development
                                # ADMIN_DATABASE_URL, _RO and _VERBS may all be
                                # the same SQLite file locally; _MIGRATIONS too

bundle exec rake authdb:dev     # local authdb from rodauth-tools templates (SQLite)
bundle exec rake db:migrate     # admin_operators + admin_actions into the same file
```

Seed a Verified account into the local authdb (or point `ADMIN_DATABASE_URL*`
at a staging copy), then allowlist it — the reason is written to `admin_actions`:

```bash
bundle exec rake 'operators:add[you@example.com]' REASON="bootstrap operator"
bundle exec puma                  # http://localhost:9292 (reads config/puma.rb)
```

Sign in, enrol TOTP when prompted, and you should see the stats board.

`COLONEL_CONSOLE_URL` is optional: set it to the tenant app's base URL and
each account's `external_id` renders as a deep link into the colonel console
(nothing is ever requested from it).

```bash
bundle exec rake authdb:status    # which authdb tables the door needs, and whether they exist
bundle exec rake audit:recent     # tail admin_actions
```

### Checks

```bash
bin/ci                            # lint, tryouts, rspec — stops at the first failure
bin/ci lint                       # one stage; also: try, rspec, audit
pre-commit run --all-files        # the commit-stage hooks over the whole tree
```

`bin/ci` is the single entry point. `rake test`, the pre-push hook and every
CI job call it, so there is no second command line to keep in sync — see
[`docs/design/quality-gates.md`](docs/design/quality-gates.md) for the layered
model, the RACK_ENV rule and how to add a check.

The direnv shell is safe: it stays `RACK_ENV=development` with
`ADMIN_DATABASE_URL` pointing at your real local authdb, and both `bin/ci` and
the specs ignore inherited URLs unless the caller set `RACK_ENV=test` first.
They build a scratch SQLite instead.

CI runs the same suite twice: once on scratch SQLite (`test`), and once on a
real PostgreSQL authdb with `db/grants/postgres/rodauth_admin_roles.sql`
applied and distinct roles per credential (`test-postgres`), which is the only place
the grants and the append-only trigger are proven rather than assumed
(`spec/grants_spec.rb`, `db/README.md`). Alongside them: `lint` (RuboCop),
`hygiene` (the pre-commit hooks over every file), `secrets` (gitleaks over the
full history) and `audit` (bundler-audit).

## Configuration

See `.env.example`. Two values are shared with the tenant app because the
identity is shared: `AUTH_SECRET` (OTP keys are HMAC'd with it) and
`ARGON2_SECRET` (password pepper). Rotate them together.

## Deploy

`deb/` builds a Debian package for Trixie: system Ruby 3.3, gems compiled from
the committed lockfile at install time, one systemd unit bound to loopback, and
the six secrets sealed with `systemd-creds` rather than written to disk. It is
delivered by `scp` and `apt install ./rodauth-admin_*.deb` — there is no apt
repository.

`deb/README.md` is the operator runbook: build, deliver, seal, migrate, check,
start, reach it over `ssh -L`, upgrade, rotate, remove.
[ADR-0002](docs/decisions/0002-debian-package.md) records why the package looks
the way it does; [ADR-0001](docs/decisions/0001-standalone-process-not-a-mount.md)
records why it is a standalone process at all.
