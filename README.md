# Rodauth Admin

Standalone admin application for the Rodauth (`full`-mode) authentication
store behind [Onetime Secret](https://github.com/onetimesecret/onetimesecret):
the ~200k-account SQL authdb that the colonel console cannot see or touch.

**Status:** Phase 1 (bootstrap) in progress. The front door works end to end
against a local authdb; deploy target and production grants are not yet
applied.

## Read first

- [`docs/CHARTER.md`](docs/CHARTER.md) — why this is its own codebase, what it
  owns, architecture, five-phase plan, open questions. Revision 2 resolves
  operator identity: operators sign in with their **production** account,
  gated by an allowlist.
- [`docs/design/database-credentials.md`](docs/design/database-credentials.md)
  — one database, three credentials: runtime, read-only, and the tenant
  app's existing migrator. [`db/README.md`](db/README.md) has the
  operational side.
- [`docs/specs/inherited/`](docs/specs/inherited/) — verbatim copies of the
  main-repo specs this grew out of, read through the charter's §5 ledger.

## Ground rules (from the charter)

- Own front door, shared identity: operators authenticate here directly with
  their existing production Rodauth account. TOTP required, every session.
- Allowlist decides who may enter. Removing the row is offboarding.
- Own audit trail: `admin_actions`, append-only, reason required, written
  from the first sign-in.
- Two runtime credentials: an app role that writes exactly what a Rodauth
  sign-in touches plus the admin's own two tables, and a SELECT-only role
  for everything else. DDL only offline, through the tenant app's existing
  migrator.
- Read-only until Phase 4. No mutation ships before the guards exist.
- Three integration seams with the main repo, no more.

## Layout

```
config.ru                    rack entry point
lib/rodauth_admin.rb         boot: env validation, admin schema check, app load
lib/rodauth_admin/
  env.rb                     every ENV read; unset RACK_ENV means production
  database.rb                app / readonly / migrator connections
  auth.rb                    the Rodauth instance (login, otp, lockout, audit_logging)
  app.rb                     the Roda app: healthz, rodauth routes, allowlist gate, heartbeat
  allowlist.rb               admin_operators reads and audited writes
  audit.rb                   admin_actions writer
  authdb_schema.rb           production authdb shape as a rodauth-tools feature list
db/migrate/                  the admin tables (Sequel migrations, own bookkeeping table)
db/grants/postgres/          the two runtime roles and every grant
views/                       layout + heartbeat; Rodauth renders its own forms
try/, spec/                  tryouts (units) and RSpec (front-door flows)
```

## Local development

```bash
cp .env.example .env            # then edit; RACK_ENV=development
bundle install
bundle exec rake authdb:dev     # local authdb from rodauth-tools templates (SQLite)
bundle exec rake db:migrate     # admin_operators + admin_actions into the same file
```

Seed a Verified account into the local authdb (or point `ADMIN_DATABASE_URL*`
at a staging copy), then allowlist it — the reason is written to `admin_actions`:

```bash
bundle exec rake 'operators:add[you@example.com]' REASON="bootstrap operator"
bundle exec rackup                # http://localhost:9292
```

Sign in, enrol TOTP when prompted, and you should see the heartbeat.

```bash
bundle exec rake test             # tryouts + rspec
bundle exec rubocop
bundle exec rake authdb:status    # which authdb tables the door needs, and whether they exist
bundle exec rake audit:recent     # tail admin_actions
```

## Configuration

See `.env.example`. Two values are shared with the tenant app because the
identity is shared: `AUTH_SECRET` (OTP keys are HMAC'd with it) and
`ARGON2_SECRET` (password pepper). Rotate them together.
