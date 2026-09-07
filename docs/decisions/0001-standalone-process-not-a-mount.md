---
title: ADR-0001 — Rodauth Admin runs as its own process, reached through an SSH tunnel
status: Accepted
decided: 2026-09-06
context: CHARTER §1, §4 ("network placement"), §7 "Naming and hosting"
---

# ADR-0001: A standalone process behind an SSH tunnel, not a mount inside the tenant app

## Question

Should `onetimesecret/onetimesecret` add `rodauth-admin` to its Gemfile and
mount the Roda app under a path with the same network protections as
`/colonel`, or should the admin run as a separate process, bound to
loopback, reached with `ssh -L`?

## Decision

Separate process, loopback bind, SSH port forward. It is never mounted
inside the tenant app.

## Why not mount

Mounting is possible (the app is plain Rack) but undoes every advantage
the charter claims for a separate codebase:

- **One process, one Gemfile.lock.** Rodauth and Sequel versions get pinned
  by the tenant; an exception or memory issue in an admin screen lands in
  the process that serves secret sharing.
- **Delete privilege in the public process.** `rodauth_admin_verbs` can
  DELETE on fifteen authdb tables. Mounting puts that URL, `AUTH_SECRET`
  and `ARGON2_SECRET` into the environment of the internet-facing app. The
  third credential exists to keep delete privilege out of anything a
  public request can reach.
- **The colonel's protections are the weakness being escaped.** Same host,
  same Rack session middleware, the shared-cookie finding (A-6). The admin's
  own cookie, TTL and MFA-fresh step-up only mean something in a separate
  process.
- **Fail-closed boot collides.** The admin validates its env and the authdb
  schema at boot and refuses to start otherwise. Inside the tenant, drift on
  an admin-only concern would refuse to boot the tenant.

## Why the tunnel

- Zero public surface, which is the "admin network placement" §4 asks for.
- The tunnel is the outer layer only: operators still sign in with password
  plus TOTP at the admin's own door and the allowlist still gates entry.
- Single-digit operators and a support workflow that already involves SSH
  make the UX cost negligible.

## Consequences

- **Host.** Prefer a small admin or jump host with authdb access over the
  database server itself: running Ruby and holding the tenant's HMAC pepper
  on the Postgres host widens what a DB-host compromise yields. The DB host
  is acceptable if it is the only box with the right network position.
- **Cookie `secure` flag.** `lib/rodauth_admin/app.rb` sets
  `secure: Env.production?`, so a browser on `http://localhost:PORT` through
  the tunnel will not send the session cookie. Needs either local TLS
  termination or an explicit env flag that relaxes the flag only when the
  bind address is loopback. Not in the Phase 4 PR; a follow-up.
  `RODAUTH_ADMIN_HOST` feeds Rodauth's `domain` (used for links, not the
  cookie) and the OTP issuer, so it is unaffected.
- **Upgrade path.** If more operators later need browser access without
  SSH, front the same standalone process with BunnyCDN Shield rules. The
  process boundary is the decision; the tunnel is the first placement.
- Resolves the "whether it deploys beside the app or on separate
  infrastructure" half of CHARTER §7 "Naming and hosting". BunnyCDN
  fronting stays open until it is needed.
