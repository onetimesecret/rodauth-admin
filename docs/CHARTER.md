---
title: Rodauth Admin — project charter
status: Accepted
decided: 2026-09-01
revision: 4 (2026-09-05) — Phase 4 decision: third runtime credential for verbs
repo-created: 2026-09-04
supersedes-in-part: onetimesecret/onetimesecret docs/specs/rodauth-admin (see docs/specs/inherited/)
published: https://claude.ai/code/artifact/b39b6c4c-0e7b-4dbb-9e28-d9f1c7ab5acb
---

# Rodauth Admin

A **dedicated codebase** for administering the Rodauth (`full`-mode)
authentication system: the SQL store behind ~200k production accounts that the
colonel console cannot see or touch today.

## 1. The decision this charter records

The in-repo spec (`docs/specs/rodauth-admin/00-scope.md`, status Proposed)
scoped this work as a graft: new panels inside the existing colonel console,
new routes inside `apps/api/colonel/`, with "no second admin app or API
namespace" listed as an explicit non-goal.

> **Pivot.** That non-goal is reversed. Rodauth Admin becomes its own codebase
> — a standalone admin application over the authdb — developed and deployed
> separately from `onetimesecret/onetimesecret`. The main-repo colonel work
> (three remaining epics: Colonel Hardening, Audit Integrity, Runtime Control
> Plane & Visibility) proceeds independently and does not wait on it.

The reversal has real advantages the original spec couldn't claim: an isolated
blast radius (a bug in an admin screen can't take down secret-sharing), its own
deploy cadence and dependency set, an authentication story that doesn't
inherit the colonel console's shared-cookie weakness, and a codebase small
enough to audit in an afternoon — which is the right property for the tool
that holds the keys.

## 2. The gap it closes

Production runs `AUTHENTICATION_MODE=full`: identity truth lives in SQL
(Sequel/Rodauth, 24 tables), while the colonel console administers only the
Familia/Redis `Customer` model. The gap assessment's Theme C findings, all of
which move here:

| ID | Finding |
|---|---|
| **C-1** | **Lockouts are invisible and unfixable.** Lockout is enabled (`max_invalid_logins 5`) but no operator can list who is locked out or clear a lockout; the only unlock path is user-email-driven. `POST /ratelimit/reset` resets OTS limiters, not Rodauth lockouts — a standing operator confusion. |
| **C-2** | **No admin verbs for MFA, password reset, SQL sessions, JWT keys, or SSO links.** `DisableMfa` is console-session-scoped by explicit design comment; every other path is self-service only. A support case with a locked-out MFA user has no sanctioned resolution. |
| **C-3** | **The sessions console reads the wrong store in full mode.** It lists Familia sessions; `account_active_session_keys` is the full-mode authority. Operators act on a picture that may not represent reality. |
| **C-4** | **No aggregate surface.** Unverified backlog, MFA adoption, active lockouts, orphan accounts, Redis↔SQL drift — the only implementation is a dev-only stub with no role check (`apps/web/auth/routes/admin.rb`). |
| **B-7** | **Half the incident timeline lives here.** Rodauth's `account_authentication_audit_logs` (failed logins, lockouts, password changes) is a store the colonel audit trail can never show. Rodauth Admin is where that half becomes readable. |

## 3. What the codebase owns

The capability table from the in-repo spec survives the pivot intact — it
enumerates authdb tables backing *enabled* features, cross-referenced against
`apps/web/auth/config.rb`. Rodauth Admin is the sole admin owner of all of it:

| Tables | Capability |
|---|---|
| `accounts` · `account_statuses` | Status (Unverified / Verified / Closed), created/updated; aggregate breakdowns |
| `account_login_failures` · `account_lockouts` | Failure counts; **list active lockouts, clear a lockout** |
| `account_otp_keys` · `account_recovery_codes` · `account_otp_unlocks` | MFA status; **disable MFA, regenerate recovery codes** |
| `account_webauthn_keys` · `account_webauthn_user_ids` | List / remove passkeys |
| `account_active_session_keys` | View / revoke SQL sessions — the full-mode session authority |
| `account_jwt_refresh_keys` | View / revoke API refresh tokens |
| `account_password_reset_keys` · `account_verification_keys` · `account_login_change_keys` · `account_email_auth_keys` | Pending tokens; resend / expire; **force a password reset** |
| `account_identities` | Linked SSO providers; unlink |
| `account_password_change_times` · `account_previous_password_hashes` | Password age; reuse-history count (never hash material) |
| `account_authentication_audit_logs` | Read-only per-account auth timeline, paginated |

Two subtleties the original spec called out still bind:

- **Two audit trails, not one.** Rodauth's auth-event log is display data;
  admin *actions* get their own audit record.
- **The join key is real.** `accounts.external_id == Customer.extid`,
  populated and maintained by `sync_auth_accounts_command.rb`, is how screens
  link back to the colonel console's customer pages.

## 4. Architecture sketch

Smallest thing that is honestly a separate product:

- **Stack:** a small Roda + Sequel application over the authdb — the same
  idioms as `apps/web/auth`, so patterns (and eventually code) transfer, but
  its own Gemfile, its own migrations for its own tables, its own CI.
  Server-rendered screens are enough; this tool's users number in the single
  digits and a Vue build pipeline is weight the codebase shouldn't carry at
  birth.
- **Database posture — two credentials, not one:** Rodauth login writes on
  every sign-in (login failures, lockouts, the auth audit log, the OTP
  last-use timestamp, recovery-code consumption), so the admin's own Rodauth
  instance gets a credential with INSERT/UPDATE/DELETE on exactly those tables
  from day one. The admin *query* path keeps a separate SELECT-only
  credential; Phase 4 mutations widen that one to UPDATE/DELETE on the token
  and key tables — never DDL, never the migrations URL.
  [Revision 4 (2026-09-05): they do not. The mutations got a *third* runtime
  credential, `rodauth_admin_verbs` / `ADMIN_DATABASE_URL_VERBS`, and the
  read-only role stays SELECT-only — a role named `_ro` that can DELETE
  misleads the next reader, and every read screen would otherwise run with
  delete privilege. See docs/design/database-credentials.md.] Rodauth's `db` setting
  takes its own Sequel database, so the split is one line of config, and both
  grant lists live in the repo, reviewed like code.
- **Its own front door, the operator's existing identity:** operators sign in
  to Rodauth Admin directly — a Rodauth instance of its own (it would be
  strange not to dogfood) — but with their *production* account. Operators
  are already Rodauth accounts with passwords and MFA enrolled; a second
  accounts table would mean two credentials, two MFA enrollments, and two
  places to offboard someone. Same identity, same MFA, and an **allowlist
  decides who may enter** — the single sign-on argument, and it wins. Shared
  identity is not shared session: the admin has its own cookie, domain, and
  TTL, so nothing about the tenant app's session reaches it and the colonel
  console's A-6 finding is still sidestepped, not inherited. Skip the
  `active_sessions` feature on this instance — otherwise operator admin
  sessions land in the production session-key table, and a Phase 4 "revoke
  all sessions" on their own account kills their admin session mid-action;
  short cookie TTL plus MFA-fresh checks cover it. Network placement (admin
  host / VPN / BunnyCDN Shield rules) adds the outer layer.
- **The allowlist is the admin's own table** — the only thing this app owns
  identity-wise, alongside `admin_actions`. A row admits an account to the
  admin; removing the row is offboarding. Two consequences of the shared
  identity are accepted, eyes open: lockout couples both ways (five bad
  attempts at the admin door lock the operator's tenant account too — correct
  for one identity, and network placement limits who can attempt it), and
  admin sign-ins land in the production auth-event log alongside the
  operator's tenant activity — acceptable, but the admin instance tags its
  audit messages, and `admin_actions` records sign-ins regardless.
- **Its own audit trail, in SQL:** an `admin_actions` table — append-only,
  reason column from day one, trivially exportable. This is the durability
  posture the Redis-backed `ColonelAuditEvent` is still working toward (Audit
  Integrity epic); here it's free because the store is already durable.
- **Read-only for as long as possible:** Phases 1–2 ship no mutation. The
  first destructive verb arrives only after the audit table and MFA-gated auth
  exist — the standalone app gets to enforce the "guards before verbs" ordering
  that the colonel console's history shows is hard to retrofit.

> **Integration seams — deliberately few.** Three touchpoints with the main
> repo, and no more:
>
> 1. read-only use of the `external_id` join to deep-link customer pages in
>    the colonel console (and eventually the reverse link from customer
>    detail);
> 2. the sessions-console dual-authority problem — the main repo's console
>    should *say* it is non-authoritative in full mode and link here, rather
>    than growing SQL awareness itself;
> 3. deleting the dev stub `apps/web/auth/routes/admin.rb` once Phase 1
>    supersedes it.
>
> Operator sign-in against the production `accounts` table is a
> database-level fact of the shared identity, not a service seam. No shared
> session, no cross-service API calls in v1.

**The residual risk is the obvious one:** compromising an operator's tenant
password gets an attacker to the MFA prompt of the admin. That is the same
posture as any internal tool behind corporate SSO, and MFA required plus
allowlist plus admin-network placement is the standard answer.

## 5. What carries over, what the pivot changes

Read against `00-scope.md` and `10-aggregate-visibility.md`
(`docs/specs/inherited/`):

| | |
|---|---|
| **Carries** | The capability table (§3), the enabled-features filter behind it, and the join-key verification. |
| **Carries** | Phase-1 substance: the nine aggregate stats, the `locked` / `orphaned` filtered lists, strict filter whitelisting, pagination caps. |
| **Carries** | Performance guardrails at 200k rows: brief stats caching, `deadline > now` on every lockout read, per-account-only audit-log display, "active session keys ≠ users online" labeling, positional status-id caution. |
| **Carries** | Graceful degradation: authdb unreachable → an explanatory state, never a 500. |
| **Changes** | "No second admin app" non-goal → reversed; that is now the whole point. The colonel-ui dependency chain (UI kit, resource stores, Zod schemas, sections.ts nav) drops away entirely. |
| **Changes** | Per-account Rodauth panels no longer graft onto `AdminCustomerDetail` — they are Rodauth Admin's own account detail page, with a deep link from the colonel customer page replacing the embedded panel. |
| **Changes** | Authorization: `role=colonel` + `verify_one_of_roles!` is a main-repo idiom; here, the operator's identity is their existing production Rodauth account (same credential, same MFA enrollment), and this codebase owns only the allowlist table, the MFA-required policy, and its own session settings. |
| **Changes** | Audit: mutations write the local `admin_actions` table, not `ColonelAuditEvent` — one store per codebase, exportable, reason-required. |
| **Changes** | Sessions-console mode-awareness (old Phase 3) is descoped from the main repo: the console labels itself non-authoritative in full mode and links here. |

## 6. Phasing

1. **Bootstrap.** Repo, CI, deploy target on the admin network, the two DB
   credentials (auth-path writes on Rodauth's login tables; SELECT-only for
   queries) [revision 4: a third, mutation-only credential joins them in
   Phase 4 rather than the read-only one being widened], sign-in with the operator's existing production account — MFA
   required, `active_sessions` off — gated by the allowlist table, and the
   `admin_actions` table (written from day one, even for sign-ins). Exit: an
   operator can log in and see a heartbeat.
2. **Aggregate visibility.** The `10-aggregate-visibility.md` content,
   relocated: stats board (status breakdown, MFA adoption, active lockouts,
   active session keys, unused recovery codes, orphans, customer-count drift)
   plus the locked and orphaned lists. Read-only. This is the remediation
   milestone for the live gap.
3. **Account detail, read-only.** Per-account page keyed by email or
   `external_id`: status, MFA inventory, sessions, pending tokens, SSO
   identities, password age, and the Rodauth auth-event timeline (B-7's
   missing half). Deep links to/from the colonel customer page via `extid`.
4. **Mutations.** In support-pain order: clear lockout (C-1) → force password
   reset & expire tokens → disable MFA / regenerate recovery codes (C-2) →
   revoke SQL sessions & JWT refresh keys → unlink SSO. Every verb: reason
   required, MFA-fresh session, `admin_actions` row.
5. **Retire the stopgaps.** Delete `apps/web/auth/routes/admin.rb`; add the
   non-authoritative banner + outbound link to the main repo's sessions
   console; fold what remains of `docs/specs/rodauth-admin/` into this
   codebase's docs, leaving a pointer behind.

## 7. Open questions

- **Operator identity source — decided (2026-09-05):** an allowlisted subset
  of the production `accounts` table. One identity, one MFA enrollment, one
  offboarding action; see §4 for the session, lockout, and audit
  consequences.
- **Naming and hosting.** ~~Repo name~~ (resolved: `onetimesecret/rodauth-admin`),
  whether it deploys beside the app or on separate infrastructure, and how
  BunnyCDN Shield fronts it.
- **Multi-region.** The diagnostics runbook's "check the other regions by
  hand" problem: does Rodauth Admin connect to one authdb per deployment, or
  federate reads across regions? V1 answer should be per-region; note the
  ambition.
- **Password-history display** — count only, but confirm with security review
  before shipping (inherited open question).
- **Redis-side reads — decided (2026-09-05):** neither, in v1. Rodauth Admin
  holds no Redis credential and makes no cross-service call, which keeps the
  §4 integration-seam count honest and the blast radius one database wide.
  The customer-count drift stat ships behind a pluggable
  `customer_count_source` seam whose default is a null source: the stat
  renders "not configured" rather than a wrong number or a 500. The intended
  future source is the tiny stats endpoint on the main app — one read, no
  credential shared, and the seam already exists to take it. Everything else
  on the Phase 2 board is computed from the authdb and is unaffected.

---

Companion to the Colonel Gap Assessment (same review, 2026-08-31). Sources:
`docs/specs/rodauth-admin/00-scope.md`, `10-aggregate-visibility.md`,
`apps/web/auth/` migrations and config, and Theme C of the gap assessment. The
in-repo spec's verified facts are treated as authoritative; where this charter
contradicts it, the contradiction is the point (§1, §5).
