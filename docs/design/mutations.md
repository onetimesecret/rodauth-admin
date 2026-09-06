# Mutations

Phase 4 (CHARTER §3, §6 item 4). The read-only screens answer "what is going
on with this account"; the verbs are the small, named set of things an
operator may change about it. Everything here exists to make a mutation
either fully guarded and recorded, or not to happen.

## The guard chain

Every verb request — GET confirm and POST execute alike — passes all of
these, in this order. The first one that refuses ends the request.

1. **Allowlist and account status** (`app.rb`, before Rodauth's own routes).
   The signed-in identity must still be a Verified authdb account *and*
   still hold an `admin_operators` row. Re-read on every request, never
   cached in the session: removing the row ends the session on the next
   click.
2. **`require_authentication`** — password.
3. **`require_two_factor_setup`** — the operator has TOTP enrolled.
4. **MFA-fresh** (`Auth#require_fresh_mfa!`, `MFA_FRESH_SECONDS = 15 * 60`).
   Rodauth records *that* a second factor was used, never *when*, so we
   stamp `session['mfa_at']` in `after_two_factor_authentication` and in
   `after_otp_setup` (otp-setup does not run the former). On a stale GET the
   step-up takes the second factor back out of `authenticated_by` and calls
   Rodauth's `require_two_factor_authenticated`, which saves the requested
   path and redirects to `/otp-auth`; a valid code returns the operator to
   the confirm page they asked for. A stale POST is redirected to its own
   confirm GET and executes nothing — Rodauth only remembers a return path
   for a GET, so stepping up from a POST would strand the operator.
5. **CSRF** (`check_csrf!`, path-scoped tokens from `route_csrf`).
6. **Reason** — a non-blank `reason` parameter, raised as
   `Audit::BlankReason` by `Verbs` *before* the transaction opens, so a
   blank reason cannot reach a DELETE.

## The transaction-with-audit rule

The mutation and its `admin_actions` row commit together, in one
`db.transaction` on one connection — `Database.verbs`, the third runtime
credential (`docs/design/database-credentials.md`), which holds exactly the
DML the verbs need plus INSERT on `admin_actions`. A verb that deleted rows
and failed to record why is the one failure mode this tool exists to
prevent, so the audit row is written inside the block, never after it.

A verb with nothing to delete still runs and records zeroes: "we tried,
there was nothing" is a different fact from "we never tried".

Secrets stay out of the trail. Regenerated recovery codes are returned for a
single render and never written to metadata; an identity's `uid` is not
recorded either (for most providers it is the customer's email address).

## The self-target rule

`disable_mfa` and `regenerate_recovery_codes` are refused on the operator's
own account (`Verbs::SELF_REFUSED` → `Verbs::SelfTarget`, HTTP 403). An
admin tool that can strip its own operator's second factor is a
privilege-escalation path with a reason field attached. Operators change
their own MFA in the tenant app. Both buttons are hidden on the operator's
own account page rather than shown and refused.

`regenerate_recovery_codes` is also refused when the account has no TOTP and
no WebAuthn key (`Verbs::NoSecondFactor`, HTTP 422): recovery codes without a
second factor are a password-only login path that looks like MFA.

## Two tenant-side dependencies

Both were verified against the tenant app on 2026-09-05 and are stated
plainly on the confirm pages, because "this did less than you thought" is
worse discovered afterwards.

- **`force-password-reset`** — the tenant app does not currently enable
  Rodauth's `password_expiration` feature. The verb invalidates outstanding
  reset links and backdates the password-change time, but it will only force
  a new password at login once the tenant enables that feature.
- **`revoke-refresh-keys`** — the tenant app does not enable `jwt_refresh`,
  so this verb normally finds nothing.

## The verbs

| slug | touches |
|---|---|
| `clear-lockout` | `account_lockouts`, `account_login_failures` |
| `force-password-reset` | `account_password_change_times` (backdated to 1970), `account_password_reset_keys` |
| `expire-tokens` | password-reset, verification, login-change and email-auth keys |
| `disable-mfa` | OTP key, OTP unlock, recovery codes, WebAuthn keys and user ids |
| `regenerate-recovery-codes` | `account_recovery_codes` (replaced wholesale) |
| `revoke-sessions` | `account_active_session_keys` |
| `revoke-refresh-keys` | `account_jwt_refresh_keys` |
| `unlink-identity` (nested: `/accounts/:id/identities/:identity_id/unlink`) | one `account_identities` row |

## Deliberately not verbs

Not "not yet": these are things this tool should not be able to do, and
adding one is a charter decision, not a feature.

- **Changing a password or a password hash.** The verbs credential has no
  access to `account_password_hashes` at all. A support tool that can set a
  customer's password can impersonate them, and the reason field would be
  the only evidence.
- **Changing an account's status.** Closing, reopening or verifying an
  account is tenant-app business with tenant-app side effects (billing,
  email, the customer record). This tool would only change a number.
- **Changing an email address.** It is the login. Changing it here silently
  re-points an identity the tenant app owns, and the customer is never told.
- **Deleting an account.** Irreversible, and there is no support ticket that
  needs it inside fifteen minutes.
