---
title: ADR-0002 — A hand-built Debian package on system Ruby, secrets from systemd-creds
status: Accepted
decided: 2026-09-07
context: ADR-0001, CHARTER §7 "Naming and hosting"
---

# ADR-0002: A hand-built Debian package on system Ruby, secrets from systemd-creds

## Question

ADR-0001 fixed the shape — one standalone Puma process, bound to loopback,
reached with `ssh -L`, on a small admin or jump host. Nothing said how that
process gets onto the host, where its interpreter and gems come from, or how
six secrets reach it without landing in cleartext on disk.

## Decision

Ship a hand-built `dpkg-deb` package (`deb/` in this repo), installed with
`apt install ./rodauth-admin_*.deb`. It runs on Trixie's system Ruby 3.3, with
gems compiled into the system gem dir by the postinst from the committed
`Gemfile.lock`. Secrets are sealed with `systemd-creds` and exported into the
environment by a generic exec wrapper, so nothing in `lib/` learns about
credentials. Loopback is enforced by the kernel, not only by Puma's bind.

### Hand-built dpkg-deb, not debhelper, not a tarball, not a container

The fleet already has `ots-backup` (`onetime/monorepo/debs/ots-backup`): a
hand-built package in Debian-policy shape — units under
`/usr/lib/systemd/system`, `deb-systemd-helper`/`deb-systemd-invoke` in the
maintainer scripts, `tmpfiles.d`, man page, changelog and DEP-5 copyright, a
lintian gate and a podman systemd end-to-end test. Two packages, one mental
model, and the second one is mostly transcription.

It also builds on a Mac with `brew install dpkg`: no source package, no
`debian/rules`, no build chroot. `Architecture: all` — the payload is Ruby
text, unit files and shell. Everything debhelper would generate for us is
under sixty lines and has already been written once.

Against a tarball: `dpkg -V` integrity checking, `Depends:` that apt actually
enforces, clean remove and purge semantics, and `was-enabled` handling across
upgrades. Against a container: the host is a small admin box with one job, and
a container would add an image registry, a runtime and a second secrets path
to reach the same loopback socket.

Cost accepted: the maintainer scripts are hand-maintained rather than
generated. The lintian gate in the e2e is what catches drift.

### System Ruby 3.3, gems compiled at configure time, no vendoring

`Gemfile` now says `ruby '~> 3.3.0'`, which is exactly Trixie's system
interpreter, so the earlier obstacle (needing a newer Ruby than Debian ships)
is gone. Gems install from the committed `Gemfile.lock` into the system gem
dir (`/var/lib/gems/3.3.0`), driven by the postinst, so a single
`apt install` yields a runnable tree; `rodauth-admin install-gems` re-runs it.

No vendoring, and no bundled build of Ruby. Vendoring native extensions means
shipping binaries built against a libc and an OpenSSL we do not control at
install time; compiling on the host means the extension matches the host's
Ruby and its libraries, which is the same thing Debian's own ruby-* packages
do.

The cost is that `build-essential`, `ruby-dev` and `libssl-dev` sit in
`Depends:` of a binary package — a Policy smell, and honest about what the
install does. Puma, nio4r, bcrypt, argon2's vendored libargon2, json and
bigdecimal compile on the host; `pg`, `ffi` and `sqlite3` come precompiled
from the lock's Linux platforms. A failed compile leaves the package
unconfigured with bundler's output on screen, which is the loud failure we
want, and `apt install -f` retries after the fix.

### systemd-creds plus a generic env wrapper; the app stays env-var only

The app reads configuration from environment variables and nothing else.
Teaching `lib/` about `$CREDENTIALS_DIRECTORY` would tie a portable Rack app to
one init system, so the mapping lives in the package instead:
`/usr/lib/rodauth-admin/with-credentials` exports each file in
`$CREDENTIALS_DIRECTORY` as the environment variable named after it, then
`exec`s Puma. It knows nothing Debian-specific and works for any directory of
secret files (`CREDENTIALS_DIRECTORY=/run/secrets` under Docker, for example).

`EnvironmentFile=%d/...` cannot do this. Environment files are read by PID 1
while it is setting the unit up, before the child's credential mount exists,
so `%d` resolves to a path with nothing in it. systemd 257 has no native
credential-to-env mapping either. The wrapper is the mechanism, not a
preference.

The trade-off, stated plainly: the secrets end up in Puma's environment, so
`/proc/<pid>/environ` holds them. That file is readable only by the service
user and root, and `ProtectProc=invisible` hides the process from other users
— but it is a real exposure that a credentials-file design would not have. It
is still strictly better than `EnvironmentFile=`: nothing is in cleartext on
disk, and `systemctl show` reveals nothing.

Six credentials are sealed and loaded: `RODAUTH_ADMIN_SESSION_SECRET`,
`AUTH_SECRET`, `ARGON2_SECRET`, `ADMIN_DATABASE_URL`, `ADMIN_DATABASE_URL_RO`
and `ADMIN_DATABASE_URL_VERBS`. `ADMIN_DATABASE_URL_MIGRATIONS` is deliberately
absent: the running unit never holds a credential that can alter the schema.

### Loopback enforced by IPAddressDeny, with a per-host authdb drop-in

ADR-0001's "zero public surface" is worth enforcing below the application.
The unit carries `IPAddressDeny=any` with `IPAddressAllow=localhost`, so even a
misconfigured bind address cannot reach the network. The authdb is the one
exception, and its address differs per host, so it is not in the package:

```
/etc/systemd/system/rodauth-admin.service.d/10-authdb.conf
[Service]
IPAddressAllow=<authdb ip>/32
```

Consequence: DNS is blocked too, so the sealed database URLs must use IP
literals. (Allowing the resolver in the same drop-in would work; using
literals keeps the allowed set to one address.) This is written down here
because a hostname in a sealed URL fails at connect time with an error that
does not obviously point at the drop-in.

The rest of the sandbox is the usual `systemd-analyze security` set
(`ProtectSystem=strict`, `NoNewPrivileges`, empty capability set,
`SystemCallFilter=@system-service`, `ProtectProc=invisible`, and so on); the
unit scores 1.4. One directive is deliberately off:
`MemoryDenyWriteExecute`. The argon2 gem binds libargon2 through ffi, and
ffi's `attach_function` maps each method trampoline writable and executable;
with W^X enforced the app dies at boot inside `ffi/function.rb`. That was
measured in the e2e, not predicted, and it is the reason the e2e starts the
real unit rather than trusting `rodauth-admin check`, whose transient unit
carries the credentials but not the sandbox.

### Migrations through a transient unit, with a credential never sealed

`rodauth-admin migrate` prompts for `ADMIN_DATABASE_URL_MIGRATIONS`, writes it
`0600` into `/run/rodauth-admin` (tmpfs) under a `trap` that removes it, and
runs `rake db:migrate` in a transient `systemd-run` unit that loads it with
`LoadCredential=`. Never `SetCredential=`, which is visible over D-Bus.

So the schema-altering credential exists only for the duration of one operator
command, is never sealed onto the host, and never appears in any unit the
service reads. Migrations stay offline and deliberate, matching `boot!`'s
refusal to migrate.

### Sealing with --with-key=host, and what re-imaging costs

`seal` passes `--with-key=host` explicitly. Hetzner Cloud instances have no
vTPM, and `--with-key=auto` would silently choose the TPM on a future host,
producing sealed files that a restored or copied credstore could not decrypt —
a failure that surfaces only at the next boot on new hardware.

Consequence, stated in the man page and the runbook: the host key is bound to
the machine, so re-imaging the VM invalidates every sealed file. The six
secrets must be re-sealed on the new host. They are recoverable from wherever
they are held of record; this is a rebuild step, not data loss.

### Fail-closed boot exits 78, and the unit never retries it

`config.ru` rescues `RodauthAdmin::ConfigurationError` around `boot!`, logs it
at fatal, and exits 78 (EX_CONFIG, sysexits(3)). The unit sets
`RestartPreventExitStatus=78`, so a bad secret or authdb schema drift stops the
service at the first attempt instead of restart-looping until the start limit
trips. `boot!` itself keeps raising — the specs depend on that — and the
process-level translation lives at the process boundary.

Sysexits rather than a Debian-specific convention: the number means the same
thing to anything else that runs this app.

## Consequences

- Resolves the "how it deploys" half of CHARTER §7 "Naming and hosting": a
  `.deb` delivered by `scp` and `apt install`, no apt repository, operator
  runbook in `deb/README.md`.
- The app gains no deployment-specific code. The one repo change outside
  `deb/` is the `exit 78` in `config.ru`.
- Six secrets and one drop-in are host state that no package upgrade manages.
  Purge removes them; re-imaging invalidates them.
- **Still open.** How BunnyCDN Shield fronts the process, if it ever needs to
  (ADR-0001's upgrade path). And whether this same package serves a future
  TLS-fronted deployment: the unit's `IPAddressDeny=any`, the loopback bind and
  the relaxed cookie `Secure` flag would all need revisiting, but the package
  shape, the credential plumbing and the gem install would not.
