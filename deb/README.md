# rodauth-admin (Debian package)

Debian package for the Rodauth Admin service on Trixie. One Puma process
bound to `127.0.0.1`, reached over an SSH tunnel ([ADR-0001](../docs/decisions/0001-standalone-process-not-a-mount.md)).
Hand-built (no debhelper) in the same shape as `ots-backup`: units under
`/usr/lib/systemd/system`, `deb-systemd-helper` / `deb-systemd-invoke` in the
maintainer scripts, `sysusers.d`, `tmpfiles.d`, man page, changelog and DEP-5
copyright under `/usr/share/doc/rodauth-admin`. Why it is built this way:
[ADR-0002](../docs/decisions/0002-debian-package.md).

No configuration file. The six secrets are sealed with `systemd-creds` and
never written to `/etc` in cleartext.

## Build

```bash
./build.sh            # version from DEBIAN/control
./build.sh 0.1.1      # explicit version
```

On macOS: `brew install dpkg` (build.sh needs `dpkg-deb`). Full end-to-end
under a Trixie systemd container, including the lintian gate:

```bash
./test/run.sh         # needs podman
```

## Deliver

```bash
scp rodauth-admin_0.1.0_all.deb host:
ssh host sudo apt install ./rodauth-admin_0.1.0_all.deb
```

`apt install` (not `dpkg -i`) so `Depends:` — system Ruby, bundler, the
compiler toolchain — get pulled in. The postinst creates the sysuser and
directories, then installs the gems from the shipped `Gemfile.lock` into
`/var/lib/gems/3.3.0`, which compiles native extensions and takes a minute or
two. It **enables the unit but does not start it**: on a first install there
are no credentials and no schema yet. A failed gem install leaves the package
unconfigured with bundler's output on screen; fix the cause and
`sudo apt install -f` (or `sudo rodauth-admin install-gems`).

## First install

Six secrets, one authdb drop-in, migrations, preflight, start.

**1. Seal the secrets.** `seal` reads the value from stdin and never echoes
it. Use `printf '%s'` — the wrapper strips trailing newlines, but a value with
an embedded one will not survive:

```bash
printf '%s' "$value" | sudo rodauth-admin seal RODAUTH_ADMIN_SESSION_SECRET
printf '%s' "$value" | sudo rodauth-admin seal AUTH_SECRET
printf '%s' "$value" | sudo rodauth-admin seal ARGON2_SECRET
printf '%s' "$value" | sudo rodauth-admin seal ADMIN_DATABASE_URL
printf '%s' "$value" | sudo rodauth-admin seal ADMIN_DATABASE_URL_RO
printf '%s' "$value" | sudo rodauth-admin seal ADMIN_DATABASE_URL_VERBS
```

On a tty, `sudo rodauth-admin seal AUTH_SECRET` with no stdin prompts
silently instead.

`AUTH_SECRET` and `ARGON2_SECRET` are **the tenant app's values** — the
identity is shared (OTP key HMAC, password pepper). The other four are this
service's own.

The three database URLs **must use IP literals**. The unit blocks all egress
except loopback and the address in the drop-in below, so DNS does not resolve.

Sealing uses `--with-key=host`, so the sealed files are bound to this machine:
re-imaging the VM invalidates all six and they must be sealed again.

**2. Allow the authdb address.**

```bash
sudo mkdir -p /etc/systemd/system/rodauth-admin.service.d
sudo tee /etc/systemd/system/rodauth-admin.service.d/10-authdb.conf <<'EOF'
[Service]
IPAddressAllow=203.0.113.10/32
EOF
sudo systemctl daemon-reload
```

**3. Migrate.** Prompts for `ADMIN_DATABASE_URL_MIGRATIONS` (again an IP
literal). The value is held `0600` on tmpfs for the length of the command and
removed on exit; it is never sealed onto the host and the running service
never holds it.

```bash
sudo rodauth-admin migrate
```

**4. Preflight.** Echoes each probe: Ruby version, `bundle check`, the six
sealed files decrypting, the sysuser, the authdb drop-in,
`systemd-analyze verify`, and finally a transient unit that runs the app's
`boot!` with the real credentials, so env validation and the schema check
happen before `systemctl start` does. Exit 0 means ready.

```bash
sudo rodauth-admin check
```

**5. Start, then add the first operator.**

```bash
sudo systemctl start rodauth-admin
systemctl status rodauth-admin
sudo rodauth-admin rake -- 'operators:add[you@example.com]' REASON="bootstrap operator"
```

Quote the rake argument: the brackets are shell globs. `REASON` is recorded in
the audit log along with the invoking user.

## Reaching it

The service listens on `127.0.0.1:9292` only, and the kernel-level
`IPAddressDeny=any` means that is not a matter of trust in Puma's bind.

```bash
ssh -L 9292:127.0.0.1:9292 host
```

Then open <http://localhost:9292> in a browser on your workstation.

The session cookie is **not** `Secure` when the app is bound to loopback. That
is deliberate and narrow (see commit b6b64a3 and
`lib/rodauth_admin/env.rb`): a browser on `http://localhost` would otherwise
never send the cookie and login would silently fail. The transport is the SSH
tunnel. If the service is ever fronted with TLS, the flag comes back.

## Upgrade

```bash
scp rodauth-admin_0.1.1_all.deb host:
ssh host sudo apt install ./rodauth-admin_0.1.1_all.deb
```

The postinst re-runs the gem install against the new lockfile (a no-op if
nothing moved) and `try-restart`s the unit — so an already-running service is
restarted and a stopped one stays stopped. Credentials, the drop-in and the
state directory are untouched. A `disable` you made by hand survives, via
`deb-systemd-helper was-enabled`.

If the release adds a migration, run `sudo rodauth-admin migrate` before the
restart takes effect; `boot!` refuses to start on schema drift and the unit
will not retry (exit 78, `RestartPreventExitStatus`).

## Rotation

Re-seal and restart:

```bash
printf '%s' "$new" | sudo rodauth-admin seal ARGON2_SECRET
sudo systemctl restart rodauth-admin
```

Rotating `AUTH_SECRET` needs a window in which both the old and new values are
accepted. `seal` only accepts the six names above, so seal the old value with
`systemd-creds` directly and add a temporary drop-in:

```bash
printf '%s' "$old" | sudo systemd-creds encrypt --with-key=host \
  --name=AUTH_OLD_SECRET - /etc/credstore.encrypted/rodauth-admin.AUTH_OLD_SECRET.cred
sudo chmod 0600 /etc/credstore.encrypted/rodauth-admin.AUTH_OLD_SECRET.cred

sudo tee /etc/systemd/system/rodauth-admin.service.d/20-auth-old-secret.conf <<'EOF'
[Service]
LoadCredentialEncrypted=AUTH_OLD_SECRET:/etc/credstore.encrypted/rodauth-admin.AUTH_OLD_SECRET.cred
EOF
sudo systemctl daemon-reload && sudo systemctl restart rodauth-admin
```

When the window closes, remove the drop-in and the `.cred` file,
`daemon-reload`, restart. `AUTH_SECRET` is shared with the tenant app, so
rotate on both sides together.

## Confext-managed /etc

On `lots`-provisioned hosts (`findmnt /etc` shows a `confext` overlay) `/etc`
is read-only, so sealing a credential and writing the drop-in both fail. Wrap
them the way `lots provision` does for every package that touches `/etc`:

```bash
ssh host sudo sh -c 'systemd-confext unmerge && printf "%s" "'"$value"'" | rodauth-admin seal AUTH_SECRET; systemd-confext refresh && systemctl daemon-reload'
```

and for the drop-in:

```bash
ssh host sudo sh -c 'systemd-confext unmerge && mkdir -p /etc/systemd/system/rodauth-admin.service.d && printf "[Service]\nIPAddressAllow=203.0.113.10/32\n" > /etc/systemd/system/rodauth-admin.service.d/10-authdb.conf; systemd-confext refresh && systemctl daemon-reload'
```

The `.cred` files and the drop-in land in the host's base `/etc` beneath the
overlay. Files written by hand there are unowned config; the fleet rule is to
ship what can be shipped from the `30-<role>-<env>` confext layer, but the
sealed credentials are host-bound (`--with-key=host`) and cannot be, so they
stay a provisioning step.

## Logs

```bash
journalctl -u rodauth-admin -f
journalctl -u rodauth-admin --since today
```

JSON lines, one object per line, from SemanticLogger under `RACK_ENV=production`.
`SyslogIdentifier=rodauth-admin`, so `journalctl -t rodauth-admin` catches the
transient units (`check`, `migrate`, `rake`) as well.

## Remove and purge

```bash
sudo apt remove rodauth-admin     # stops the service, leaves credentials and state
sudo apt purge  rodauth-admin     # also removes the sealed .cred files, the
                                  # drop-in directory, /var/lib/rodauth-admin
                                  # and /run/rodauth-admin
```

Purge never touches `/etc/credstore.encrypted` itself (other services may seal
into it) — only `rodauth-admin.*.cred`. The sysuser stays, per Debian practice.
Gems in `/var/lib/gems/3.3.0` stay in both cases: they are shared with anything
else on the host using system Ruby. Remove them by hand with `gem uninstall` if
this was the only consumer.

## What is where

| Path | What |
|---|---|
| `/usr/lib/systemd/system/rodauth-admin.service` | The unit (packaged; do not edit — use a drop-in) |
| `/etc/systemd/system/rodauth-admin.service.d/10-authdb.conf` | Per-host authdb `IPAddressAllow` |
| `/etc/credstore.encrypted/rodauth-admin.*.cred` | The six sealed secrets, host-bound |
| `/usr/share/rodauth-admin/` | App tree: `config.ru`, `lib/`, `views/`, `db/`, `Gemfile.lock`, `.bundle/config` |
| `/usr/sbin/rodauth-admin` | Operator CLI: `seal`, `check`, `migrate`, `rake`, `install-gems` |
| `/usr/lib/rodauth-admin/with-credentials` | Credential-to-environment exec wrapper |
| `/var/lib/rodauth-admin/` | `StateDirectory` and `HOME` for the service user, 0750 |
| `/var/lib/gems/3.3.0/` | Gems, installed by the postinst from the shipped lockfile |
| `/run/rodauth-admin/` | tmpfs, root 0700; holds the migrator URL for the length of one `migrate` |
| `man 8 rodauth-admin` | CLI reference |
