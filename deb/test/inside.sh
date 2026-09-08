#!/bin/bash
#
# inside.sh — runs inside the systemd test container (see run.sh).
#
# Builds the .deb from the read-only /src mount, gates it with lintian,
# builds a real PostgreSQL authdb with the repo's own rake tasks and the
# reviewed grant file, installs the package, and then walks the runbook in
# the order an operator walks it: install (not started) -> start refused
# without credentials -> seal x6 -> authdb drop-in -> migrate -> check ->
# start -> serve /healthz on loopback only -> rake under a transient unit
# -> upgrade -> remove/purge.
#
# Every exact string this file asserts on is marked `# CONTRACT:` and
# collected at the top, so a mismatch with deb/DEBIAN/* or usr/sbin/
# rodauth-admin is reconciled in one place.

set -euo pipefail

SRC=/src/rodauth-admin
WORK=/tmp/rodauth-admin-build
# Bundler's home for the DEVELOPMENT install (all groups, needed by
# `rake authdb:dev`). Deliberately not the system gem dir: the package's
# own postinst install must be the only thing that writes /var/lib/gems,
# and the lockfile's `BUNDLED WITH 4.0.9` must not leak a bundler 4 there.
DEVBUNDLE=/tmp/devbundle

PKG=rodauth-admin
UNIT=rodauth-admin.service
# CONTRACT: unit name, from deb/usr/lib/systemd/system/rodauth-admin.service
SVC_USER=rodauth-admin
# CONTRACT: sysuser name, from deb/usr/lib/sysusers.d/rodauth-admin.conf
APPDIR=/usr/share/rodauth-admin
# CONTRACT: build.sh stages the app allowlist here
STATEDIR=/var/lib/rodauth-admin
# CONTRACT: StateDirectory=rodauth-admin, 0750 rodauth-admin:rodauth-admin
RUNDIR=/run/rodauth-admin
# CONTRACT: tmpfiles.d d /run/rodauth-admin 0700 root root
CREDSTORE=/etc/credstore.encrypted
DROPIN_DIR=/etc/systemd/system/rodauth-admin.service.d
DROPIN="$DROPIN_DIR/10-authdb.conf"
# CONTRACT: the authdb drop-in path named in the unit's comment, the man
# page, deb/README.md, and (as a probe) `rodauth-admin check`
CLI=/usr/sbin/rodauth-admin
# CONTRACT: operator CLI path
PORT=9292
# CONTRACT: Environment=PORT=9292 and Environment=RODAUTH_ADMIN_BIND=127.0.0.1

# CONTRACT: the six credential names, in unit order. Sealed to
# /etc/credstore.encrypted/rodauth-admin.<NAME>.cred by `rodauth-admin seal
# NAME`, which reads the value from stdin.
CRED_NAMES=(
  RODAUTH_ADMIN_SESSION_SECRET
  AUTH_SECRET
  ARGON2_SECRET
  ADMIN_DATABASE_URL
  ADMIN_DATABASE_URL_RO
  ADMIN_DATABASE_URL_VERBS
)
# CONTRACT: credential file name template
cred_path() { echo "$CREDSTORE/rodauth-admin.$1.cred"; }

# CONTRACT: postinst first-install line, verbatim and on a line of its own.
FIRST_INSTALL_LINE='rodauth-admin is installed but not started: seal the six secrets (rodauth-admin seal NAME), add the authdb drop-in, run rodauth-admin migrate, then rodauth-admin check and systemctl start rodauth-admin'

# CONTRACT: `rodauth-admin check` output shape — one `+ cmd` echo per probe,
# `ok: ...` per satisfied probe, `FAIL: ...` on the first unsatisfied one,
# and a non-zero exit on that first FAIL.
CHECK_PROBE_RE='^\+ '
CHECK_OK_RE='^ok: '
CHECK_FAIL_RE='^FAIL: '

# CONTRACT: RestartPreventExitStatus=78 in the unit, paired with config.ru
# exiting 78 (EX_CONFIG) on RodauthAdmin::ConfigurationError.
EX_CONFIG=78

# --- the test authdb -------------------------------------------------------
# Role names and the grant file's expectations come from
# db/grants/postgres/rodauth_admin_roles.sql and db/README.md:
#   ots_migrator        owns every table; ADMIN_DATABASE_URL_MIGRATIONS
#   rodauth_admin_app   ADMIN_DATABASE_URL
#   rodauth_admin_ro    ADMIN_DATABASE_URL_RO
#   rodauth_admin_verbs ADMIN_DATABASE_URL_VERBS
DBNAME=onetime_authdb_e2e
PGHOST_LIT=127.0.0.1   # IP literal on purpose: IPAddressDeny=any blocks DNS
PGPORT=5432
MIG_PW=e2e_migrator_pw
APP_PW=e2e_app_pw
RO_PW=e2e_ro_pw
VERBS_PW=e2e_verbs_pw
MIG_URL="postgres://ots_migrator:$MIG_PW@$PGHOST_LIT:$PGPORT/$DBNAME"
APP_URL="postgres://rodauth_admin_app:$APP_PW@$PGHOST_LIT:$PGPORT/$DBNAME"
RO_URL="postgres://rodauth_admin_ro:$RO_PW@$PGHOST_LIT:$PGPORT/$DBNAME"
VERBS_URL="postgres://rodauth_admin_verbs:$VERBS_PW@$PGHOST_LIT:$PGPORT/$DBNAME"

step() { echo "--- $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# psql as the cluster superuser. cd /: postgres cannot stat the caller's cwd.
psql_su() { (cd / && runuser -u postgres -- psql -v ON_ERROR_STOP=1 "$@"); }
# One scalar out of the database, whitespace stripped.
psql_val() { psql_su -tAX -d "$DBNAME" -c "$1"; }

# Anything run as the service user runs the way the unit runs it: absolute
# bundle, the app dir as cwd, HOME on the state dir (bundler wants a
# writable home or it warns).
as_service_user() {
  runuser -u "$SVC_USER" -- env -i \
    HOME="$STATEDIR" PATH=/usr/local/bin:/usr/bin:/bin RACK_ENV=production \
    sh -c "cd $APPDIR && $*"
}

# The newest .deb build.sh produced. Its output directory is build.sh's
# business, so search the whole work tree rather than pinning a path.
find_deb() {
  find "$WORK" -maxdepth 3 -name "${PKG}_*_all.deb" -newermt '-1 hour' \
    -printf '%T@ %p\n' | sort -rn | head -n 1 | cut -d' ' -f2-
}

# A fingerprint of the system gem dir, so the upgrade stage can assert the
# gems were left alone.
gem_fingerprint() {
  find /var/lib/gems/3.3.0/gems -maxdepth 1 -mindepth 1 -printf '%f\n' | sort | sha256sum
}

# systemd's own view, one property, unquoted.
prop() { systemctl show -p "$1" --value "$UNIT"; }

# The unit's journal as plain message text.
jtext() { journalctl -u "$UNIT" --no-pager -o cat 2>/dev/null || true; }

# =============================================================================
step "0. container quirk: make the root mount shared"
# =============================================================================
# podman starts the container with private mount propagation. systemd sets a
# unit's credentials up in a forked child that unshares a mount namespace,
# builds the tmpfs and MS_MOVEs it to /run/credentials/<unit>; that mount
# only reaches the service's namespace by propagation, which private
# blocks. Result: $CREDENTIALS_DIRECTORY is set but does not exist. A real
# host boots with / shared (systemd does that itself as PID 1 of a VM), so
# this is the container's problem alone, fixed before the first unit runs.
findmnt -no PROPAGATION / | grep -q shared || mount --make-rshared /
[[ $(findmnt -no PROPAGATION /) == *shared* ]] || fail "could not make / rshared; credentials cannot work in this container"

# =============================================================================
step "1a. build the package from the read-only source mount"
# =============================================================================
rm -rf "$WORK"
cp -R "$SRC" "$WORK"
find "$WORK" -maxdepth 3 -name '*.deb' -delete   # stale builds in the checkout
[[ -x "$WORK/deb/build.sh" ]] || fail "deb/build.sh missing or not executable"
"$WORK/deb/build.sh"
deb=$(find_deb)
[[ -n "$deb" && -f "$deb" ]] || fail "no .deb built"
echo "built: $deb"

step "1b. lintian gate (errors and warnings fail; overrides must match)"
# --allow-root: lintian refuses to run as root otherwise. Pedantic/info tags
# are displayed for the record but do not fail — except stale overrides,
# which lintian only reports at info level.
lintian --allow-root --fail-on error,warning --tag-display-limit 0 \
  --display-info --pedantic "$deb" 2>&1 | tee /tmp/lintian.out
if grep -Eq ' (unused|mismatched|malformed)-override ' /tmp/lintian.out; then
  fail "lintian override in usr/share/lintian/overrides/$PKG is stale"
fi

# =============================================================================
step "2a. start postgresql, create the migrator role and the authdb"
# =============================================================================
systemctl start postgresql
for _ in $(seq 1 60); do
  psql_su -tAX -d postgres -c 'SELECT 1' >/dev/null 2>&1 && break
  sleep 0.5
done
psql_su -tAX -d postgres -c 'SELECT version()' >/dev/null || fail "postgres never accepted connections"

psql_su -d postgres -c "CREATE ROLE ots_migrator LOGIN PASSWORD '$MIG_PW';"
psql_su -d postgres -c "CREATE DATABASE $DBNAME OWNER ots_migrator;"

# The three runtime roles are created here rather than by the grant file so
# their passwords are known to this test. The grant file's CREATE ROLE
# branches are guarded (\if on pg_roles) and will leave them exactly as they
# are, password included — which is the documented upgrade path, and is
# therefore also what this test exercises.
psql_su -d postgres -c "CREATE ROLE rodauth_admin_app LOGIN PASSWORD '$APP_PW';"
psql_su -d postgres -c "CREATE ROLE rodauth_admin_ro LOGIN PASSWORD '$RO_PW';"
psql_su -d postgres -c "CREATE ROLE rodauth_admin_verbs LOGIN PASSWORD '$VERBS_PW';"

step "2b. development bundle (all groups) for the repo's rake tasks"
# BUNDLE_PATH: keeps every gem this stage installs inside $DEVBUNDLE, so the
# only thing that ever writes /var/lib/gems is the package's postinst.
# BUNDLE_VERSION=system: Gemfile.lock says `BUNDLED WITH 4.0.9`, trixie ships
# bundler 2.6.7, and without this every invocation tries to gem-install
# bundler 4 — which as root would succeed and put a bundler-4* directory in
# the system gem dir, exactly the leak asserted against below.
export BUNDLE_VERSION=system
export BUNDLE_PATH="$DEVBUNDLE"
(cd "$WORK" && bundle install)

step "2c. build Rodauth's tables: rake authdb:dev against the authdb"
# authdb:dev connects as the MIGRATOR (RodauthAdmin::Database.migrator) and
# builds the tenant app's Rodauth schema from the rodauth-tools templates,
# including the two SECURITY DEFINER password functions the grant file
# grants EXECUTE on. It refuses to run with RACK_ENV=production.
# The admin's own tables (admin_operators, admin_actions,
# admin_schema_info) are NOT created here: those come from db/migrate via
# `rake db:migrate`, and running that is the point of step 7 —
# `rodauth-admin migrate` is what is under test, so it stays unrun here.
(cd "$WORK" && RACK_ENV=development ADMIN_DATABASE_URL_MIGRATIONS="$MIG_URL" \
  bundle exec rake authdb:dev)
[[ $(psql_val "SELECT to_regclass('public.accounts') IS NOT NULL") == t ]] \
  || fail "authdb:dev did not create accounts"
[[ $(psql_val "SELECT to_regclass('public.admin_operators') IS NULL") == t ]] \
  || fail "admin_operators exists before rodauth-admin migrate ran"

# The grant file is applied in step 7, not here: it GRANTs on admin_operators,
# admin_actions and admin_schema_info, and its own header says to run it
# AFTER the admin migrations have created them. Under ON_ERROR_STOP an early
# run would abort half-applied.

unset BUNDLE_PATH BUNDLE_VERSION

# =============================================================================
step "3a. apt install ./${PKG}_*.deb"
# =============================================================================
# tr -d '\r': apt runs dpkg's maintainer scripts on a pty, so every line
# they print arrives CRLF and would defeat grep -x.
(cd "$(dirname "$deb")" && apt install -y "./$(basename "$deb")") 2>&1 \
  | tr -d '\r' | tee /tmp/apt-install.out

step "3b. postinst prints the next-steps line verbatim on first install"
grep -qxF "$FIRST_INSTALL_LINE" /tmp/apt-install.out \
  || fail "postinst did not print the first-install next-steps line verbatim"

step "3c. postinst installed the gems: bundle check passes as the service user"
# --dry-run: plain `bundle check` re-locks and touches Gemfile.lock, which
# the unit cannot do under ProtectSystem=strict. Same invocation as
# ExecStartPre.
as_service_user "/usr/bin/bundle check --dry-run" \
  || fail "bundle check --dry-run fails as $SVC_USER in $APPDIR"

step "3d. no bundler 4 leaked into the system gem dir"
if compgen -G '/var/lib/gems/3.3.0/gems/bundler-4*' >/dev/null; then
  fail "bundler-4* in /var/lib/gems/3.3.0/gems: BUNDLE_VERSION=system is not in effect"
fi

step "3e. sysuser, state dir, run dir"
id "$SVC_USER" >/dev/null || fail "sysuser $SVC_USER not created"
[[ -d "$STATEDIR" ]] || fail "$STATEDIR not created"
[[ $(stat -c '%a %U:%G' "$STATEDIR") == "750 $SVC_USER:$SVC_USER" ]] \
  || fail "bad perms on $STATEDIR: $(stat -c '%a %U:%G' "$STATEDIR")"
[[ -d "$RUNDIR" ]] || fail "$RUNDIR not created by tmpfiles.d"
[[ $(stat -c '%a %U:%G' "$RUNDIR") == '700 root:root' ]] \
  || fail "bad perms on $RUNDIR: $(stat -c '%a %U:%G' "$RUNDIR")"
[[ -d "$CREDSTORE" ]] || fail "$CREDSTORE not created by tmpfiles.d"

step "3f. unit enabled but deliberately not started on first install"
[[ $(systemctl is-enabled "$UNIT") == enabled ]] \
  || fail "unit not enabled: $(systemctl is-enabled "$UNIT" || true)"
[[ $(systemctl is-active "$UNIT" || true) == inactive ]] \
  || fail "unit must not be started on first install: $(systemctl is-active "$UNIT" || true)"

step "3g. the man page resolves"
man -w rodauth-admin >/dev/null || fail "man -w rodauth-admin does not resolve"

# =============================================================================
step "4. dpkg -V: shipped md5sums match"
# =============================================================================
dpkg -V "$PKG"
pkg_version=$(dpkg-query -W -f '${Version}' "$PKG")
[[ -n "$pkg_version" ]] || fail "no installed version"
echo "installed version: $pkg_version"
gems_before=$(gem_fingerprint)

# =============================================================================
step "5. systemctl start BEFORE sealing: fails on the missing credentials"
# =============================================================================
for n in "${CRED_NAMES[@]}"; do
  [[ ! -e "$(cred_path "$n")" ]] || fail "$(cred_path "$n") exists before seal"
done
if systemctl start "$UNIT" 2>/tmp/start-nocreds.out; then
  fail "unit started with no sealed credentials"
fi
# A missing credential file fails the unit before ExecStart; Restart=on-failure
# then retries it every RestartSec=10s until StartLimitBurst=3 in 5min trips,
# so right after `start` the state is `activating (auto-restart)`. What the
# design promises is that it ends in `failed` and never `active`: poll for
# the terminal state (3 attempts x 10s, generous margin), and fail the
# moment it is active.
for _ in $(seq 1 90); do
  st=$(systemctl is-active "$UNIT" 2>/dev/null || true)
  [[ $st != active ]] || fail "unit became active without credentials"
  [[ $st == failed ]] && break
  sleep 1
done
[[ $(systemctl is-failed "$UNIT" || true) == failed ]] \
  || fail "unit did not settle into failed after the credential-less start: $(systemctl is-active "$UNIT" || true)"
echo "after the credential-less start: Result=$(prop Result) NRestarts=$(prop NRestarts)"
systemctl reset-failed "$UNIT"

# =============================================================================
step "6a. seal the six credentials"
# =============================================================================
# 64 random bytes, hex — comfortably over Rack::Session's minimum, and the
# short-secret negative case below depends on this one being long.
hexbytes() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
SESSION_SECRET=$(hexbytes 64)
AUTH_SECRET_V=$(hexbytes 32)
ARGON2_SECRET_V=$(hexbytes 32)

seal() { printf '%s' "$2" | "$CLI" seal "$1"; }
seal RODAUTH_ADMIN_SESSION_SECRET "$SESSION_SECRET"
seal AUTH_SECRET "$AUTH_SECRET_V"
seal ARGON2_SECRET "$ARGON2_SECRET_V"
seal ADMIN_DATABASE_URL "$APP_URL"
seal ADMIN_DATABASE_URL_RO "$RO_URL"
seal ADMIN_DATABASE_URL_VERBS "$VERBS_URL"

for n in "${CRED_NAMES[@]}"; do
  p=$(cred_path "$n")
  [[ -f "$p" ]] || fail "seal did not write $p"
  [[ $(stat -c '%a %U:%G' "$p") == '600 root:root' ]] \
    || fail "bad perms on $p: $(stat -c '%a %U:%G' "$p")"
  systemd-creds decrypt --name="$n" "$p" - >/dev/null \
    || fail "$p does not decrypt under --name=$n"
done

step "6b. check FAILS while the authdb drop-in is absent"
# Decision, recorded here because the harness has to pick one: `check`'s
# probe order (plan, `check` row) is ruby -> bundle check -> the six .cred
# files -> the sysuser -> THE AUTHDB DROP-IN -> systemd-analyze verify ->
# boot! under a transient unit. Everything before the drop-in is now
# satisfied, so the drop-in is the first probe that can fail, and it fails
# deterministically: the file has not been written yet. The admin tables are
# also still missing, but boot! is the last probe and check exits non-zero
# on the FIRST FAIL, so it never gets that far. Asserting on the drop-in
# rather than on the schema is therefore the assertion that holds.
[[ ! -e "$DROPIN" ]] || fail "$DROPIN exists before this stage writes it"
if "$CLI" check >/tmp/check-nodropin.out 2>&1; then
  cat /tmp/check-nodropin.out >&2
  fail "check passed with no authdb drop-in and no admin tables"
fi
cat /tmp/check-nodropin.out
grep -q "$CHECK_FAIL_RE" /tmp/check-nodropin.out \
  || fail "check exited non-zero without printing a 'FAIL: ' line"
# check names the directory, not the file: 10-authdb.conf is the runbook's
# convention, any *.conf drop-in satisfies the probe.
grep "$CHECK_FAIL_RE" /tmp/check-nodropin.out | grep -qF "$DROPIN_DIR" \
  || fail "the FAIL line does not name the missing drop-in dir $DROPIN_DIR"
# Exactly one: check stops at the first FAIL.
[[ $(grep -c "$CHECK_FAIL_RE" /tmp/check-nodropin.out) -eq 1 ]] \
  || fail "check printed more than one FAIL line; it must exit on the first"

step "6c. write the authdb drop-in"
mkdir -p "$DROPIN_DIR"
cat > "$DROPIN" <<EOF
[Service]
# The authdb address, per host. The base unit is IPAddressDeny=any.
IPAddressAllow=$PGHOST_LIT/32
EOF
chmod 0644 "$DROPIN"
systemctl daemon-reload

# =============================================================================
step "7a. rodauth-admin migrate (migrator URL on stdin)"
# =============================================================================
printf '%s' "$MIG_URL" | "$CLI" migrate

step "7b. the admin tables exist"
for t in admin_schema_info admin_operators admin_actions; do
  [[ $(psql_val "SELECT to_regclass('public.$t') IS NOT NULL") == t ]] \
    || fail "$t not created by rodauth-admin migrate"
done

step "7c. the migrator credential left nothing behind in $RUNDIR"
[[ -z $(find "$RUNDIR" -mindepth 1 -print -quit) ]] \
  || fail "$RUNDIR is not empty after migrate: $(ls -la "$RUNDIR")"

step "7d. apply db/grants/postgres/rodauth_admin_roles.sql as the superuser"
# Verbatim, with the documented invocation: the file is reviewed like code,
# so it is executed like code. The three roles already exist, so it takes
# its \else branch and leaves their passwords alone.
psql_su -d postgres \
  -v dbname="$DBNAME" \
  -v app_pw="$APP_PW" -v ro_pw="$RO_PW" -v verbs_pw="$VERBS_PW" \
  -f "$WORK/db/grants/postgres/rodauth_admin_roles.sql"

# =============================================================================
step "8a. rodauth-admin check passes"
# =============================================================================
"$CLI" check 2>&1 | tee /tmp/check-ok.out
grep -q "$CHECK_PROBE_RE" /tmp/check-ok.out || fail "check printed no '+ cmd' probe echoes"
grep -q "$CHECK_OK_RE" /tmp/check-ok.out || fail "check printed no 'ok: ' lines"
! grep -q "$CHECK_FAIL_RE" /tmp/check-ok.out || fail "check printed a FAIL line while passing"
echo "check probes: $(grep -c "$CHECK_PROBE_RE" /tmp/check-ok.out), ok lines: $(grep -c "$CHECK_OK_RE" /tmp/check-ok.out)"

step "8b. negative: a 10-byte session secret is a ConfigurationError"
printf '%s' 'tooshort12' | "$CLI" seal RODAUTH_ADMIN_SESSION_SECRET
if "$CLI" check >/tmp/check-shortsecret.out 2>&1; then
  cat /tmp/check-shortsecret.out >&2
  fail "check passed with a 10-byte RODAUTH_ADMIN_SESSION_SECRET"
fi
cat /tmp/check-shortsecret.out
grep -q "$CHECK_FAIL_RE" /tmp/check-shortsecret.out \
  || fail "check did not print a FAIL line for the short session secret"
# The app's own message, surfaced through check rather than reworded by it.
grep -qF RODAUTH_ADMIN_SESSION_SECRET /tmp/check-shortsecret.out \
  || fail "check's failure output does not name RODAUTH_ADMIN_SESSION_SECRET"

step "8c. negative: the unit exits $EX_CONFIG and RestartPreventExitStatus holds"
if systemctl start "$UNIT" 2>/dev/null; then
  fail "unit started with a 10-byte session secret"
fi
sleep 13   # past RestartSec=10s: there must be no second attempt
[[ $(systemctl is-active "$UNIT" || true) != active ]] || fail "unit became active on a bad secret"
[[ $(systemctl is-failed "$UNIT" || true) == failed ]] \
  || fail "unit not failed after the bad-secret start: $(systemctl is-failed "$UNIT" || true)"
main_status=$(prop ExecMainStatus)
[[ "$main_status" == "$EX_CONFIG" ]] \
  || fail "ExecMainStatus is '$main_status', expected $EX_CONFIG (EX_CONFIG from config.ru)"
nrestarts=$(prop NRestarts)
[[ "$nrestarts" == 0 ]] \
  || fail "NRestarts is $nrestarts: RestartPreventExitStatus=$EX_CONFIG was not honoured"
systemctl reset-failed "$UNIT"

step "8d. re-seal the good session secret; check passes again"
printf '%s' "$SESSION_SECRET" | "$CLI" seal RODAUTH_ADMIN_SESSION_SECRET
"$CLI" check >/tmp/check-ok2.out 2>&1 || { cat /tmp/check-ok2.out >&2; fail "check does not pass after re-sealing"; }

# =============================================================================
step "9a. systemctl start"
# =============================================================================
systemctl start "$UNIT"
[[ $(systemctl is-active "$UNIT") == active ]] || fail "unit not active after start"

step "9b. /healthz returns JSON over loopback"
health=''
for _ in $(seq 1 40); do
  if health=$(curl -fsS "http://127.0.0.1:$PORT/healthz" 2>/dev/null); then
    break
  fi
  sleep 0.5
done
[[ -n "$health" ]] || fail "no response from http://127.0.0.1:$PORT/healthz"
echo "healthz: $health"
[[ "$health" == *'{'* ]] || fail "/healthz did not return JSON: $health"

step "9c. the listener is loopback only"
ss -ltn > /tmp/ss.out
cat /tmp/ss.out
grep -q "127\.0\.0\.1:$PORT" /tmp/ss.out || fail "nothing listening on 127.0.0.1:$PORT"
! grep -q "0\.0\.0\.0:$PORT" /tmp/ss.out || fail "listening on 0.0.0.0:$PORT"
! grep -qE "\[::\]:$PORT|\*:$PORT" /tmp/ss.out || fail "listening on [::]:$PORT"

step "9d. systemctl show -p Environment leaks none of the sealed values"
env_show=$(systemctl show -p Environment "$UNIT")
for v in "$SESSION_SECRET" "$AUTH_SECRET_V" "$ARGON2_SECRET_V" "$APP_URL" "$RO_URL" "$VERBS_URL"; do
  ! grep -qF -- "$v" <<<"$env_show" || fail "a sealed value is visible in systemctl show -p Environment"
done
# The passwords on their own, in case a URL is reformatted somewhere.
for v in "$APP_PW" "$RO_PW" "$VERBS_PW" "$MIG_PW"; do
  ! grep -qF -- "$v" <<<"$env_show" || fail "a database password is visible in systemctl show -p Environment"
done

step "9e. the sandbox holds: no SIGSYS, EPERM or W^X denial in the journal"
jtext > /tmp/journal.out
! grep -q 'SIGSYS' /tmp/journal.out || fail "SIGSYS in the journal: SystemCallFilter is too narrow"
! grep -q 'Operation not permitted' /tmp/journal.out || fail "'Operation not permitted' in the journal"
! grep -q 'Cannot allocate memory' /tmp/journal.out \
  || fail "'Cannot allocate memory' in the journal: MemoryDenyWriteExecute vs an mmap PROT_EXEC"

step "9f. the app logs JSON"
grep -q '^{' /tmp/journal.out || fail "no JSON log line in the unit's journal"

step "9g. systemd-analyze security (recorded, not asserted)"
systemd-analyze security "$UNIT" --no-pager | tail -n 5

# =============================================================================
step "10. rodauth-admin rake -- operators:list under a transient unit"
# =============================================================================
"$CLI" rake -- operators:list 2>&1 | tee /tmp/rake-list.out

# =============================================================================
step "11a. rebuild at 0.1.1 and upgrade"
# =============================================================================
active_before=$(prop ActiveEnterTimestampMonotonic)
"$WORK/deb/build.sh" 0.1.1
deb2=$(find "$WORK" -maxdepth 3 -name "${PKG}_0.1.1_all.deb" | head -n 1)
[[ -n "$deb2" && -f "$deb2" ]] || fail "no 0.1.1 .deb built"
(cd "$(dirname "$deb2")" && apt install -y "./$(basename "$deb2")") 2>&1 \
  | tr -d '\r' | tee /tmp/apt-upgrade.out

step "11b. the upgrade restarted a running service"
[[ $(dpkg-query -W -f '${Version}' "$PKG") == 0.1.1 ]] || fail "0.1.1 not installed"
for _ in $(seq 1 40); do
  [[ $(systemctl is-active "$UNIT" || true) == active ]] && break
  sleep 0.5
done
[[ $(systemctl is-active "$UNIT" || true) == active ]] \
  || fail "unit not active after the upgrade: $(systemctl is-active "$UNIT" || true)"
active_after=$(prop ActiveEnterTimestampMonotonic)
[[ "$active_after" != "$active_before" ]] \
  || fail "ActiveEnterTimestamp unchanged: the upgrade did not restart the service"

step "11c. the upgrade did not touch the system gem dir"
[[ $(gem_fingerprint) == "$gems_before" ]] || fail "the system gem dir changed across the upgrade"

step "11d. first-install line is NOT printed on upgrade"
! grep -qxF "$FIRST_INSTALL_LINE" /tmp/apt-upgrade.out \
  || fail "the first-install next-steps line was printed on an upgrade"

# =============================================================================
step "12a. dpkg -r: service stopped, sealed credentials kept"
# =============================================================================
dpkg -r "$PKG"
[[ $(systemctl is-active "$UNIT" || true) != active ]] || fail "unit still active after dpkg -r"
for n in "${CRED_NAMES[@]}"; do
  [[ -f "$(cred_path "$n")" ]] || fail "$(cred_path "$n") removed by dpkg -r (remove must keep secrets)"
done

step "12b. dpkg -P: credentials, state dir and drop-in gone; sysuser stays"
dpkg -P "$PKG"
for n in "${CRED_NAMES[@]}"; do
  [[ ! -e "$(cred_path "$n")" ]] || fail "$(cred_path "$n") survived dpkg -P"
done
[[ -d "$CREDSTORE" ]] || fail "purge removed the shared $CREDSTORE directory"
[[ ! -e "$STATEDIR" ]] || fail "$STATEDIR survived dpkg -P"
[[ ! -e "$DROPIN_DIR" ]] || fail "$DROPIN_DIR survived dpkg -P"
id "$SVC_USER" >/dev/null || fail "sysuser $SVC_USER was removed on purge (Debian practice: it stays)"

echo "--- all stages passed"
