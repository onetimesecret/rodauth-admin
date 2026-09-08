#!/bin/bash
#
# Build rodauth-admin_<version>_all.deb from this tree plus an allowlist
# of application files from the repository root.
#
# Usage: ./build.sh [version]
# Version defaults to the Version field in DEBIAN/control.
# Needs dpkg-deb (macOS: brew install dpkg). BSD and GNU userland both:
# no GNU-only flags below.

set -euo pipefail
cd "$(dirname "$0")"
repo=$(cd .. && pwd)

command -v dpkg-deb >/dev/null 2>&1 || {
  echo "dpkg-deb not found (macOS: brew install dpkg)" >&2
  exit 1
}

version=${1:-$(awk '/^Version:/ {print $2}' DEBIAN/control)}
[[ -n "$version" ]] || { echo "could not determine version" >&2; exit 1; }

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
pkg="$stage/rodauth-admin"

# DEP17 / trixie: nothing under aliased /lib, /bin, /sbin — only usr.
mkdir -p "$pkg"
cp -R DEBIAN usr "$pkg/"

# The application, as an explicit allowlist. Everything else in the
# checkout stays out of the package: bin/, spec/, try/, docs/, coverage/,
# tmp/, data/, README.md and every dotfile. An allowlist rather than an
# exclude list, because the failure mode of the latter is shipping a .env.
app="$pkg/usr/share/rodauth-admin"
mkdir -p "$app"
for item in config.ru config lib views db Gemfile Gemfile.lock Rakefile; do
  [[ -e "$repo/$item" ]] || { echo "missing $repo/$item" >&2; exit 1; }
  cp -R "$repo/$item" "$app/"
done

# Bundler settings, shipped rather than set per call, so install-gems, the
# unit's ExecStartPre and every transient unit agree.
mkdir -p "$app/.bundle"
cat > "$app/.bundle/config" <<'EOF'
---
# `bundle exec` without this re-locks and touches Gemfile.lock, which
# lives under /usr and is read-only to the service (ProtectSystem=strict).
BUNDLE_FROZEN: "true"
BUNDLE_WITHOUT: "development:test"
# The lockfile says BUNDLED WITH 4.0.9 (developers run Bundler 4). Without
# this, trixie's bundler 2.6.7 tries to gem-install bundler 4 on every
# invocation: it succeeds as root and fails inside the sandbox, so the
# service would break in a way no root-run test reproduces.
BUNDLE_VERSION: "system"
EOF

# Policy 12.1 man pages, 12.3 changelog + copyright under
# /usr/share/doc/<pkg>; gzip -9n (no timestamp) for reproducibility.
doc="$pkg/usr/share/doc/rodauth-admin"
man8="$pkg/usr/share/man/man8"
mkdir -p "$doc" "$man8"
gzip -9n -c changelog > "$doc/changelog.gz"
cp copyright "$doc/copyright"
for m in man/*.8; do
  gzip -9n -c "$m" > "$man8/$(basename "$m").gz"
done

# dpkg-deb records ownership via --root-owner-group and modes from the
# staged tree; git does not track modes beyond +x, so set them all.
find "$pkg" -type d -exec chmod 0755 {} +
find "$pkg" -type f -exec chmod 0644 {} +
chmod 0755 "$pkg"/DEBIAN/postinst "$pkg"/DEBIAN/prerm "$pkg"/DEBIAN/postrm \
  "$pkg"/usr/sbin/* "$pkg"/usr/lib/rodauth-admin/with-credentials

# dh_md5sums equivalent so `dpkg -V rodauth-admin` / debsums can verify
# the payload. The package ships no conffiles (its configuration is the
# credstore and an admin-written drop-in), so nothing is excluded.
( cd "$pkg" && find usr -type f -print0 \
    | LC_ALL=C sort -z | xargs -0 md5sum ) > "$pkg/DEBIAN/md5sums"
chmod 0644 "$pkg/DEBIAN/md5sums"

# dpkg-deb does not compute Installed-Size (dpkg-gencontrol would):
# KiB of the payload, excluding DEBIAN (deb-control(5)).
size_kib=$(du -sk "$pkg"/usr | awk '{s += $1} END {print s}')
awk -v v="$version" -v s="$size_kib" '
  /^Version:/ {print "Version: " v; print "Installed-Size: " s; next}
  /^Installed-Size:/ {next}
  {print}' DEBIAN/control > "$pkg/DEBIAN/control"

dpkg-deb --build --root-owner-group "$pkg" "rodauth-admin_${version}_all.deb"
