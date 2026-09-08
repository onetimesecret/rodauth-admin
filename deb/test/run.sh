#!/bin/bash
#
# run.sh — repeatable end-to-end test of the rodauth-admin .deb.
#
# Builds a Trixie systemd container image (layer-cached), boots a throwaway
# container, then builds, installs, and exercises the package inside it via
# inside.sh. The container is removed on exit, so every run starts from
# scratch.
#
# The REPO ROOT is mounted read-only at /src/rodauth-admin: deb/build.sh
# stages the app files (config.ru, config/, lib/, views/, db/, Gemfile,
# Gemfile.lock, Rakefile) from there, and inside.sh also runs the repo's
# own `rake authdb:dev` to build the test authdb.
#
# The container needs outbound network: both bundle installs fetch from
# rubygems.org and compile native extensions. Nothing is vendored.
#
# Usage: ./run.sh [--shell]
#   --shell  keep the container running afterward for poking around:
#            podman exec -it rodauth-admin-test bash

set -euo pipefail
cd "$(dirname "$0")"

IMAGE=localhost/rodauth-admin-test
NAME=${RODAUTH_ADMIN_TEST_NAME:-rodauth-admin-test}
KEEP=0
if [[ "${1:-}" == "--shell" ]]; then
  KEEP=1
elif [[ -n "${1:-}" ]]; then
  echo "usage: ${0##*/} [--shell]" >&2
  exit 64
fi

podman build -q -t "$IMAGE" -f Containerfile .

podman rm -f "$NAME" >/dev/null 2>&1 || true
if [[ "$KEEP" -eq 0 ]]; then
  trap 'podman rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
fi

# --privileged: the unit's PrivateTmp/ProtectSystem sandboxing and the
# transient units' credential mounts need mount namespaces inside the
# container. Local test container only.
# ../.. is the repo root (this file lives in deb/test/).
podman run -d --name "$NAME" --privileged --systemd=always \
  -v "$(cd ../.. && pwd)":/src/rodauth-admin:ro \
  "$IMAGE" >/dev/null

# Wait for the manager to settle; "degraded" is acceptable here.
podman exec "$NAME" systemctl is-system-running --wait >/dev/null || true

if podman exec "$NAME" bash /src/rodauth-admin/deb/test/inside.sh; then
  echo "PASS: rodauth-admin e2e"
else
  rc=$?
  echo "FAIL: rodauth-admin e2e (rc=$rc)" >&2
  if [[ "$KEEP" -eq 1 ]]; then
    echo "container '$NAME' kept: podman exec -it $NAME bash" >&2
  fi
  exit "$rc"
fi

if [[ "$KEEP" -eq 1 ]]; then
  echo "container '$NAME' kept: podman exec -it $NAME bash"
fi
