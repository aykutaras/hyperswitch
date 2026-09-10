#!/usr/bin/env bash
# Build the router, consumer and producer images from this checkout.
#
#   scripts/pinnacle_build_images.sh [connector]
#
# Given a connector name, each image is also checked to contain it.
#
# One cargo build feeds all three images: the Dockerfile reads BINARY only after
# the cargo step, so consumer and producer reuse the router's cached layer
# (measured: router 31m24s, then 19s and 17s).
#
# Memory is the constraint (hyperswitch-k8s DEPLOYMENT_GUIDE.md §10):
#   - `release` links the whole program in one rustc process and was killed at
#     both 15.7 and 19.6 GB, so this builds `release-fast` (no LTO).
#   - `release-fast` was SIGKILLed at 11.7 GB and built at 15.7 GB with the
#     cluster stopped, peaking at 11.9 GB.
set -euo pipefail

cd "$(dirname "$0")/.."

CONNECTOR=${1:-}
PROFILE=release-fast
MIN_VM_GB=${MIN_VM_GB:-15}
# Our images keep the upstream tag this branch was cut from (§10).
TAG=${TAG:-$(git describe --tags --abbrev=0 --match 'v[0-9]*')}

fail() { echo "error: $*" >&2; exit 1; }

if [ -n "$CONNECTOR" ] && ! [[ "$CONNECTOR" =~ ^[a-z0-9_]+$ ]]; then
  fail "connector name must be lowercase letters, digits and underscores: '$CONNECTOR'"
fi

[ -z "$(git status --porcelain)" ] \
  || fail "uncommitted changes; build from a commit so the images can be traced back to it"

if [ -z "${ALLOW_RUNNING_CLUSTER:-}" ] && kubectl --context orbstack get --raw /readyz >/dev/null 2>&1; then
  fail "the OrbStack Kubernetes cluster is running. The only successful release-fast build had it stopped; stop it, or set ALLOW_RUNNING_CLUSTER=1"
fi

vm_bytes=$(docker info --format '{{.MemTotal}}')
if [ "$vm_bytes" -lt $((MIN_VM_GB * 1024 * 1024 * 1024)) ]; then
  fail "the Docker VM has $((vm_bytes / 1024 / 1024 / 1024)) GB; release-fast needs more than 11.7 GB. Set OrbStack's memory to 16 GB"
fi

build() {
  local image=$1
  shift
  echo "==> building $image"
  docker build --build-arg CARGO_BUILD_PROFILE="$PROFILE" "$@" -t "$image" .
  if [ -n "$CONNECTOR" ]; then
    docker run --rm --entrypoint sh "$image" -c "grep -q '$CONNECTOR' /local/bin/\$BINARY" \
      || fail "$image does not contain '$CONNECTOR'"
    echo "    contains '$CONNECTOR'"
  fi
}

build "pinnacle/hyperswitch-router:$TAG" --build-arg BINARY=router
build "pinnacle/hyperswitch-consumer:$TAG" --build-arg BINARY=scheduler --build-arg SCHEDULER_FLOW=consumer
build "pinnacle/hyperswitch-producer:$TAG" --build-arg BINARY=scheduler --build-arg SCHEDULER_FLOW=producer

echo "Built $TAG images from $(git rev-parse --short HEAD) ($(git branch --show-current))."
