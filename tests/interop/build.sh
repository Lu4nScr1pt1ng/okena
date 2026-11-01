#!/bin/bash
# The okena-interop image (tests/interop/Dockerfile) from build/okena.
#   tests/interop/build.sh [TAG]      (default okena-interop)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CTX=$(mktemp -d)
trap 'rm -rf "$CTX"' EXIT
cp "$ROOT/build/okena" "$ROOT"/tests/interop/{Dockerfile,run_endpoint.sh,files.py} "$CTX"
docker build -q -t "${1:-okena-interop}" "$CTX"
