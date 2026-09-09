#!/bin/sh
# Clean-venv install smoke for Northstar Agent OS (P5).
# Installs every packaged component into a throwaway venv, then checks
# `northstar --version`, `tools`, and the public governance bench.
# Never touches a checkout .venv and never publishes.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
SMOKE_ROOT=$(mktemp -d /tmp/ns-install-smoke-XXXXXX)
cleanup() { rm -rf "$SMOKE_ROOT"; }
trap cleanup EXIT INT HUP TERM

python3 -m venv "$SMOKE_ROOT/venv"
"$SMOKE_ROOT/venv/bin/python" -m pip install --upgrade pip -q
for c in northstar-run-contract northstar-host northstar-durable-run \
         northstar-agent-interop northstar-agent-runtime; do
  "$SMOKE_ROOT/venv/bin/pip" install --quiet "$ROOT/components/$c"
done

"$SMOKE_ROOT/venv/bin/northstar" --version | grep -E 'northstar '
"$SMOKE_ROOT/venv/bin/northstar" tools >/dev/null
"$SMOKE_ROOT/venv/bin/northstar" bench --json | python3 -c \
  'import json,sys; r=json.load(sys.stdin); assert r["ok"] and r["failed"]==0, r'
echo "install-smoke: OK (version + tools + governance bench)"
