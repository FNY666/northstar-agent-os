#!/bin/sh
# Clean-wheel install smoke for Northstar Agent OS.
# Builds every packaged component into a temporary directory, installs only
# those wheels into a clean target directory, then checks the installed CLI.
# Never touches a checkout .venv and never publishes.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
SMOKE_ROOT=$(mktemp -d /tmp/ns-install-smoke-XXXXXX)
cleanup() { rm -rf "$SMOKE_ROOT"; }
trap cleanup EXIT INT HUP TERM

for c in northstar-run-contract northstar-run-evidence northstar-host northstar-durable-run \
         northstar-agent-interop northstar-agent-runtime; do
  python3 -m pip wheel --quiet --no-build-isolation --no-deps \
    --wheel-dir "$SMOKE_ROOT/dist" "$ROOT/components/$c"
done

python3 -m pip install --quiet --no-index --target "$SMOKE_ROOT/site" \
  --find-links "$SMOKE_ROOT/dist" "$SMOKE_ROOT"/dist/*.whl

PYTHONPATH="$SMOKE_ROOT/site" PYTHONNOUSERSITE=1 python3 -m cli --version | grep -E 'northstar '
PYTHONPATH="$SMOKE_ROOT/site" PYTHONNOUSERSITE=1 python3 -m cli tools >/dev/null
PYTHONPATH="$SMOKE_ROOT/site" PYTHONNOUSERSITE=1 python3 -c "from sealed_receipt import CompletionEvidence, SealedRunReceipt, seal_run_receipt, verify_run_receipt"
PYTHONPATH="$SMOKE_ROOT/site" PYTHONNOUSERSITE=1 python3 -m cli bench --json | python3 -c \
  'import json,sys; r=json.load(sys.stdin); assert r["ok"] and r["failed"]==0, r'
echo "install-smoke: OK (wheels + offline target install + version + tools + governance bench)"
