#!/bin/sh
# Northstar Agent Runtime — zero-setup offline demo.
#
# No API key, no network, no model SDK: the scripted provider supplies the
# model turn while the full governed loop (events, permission gate, ceilings,
# sessions) runs exactly as it would against a live model.
#
# Usage:  sh run_offline.sh          (from this directory)
set -eu

RUNTIME_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../../components/northstar-agent-runtime" && pwd)"
WORKSPACE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/workspace" && pwd)"
DEMO_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

cd "$RUNTIME_DIR"

echo "== demo: one governed run, offline =="
echo "   workspace: $WORKSPACE_DIR"
echo "   provider : scripted (no API key required)"
echo

python3 -m cli run \
    --workspace "$WORKSPACE_DIR" \
    --prompt "Read notes.txt and summarise what it says in one sentence." \
    --script "$DEMO_DIR/script.json" \
    --session-dir /tmp/northstar-demo-sessions \
    --json

echo
echo "== demo transcript (audit trail) =="
SESSION_FILE="$(ls -t /tmp/northstar-demo-sessions/*.jsonl 2>/dev/null | head -n 1)"
if [ -n "${SESSION_FILE:-}" ]; then
    echo "   $SESSION_FILE"
    wc -l "$SESSION_FILE" | sed 's/^/   /'
else
    echo "   (no transcript written)"
fi
