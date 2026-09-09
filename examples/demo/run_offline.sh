#!/bin/sh
# Northstar Agent OS — zero-setup offline product-path demo.
#
# No API key, no network, no model SDK: the scripted provider supplies the
# model turn while the full governed loop (events, permission gate, ceilings,
# sessions, checkpoints, resume-with-budget-inheritance) runs exactly as it
# would against a live model.
#
# Uses the product entry `agent` so session + per-turn checkpoints are on by
# default (transcript under <workspace>/.northstar/sessions), then `resume
# latest` to show the fork-on-read continuation path.
#
# Usage:  sh run_offline.sh          (from this directory)
#         make demo                  (from the repository root)
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
WORKSPACE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/workspace" && pwd)"
DEMO_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
NORTHSTAR="$ROOT/bin/northstar"
SESSION_DIR="$WORKSPACE_DIR/.northstar/sessions"

# Clean prior demo transcripts so the listing is this run only.
rm -rf "$SESSION_DIR"

echo "== demo: one governed agent turn, offline (product path) =="
echo "   entry    : bin/northstar agent"
echo "   workspace: $WORKSPACE_DIR"
echo "   provider : scripted (no API key required)"
echo "   sessions : $SESSION_DIR (product default)"
echo

"$NORTHSTAR" agent \
    --workspace "$WORKSPACE_DIR" \
    --prompt "Read notes.txt and summarise what it says in one sentence." \
    --script "$DEMO_DIR/script.json" \
    --json

echo
echo "== demo transcript (audit trail) =="
SESSION_FILE="$(ls -t "$SESSION_DIR"/*.jsonl 2>/dev/null | head -n 1 || true)"
if [ -n "${SESSION_FILE:-}" ]; then
    echo "   $SESSION_FILE"
    wc -l "$SESSION_FILE" | sed 's/^/   /'
    if grep -q '"type":"checkpoint"' "$SESSION_FILE" 2>/dev/null; then
        echo "   checkpoint: present (product default cadence)"
    else
        echo "   checkpoint: missing (unexpected on product path)" >&2
        exit 1
    fi
    PARENT_ID="$(basename "$SESSION_FILE" .jsonl)"
    PARENT_BYTES="$(wc -c < "$SESSION_FILE" | tr -d ' ')"
else
    echo "   (no transcript written)" >&2
    exit 1
fi

echo
echo "== demo resume: fork from latest checkpoint (budget/turns inherited) =="
echo "   entry    : bin/northstar resume latest"
echo "   parent   : $PARENT_ID (must stay byte-identical after the fork)"
echo

"$NORTHSTAR" resume latest \
    --workspace "$WORKSPACE_DIR" \
    --prompt "Continue: confirm you still remember the notes summary in one short line." \
    --scripted-text "续跑就绪。父会话检查点已继承；notes.txt 的摘要仍在上下文里。" \
    --json

echo
echo "== demo sessions list (product default dir, no --session-dir required) =="
"$NORTHSTAR" sessions list --workspace "$WORKSPACE_DIR"

CHILD_COUNT="$(ls -1 "$SESSION_DIR"/*.jsonl 2>/dev/null | wc -l | tr -d ' ')"
if [ "$CHILD_COUNT" -lt 2 ]; then
    echo "   resume fork did not write a child transcript" >&2
    exit 1
fi
AFTER_PARENT_BYTES="$(wc -c < "$SESSION_DIR/$PARENT_ID.jsonl" | tr -d ' ')"
if [ "$AFTER_PARENT_BYTES" != "$PARENT_BYTES" ]; then
    echo "   parent transcript was modified by resume (fork invariant broken)" >&2
    exit 1
fi
echo "   parent untouched: $PARENT_ID ($PARENT_BYTES bytes)"
echo "   transcripts now : $CHILD_COUNT (parent + forked child)"
