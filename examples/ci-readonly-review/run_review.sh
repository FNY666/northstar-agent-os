#!/bin/sh
# Read-only code-review run for CI. Never writes into the reviewed repository.
#
# What makes this review *governed*:
#   --read-only     Write and Edit are denied at the permission gate
#   --max-turns/-budget  ceilings so a review cannot run away
#   --halt-on-denial     a denied call ends the run as error_permission_denied
#   --session-dir  an append-only audit transcript of everything the agent did
#
# Usage:
#   REVIEW_WORKSPACE=/path/to/repo REVIEW_PROMPT_FILE=/path/prompt.md sh run_review.sh
#
# Environment:
#   REVIEW_WORKSPACE     repository to review (default: current directory)
#   REVIEW_PROMPT_FILE   markdown file with review instructions (default: prompt.md)
#   REVIEW_PROVIDER      anthropic (default) or scripted (offline smoke)
#   REVIEW_MODEL         model id (default: claude-sonnet-4-5)
#   REVIEW_MAX_TURNS     ceiling (default: 30)
#   REVIEW_MAX_USD       budget ceiling in USD (default: 0.50)
#   REVIEW_SESSION_DIR   where the audit transcript lands (default: ./.northstar-reviews)
#   ANTHROPIC_API_KEY    required when REVIEW_PROVIDER=anthropic
set -eu

WORKSPACE="${REVIEW_WORKSPACE:-$PWD}"
PROMPT_FILE="${REVIEW_PROMPT_FILE:-$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/prompt.md}"
PROVIDER="${REVIEW_PROVIDER:-anthropic}"
MODEL="${REVIEW_MODEL:-claude-sonnet-4-5}"
MAX_TURNS="${REVIEW_MAX_TURNS:-30}"
MAX_USD="${REVIEW_MAX_USD:-0.50}"
SESSION_DIR="${REVIEW_SESSION_DIR:-$(pwd)/.northstar-reviews}"
SCRIPT_FILE="${REVIEW_SCRIPT:-}"

if [ "$PROVIDER" = "anthropic" ] && [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    echo "run_review.sh: REVIEW_PROVIDER=anthropic needs ANTHROPIC_API_KEY" >&2
    echo "               (for an offline CI smoke, set REVIEW_PROVIDER=scripted)" >&2
    exit 64
fi

cd "$(CDPATH= cd -- "$(dirname -- "$0")/../../components/northstar-agent-runtime" && pwd)"

# Offline smoke: the scripted provider needs a reply script. Default to a canned
# verdict so a CI smoke exercises every flag and still ends in a parseable
# VERDICT block instead of a placeholder reply.
if [ "$PROVIDER" = "scripted" ] && [ -z "$SCRIPT_FILE" ]; then
    SCRIPT_FILE="$(mktemp "${TMPDIR:-/tmp}/northstar-review.XXXXXX.json")"
    trap 'rm -f "$SCRIPT_FILE"' EXIT HUP INT TERM
    cat > "$SCRIPT_FILE" <<'EOF'
[{"text": "VERDICT: approve\nSEVERITY: none\nTOP_ISSUE: none (offline scripted smoke; set REVIEW_PROVIDER=anthropic for a real review)"}]
EOF
fi

echo "== read-only review =="
echo "   workspace   : $WORKSPACE"
echo "   provider    : $PROVIDER"
echo "   model       : $MODEL"
echo "   ceilings    : max_turns=$MAX_TURNS max_budget_usd=$MAX_USD"
echo "   session-dir : $SESSION_DIR (audit transcript)"
echo

python3 -m cli run \
    --workspace "$WORKSPACE" \
    --prompt-file "$PROMPT_FILE" \
    --provider "$PROVIDER" \
    --model "$MODEL" \
    --read-only \
    --max-turns "$MAX_TURNS" \
    --max-budget-usd "$MAX_USD" \
    --halt-on-denial \
    --session-dir "$SESSION_DIR" \
    ${SCRIPT_FILE:+--script "$SCRIPT_FILE"} \
    --json
