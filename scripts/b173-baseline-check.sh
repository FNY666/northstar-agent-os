#!/usr/bin/env bash
# b173-baseline-check.sh -- compare the current runtime full-suite failure
# set against a stored baseline file.
#
#   scripts/b173-baseline-check.sh [BASELINE_FILE]
#
# Default baseline: /home/muse-newapi/b173-baseline-failures-2026-11-14.txt
#
# Behaviour:
#   * clears the /tmp/nsar-* scratch residue the runtime suite leaves behind
#     (a full tmpfs produces three spurious "Disk quota exceeded" errors)
#   * runs the full runtime test suite
#   * extracts the raw "FAIL:"/"ERROR:" lines, sorts them, and diffs them
#     against the baseline
#
# Output:  "BASELINE MATCH"  or  "BASELINE DRIFT", followed by the diff.
# Exit:    0 = match, 1 = drift, 2 = could not run (missing baseline, etc.)
#
# READ-ONLY with respect to the repository: it writes nothing into the repo,
# and it never re-takes a baseline.  Re-taking a baseline is a human
# decision -- this script only compares.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="$REPO_ROOT/components/northstar-agent-runtime"
BASELINE="${1:-/home/muse-newapi/b173-baseline-failures-2026-11-14.txt}"

if [ ! -f "$BASELINE" ]; then
  echo "BASELINE CHECK ERROR: baseline file not found: $BASELINE" >&2
  exit 2
fi
if [ ! -d "$RUNTIME_DIR" ]; then
  echo "BASELINE CHECK ERROR: runtime component not found: $RUNTIME_DIR" >&2
  exit 2
fi

WORK="$(mktemp -d /tmp/b173-baseline-check.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# 1. Clear the scratch residue first (see b173-runtime-suite-tmp-scratch-leak).
find /tmp -maxdepth 1 -type d -name "nsar-*" -exec rm -rf {} + 2>/dev/null || true

# 2. Run the full runtime suite.
MODS=$(cd "$RUNTIME_DIR" && ls tests/test_*.py | xargs -n1 basename | sed 's/\.py$//' | tr '\n' ' ')
SUITE_LOG="$WORK/fullsuite.txt"
( cd "$RUNTIME_DIR" && PYTHONPATH=.:tests python3 -m unittest $MODS ) >"$SUITE_LOG" 2>&1

grep -E "^(Ran|OK|FAILED)" "$SUITE_LOG" | tail -3 | sed 's/^/suite: /'

# 3. Extract the failure lines and compare with the baseline.
ACTUAL="$WORK/actual.txt"
EXPECTED="$WORK/expected.txt"
grep -E "^(FAIL|ERROR):" "$SUITE_LOG" | sort > "$ACTUAL"
grep -E "^(FAIL|ERROR):" "$BASELINE" | sort > "$EXPECTED"

if diff -q "$EXPECTED" "$ACTUAL" >/dev/null 2>&1; then
  echo "BASELINE MATCH: $(wc -l < "$ACTUAL") failure item(s) identical to $BASELINE"
  exit 0
fi

echo "BASELINE DRIFT: expected $(wc -l < "$EXPECTED") item(s), found $(wc -l < "$ACTUAL") item(s)"
echo "--- diff (< only in baseline, > only in current run) ---"
diff "$EXPECTED" "$ACTUAL"
exit 1
