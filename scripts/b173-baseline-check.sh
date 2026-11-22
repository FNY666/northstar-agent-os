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
#   * REFUSES to measure when /tmp is nearly full, or when the run itself
#     hit "Disk quota exceeded" -- those failures are environmental, and
#     reporting them as drift reads as "the code regressed"
#   * runs the full runtime test suite
#   * extracts the raw "FAIL:"/"ERROR:" lines, sorts them, and diffs them
#     against the baseline
#
# Output:  "BASELINE MATCH"  or  "BASELINE DRIFT", followed by the diff.
# Exit:    0 = match, 1 = drift, 2 = could not run (missing baseline, a
#          tmpfs too full to measure on, or a run that hit the quota)
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

# 1b. Refuse to measure on a tmpfs that is nearly full.
#
# The runtime suite writes its scratch under /tmp, and a tmpfs that has
# filled up makes the suite fail with
#
#     OSError: [Errno 122] Disk quota exceeded
#
# in tests that have nothing to do with the code under test -- the
# "list at 500 entries" test fails because it cannot create its 540
# fixture files, not because the listing cap is wrong.
#
# Measured 2026-11-22: with /tmp at 79% the check reported four such
# errors as DRIFT, which reads as "the code regressed" when nothing
# about the code changed.  A check that cannot tell an environmental
# failure from a code failure is not a check.
#
# So: if the tmpfs is nearly full, the measurement is refused (exit 2)
# rather than reported as drift.  "The disk is full" and "the code
# broke" are different facts and must not be reported as one.
TMP_AVAIL_KB=$(df -Pk /tmp 2>/dev/null | awk 'NR==2 {print $4}')
if [ -n "${TMP_AVAIL_KB:-}" ] && [ "$TMP_AVAIL_KB" -lt 1048576 ]; then
  echo "BASELINE CHECK ERROR: /tmp has only $((TMP_AVAIL_KB / 1024)) MiB free;" >&2
  echo "  the runtime suite writes its scratch there, and a full tmpfs" >&2
  echo "  produces spurious 'Disk quota exceeded' errors that would" >&2
  echo "  read as code drift.  Free some space and re-run." >&2
  exit 2
fi

# 2. Run the full runtime suite.
#
# B173_BASELINE_CHECK_SKIP_SUITE=1 skips the suite and compares the
# baseline against an EMPTY failure set.  It exists so the guards above
# can be exercised in a test without paying for a full-suite run: it
# still performs the pre-flight tmpfs check and still reports the
# verdict, but it measures nothing.  It is a test hook, not a mode for
# ordinary use.
MODS=$(cd "$RUNTIME_DIR" && ls tests/test_*.py | xargs -n1 basename | sed 's/\.py$//' | tr '\n' ' ')
SUITE_LOG="$WORK/fullsuite.txt"
if [ "${B173_BASELINE_CHECK_SKIP_SUITE:-0}" = "1" ]; then
  echo "suite: SKIPPED (B173_BASELINE_CHECK_SKIP_SUITE=1)"
  : > "$SUITE_LOG"
else
  ( cd "$RUNTIME_DIR" && PYTHONPATH=.:tests python3 -m unittest $MODS ) >"$SUITE_LOG" 2>&1
  grep -E "^(Ran|OK|FAILED)" "$SUITE_LOG" | tail -3 | sed 's/^/suite: /'
fi

# 2b. A run that hit the disk-quota wall is an ENVIRONMENTAL failure, not
# a code failure.  The tmpfs check above catches the common case, but a
# quota can also be reached DURING the run, by the suite's own scratch.
# Either way, the measurement is not a measurement of the code.
if grep -q "Disk quota exceeded" "$SUITE_LOG"; then
  echo "BASELINE CHECK ERROR: the suite hit 'Disk quota exceeded' during" >&2
  echo "  the run.  These failures are environmental, not code drift, so" >&2
  echo "  no comparison is reported.  Free space under /tmp and re-run." >&2
  grep -B 1 "Disk quota exceeded" "$SUITE_LOG" | head -20 >&2
  exit 2
fi

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
