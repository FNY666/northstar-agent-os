#!/usr/bin/env bash
# b173-baseline-check.sh -- compare the current runtime full-suite failure
# set against a stored baseline file.
#
#   scripts/b173-baseline-check.sh [BASELINE_FILE]
#
# Default baseline: the coordinator's pointer,
# /home/muse-newapi/b173-baseline-CURRENT, which names the baseline file
# in force.  See the selection block below.
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

# The baseline file to compare against.
#
# The authority is the COORDINATOR's file, outside the repository, and it
# is named by a POINTER, not by a hardcoded filename:
#
#     /home/muse-newapi/b173-baseline-CURRENT
#
# That pointer holds the name of the baseline file in force (one line).
# `docs/design/r6-baseline-unify.md` §5.1 says the coordinator re-takes
# the baseline "when main advances" and then "repoints
# b173-baseline-CURRENT at it", so the pointer IS the mechanism -- a
# hardcoded name would keep comparing against a retired baseline
# forever, and would report DRIFT for a tree that is actually clean.
#
# Measured 2026-11-22: the pointer named a 26-item baseline, a
# hardcoded legacy name held 30 items, and the newest baseline on the
# machine held ZERO.  A check that compared against the hardcoded name
# would have reported 30 spurious failures.
#
# A CI runner has no /home/muse-newapi, so a checkout-local file is
# also accepted:
#     docs/baseline/current.failures.txt
# The in-repository copy is what makes the check runnable off this
# machine at all -- see §A-7 in docs/design/baseline-attribution.md.
# RE-TAKING a baseline is the coordinator's decision (r6-baseline-unify
# §5.1), so this script only ever COMPARES; it never writes one.
#
# The ORDER below is the behaviour, and it is pinned by a test that
# RUNS the selection rather than reading the file's text: the
# coordinator's authority comes FIRST, the checkout-local copy is a
# fallback.
BASELINE=""
# The coordinator's pointer, if it exists, names the authority.
COORDINATOR_BASELINE=""
COORDINATOR_DIR="${B173_BASELINE_DIR:-/home/muse-newapi}"
CURRENT_POINTER="$COORDINATOR_DIR/b173-baseline-CURRENT"
if [ -f "$CURRENT_POINTER" ]; then
  # The pointer holds ONE line: the file's name, next to the pointer.
  CURRENT_NAME="$(head -n 1 "$CURRENT_POINTER" | tr -d '\r' | sed 's/[[:space:]]*$//')"
  if [ -n "$CURRENT_NAME" ]; then
    case "$CURRENT_NAME" in
      /*) COORDINATOR_BASELINE="$CURRENT_NAME" ;;
      *)  COORDINATOR_BASELINE="$COORDINATOR_DIR/$CURRENT_NAME" ;;
    esac
  fi
fi
for candidate in \
    "${1:-}" \
    "${B173_BASELINE_FILE:-}" \
    "$COORDINATOR_BASELINE" \
    "$COORDINATOR_DIR/b173-baseline-failures-2026-11-14.txt" \
    "$REPO_ROOT/docs/baseline/current.failures.txt" \
    "$REPO_ROOT/docs/baseline/b173-baseline-failures-2026-11-14.txt"; do
  [ -n "$candidate" ] || continue
  if [ -f "$candidate" ]; then BASELINE="$candidate"; break; fi
done

if [ -z "$BASELINE" ]; then
  echo "BASELINE CHECK ERROR: no baseline file found." >&2
  echo "  Looked at: the argument, \$B173_BASELINE_FILE," >&2
  echo "    the coordinator's baseline, via $CURRENT_POINTER," >&2
  echo "    $COORDINATOR_DIR/b173-baseline-failures-2026-11-14.txt," >&2
  echo "    $REPO_ROOT/docs/baseline/current.failures.txt," >&2
  echo "    $REPO_ROOT/docs/baseline/b173-baseline-failures-2026-11-14.txt" >&2
  exit 2
fi
if [ ! -d "$RUNTIME_DIR" ]; then
  echo "BASELINE CHECK ERROR: runtime component not found: $RUNTIME_DIR" >&2
  exit 2
fi
# Say WHICH baseline was chosen, always.  A drift report that does not
# name the baseline it compared against cannot be acted on, and the
# choice is not obvious -- it depends on a pointer file.
echo "baseline file: $BASELINE"

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
# The RUNNER matters, and it was wrong.
#
# CI runs the component suite with `pytest -q tests`; this script ran it
# with `python -m unittest <modules>`.  unittest's discovery only finds
# test METHODS inside TestCase classes.  The suite also has 9,945
# standalone module-level `test_*` FUNCTIONS, in 811 files, which
# unittest's discovery does not see at all:
#
#     unittest discovery:  23,171 tests
#     pytest:              33,295 tests
#
# So the check was measuring 70% of the suite, and CI was measuring all
# of it -- and the two disagreed about what "the suite" is.  A drift
# check that watches a different suite than the one CI runs is not
# watching the thing CI watches.
#
# The runner is therefore selectable, and defaults to the one CI uses:
#
#     B173_BASELINE_RUNNER=pytest     (default) -- the same suite CI runs
#     B173_BASELINE_RUNNER=unittest   -- the legacy runner
#
# The failure LINES differ between the runners (pytest prints
# "FAILED tests/test_x.py::TestY::test_z", unittest prints
# "FAIL: test_z (test_x.TestY)"), so a baseline file is only comparable
# against the runner that produced it.  The runner used is echoed, and
# the baseline file carries its runner in its header.
#
# B173_BASELINE_CHECK_SKIP_SUITE=1 skips the suite and compares the
# baseline against an EMPTY failure set.  It exists so the guards above
# can be exercised in a test without paying for a full-suite run: it
# still performs the pre-flight tmpfs check and still reports the
# verdict, but it measures nothing.  It is a test hook, not a mode for
# ordinary use.
RUNNER="${B173_BASELINE_RUNNER:-pytest}"
SUITE_LOG="$WORK/fullsuite.txt"
if [ "${B173_BASELINE_CHECK_SKIP_SUITE:-0}" = "1" ]; then
  echo "suite: SKIPPED (B173_BASELINE_CHECK_SKIP_SUITE=1)"
  : > "$SUITE_LOG"
else
  echo "suite runner: $RUNNER"
  case "$RUNNER" in
    pytest)
      ( cd "$RUNTIME_DIR" && PYTHONPATH=.:tests python3 -m pytest -q tests ) >"$SUITE_LOG" 2>&1
      ;;
    unittest)
      MODS=$(cd "$RUNTIME_DIR" && ls tests/test_*.py | xargs -n1 basename | sed 's/\.py$//' | tr '\n' ' ')
      ( cd "$RUNTIME_DIR" && PYTHONPATH=.:tests python3 -m unittest $MODS ) >"$SUITE_LOG" 2>&1
      ;;
    *)
      echo "BASELINE CHECK ERROR: unknown runner: $RUNNER" >&2
      exit 2
      ;;
  esac
  grep -E "^(Ran|OK|FAILED)|passed|failed" "$SUITE_LOG" | tail -3 | sed 's/^/suite: /'
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
#
# The two runners print failures in different shapes, so each is
# normalised to ONE line per failing item:
#
#     unittest:  "FAIL: test_x (test_mod.TestClass)"
#     pytest:    "FAILED tests/test_mod.py::TestClass::test_x"
#
# Both become "kind|item".  The baseline file is written in the same
# normalised shape, so a baseline is comparable against either runner
# -- but only if it was TAKEN with that runner, because a suite that
# passes under pytest may still have unittest-only failures and vice
# versa.  The runner is recorded in the baseline's header.
ACTUAL="$WORK/actual.txt"
EXPECTED="$WORK/expected.txt"
extract_failures() {
  # unittest shape: "FAIL: test_x (test_mod.TestClass)"
  #
  # The item is named by its CLASS -- "test_mod.TestClass" -- and the
  # method name is already the first field, so the class alone is the
  # stable identifier.  It becomes "FAIL|test_mod.TestClass".
  grep -E "^(FAIL|ERROR):" "$1" \
    | sed -E 's/^(FAIL|ERROR): [^ ]+ \(([^)]*)\)$/\1|\2/'
  # pytest shape: "FAILED tests/test_mod.py::TestClass::test_x" (the
  # class is optional, so there may be one colon or two).
  #
  # The trailing " - <reason>" is stripped FIRST, before the id is
  # parsed: a lazy match on the id leaves the reason attached, because
  # the optional group never has to match.
  grep -E "^(FAILED|ERROR) " "$1" \
    | sed -E 's/ - .*$//' \
    | sed -E 's/^(FAILED|ERROR) [^ ]+\.py::([^:]+)::(.+)$/\1|\2.\3/' \
    | sed -E 's/^(FAILED|ERROR) [^ ]+\.py::(.+)$/\1|\2/'
}
extract_failures "$SUITE_LOG" | sort -u > "$ACTUAL"
extract_failures "$BASELINE" | sort -u > "$EXPECTED"

if diff -q "$EXPECTED" "$ACTUAL" >/dev/null 2>&1; then
  echo "BASELINE MATCH: $(wc -l < "$ACTUAL") failure item(s) identical to $BASELINE"
  exit 0
fi

echo "BASELINE DRIFT: expected $(wc -l < "$EXPECTED") item(s), found $(wc -l < "$ACTUAL") item(s)"
echo "baseline file: $BASELINE"
echo "--- diff (< only in baseline, > only in current run) ---"
diff "$EXPECTED" "$ACTUAL"
exit 1
