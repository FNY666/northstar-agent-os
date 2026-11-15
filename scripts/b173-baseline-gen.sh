#!/usr/bin/env bash
# b173-baseline-gen.sh -- take a runtime-suite baseline for one commit sha.
#
#   scripts/b173-baseline-gen.sh <commit-sha> [output-dir]
#
# The output is the *failure set* of the full runtime unittest suite, run in a
# clean detached worktree at <commit-sha>:
#
#   line 1   "# baseline of <sha> ..."   -- the file carries its own provenance
#   line 2+  the sorted, de-duplicated "FAIL:"/"ERROR:" lines
#
# Why one file per sha: a baseline is only meaningful if you can say *which*
# tree it came from.  Several baselines in this batch were byte-identical but
# came from different trees, and two files with the same name differed by
# three items.  Naming the file after the sha makes the comparison
# reproducible: "identical to the baseline" becomes "identical to the failure
# set of <sha>".
#
# Properties:
#   * idempotent -- the same sha produces a byte-identical file (no
#     timestamps, no host names, no run order dependence)
#   * self-cleaning -- the worktree is removed and the /tmp/nsar-* scratch
#     residue the suite leaves behind is cleared
#   * read-only w.r.t. the repository -- it writes nothing into the checkout
#
# Environment overrides (all optional; the defaults are the production path):
#   B173_BASELINE_GEN_REPO  repository to take the baseline from
#                           (default: the checkout this script lives in)
#   B173_BASELINE_DIR      directory to write the baseline file into
#                           (default: /home/muse-newapi)
#
# Exit: 0 = baseline written, 1 = usage/setup error, 2 = the suite could not
#       be run in the worktree.
set -uo pipefail

REPO_ROOT="${B173_BASELINE_GEN_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
OUT_DIR="${2:-${B173_BASELINE_DIR:-/home/muse-newapi}}"
SHA="${1:-}"

if [ -z "$SHA" ]; then
  echo "usage: $(basename "$0") <commit-sha> [output-dir]" >&2
  exit 1
fi
if ! git -C "$REPO_ROOT" cat-file -e "${SHA}^{commit}" 2>/dev/null; then
  echo "BASELINE GEN ERROR: not a commit in this repository: $SHA" >&2
  exit 1
fi
# Normalise to the full 40-hex sha so the file name is unambiguous.
SHA=$(git -C "$REPO_ROOT" rev-parse "${SHA}^{commit}")

OUT_FILE="$OUT_DIR/b173-baseline-${SHA}.failures.txt"
WORK="$(mktemp -d /tmp/b173-baseline-gen.XXXXXX)"
WT="$WORK/wt"

cleanup() {
  git -C "$REPO_ROOT" worktree remove --force "$WT" >/dev/null 2>&1 || true
  git -C "$REPO_ROOT" worktree prune >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# 1. Clean detached worktree at the requested sha.
git -C "$REPO_ROOT" worktree add --detach "$WT" "$SHA" >/dev/null 2>&1 || {
  echo "BASELINE GEN ERROR: could not create worktree for $SHA" >&2
  exit 2
}

RUNTIME_DIR="$WT/components/northstar-agent-runtime"
if [ ! -d "$RUNTIME_DIR" ]; then
  echo "BASELINE GEN ERROR: no runtime component in worktree for $SHA" >&2
  exit 2
fi

# 2. Clear the /tmp/nsar-* scratch residue first: a full tmpfs makes three
#    unrelated cases report a spurious "Disk quota exceeded" error.
find /tmp -maxdepth 1 -type d -name "nsar-*" -exec rm -rf {} + 2>/dev/null || true

# 3. Run the full runtime suite.  The module-list form is used (not
#    `unittest discover`): tests/ has no __init__.py, and Python 3.11+
#    refuses to discover into a non-importable start directory.  This is the
#    same invocation as scripts/b173-baseline-check.sh.
LOG="$WORK/suite.log"
MODS=$(cd "$RUNTIME_DIR" && ls tests/test_*.py | xargs -n1 basename | sed 's/\.py$//' | tr '\n' ' ')
( cd "$RUNTIME_DIR" && PYTHONPATH=.:tests python3 -m unittest $MODS ) \
  >"$LOG" 2>&1
SUITE_RC=$?

if ! grep -qE '^Ran [0-9]+ tests' "$LOG"; then
  echo "BASELINE GEN ERROR: suite did not run in worktree for $SHA" >&2
  grep -E '^(Ran|OK|FAILED)' "$LOG" | tail -3 >&2
  exit 2
fi
if grep -qE '^(ImportError|ModuleNotFoundError):' "$LOG"; then
  echo "BASELINE GEN ERROR: suite could not import in worktree for $SHA" >&2
  exit 2
fi

# 4. Extract the failure set.  GNU grep is used explicitly: the interactive
#    shell has a `grep` function backed by ugrep, which rejects some BREs.
ITEMS="$WORK/items.txt"
/usr/bin/grep -E '^(FAIL|ERROR): ' "$LOG" | LC_ALL=C sort -u > "$ITEMS" || true

# 5. Write the file.  The first line records the sha; nothing else varies
#    between runs, so re-running for the same sha is byte-identical.
mkdir -p "$OUT_DIR"
{
  echo "# baseline of $SHA -- northstar-agent-runtime full suite, sorted FAIL:/ERROR: items"
  cat "$ITEMS"
} > "$OUT_FILE"

# 5b. Keep the raw suite log next to the baseline.  The failure set is the
#     artifact that gets compared, but the log is what makes a surprising
#     item explainable (a flaky item, a quota error, an import failure).
LOG_OUT="$OUT_DIR/b173-baseline-${SHA}.suite.log"
cp "$LOG" "$LOG_OUT" 2>/dev/null || true

echo "BASELINE WRITTEN: $OUT_FILE"
echo "  sha:     $SHA"
echo "  items:   $(wc -l < "$ITEMS")"
echo "  suite:   $(grep -E '^Ran [0-9]+ tests' "$LOG" | tail -1)"
echo "  verdict: $(grep -E '^(OK|FAILED)' "$LOG" | tail -1)"
echo "  suite_rc: $SUITE_RC"
echo "  log:     $LOG_OUT"
exit 0
