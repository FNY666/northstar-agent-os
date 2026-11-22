#!/usr/bin/env bash
# b173-census-all.sh -- mutant census over ALL modules of a slice.
#
#   scripts/b173-census-all.sh <slug> <module-relative-path>...
#
# For each module it copies the runtime component into a throwaway tree,
# plants semantic faults one at a time, and asks the module's OWN test
# suite whether it notices.  The verdict line per module is
#
#   MUTANT RESULT: killed k/n
#
# with the surviving sites listed above it.
#
# READ-ONLY with respect to the repository: everything is written under
# /tmp, and each module's source is restored from the pristine copy
# after its census.
#
# Why the pairing matters (measured 2026-11-22)
# ---------------------------------------------
# The rule "pair each module with the test file that mentions it" is not
# a detail.  The script used to pass `--test-module
# test_cancellation_gate` for EVERY module, so a module that suite does
# not exercise was measured with the wrong tests and every mutant in it
# "survived":
#
#   === MODULE merged_tree_review.py ===
#   MUTANT and@156 SURVIVED (and -> or)
#   ...
#   MUTANT RESULT: killed 0/8
#
# That is a false accusation of a weak test suite -- the mirror image of
# the stale-bytecode false kill, in which a mutant looked SURVIVING when
# the tests had actually caught it.  With the pairing fixed, the same
# census reports:
#
#   === MODULE merged_tree_review.py ===
#   --- module=merged_tree_review.py test=test_merged_tree_review ---
#   MUTANT gt@451 SURVIVED (> -> >=)
#   MUTANT eq@494 SURVIVED (== -> !=)
#   MUTANT RESULT: killed 37/39
#
# The two survivors are genuinely equivalent mutants: `span.split(".")`
# always yields at least two parts when "." is in the span, which is
# checked two lines above, so `len(parts) > 1` and `len(parts) >= 1`
# cannot disagree; and `len(parts) == 2` is reachable only after
# `len(parts) < 2` has already returned.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="$REPO_ROOT/components/northstar-agent-runtime"
PROBE="${B173_MUTANT_PROBE:-$REPO_ROOT/scripts/b173-mutant.py}"

SLUG="${1:-census}"
shift || true
if [ "$#" -eq 0 ]; then
  echo "usage: b173-census-all.sh <slug> <module-relative-path>..." >&2
  exit 2
fi

WT="/tmp/b173-census-${SLUG}"
rm -rf "$WT"; mkdir -p "$WT/components"
cp -a "$RUNTIME_DIR" "$WT/components/"
find "$WT" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null

if [ ! -f "$PROBE" ]; then
  echo "CENSUS ERROR: probe not found at $PROBE" >&2
  exit 2
fi

for m in "$@"; do
  echo "=== MODULE $m ==="
  MODPATH="$WT/components/northstar-agent-runtime/$m"
  if [ ! -f "$MODPATH" ]; then
    echo "MUTANT SKIP: module not found: $m"
    continue
  fi
  # Pair the module with the test file that actually EXERCISES it.
  #
  # The module's OWN test file wins outright.  The old rule -- take the
  # first test file that MENTIONS the module -- loses that race to a file
  # that merely imports a constant, and the module is then measured with
  # a suite that barely touches it.  Measured 2026-11-22, 144 of the
  # component's modules were paired that way.  For `a2a_gates`:
  #
  #   first-mention  test_a2a_budget_combo.py   killed 10/43
  #   its own file   test_a2a_gates.py          killed 37/43
  #
  # The first number is a FALSE accusation of a weak test suite -- the
  # mirror image of the stale-bytecode false kill, in which a mutant
  # looked SURVIVING when the tests had actually caught it.
  MODBASE=$(basename "$m" .py)
  TESTF=""
  if [ -f "$WT/components/northstar-agent-runtime/tests/test_${MODBASE}.py" ]; then
    TESTF="$WT/components/northstar-agent-runtime/tests/test_${MODBASE}.py"
  fi
  if [ -z "$TESTF" ]; then
    for cand in "$WT"/components/northstar-agent-runtime/tests/test_[^/]*\.py; do
      [ -f "$cand" ] || continue
      if grep -qE "(^|[^A-Za-z0-9_])${MODBASE}([^A-Za-z0-9_]|$)|from ${MODBASE} import|import ${MODBASE}" "$cand" 2>/dev/null; then
        TESTF="$cand"; break
      fi
    done
  fi
  if [ -z "$TESTF" ]; then
    echo "MUTANT SKIP: no test file exercises ${MODBASE}"
    continue
  fi
  TMOD=$(basename "$TESTF" .py)
  echo "--- module=$m test=$TMOD ---"
  python3 "$PROBE" --file "$MODPATH" \
    --test-module "$TMOD" --workdir "$WT/components/northstar-agent-runtime" \
    --tries 400 --no-early-stop 2>&1
  RC=$?
  # Restore the module from the pristine source after every census, so an
  # interrupted census cannot contaminate the next one.
  cp "$RUNTIME_DIR/$m" "$MODPATH"
  find "$WT" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null
  echo "--- census exit $RC for $m ---"
done
echo "CENSUS WORKTREE KEPT AT $WT"
