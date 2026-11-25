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
#
# The scope is the UNION (measured 2026-11-25)
# ---------------------------------------------
# Fixing the pairing was not enough: pairing a module with ONLY its own
# suite still understates its coverage.  `job_queue.py` is exercised by
# four suites, and its own suite alone leaves 42 mutants reported as
# SURVIVED that the siblings catch:
#
#   its own suite alone            killed 43/85   (42 survivors)
#   union of the four suites       killed 76/85   (9 survivors)
#
# Every one of those 33 extra "survivors" was a FALSE accusation of a
# weak test suite.  The nine that remain at the union scope are
# §22.8's nine shapes: the `or` in the dequeue skip loop, and the eight
# `and`s in the module's own `main()` self-check's assertion chains.
#
# And the defect is NOT confined to job_queue.py.  Measured 2026-11-25
# over the runtime's 1620 top-level modules, 123 of them are referenced
# by MORE THAN ONE suite, so the single-suite pairing understated the
# scope for 7.6% of the runtime.  `agents.py` is exercised by ELEVEN
# suites.
#
# So the scope is resolved by scripts/census-scope.py, which finds every
# suite that genuinely IMPORTS the module (an AST decision, not a grep:
# two suites mention `job_queue.py` in prose and import it in neither).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="$REPO_ROOT/components/northstar-agent-runtime"
PROBE="${B173_MUTANT_PROBE:-$REPO_ROOT/scripts/b173-mutant.py}"
SCOPE_RESOLVER="${B173_CENSUS_SCOPE:-$REPO_ROOT/scripts/census-scope.py}"

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

if [ ! -f "$SCOPE_RESOLVER" ]; then
  echo "CENSUS ERROR: scope resolver not found at $SCOPE_RESOLVER" >&2
  exit 2
fi

for m in "$@"; do
  echo "=== MODULE $m ==="
  MODPATH="$WT/components/northstar-agent-runtime/$m"
  if [ ! -f "$MODPATH" ]; then
    echo "MUTANT SKIP: module not found: $m"
    continue
  fi
  # Pair the module with EVERY suite that references it.
  #
  # The scope is the UNION.  A module's real coverage is the union of the
  # suites that reference it, and a narrower scope UNDERSTATES it, which
  # turns "no suite covers this" into a false accusation of a weak test
  # suite -- the mirror image of the stale-bytecode false kill.
  #
  # Measured 2026-11-25 on `job_queue.py`:
  #
  #   its own suite alone   test_job_queue                    killed 43/85
  #   the four-suite union  +test_leased_task_claim
  #                         +test_refusal_hold
  #                         +test_refusal_hold_queue_wiring
  #
  # The narrow scope reported 42 survivors; the union reports 9.  The 33
  # extra "survivors" were mutants the sibling suites DO catch, so every
  # one of them was a false accusation.
  #
  # The earlier rule took the FIRST test file that MENTIONS the module,
  # which loses that race to a file that merely names it in a comment.
  # Measured 2026-11-22, 144 of the component's modules were paired that
  # way.  For `a2a_gates`:
  #
  #   first-mention  test_a2a_budget_combo.py   killed 10/43
  #   its own file   test_a2a_gates.py          killed 37/43
  #
  # So "references" is decided by a REAL IMPORT read from the AST, not by
  # a grep: `test_graph_database.py` and `test_status_page.py` both MENTION
  # `job_queue.py` in prose, but neither imports it, and neither exercises
  # it.  See scripts/census-scope.py.
  MODBASE=$(basename "$m" .py)
  TMOD=$(python3 "$SCOPE_RESOLVER" --root "$WT/components/northstar-agent-runtime" \
    "$MODBASE" 2>/dev/null | sed 's/^[^:]*: *//')
  if [ -z "$TMOD" ]; then
    echo "MUTANT SKIP: no test file exercises ${MODBASE}"
    continue
  fi
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
