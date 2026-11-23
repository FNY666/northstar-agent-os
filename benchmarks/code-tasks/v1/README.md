# Northstar offline code task pack v1

This directory freezes the identity and public contract of 24 small offline
coding tasks. The allocation is 12 Python and 12 TypeScript tasks: 8 bug fixes,
6 features, 4 behavior-preserving refactors, 3 build/test repairs, and 3
security fixes.

Run the contract validator from the repository root:

```bash
python3 scripts/validate-code-task-pack.py --json
python3 scripts/validate-code-task-pack.py \
  --agent-view py-bug-001-bounded-retry
```

The agent view contains only the public task fields. `evaluator_suite` is an
evaluator routing key and must never be mounted into an agent workspace. During
evaluation, the harness will copy only a clean fixture repository and the
public projection into the task sandbox, apply the delivered patch to a second
clean checkout, and mount hidden checks only in that evaluator checkout.

Task identity, prompt, and acceptance boundaries are locked. All 24 tasks are
now `materialized`: each has a runnable fixture, public checks, hidden checks,
and pinned fixture/evaluator tree digests. The agent-visible projection contains
the task contract and public check commands; hidden suites and reference repairs
are kept outside the prepared workspace.

Prepare an agent-visible fixture with a deterministic initial Git commit, then
evaluate the delivered patch against another clean copy of the pinned fixture:

```bash
python3 scripts/run-code-task-pack.py prepare \
  py-bug-001-bounded-retry /tmp/northstar-task --git
python3 scripts/run-code-task-pack.py evaluate-patch \
  py-bug-001-bounded-retry /path/to/changes.patch
```

The receipt includes the pack, fixture, evaluator, and patch digests, initial
commit, changed paths, and public/hidden command outcomes. The development
`evaluate TASK_ID CANDIDATE` command still accepts a candidate directory and
labels its result `candidate_copy`; patch evaluation is labeled `patch_replay`.
Neither command exposes evaluator routing in the prepared task view.

The evaluator runs commands with a small environment that excludes caller
credentials and runtime injection options. It bounds total check time and
output, returns structured timeout receipts, and kills the command process
group on completion. Reserved task/evaluator paths and special files are
rejected. The complete pack requires Python 3.11+; TypeScript fixtures are verified
with Node 24's built-in type stripping and need no package download.

These local commands do not create a network namespace. Their receipts report
`network_enforced: false` and `release_eligible: false`. Release baseline runs
must use a network-disabled sandbox and attach its independently verified
receipt before claiming a benchmark score. Current scripted-provider integration
tests verify the delivery mechanism; they do not measure a real model's coding
success rate. Node runs the TypeScript fixtures by stripping types; static
TypeScript type checking is not currently part of the score.

## Fixture quality controls

Every untouched fixture must fail its acceptance checks, and its reference
repair must pass after patch replay onto another clean initial repository:

```bash
python3 scripts/check-code-task-pack.py \
  --write /tmp/northstar-code-task-controls-v1.json \
  --write-summary /tmp/northstar-code-task-controls-summary-v1.json
python3 scripts/check-code-task-pack.py \
  --task py-build-001-package-data --json
```

The [recorded control baseline](controls-baseline.json) contains the frozen pack,
fixture, evaluator, reference, patch, and initial-commit fingerprints. It records
24 rejected original fixtures and 24 passing reference repairs, with
`real_model_evaluated: false`. CI repeats the entire control run. The detailed
JSON report records individual command outcomes and toolchain versions and is
updated atomically after each completed task.

The flaky-test repair checks test coverage by forcing the production timeout
predicate to return only true and then only false. A weakened candidate suite
must not pass both mutants. Transport fixtures replace ambient fetch so their
initial broken implementation cannot make external requests during controls.

The package-data task builds a dependency-free wheel and tests resource loading
after installation into a separate directory. Its format follows the
[PyPA wheel specification](https://packaging.python.org/en/latest/specifications/binary-distribution-format/)
and uses [Python package resources](https://docs.python.org/3/library/importlib.resources.html).
The complete task pack requires Python 3.11+ and Node 24; no npm install or
package-index download is needed.
