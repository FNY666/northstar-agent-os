# swe-failure-modes — classify failed patches, route each mode to its check

**Module:** `components/northstar-agent-runtime/swe_failure_modes.py`
**Tests:** `components/northstar-agent-runtime/tests/test_swe_failure_modes.py`
**Slice:** `B173 swe-failure-modes`

## The gap

A failed patch is one undifferentiated thing in Northstar today: the tests
are red, so the loop says "run the tests again". One review checklist for
all failures. That is wrong for at least four different reasons, and the
Real-SWE failure taxonomy (frontier #16) is the evidence — different models
miss in different ways, and *a missed requirement is not caught by an
integration suite, and an integration break is not caught by re-reading the
instruction against the diff.*

### What Northstar has today (read from the code)

| module | what it classifies | what it routes to |
| --- | --- | --- |
| `tool_failure.py` | **tool-call** failures: `error_code`, `denial_kind` (`ToolFailure.denial_kind`), `ends_turn`, `retryable`, `retry_after_ms`, a structured `ToolResultRemedy` (`kind`, `path`, `provider`, `managed`) | a remedy: `staged_for_review`, `auth_expired`, `auth_overridden`, `timeout` — i.e. *what the harness should do about the call*, not *what kind of patch failure this is* |
| `failure_detector.py` | **liveness**: phi-accrual suspicion over heartbeats (`HeartbeatRecord`, `SuspicionRecord`), `DEFAULT_THRESHOLD = 8.0`, `DEFAULT_WINDOW_SIZE = 1000`, `DEFAULT_MIN_SAMPLES = 2` | a suspicion verdict — the node is probably dead |
| `mutation_tester.py` | **mutants**: `MutantRecord` / `KillRecord` / `SurviveRecord`, a pinned operator table (`arith-op`, `compare`, `bool-lit`, `int-lit`, `stmt-delete`), mutation score as an exact `Fraction` | whether the suite *killed* the mutant — i.e. whether the tests have teeth |
| `planted_fault.py` | **planted faults**: a `PlantNote` (field, wrong value, true value) committed to before the check, `CheckOutcome.caught`, a hash-chained `EvidenceLedger` | whether a blind checker caught the plant |

**The answer to "does a failed patch get classified today?": no.** None of
these four modules takes a *patch* and asks *what kind of wrong it is*.
`tool_failure.py` classifies the failure of a *tool call* (a validation
error, a denial, a provider fault) — its taxonomy is about the call, not
about the diff, and its remedy vocabulary has no member for "you missed a
requirement". `failure_detector.py` answers "is the process alive". The
other two answer "did the check have teeth", not "why did the patch fail".
So today every failed patch takes the same route: rerun the tests.

## What this slice adds

`swe_failure_modes.py` is the missing half.

```
classify(record)  -> Classification(mode, rule, reason, evidence, failed_tests)
route(classification, record) -> CheckList(mode, route, checks)
cost_per_delivery(total_cost, verified_deliveries) -> DeliveryCost
apportion_cost_by_mode(mode_costs, mode_resolved) -> tuple[ModeCost, ...]
```

Four modes plus an explicit `UNKNOWN`:

| mode | meaning |
| --- | --- |
| `REQUIREMENT_MISS` | the patch did not implement the behaviour the instruction asked for |
| `INTEGRATION_BREAK` | the code runs, but it broke something else |
| `UNVERIFIED_ASSUMPTION` | the patch depends on an assumption about the existing system that nobody verified |
| `WRONG_LAYER` | the symptom was fixed, at the wrong layer |
| `UNKNOWN` | it fits none of the four — reported explicitly, never forced into a bucket |

## The record: two sides, or no classification

`FailureRecord` carries both sides of the failure, because without both the
classifier cannot work at all:

* **the instruction side** — `instruction`, `instruction_requirements`,
  `requirement_files` (which file implements which requirement);
* **the patch side** — `changes` (`PatchChange`: file, added lines,
  symbols), `failed_tests`, `all_tests`, `repo_symbols`,
  `unknown_references`, `symptom_layer`, `root_cause_layer`.

A record with only one side classifies as `UNKNOWN`. That is a design
decision, not a gap: "the patch changed `billing/parser.py` and
`tests/test_legacy.py` went red" is *not* by itself an integration break,
because the test might have been red before the patch.

## The rules

The rules are deterministic — no model inference, no thresholds to tune —
and are checked in a fixed order, first match wins.

The order is load-bearing:

1. **`symptom-only` → `WRONG_LAYER`.** The symptom layer's test passes and
   a neighbouring layer's test fails. Checked first because it is the
   strongest signal there is (the patch demonstrably did not fix the thing
   the caller asked about) and it is invisible to the other three rules.
2. **`assumption-unverified` → `UNVERIFIED_ASSUMPTION`.** The patch refers
   to a name the codebase does not define. Checked second because a name
   that does not exist is a factual defect in the patch whatever else is
   true.
3. **`requirement-unmet` → `REQUIREMENT_MISS`.** A failing test maps onto a
   behaviour the instruction explicitly required, *and* the patch never
   touched the file implementing it.
4. **`integration-off-target` → `INTEGRATION_BREAK`.** A failing test
   belongs to none of the changed files *and* it passed before the patch.
   Both halves are needed: "elsewhere" without "was green" is a
   pre-existing failure, not a break.
5. **`no-rule-matched` → `UNKNOWN`.**

### Thresholds, pinned

| constant | value | meaning |
| --- | --- | --- |
| `REQUIREMENT_MATCH` | `"exact-file"` | a requirement counts as met by the patch when the patch touched a file the requirement names, compared by exact path |
| `TEST_MATCH` | `"file-or-target"` | a failing test belongs to a changed file when the test's `target_file` or its own file matches the changed file's stem |
| `MIN_BROKEN_BY_PATCH` | `1` | one green-before test broken elsewhere is already an integration break |

There is exactly one setting of each constant, and it is written here.

### How a test is matched to a requirement

Deterministic, in this order: (1) the requirement string appears in the
test name; (2) the test's `target_file` is one of the requirement's
implementing files; (3) every content word of the requirement (words of 3+
letters, minus a pinned stop-word list) prefixes some word of the test name —
so "reject an expired token" matches "test_rejects_expired_token".

### How a test is matched to a layer

`target_file` if given, else the test's own file; plus the stem rule — the
layer's file stem, with a leading `test_` removed, equals the test's file
stem — so `store/store.py` owns `tests/test_store.py`. The stem rule is
what lets a caller name the symptom layer without also mapping every test
file.

## The routes

Each mode routes to exactly one check, and each checklist is the same
fixed structure: **check name + inputs + criterion**. The criterion is a
decision standard (what must hold for the check to pass), never a
free-text instruction.

| mode | route | what the checklist lists |
| --- | --- | --- |
| `REQUIREMENT_MISS` | `instruction-diff-readback` | each required behaviour, its implementing file, and whether the patch covered it (`"covered by patch"` / `"NOT covered by patch"`), plus the files the patch did change |
| `INTEGRATION_BREAK` | `regression-suite` | each broken test (with its location) and the files the patch changed |
| `UNVERIFIED_ASSUMPTION` | `assumption-verification` | each external name the patch refers to, and the evidence that it does not exist |
| `WRONG_LAYER` | `layer-crossing-check` | the symptom layer and the root-cause layer, and the status of each |
| `UNKNOWN` | `unknown-triage` | the failed tests and the classification's own evidence — the module never invents a route for an unclassified failure |

The routes are the source's own implication, applied: "a requirements-miss
model is caught by comparing the diff to the original ask, while an
integration-error model requires running the tool against real data -- one
checklist cannot cover both."

## Cost: per verified delivery, not per run

The source's cost shape: Fable 5.1 at 38.8% resolution costs $6.96 per
rollout and "~$17.94" per resolved task — "its true cost per completed fix
(~$17.94) runs more than double its per-attempt price". A failed attempt
delivers nothing, so the divisor is the **verified deliveries**, not the
runs.

`cost_per_delivery(total_cost, verified_deliveries, total_runs=..., cost_per_run=...)`
returns `total_cost / verified_deliveries`, and `None` when there are no
verified deliveries — "no evidence", not "free".

`apportion_cost_by_mode(mode_costs, mode_resolved)` splits the cost across
the failure modes after classification: how much each mode cost, how many
deliveries it produced, and its own cost per delivery. Every mode in the
pinned order appears, even one that never fired — "this mode never fired"
is information, and dropping it would make two reports incomparable.

**The module does no pricing and no estimation.** Every number in the
result comes from the caller; the module does arithmetic.

## Mapping to the source

### Verbatim from the source

Real-SWE, frontier #16, rank 4 — industry write-up by Specific Labs, via
constructionaibrief, 2026-09-14. This is a **secondary** write-up, not the
benchmark paper; the underlying task count is not stated there.

* Resolution, pass@1 averaged over eight runs per task: "Claude Code
  (Fable 5.1)" **38.8%**, "Codex CLI (GPT-6 Astra)" **33.8%**, "Gemini 3.8
  Flash" **31.2%**.
* Cost: Fable 5.1 **$6.96** per rollout, **~$17.94** per resolved task;
  Gemini 3.8 Flash **$2.50** per rollout, **~$8.01** per resolved task.
  Codex CLI's cost cells are empty in the source.
* "The median task touches 11 files and the median instruction runs about
  1,742 characters"; scores are "pass@1, averaged over eight runs per
  task".
* Failure taxonomy: "Grok 4.6's failures were dominated by missed
  requirements -- 67.2% of its misses"; "Gemini 3.8 Flash's failures were
  mostly integration errors (49.1%)"; "GPT-5.6 Sol's failures leaned
  toward unverified assumptions about how the existing system worked
  (43.3%)"; "Fable 5.1 and GPT-6 Astra spread their failures more evenly
  across categories, with no single failure type above 37%."
* The cost implication: "Because Fable 5.1 fails on 6 out of 10 tasks, its
  true cost per completed fix (~$17.94) runs more than double its per-attempt
  price."

The source supplies the **failure categories** (missed requirements,
integration errors, unverified assumptions) and the **cost shape** (per
resolved task, not per attempt). It does not name a wrong-layer mode, does
not specify thresholds, and does not specify check routing.

### Northstar extensions (marked as such, not presented as the source's)

* The `WRONG_LAYER` mode. The source's taxonomy is about what the patch
  *did*; a symptom fixed at the wrong layer is Northstar's addition.
* The `UNKNOWN` bucket, the deterministic rule set, the rule order, the
  pinned thresholds, and the four check routes. The source's implication
  ("one checklist cannot cover both") motivates the routing; the routes
  themselves are Northstar's.
* The `UNKNOWN` mode's cost bucket.
* The record shape (`FailureRecord`, `PatchChange`, `TestOutcome`) and the
  evidence/routing result shapes.

## Honest scope

* The module **performs no model inference and no test execution**. It
  classifies a failure record the caller supplies, and routes it. It
  cannot tell whether a patch was bad without being told which tests
  failed and what the patch changed.
* The `WRONG_LAYER` rule needs the caller to name the symptom layer and
  the root-cause layer; the module does not discover layers on its own.
  When the caller does not name them, the failure is not classified as
  `WRONG_LAYER`.
* The `UNVERIFIED_ASSUMPTION` rule fires on names the caller reports as
  absent, or on symbols the patch names that are missing from a
  **non-empty** `repo_symbols`. An empty `repo_symbols` means "the caller
  did not tell us", not "nothing exists", so it never fires on its own.
* `MIN_BROKEN_BY_PATCH = 1`: a single green-before test broken elsewhere is
  an integration break. This is deliberately sensitive; the integration
  suite, not the classifier, is what decides whether the breakage matters.
* **The module is not declared in `pyproject.toml`.** The runtime
  component's `test_module_layout.test_every_module_is_installed` asserts
  that every module on disk appears in `[tool.setuptools] py-modules`. That
  test already fails at this slice's parent commit — with `annotation_pin`,
  `artifact_authority`, `cancellation_tombstone`, `coverage_manifest`,
  `endpoint_identity`, `horizon_gate`, `key_custody`, `ledger_concurrency`,
  `retry_config`, `revision_checked_tool_results` and others undeclared —
  and `swe_failure_modes` joins the same list, so **no new test failure
  appears**. The declaration is still owed; this slice's writable-file set
  covers only the module, its tests and this design doc, so it is left to
  the slice that owns the packaging metadata.
