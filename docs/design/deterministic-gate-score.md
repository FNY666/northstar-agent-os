# Deterministic gate score — multi-gate pass rule with ERRORED/UNSCORED kept out of aggregates

Status: implemented (`components/northstar-agent-runtime/deterministic_gate_score.py`).
Scope: the evaluation-side gap Northstar's `evaluation_harness.py` leaves open — a
case that fails *infrastructure-wise* has nowhere to go today.

Every claim below is tagged:

- **[SOURCE]** — quoted verbatim from the source named in the line.
- **[CODE]** — a fact about the Northstar repository, with the file it comes from.
- **[EXTENSION]** — a Northstar design decision. Not in any source.

---

## 1. The gap in Northstar today

**[CODE]** `components/northstar-agent-runtime/evaluation_harness.py` books one
host-declared verdict per case per run: a `CaseResult` carries `passed: bool` and
`metric: float` in [0, 1], and `EvaluationHarness.score(...)` requires every suite
case to be scored exactly once (`MissingCaseError` / `DuplicateRunError` /
`UnknownCaseError` are raised fail-closed).

**[CODE]** That shape has no way to express "the scorer died before it could
decide". A case whose scorer hits an API error can only be booked as `passed=False,
metric=0.0` — which books an infrastructure fault as a *model* failure — or not
booked at all, which makes the run incomplete and voids the comparison the
module exists to protect.

**[CODE]** `components/northstar-agent-runtime/ledger_concurrency.py` already knows
a third state at the *verification* level:

```python
OUTCOME_PASSED = "passed"
OUTCOME_FAILED = "failed"
OUTCOME_INFRA = "infra"
```

with the docstring rule that `infra` "is a *third* state, never a synonym for
`failed`: an environment failure says nothing about the proposal under test"
(`ledger_concurrency.py:106-110`, `VerificationResult` at `ledger_concurrency.py:585-596`).

**[CODE]** That tri-state lives at the level of *one verification run*, not at the
level of *one scored case in an aggregate*. There is no module in the runtime that
decomposes a case into named gates, and no module that keeps an errored or
unscored case out of a pass-rate denominator.

---

## 2. What the sources say

### 2.1 Agents' Last Exam (arXiv 2606.05405)

**[SOURCE]** Abstract (read 2026-11-13):

> "55 sub fields grouped into 13 industry clusters covering 1K+ tasks"

> "in collaboration with 250+ industry experts"

> "the average full pass rate is below 1%"

**[SOURCE]** Appendix C.3.5, Table 4 — "Distribution of judge type and execution
locale across the open-sourced task workflows in the ALE reference task tree."

| judge type per task workflow | share |
|---|---|
| Code-based (deterministic) | 93.2% |
| LLM-as-judge | 6.8% |

**[SOURCE]** Appendix C.3.3, "Composition patterns":

> "Gate-and-score. A hard precondition that forces 0 on failure, followed by a continuous score."

> "Used to prevent reward hacking by superficially close artifacts."

**[SOURCE]** §C.3.3 / task cards:

> "failure on the gate forces the task score to 0 regardless of partial progress on other criteria"

**[SOURCE]** §4.1:

> "Each run is capped at five hours; the overall timeout rate is 3.8%"

**[SOURCE]** §C.3.6, "Output presence and shape checks": workflows treat "no output
produced" or "output in the wrong shape" as "score 0 rather than as a crash", so a
timeout or refusal still yields a defined number.

### 2.2 Inspect AI — "Scoring Policy" (read 2026-11-14)

Source: <https://inspect.aisi.org.uk/scoring-policy.html>

**[SOURCE]** The three outcomes of a scorer:

> "Return a Score with a verdict on the model. It counts in the denominator of the resultant metrics."

> "Return Score.unscored() when the scorer could not render a verdict."

> "Raise an error when scoring fails."

**[SOURCE]** What unscored does:

> "Score.unscored() produces a Score whose value is NaN, which Inspect excludes from metric computation."

> "An unscored result completes scoring normally and does not trigger a sample retry."

> "The value is excluded from metrics, with unscored counts calculated after epoch reduction."

**[SOURCE]** What a raised error does:

> "The exception is recorded in sample.error, and the failing scorer produces no score."

**[SOURCE]** Retry and failure thresholds:

> "retry_on_error enables retries for sample errors. Each retry can rerun solving and scoring."

> "fail_on_error controls the failure threshold."

> "The default (True) aborts the run on the first error."

**[SOURCE]** `score_on_error`:

> "score_on_error enables scoring on partial state after a solver error."

> "it runs the scorer on whatever partial state was reached and counts the result."

> "The solver error remains recorded in sample.error."

---

## 3. The Northstar mapping

### 3.1 The pass rule

**[EXTENSION]** The source's gate-and-score pattern is a *composition pattern inside
one task's `evaluate()`*, expressed in the paper as "a hard precondition that
forces 0 on failure". Northstar lifts it to a first-class ledger concept: a case
declares a **set of named deterministic gates**, and the case passes **iff every
gate passes**.

The reason to lift it rather than keep it inline: the failure must be
*attributable*. A case scored 0 with no gate name says only "something was
wrong"; a case scored 0 with `failed_gates == ("schema_valid",)` says which
check rejected it, and the aggregate can then count failures per gate
(`Aggregates.failure_gates`).

**[EXTENSION]** The Northstar gate shape reuses the *form* of
`blind_rerunner.BlindCheck` — a named, runnable check that carries an assertion —
but not its semantics. `BlindCheck` deliberately produces no verdict (the
`blind_rerunner` docstring: "No comparison result is a pass/fail verdict"). A
gate in this module **must** produce a verdict, so `Gate` is its own type:

```python
@dataclass(frozen=True)
class Gate:
    name: str          # unique within a case
    check: Callable[[Any], bool]
    evidence: str      # pointer to what the gate judged
```

**[EXTENSION]** A gate is expected to be a pure function of the case artifact.
The module calls it exactly once per scoring attempt and books only the boolean
plus the evidence pointer. The artifact itself never enters the ledger — only
its `sha256:` digest pin, the same discipline as `evaluation_harness.py`.

**[EXTENSION]** Fail-closed edges of the gate set:

| input | rule | error |
|---|---|---|
| empty gate set | refused — it could trivially "pass all gates" | `EmptyGateSetError` |
| duplicate gate name | refused | `DuplicateGateError` |
| gate name not a non-empty whitespace-free str ≤ 256 chars | refused | `BadGateSetError` |
| `check` not callable | refused | `BadGateSetError` |
| `check` returns a non-bool | refused — no truthiness coercion | `GateExecutionError` |
| `check` raises | refused — an execution failure is not a verdict | `GateExecutionError` |

**[EXTENSION]** Every gate is run even after one fails, so a failure names *all*
the failing gates, not only the first.

### 3.2 The three states

**[SOURCE]** Inspect AI's scorer has three outcomes: a score, `Score.unscored()`,
or a raised error.

**[EXTENSION]** Northstar names them `scored`, `unscored`, `errored` and models
them as `CaseOutcome` with an explicit outcome field rather than as exceptions
plus absence. The mapping to the repo's existing verification tri-state
(`ledger_concurrency.py`) is:

| this module | Inspect AI | `ledger_concurrency.py` | meaning |
|---|---|---|---|
| `scored`, `passed=True` | `Score(CORRECT)` | `passed` | the case passed |
| `scored`, `passed=False` | `Score(INCORRECT)` | `failed` | the case failed |
| `unscored` | `Score.unscored()` | — | no verdict was reachable |
| `errored` | raised error | `infra` | the environment broke, not the work |

`unscored` has no counterpart in `ledger_concurrency.py`: that module's `infra`
means "the gate did not run", which in Inspect terms is the *error* path, not the
no-verdict path. The distinction Northstar keeps is the one Inspect keeps:
**no verdict** (the scorer ran but could not decide) versus **error** (the
scorer could not run at all). Only the second is retryable.

**[EXTENSION]** The concrete state semantics:

- `scored` — carries `passed: bool` and `metric: float` in [0, 1]. The metric is
  1.0 when every gate passed and 0.0 otherwise (binary gates; the pass rule is
  boolean, not a partial-credit sum).
- `unscored` — `passed is None`, `metric` is NaN, a reason string is recorded.
- `errored` — `passed is None`, `metric` is NaN, the error text is recorded.

**[EXTENSION]** `CaseOutcome` refuses to be constructed inconsistently: a
`scored` outcome needs a bool and a finite metric in [0, 1]; an `unscored` or
`errored` outcome must have no verdict and a NaN metric; a passed case may not
name failed gates; a failed case **must** name them.

### 3.3 The aggregate denominator

**[SOURCE]** Inspect: a scored result "counts in the denominator of the resultant
metrics"; unscored is "excluded from metric computation"; a raised error
"produces no score".

**[EXTENSION]** So the Northstar pass rate is

```
pass rate = passed scored cases / scored cases
```

with `errored` and `unscored` **out** of the denominator. Concretely, a run with
one passed, one failed, one errored and one unscored case reports `1/2`, not
`1/4` — the errored case is not a model failure and the unscored case is not a
verdict.

**[EXTENSION]** The report always states all three counts
(`scored_count`, `unscored_count`, `errored_count`) plus `passed_count`, and
carries `pass_rate_text` as exact `"n/m"` text (or `"n/a"` when nothing was
scored) — the same no-floats discipline as `evaluation_harness.py`'s
`pass_rate_text`. A bare pass rate is not a report.

**[EXTENSION]** `mean_metric_text` is an exact fraction of the scored cases only.

### 3.4 `score_on_error`

**[SOURCE]** Inspect's `score_on_error` "enables scoring on partial state after a
solver error", it "runs the scorer on whatever partial state was reached and
counts the result", and "the solver error remains recorded in sample.error".

**[EXTENSION]** Northstar's version: when the solver raised and `score_on_error`
is set, the state the solver had reached is scored by the same gate set. The
outcome is then `scored` — in the denominator, possibly failed, with the failing
gate named — and the error text stays on the outcome. Without
`score_on_error`, the same failure is booked `errored`.

**[EXTENSION]** The two paths are not equivalent in bookkeeping and the tests
pin both: `errored` keeps the case out of the denominator and leaves it
retryable; `score_on_error` puts it in the denominator as a failure and makes it
final.

### 3.5 Retry eligibility

**[SOURCE]** "An unscored result completes scoring normally and does not trigger
a sample retry." / "retry_on_error enables retries for sample errors. Each retry
can rerun solving and scoring."

**[EXTENSION]** Northstar's per-case retry rule:

| state | retryable | why |
|---|---|---|
| `errored` | **yes** | the source's error path; the run may be retried |
| `unscored` | no | the source is explicit: no verdict does not trigger a retry |
| `scored` | no | the case already has a verdict; a second booking is refused |

**[EXTENSION]** The retry is a re-booking of the same `case_id`: the attempt
counter rises (`CaseOutcome.attempt`), the previous errored booking is replaced,
and the final aggregate counts the case exactly once.

**[EXTENSION]** Northstar does **not** implement Inspect's `fail_on_error`
run-level threshold. A run-level abort policy is a host decision; this module
books per-case states and leaves the run policy to the caller.

---

## 4. The API surface

```
Gate(name, check, evidence)          # a named deterministic check
CaseSpec(case_id, artifact_digest)   # pinned identity (digest only)
GateScoreLedger
  .score(case_id, digest, gates, artifact, seq, error="", score_on_error=False)
  .mark_unscored(case_id, digest, reason, seq)
  .mark_errored(case_id, digest, error, seq)
  .booking(case_id) / .outcomes() / .report() / .retryable_cases()
score_case(ledger, case_id, digest, gates, solve, seq, score_on_error=..., partial=...)
run_gates(gates, artifact) -> GateReport
aggregate(outcomes) -> Aggregates
is_retryable(outcome) -> bool
```

**[EXTENSION]** `score_case` is the one-call driver for the three real paths:

- `solve()` returns the artifact → the gates run → `scored`;
- `solve()` returns `NO_VERDICT` → `unscored`;
- `solve()` raises → `errored` (or `scored` on the partial state when
  `score_on_error` and `partial` are given).

**[EXTENSION]** Determinism: no wall clock anywhere. The caller supplies the
`seq`, which must be a strictly increasing int per ledger instance (a rewind
raises `SeqOrderError`; a rejected mutation still consumes its seq).

---

## 5. Honest limits

- **[EXTENSION]** A gate is a *declared* deterministic check. The module runs it
  and books the verdict; it cannot prove a gate is fair, complete, or free of
  side effects.
- **[EXTENSION]** A booked score is a ledger entry, not a verified measurement —
  the same limit `evaluation_harness.py` states for host-reported scores.
- **[EXTENSION]** The ledger is in-memory. Pair it with the durable audit writer
  if eval state must survive a restart.
- **[EXTENSION]** The metric is binary (1.0 / 0.0) because the pass rule is
  boolean. ALE's own pattern pairs a hard gate with a *continuous* score after
  it; Northstar's ledger books the gate verdict, not a partial-credit score.
- **[EXTENSION]** The three-state names are Northstar's. Inspect's names are
  `Score` / `Score.unscored()` / raised exception; `ledger_concurrency.py`'s are
  `passed` / `failed` / `infra`. The mapping table in §3.2 is the whole
  correspondence.

---

## 6. Background numbers (not acceptance criteria)

**[SOURCE]** ALE's 93.2% deterministic share and the below-1% average full-pass
rate are **paper figures**, cited for context only. They are not this slice's
acceptance criteria and are not asserted anywhere in the Northstar code. The
acceptance criteria for this slice are the rules in §3.
