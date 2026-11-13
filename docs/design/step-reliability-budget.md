# Step reliability budget: from per-step success rate to run-level failure probability

Module: `components/northstar-agent-runtime/step_reliability_budget.py`
Tests: `components/northstar-agent-runtime/tests/test_step_reliability_budget.py`

## The gap this closes

Northstar reports **pass counts** ("24/24 tests green").  Pass counts describe
the *test suite*, not the *run*.  A long-horizon run is a sequence of hundreds
of steps, and the run's reliability is not the step's reliability: under the
independent-steps model a run of `n` steps at per-step success rate `p`
succeeds as a whole with probability `p**n`.  A step that is 95% reliable is
therefore a *30-step run that is 79% likely to contain an error*, and a
*318-step run that is essentially certain to contain one*.

Northstar's existing budget machinery does not cover this.  Read before
writing:

* `budget.py` — run-level **cost** budget: provider-reported usage priced
  against a pricing table (`price_for`, `compute_cost`, `Budget`).  It
  answers "how much has this run spent?", never "is this run likely to work?".
* `per_call_budget.py` — per-call **estimate** ceilings, charged up front
  (`PerCallBudget.check_and_charge`) and reconciled afterwards
  (`observe_model`).  It answers "does this one call fit?", never "will the
  whole run work?".
* `failure_budget_combo.py` — turns **budget exhaustion** into an incident
  (`budget_bundle_from_exhaustion`, `FailureBudgetManager`,
  `failure_budget_digest`).  It is a *digest and audit* of an already-spent
  budget, not reliability arithmetic.  Nothing anywhere in the runtime
  converts a per-step success rate into a run-level failure probability, and
  nothing refuses to start a run whose measured rate cannot reach the target.

This slice adds exactly that conversion and that gate.  It does **not**
change any execution loop, does not retry, and does not observe a live run.

## Source (verbatim, marked as source)

tuput, "AI News: Agents in Production, Independent Tests — October 2026",
2026-10-08, read in full:
<https://www.tuput.com/blog/ai-news-agents-in-production-independent-tests-october-2026/>

The article quotes the OSWorld 2.0 paper (arXiv:2606.29537, posted 28 June
2026, revised 13 July).  The relevant passage, quoted verbatim from the
article:

> Computer-use agents finish a fifth of long workflows
>
> OSWorld 2.0, posted to arXiv on 28 June 2026 and revised on 13 July, tests
> agents on real computer tasks. It has 108 workflows, and a skilled person
> takes a median of about 1.6 hours per task. A task counts as done only if
> it is fully completed within 500 steps.
>
> In the authors' own runs as of the July revision, the best was Claude Opus
> 4.8 with maximum thinking, which fully completed 20.6% of tasks and reached
> 54.8% on a partial-credit score. GPT-5.5 plateaued near 13%. Claude Opus
> 4.7 averaged 318 tool calls per task, against about 30 in the original
> OSWorld.

Figures used from the source, each verbatim:

| Figure | Verbatim text |
| --- | --- |
| Workflow count | "It has 108 workflows" |
| Human median time | "a skilled person takes a median of about 1.6 hours per task" |
| Step cap | "fully completed within 500 steps" |
| Best full completion | "fully completed 20.6% of tasks" |
| Best partial credit | "reached 54.8% on a partial-credit score" |
| GPT-5.5 | "GPT-5.5 plateaued near 13%" |
| Trajectory length (long) | "Claude Opus 4.7 averaged 318 tool calls per task" |
| Trajectory length (original) | "against about 30 in the original OSWorld" |

**What the source does *not* say.**  The article contains no reliability
arithmetic: it does not state `1 - p**n`, does not state a per-step success
rate of 95%, and does not state a "79% of runs contain an error" figure.  The
article's own scope is benchmark reporting ("Passing the tests is not the
same as being merged") and independent review.  Any reliability arithmetic over
the source's trajectory lengths is therefore a **Northstar extension**, marked
as such below, and is verified as arithmetic in the tests — it is never
presented as the source's number.

## Northstar extensions (not source content)

Everything in this section is defined by this slice.

### 1. The independence assumption

The model assumes **steps fail independently**.  This is a *modelling
assumption of this module*, not a measurement and not a claim of the source.

Real trajectories are **correlated**: a step that fails often leaves the
agent in a state that makes the next step fail too (a mis-parsed screen, a
file that was never written, a lost credential).  Under positive correlation
the true probability of a run containing an error is **higher** than
`1 - p**n`, so the formula below gives the *optimistic* side of the bound.
The number is a floor on the risk, not an estimate of it.  This caveat is
repeated in the module docstring and is asserted nowhere as a fact about the
world — it is a stated premise of the arithmetic.

### 2. The three conversions

| Function | Formula | Meaning |
| --- | --- | --- |
| `run_failure_probability(p_step, n)` | `1 - p_step**n` | probability the run contains at least one error |
| `required_step_rate(p_target, n)` | `p_target ** (1/n)` | per-step rate needed to reach the target run-level success |
| `max_steps(p_meas, p_target)` | `floor(ln(p_target) / ln(p_meas))` | longest trajectory whose run-level success still meets the target |

`max_steps` returns `None` when `p_meas >= 1`: a flawless step cannot fail at
any length, so there is no finite bound and no integer to return.  `None` is
documented as "unbounded" — it is not a default value.

### 3. Fail-closed admission

`admit(p_meas, p_target, n)` is the pre-run gate:

* `p_req = required_step_rate(p_target, n)`
* admitted iff `p_meas >= p_req`
* otherwise the verdict carries `gap = p_req - p_meas` and
  `predicted_failure_probability = run_failure_probability(p_meas, n)`

A refusal is **data, not an exception**: `AdmissionVerdict` carries the
verdict and the numbers that justify it, so a caller can report the gap
instead of crashing.  (Contrast the fail-closed *input validation* below,
which does raise: an illegal argument is a programming error, a refusal is a
business outcome.)

### 4. Where "measured" comes from

The per-step success rate is expected to come from Northstar's own tool-call
success statistics.  This module does **not** collect them; it consumes the
number.  The three-state verification vocabulary already in the runtime
(`passed` / `failed` / `infra`, `ledger_concurrency.py:109-114`) is the
natural upstream, and `infra` must not be counted as a step failure: an
environment failure says nothing about the agent's per-step reliability.

## Fail-closed input validation

Every public function validates its arguments and raises
`StepReliabilityError` (a `ValueError` subclass) rather than returning a
plausible-looking number:

* rates must be real numbers strictly inside `(0, 1]` — `0.0`, negatives,
  `> 1`, `NaN`, `inf`, `bool` and non-numeric types are refused;
* step counts must be non-negative `int` — negatives, floats (even integral
  ones like `30.0`) and `bool` are refused.

The module never guesses a default value for an illegal input.

## Boundaries

| Case | Result |
| --- | --- |
| `n == 0` | `run_failure_probability` → `0.0`; `required_step_rate` → `1.0`; `admit` → admitted (nothing can fail) |
| `p_step == 1.0` | failure probability `0.0` at any length |
| `p_target == 1.0` | required rate `1.0`; `max_steps(0.9, 1.0)` → `0` |
| `p_meas >= 1.0` | `max_steps` → `None` (unbounded) |

## The three real paths, driven end to end

All three are asserted in the test suite, against reference values computed
**independently** of the module's own formulas (exact rational powers for
`1 - p**n`, `decimal` logs for `ln`-based ratios) to `1e-9`.

### Path A — the OSWorld 2.0 trajectory lengths

`p = 0.95`:

* `n = 30` (the original OSWorld length): `run_failure_probability` =
  `0.7853612360570628` — about **78.5%** of runs contain at least one error.
* `n = 318` (the Claude Opus 4.7 average): `0.9999999175659795` — within
  float precision of **1.0**; essentially every run contains an error.

The `30` and `318` are the source's; the `0.95` and the arithmetic are this
slice's.

### Path B — target 0.8 over 318 steps

`required_step_rate(0.8, 318)` = `0.9992985368595187` ≈ **0.9993**: to finish
an OSWorld-2.0-length trajectory with 80% run-level success, the agent must
be 99.93% reliable *per step*.

`admit(0.95, 0.8, 318)` refuses:

* `admitted` = `False`
* `gap` = `0.04929853685951879` (required minus measured)
* `predicted_failure_probability` = `0.9999999175659795`

### Path C — measured 0.999 against target 0.8

`max_steps(0.999, 0.8)` = **223**.  A 223-step run at 0.999 still reaches
0.8; 224 steps does not (`0.999**223 >= 0.8 > 0.999**224`).  `admit` agrees:
0.999 at 223 steps is admitted, at 224 steps it is refused.

## What this slice does not do

* It does not collect or measure the per-step success rate.
* It does not change any execution loop, retry policy or budget gate.
* It does not observe a live provider or run a live benchmark.
* It does not claim that the independent-steps model is accurate for real
  trajectories — see the caveat above.

## Reproducing

```
cd components/northstar-agent-runtime
python3 -m unittest tests.test_step_reliability_budget
```

31 test methods, no network, no wall-clock, no fixtures.
