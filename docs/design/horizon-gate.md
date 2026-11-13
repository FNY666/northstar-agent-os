# Horizon gate: admit tasks only within the verified 80% horizon

Status: implemented for B173 slice "horizon-gate". The runtime had the
*parts* of a horizon gate — but nothing that asks, before a task starts,
"how long does this take in human time, and is that inside the horizon this
agent has actually verified?"

Module: `components/northstar-agent-runtime/horizon_gate.py`
Schema pin: `northstar.horizon-gate.v1` — module version pin:
`horizon-gate.v1`

## What the code said before this slice

Read from the code, not assumed:

* **`long_horizon.py`** is the Manager / Executor / Auditor loop that runs a
  task *while it runs*. `LongHorizonLoop` is constructed with an objective
  and starts round 0. There is no admission step, and no notion of a task's
  expected duration anywhere in the module. "Horizon" in `long_horizon.py`
  means "many rounds", not "how long a task may take".
* **`budget.py`** bounds *spend*: `max_turns`, `max_tool_calls`,
  `max_budget_usd`, priced from per-million token rates. Its unit is money
  and tokens. `compute_budget.py` bounds compute (device class, spend
  authority). Neither knows about human time; neither compares a task to a
  horizon.
* **`evaluation_harness.py`** reports results as `"n/m"` pass-rate text
  plus a mean metric (`ReportView.pass_rate_text`, `mean_metric_text`).
  It reports **no interval**: a bare pass count hides how much of the
  number is precision.
* Nothing in the runtime stores an estimated human duration for a task,
  and nothing compares one against a horizon. A task needing three human
  hours is handed straight to the agent; the failure only surfaces after the
  hours are spent.

So: **no horizon admission existed, and no horizon interval was reported
anywhere.**

## What this module does

`HorizonGate` is a declaration + a decision, both fail-closed.

### Declaration — three mandatory inputs

| input | meaning | missing ⇒ |
|---|---|---|
| `verified_80_horizon_minutes` | the agent's verified 80% horizon, in **human minutes** | refused |
| `horizon_interval` | the `(low, high)` interval of that horizon | refused |
| `task_count` | how many tasks pinned the horizon down | refused |

A horizon with no interval and no sample size is not a verified horizon, it
is a guess — so the gate refuses to be constructed without all three. There
are no defaults for any of them.

Two further construction refusals:

* **A 50% horizon is refused** (`horizon_percentile != 80`). The 50% horizon
  is the *headline* number; the 80% horizon is the reliability line for
  autonomous operation. Admitting at 50% means running a coin flip and
  reporting it as a capability.
* **A horizon above 960 minutes (16 hours) is refused.** Measurements above
  about 16 hours "aren't reliable with the current tasks".

### Decision — three states, never a boolean

`admit(task_human_minutes) -> Admission`:

* **`ADMITTED`** — the task is within the verified 80% horizon. The verdict
  carries the task minutes, the horizon, the interval and the task count.
* **`FLAGGED`** — the task sits inside the horizon's interval but within
  `margin_minutes` of the interval's upper bound (default **10** minutes,
  caller-supplied). It is taken in, but only with enhanced monitoring; the
  verdict says why and recommends it.
* **`REFUSED`** — the task is longer than the 80% horizon and not rescued by
  the interval. The verdict carries the **overage in minutes** and
  recommends decomposing the task or routing it to a human. Nothing is
  taken in: the gate records the refusal and holds no task.

`FLAGGED` and `REFUSED` are different decisions, so the verdict is a
three-state `AdmissionStatus` enum, not a bool. (`Admission.admitted` exists
for convenience and means "admitted *or* flagged in".)

**Precedence** (documented, deliberate): the flag band is evaluated first.
A task inside the verified interval but near its top is *within the
uncertainty band* of the horizon, and the honest reading of a band is
"watch it", not "refuse it". A task outside the band that is longer than the
80% horizon is refused outright. A task above the interval's top bound and
over the horizon is **refused**, not flagged — the flag band is strictly
inside the interval.

### Report — interval, not a bare number

`report() -> HorizonReport` states the 80% horizon, the interval
(low/high/width), the task count, and a **pinning verdict**:

| task count | verdict | source's 90% interval for a 60-minute horizon |
|---|---|---|
| `< 30` | `not_pinned` ("NOT pinned") | 27min–2.3h (at 30 tasks) |
| `≥ 150` | `basically_pinned` | 38–74min (at 150 tasks) |
| `≥ 1,000` | `pinned` | 58–73min (at 1,000 tasks) |

## Mapping to the source

Source: METR time horizons (frontier #11, rank 3),
<https://www.agenticsystems.ai/blog/time-horizons/> (2026-10-03, explaining
METR Time Horizon 1.1 of January 2026). Verbatim from the task book:

* "The 50% horizon doubles roughly every 7 months"; 131 days since 2023,
  89 days since 2024 (Time Horizon 1.1, 228 tasks, up from 170).
* Claude Opus 4.5's 50% horizon CI: 1h49m–20h25m — "about 2× in each
  direction".
* "The 80% horizon is much shorter — in the synthetic example it is about a
  third of the 50% horizon" (METR: the 80% horizon is 4–6× shorter).
* Measurements above about 16 hours "aren't reliable with the current
  tasks" ⇒ `MAX_RELIABLE_HORIZON_MINUTES = 960`.
* 30 tasks → 27min–2.3h; 150 tasks → 38–74min; 1,000 tasks → 58–73min
  ⇒ the pinning ladder and its exact thresholds.
* "It takes hundreds of tasks to pin a horizon down" ⇒ the `not_pinned`
  wording.
* Human-baseline conventions can shift an estimate by more than 1.25× ⇒ why
  the report carries the interval and the task count, not just a point.

**Northstar extensions** (this module, not the source):

* The gate refuses a 50% horizon at construction, with the reason stated.
* The 960-minute ceiling is enforced as a construction refusal.
* The interval and the task count are mandatory; the gate does not exist
  without them.
* The `FLAGGED` third state and the proximity margin (default 10 minutes)
  are Northstar's own.
* The task unit is **human minutes** — the source's unit, carried through
  unchanged.

## Honest scope

* The horizon, its interval and the task estimate are **caller-supplied**.
  This module does not measure how long a human takes; it applies a
  declared, verified horizon to a declared estimate. A caller that lies
  about either gets a useless gate.
* The gate is pure and in-memory. It holds no tasks of its own beyond the
  acceptances it has recorded, and it persists nothing.
* It is a **library, not a wiring change**. `long_horizon.py`,
  `task_manager.py` and `task_queue.py` are **not** modified by this slice;
  a host adopts the gate by calling `HorizonGate.admit()` on a task's
  estimated human duration before it starts the task.
* The module is **not declared in `pyproject.toml`.** The runtime component's
  `test_module_layout.test_every_module_is_installed` asserts that every
  module on disk appears in `[tool.setuptools] py-modules`. That test
  already fails at this slice's parent commit — with `annotation_pin`,
  `artifact_authority`, `cancellation_tombstone`, `coverage_manifest`,
  `endpoint_identity`, `evidence_independence`, `key_custody`,
  `ledger_concurrency`, `retry_config`, `revision_checked_tool_results`,
  `state_budget`, `strands_checkpoint`, `swe_failure_modes` and
  `tool_output_filter` undeclared — and `horizon_gate` joins the same list,
  so **no new test failure appears**. The declaration is still owed; this
  slice's writable-file set covers only the module, its tests and this
  design doc, so it is left to the slice that owns the packaging metadata.

## Tests

`components/northstar-agent-runtime/tests/test_horizon_gate.py` — 38 test
methods in five classes:

* `DeclarationTests` (12) — the three mandatory inputs, the 50% refusal, the
  960-minute refusal, the interval shape, the task-count shape.
* `AdmissionTests` (13) — admit / refuse / flag, the overage, the
  three-state verdict, the caller-supplied margin, bad task durations.
* `ReportTests` (6) — the report's contents and the pinning ladder's exact
  boundaries (29/30, 149/150, 999/1000).
* `FullPathTests` (5) — the three real paths driven end to end on a live
  gate: an admitted task taken in, an over-horizon task **not** taken in
  with the overage and the "decompose or route to a human" recommendation, a
  near-the-top task taken in with a flag and an enhanced-monitoring
  recommendation.
* `ModuleShapeTests` (2) — the version/unit/schema pins and the thresholds
  that come from the source.
