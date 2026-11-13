# capability-ceiling-probe — fail-first admission, calibration error, ceiling routing

Module: `components/northstar-agent-runtime/capability_ceiling_probe.py`
Tests: `components/northstar-agent-runtime/tests/test_capability_ceiling_probe.py`
Status: implemented, measured, documented. No version bump, no tag, no merge.

## 1. What was missing (read from the code)

| existing module | what it does | what it does **not** do |
|---|---|---|
| `capability_eval.py` | ledger of capability claims: register → book probe → host-declared outcome (`pass`/`fail`/`partial`/`timeout`/`error`) + score → verdict → profile | no difficulty score; no calibration; nothing compares a claimed confidence with what happened |
| `confidence_gate.py` | gates *authorization* on a confidence tier (allow / observer / escalate / deny) | its own docstring: "Not the calibrator -- host provides confidence scores." It consumes a number, never checks it |
| `exploit_difficulty.py` | one-way difficulty ratchet for the `exploit` category only | rates a *target class*, not this agent's ceiling; no calibration |
| `horizon_gate.py` | admits a task inside a **declared** verified 80% horizon | its registration discipline is what this module copies (a number is only as good as its evidence) |
| whole repo | — | no module measures a calibration error; `calibrat` appears only as an inline word in unrelated files |

So: **nothing measured a capability ceiling, and nothing measured confidently-wrong.**
A model that scores in the single digits on a hard exam while reporting 95%
confidence — exactly the failure HLE reports — was invisible to the runtime.

## 2. Source mapping

### 2.1 Verbatim from the source (Humanity's Last Exam, arXiv:2501.14249)

These numbers and rules are the source's, quoted unchanged:

- **2,500** expert-written, multi-domain, closed-book, auto-gradable questions.
- **76%** exact-match, **24%** multiple-choice; about **14%** multimodal.
- **Fail-first admission**: a question is admitted only if it *stops a frontier
  model*. Roughly **70,000** candidates were filtered to **13,000**, and
  **2,500** survived final review; about **500** are held out unpublished.
- Early frontier models scored in the single digits while their **calibration
  error exceeded 70%** — wrong *and* confident. HLE measures capability and
  calibration together.

### 2.2 Northstar extensions (this module, **not** the source)

| extension | why | value |
|---|---|---|
| **difficulty proxy** | HLE has a curated question bank; Northstar has no equivalent, so "how hard is this task" is proxied by the METR-style estimate of how many minutes a human needs for it | `DIFFICULTY_UNIT = "human_minutes"`, `DIFFICULTY_PROXY = "metr-human-minutes"` |
| calibration-error threshold | the source's "over 70%" is a whole-model figure on HLE; this module aggregates per difficulty bucket | `DEFAULT_CALIBRATION_THRESHOLD = 0.20` |
| difficulty buckets | calibration is aggregated per difficulty band | `BUCKET_EDGES = (30, 60, 120, 240, 480)` human minutes |
| decomposition band | how far over the ceiling a task can be and still be worth splitting | `DECOMPOSE_FACTOR = 2.0` |

**The difficulty score is the METR human-minutes proxy — a Northstar
extension, not an HLE mechanism.** HLE never scores difficulty in human
minutes; it curates questions by hand. Every threshold above is a
Northstar choice and is marked as such here and in the module docstring.

## 3. The rules, fixed

### 3.1 Fail-first admission

A task the agent has **passed** is not a capability-ceiling probe and is
refused outright:

```python
ledger.admit_probe(CeilingProbe("easy", 10.0, 0.95, passed=True))
# -> NotAFailureError
```

Only a task the agent got **wrong** enters the probe library. The
refusal is loud and total: the task is not recorded at all, and its probe
id stays free for a later genuine failure.

`observe()` is the softer door used when a *pass* still deserves to be
counted — as a calibration observation, and as the only thing that may
raise the ceiling. `observe()` records the pass but does not admit it to
the probe library (`Submission.admitted` is `False`).

### 3.2 Calibration error

Every observation registers three things: the **difficulty** (proxy),
the agent's **confidence** (0–1), and the **actual outcome** (pass/fail).

Per bucket, the calibration error is defined and frozen as:

```
error = mean(confidence) - accuracy
```

`accuracy` is the fraction of observations in the bucket that were
correct. The error is signed: positive means overconfident, negative
means underconfident. A bucket whose `abs(error)` exceeds
`calibration_threshold` is flagged `miscalibrated`.

The case the source reports is exactly this module's `overconfident`
direction: confidence 0.93 on a task the agent failed → error `+0.93` →
miscalibrated.

Empty buckets are **omitted**, never zero-filled: a bucket with no
observations has no calibration error, and reporting `0.0` for it would
invent a number.

### 3.3 The ceiling only rises on measured evidence

- The ceiling starts as `None` (unmeasured). It is never inferred.
- A **measured pass** raises it to that task's difficulty (never lowers it).
- A **failure** never lowers it and never raises it. A failure says
  *"this task is above the ceiling"*; it does not say *"the ceiling was
  wrong"*. This is the rule the brief pins: *one failure does not lower
  the ceiling*.
- `declared_ceiling_human_minutes` lets a caller start from a declared
  ceiling; it is reported as `ceiling_source = "declared"`, and any
  measured pass above it flips the source to `"measured"`.
- A pass *at* the ceiling is not a raise: `ceiling_raised_to` is `None`.

The registration discipline is deliberately the one `horizon_gate.py`
uses — a horizon/ceiling is only as good as the evidence behind it, and
this module reports that evidence (`ceiling_source`) next to the number.

### 3.4 Over-ceiling routing

`route(difficulty)` compares a task estimate against the verified ceiling:

| condition | route | meaning |
|---|---|---|
| `difficulty <= ceiling` | `ATTEMPT` | inside the ceiling — take it |
| `ceiling < difficulty <= ceiling * 2` | `DECOMPOSE` | over the ceiling but splittable — split it |
| `difficulty > ceiling * 2` | `HUMAN` | far over — hand it to a person |
| no ceiling measured | `DECOMPOSE` | an unknown ceiling admits nothing; the ceiling is never invented to fill the gap |

**Routing is bookkeeping plus a verdict, never a dispatch.** The module
records the verdict in `ledger.verdicts`; it does not send anything to a
human and it does not split anything.

## 4. API

```python
from capability_ceiling_probe import (
    CeilingLedger, CeilingProbe, CalibrationBucket, RoutingVerdict,
    Submission, RouteTarget, bucket_for,
    BadProbeError, DuplicateProbeError, NotAFailureError,
)

probe = CeilingProbe("p-1", 90.0, 0.93, passed=False)
probe.bucket        # "60-120"
probe.error         # 0.93  (confidence - actual correctness)

ledger = CeilingLedger(calibration_threshold=0.20)
ledger.admit_probe(probe)            # -> Submission(admitted=True)
ledger.observe(CeilingProbe("p-2", 30.0, 0.95, passed=True))
ledger.verified_ceiling_human_minutes   # 30.0
ledger.ceiling_source                    # "measured"
ledger.calibration()                     # tuple[CalibrationBucket, ...]
ledger.miscalibrated_buckets()           # only the flagged ones
ledger.route(90.0)                       # -> RoutingVerdict(route=HUMAN)
ledger.probes / ledger.passes / ledger.verdicts
```

Records are frozen dataclasses and carry `as_dict()` with the schema pin
(`northstar.capability-ceiling-probe.v1`) and the version pin
(`capability-ceiling-probe.v1`). The module is pure, in-memory and
stdlib-only.

## 5. Honest scope / open items

Open (deliberately not built in this slice):

- **No persistence.** The ledger is in-memory; the caller owns durability.
- **The difficulty estimate is caller-supplied.** A caller that lies about
  the human-minute estimate gets a useless ceiling. The module does not
  measure human time.
- **No dispatch.** `DECOMPOSE`/`HUMAN` are verdicts, not actions.
- **Not wired into `capability_eval.py` or `confidence_gate.py`.** This
  slice adds a new module only; it does not change existing modules, so
  the runtime does not yet enforce this gate on any real path.
- **Per-model ceilings.** One ledger is one agent's ceiling; comparing two
  agents means two ledgers.
- The source's "over 70%" whole-model calibration error is **not**
  reproduced here: this module reports *per-bucket* error with a
  Northstar-chosen threshold, and the two numbers are not comparable.
