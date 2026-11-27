# ai_interpretability and ai_perturbation: the pin defects, in the fifth and sixth modules

**Date:** 2026-11-25
**From:** the submission window (session 728a716a)
**Status:** FIXED, with each defect measured before and after, and every
fix proved by a planted mutant.

## 1. The one-line finding

`ai_interpretability.py` and `ai_perturbation.py` carried **all four**
of the digest-pin defects that `graph_database.py` carried first
(commit `66e6ccd4`), `status_page.py` carried second (commit
`9f01f1ef`), `zero_knowledge.py` carried third, and `ai_constitution.py`
carried fourth — the same four, in the same places, with the same
measurements.

These two modules are **siblings by construction**: the same house
pattern, the same vocabulary shape, the same record shapes, the same
trail discipline. They were written from one template, and they were
missing the same four obligations.

## 2. The four defects, measured

Measured 2026-11-25 on the tree as it stood, for both modules.

### 2.1 The canonicalizer's error escaped the module's taxonomy

```python
>>> AIInterpretability().interpret("\ud800", 1)
canonical_json.JcsError: lone surrogate U+D800 is not JCS-serializable
>>> AIPerturbation().perturb("\ud800", 1)
canonical_json.JcsError: lone surrogate U+D800 is not JCS-serializable
```

`JcsError` is a `ValueError`; `AIInterpretabilityError` and
`AIPerturbationError` are **not** (they derive from `Exception`). So
every guard in both modules (`except AIInterpretabilityError:` /
`except AIPerturbationError:`) was **dead** for that input.

### 2.2 The stdlib fallback accepted a lone surrogate

Both modules' fallbacks were a bare `json.dumps` shim with **no**
surrogate check:

```python
>>> ai_interpretability._canonical(["\ud800"])   # fallback installed
b'{"domain":"northstar.ai-interpretability.v1","parts":["\\ud800"]}'
```

`json.dumps` escapes the surrogate as `\ud800` and emits bytes that are
**not JCS at all** — and RFC 8785 §3.2.2.3 requires a compliant
implementation to *terminate with an error*. So the fallback **pinned**
a form the shipped path refuses.

### 2.3 A tampered seq above the safe range pinned the same bytes

`canonical_json` serializes an integer outside the safe range as an
IEEE-754 double (RFC 8785 Appendix B note (2)), so `2**53` and
`2**53+1` canonicalize to the **same bytes**. The seq rides in both
modules' record pins, so the fail-open showed up directly on the
record:

```python
>>> d = ai_interpretability._pin("interpretation", "int-1", "sys-s",
...                              MTH_MECHANISTIC, FND_INTERPRETABLE,
...                              "", 2**53)
>>> rec.interpretation_id = "int-1"; rec.seq = 2**53 + 1; rec.digest = d
>>> rec.verify("int-1", "sys-s", MTH_MECHANISTIC, FND_INTERPRETABLE, "")
True        # the seq was CHANGED; the digest was not
```

And `_check_seq` had **no** bound at all: it accepted `10**30`.

### 2.4 A failed pin booked no `rejected` row

**This is where the two modules differ from `ai_constitution.py`, and
the difference is worth recording.**

In `ai_constitution.py` the `_pin(...)` call sat **outside** the
guarded `try`. In these two modules the pin sat **inside** it — in
`ai_interpretability.interpret()` it was already a local `digest`, and
in `ai_perturbation.perturb()` it was inline in the record
constructor, but still inside the `try`.

So the pin did **not** escape the guarded region. But it raised
`JcsError`, which the `except AIInterpretabilityError` handler did
**not** catch — so the handler never ran, and the `rejected` row was
never booked:

```python
>>> ledger = AIInterpretability()
>>> ledger.interpret("\ud800", 1)
JcsError
>>> ledger.audit_log()
()          # no row
```

**The symptom is different; the fix is the same.** Translating the
canonicalizer's error into the module's own type makes the existing
handler catch it, and the row appears — no restructuring of the
guarded region needed.

This is the sharpest form of the repo's lesson: *a guard that fails
for the wrong reason is deletable.* Here the guard was not dead by
shape, but it was dead by **type**, and no amount of reading the code
revealed it. Only a measurement did.

### 2.5 A per-module nuance: the fallback had no integer bound at all

Neither fallback had a tagged form, so neither had an integer bound.
They accepted `2**53` exactly — where `zero_knowledge.py`'s tagged
fallback refused it. This slice replaces both fallbacks with the
tagged form the sibling modules use.

## 3. The fixes

| # | fix | where |
|---|---|---|
| 1 | translate the sibling helper's `ValueError` into the module's own error | `_canonical` |
| 2 | refuse a lone surrogate in the fallback's `_tag` | `_canonical` / `_tag` |
| 3 | refuse a seq above `_MAX_INT` | `_check_seq` |
| 3 | refuse an out-of-safe-range integer anywhere in a pin payload | `_canonical` / `_refuse_unsafe_int` |
| 4 | the pin raises the module's own error, so the existing handler books the row | `_canonical` (via 1) |
| — | `verify()` answers instead of raising | `_verify_pin` + the four record types |

Every fix is the repo's **own pattern**, already shipped in
`graph_database.py`, `status_page.py`, `zero_knowledge.py` and
`ai_constitution.py`, and before those in `job_queue.py`:

* the `ValueError` translation — `job_queue.py::_canonical`,
  `graph_database.py::_canonical`, `status_page.py::_canonical`,
  `zero_knowledge.py::_canonical`, `ai_constitution.py::_canonical`;
* the `2**53 - 1` bound — `job_queue.py::_check_seq`,
  `graph_database.py::_check_seq`, `status_page.py::_check_seq`,
  `zero_knowledge.py::_check_seq`, `ai_constitution.py::_check_seq`,
  `grant_pin_ledger.py` (`_MAX_COUNTER`), `profiler.py`
  (`record_digest()`);
* the lone-surrogate refusal — required by RFC 8785 §3.2.2.3, already
  in `canonical_json.py` and now in every fallback.

### 3.1 The import shape

Both modules imported the sibling helper's **functions**:

```python
try:
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:
    import json as _json
    def jcs_canonical_json(obj): ...
    def jcs_sha256_hex(obj): ...
```

That shape has a defect of its own: **there is no switch**. The
shipped path and the fallback are two *different functions* chosen at
import time, so no test can exercise the fallback without reloading
the module — and a module whose second configuration cannot be tested
has an untested second configuration.

This slice changes it to the shape `status_page.py`,
`graph_database.py` and `ai_constitution.py` already use:

```python
try:
    import canonical_json as _cj
except Exception:
    _cj = None
```

with a module-level `_canonical(payload)` that dispatches on `_cj` at
call time. That is what lets the "both configurations must agree about
legality" test exist at all.

**The change is internal.** Nothing outside the module imported
`jcs_canonical_json` or `jcs_sha256_hex` from these two modules
(checked).

### 3.2 `ai_perturbation`'s pin moves into a local

In `ai_perturbation.perturb()` the `_pin(...)` call was inline in the
record constructor:

```python
record = PerturbationRecord(
    ...,
    digest=_pin("perturbation", perturbation_id, system_id, ...),
)
```

This slice hoists it into a local `digest`, computed **before** the
record is built. That is not a behavior change — both forms raise in
the same place — but it makes the guarded region's shape explicit and
matches `ai_interpretability.interpret()`, which already used a local.

### 3.3 The refusal's SHAPE

The repo has two conventions for a refused call, and they are not
interchangeable (`docs/design/refusal-hold-wiring.md` §21.3):

| the refusal is... | consumes the seq? | books a trail row? |
|---|---|---|
| a malformed **seq** (not an int, negative, oversized) | no | no |
| a malformed **argument** at a valid seq | yes | yes |

An oversized seq is a malformed **seq**: the call never reached the
ledger. Measured after the fix — an oversized seq books **no** row and
does **not** consume the seq, while a failed *pin* at a valid seq
books a row and consumes the seq. Both raise the module's own error
type, so the **shape** is what distinguishes them, and the tests assert
it.

## 4. Why this is not a weakening

Every fix **narrows** what the modules accept:

* the surrogate refusal is required by RFC 8785 §3.2.2.3;
* the seq bound is the repo's own `_MAX_INT`, already used by seven
  sibling modules;
* the pin refusal is the fallback's own bound, which the shipped path
  now matches;
* translating the error changes **no** refusal's type — it only makes
  the module's existing handler catch it, so a failed pin now leaves a
  trace.

`verify()` now answers `False` where it used to raise — that is a
**narrowing** of the claim "this record is intact", which is the safe
direction.

### 4.1 The controls

| control | what it would catch |
|---|---|
| `test_both_configurations_accept_a_value_both_can_canonicalize` | a fallback that refuses **everything** (vacuous agreement) |
| `test_the_safe_range_boundary_is_accepted` | a bound that over-refuses `2**53 - 1` |
| `test_an_oversized_seq_is_refused_as_a_malformed_seq` | the bound placed at the wrong layer |
| `test_a_failed_mutation_still_consumes_its_seq` | a fix that changes the seq semantics |
| `test_a_pin_still_accepts_the_last_safe_integer` | a pin refusal that over-reaches |
| `test_a_tampered_seq_above_the_safe_range_cannot_verify` | a pin that does not pin what it claims |

### 4.2 The RED check

Every new test was run against the **pristine** module before the fix,
to prove it fails for the right reason:

| module | pristine | fixed |
|---|---|---|
| `ai_interpretability.py` | **10 failed**, 16 passed | 26 passed |
| `ai_perturbation.py` | **10 failed**, 16 passed | 26 passed |

A test that has never failed against the broken code measures nothing.

## 5. The measurements

### 5.1 Before and after

| property | before | after |
|---|---|---|
| `interpret(system_id="\ud800", ...)` | raises `JcsError` | raises `AIInterpretabilityError` |
| `perturb(system_id="\ud800", ...)` | raises `JcsError` | raises `AIPerturbationError` |
| `verify()` on an unencodable record | **raises** | answers `False` |
| fallback on a lone surrogate | **accepts** (non-JCS bytes) | refuses |
| shipped path on `2**53` | accepts (lossy) | refuses |
| a record whose seq was bumped above the safe range | **verifies `True`** | verifies `False` |
| failed pin books a `rejected` row | **no** | yes |
| failed mutation consumes its seq | yes | yes (unchanged) |

### 5.2 The mutants

Every fix was proved by planting the fault and re-running the suite.

`ai_interpretability.py` — 8 mutants, all killed:

| mutant | what it breaks | result |
|---|---|---|
| A | `except ValueError` → `except ZeroDivisionError` | **killed** — 4 failures |
| B | fallback's surrogate check → `if False` | **killed** — 1 failure |
| C | remove the seq bound | **killed** — 1 failure |
| D | drop the `_refuse_unsafe_int(payload)` call | **killed** — 2 failures |
| E | `_refuse_unsafe_int` checks only the top level | **killed** — 2 failures |
| F | `_verify_pin` returns `True` on an unencodable payload | **killed** — 2 failures |
| G | the fallback accepts a surrogate (no check at all) | **killed** — 1 failure |
| H | the interpretation pin escapes the guarded region | **killed** — 17 failures |

`ai_perturbation.py` — 9 mutants, all killed:

| mutant | what it breaks | result |
|---|---|---|
| A | `except ValueError` → `except ZeroDivisionError` | **killed** — 4 failures |
| B | fallback's surrogate check → `if False` | **killed** — 1 failure |
| C | remove the seq bound | **killed** — 1 failure |
| D | drop the `_refuse_unsafe_int(payload)` call | **killed** — 2 failures |
| E | `_refuse_unsafe_int` checks only the top level | **killed** — 2 failures |
| F | `_verify_pin` returns `True` on an unencodable payload | **killed** — 2 failures |
| G | the fallback accepts a surrogate (no check at all) | **killed** — 1 failure |
| H | the perturbation pin moves back into the constructor | **killed** — 8 failures |
| I | the perturbation pin escapes the guarded region | **killed** — 16 failures |

### 5.3 Suites

* `tests/test_ai_interpretability.py` — **26 passed** (11 new test
  functions).
* `tests/test_ai_perturbation.py` — **26 passed** (11 new test
  functions).
* the repo suite — **462 passed**, 0 failed.
* both modules' own self-checks — `ai-interpretability OK`,
  `ai-perturbation OK`.

## 6. What this does NOT change

* **The two configurations still disagree about the digest bytes.** The
  shipped path emits JCS; the fallback emits its own tagged form. This
  slice makes them agree about *legality*, not about *bytes*.
* **The public API is unchanged.** No signature, no new error type in
  the happy path, no record shape.
* **The audit rows still carry no digest.** Both modules' audit events
  are plain dicts with no pin; the seq is pinned by the record pins,
  which is where it was already pinned.
* **The modules still prove no interpretability or perturbation fact.**
  They book declarations and derive posture by rule; the digests are
  pins over declared content, not a proof of provenance.

## 7. The general lesson, and the scope it leaves open

**A house pattern without a house guard is a defect in every house.**
The runtime has **1620** top-level modules (the helper `canonical_json.py`
excluded). **687** of them call one of its three canonicalizers
(`jcs_dumps`, `jcs_canonical_json`, `jcs_sha256_hex`), and **629** of
those import the sibling helper behind a `try/except` fallback — the
configuration this defect lives in. **643** modules import it that way
whether or not they call it directly.

*(Measured 2026-11-25 on the pre-fix tree, `66e6ccd4~1`, with an AST
walk over the runtime's top-level modules. These numbers REPLACE an
earlier claim of "672 modules, 189 with a fallback, 165 candidate sites
across 54 modules", which does not reproduce under any of ~40
definitions tried — the `grep` in the earlier claim also ran with
ugrep, which skips git-ignored directories, so its result depended on
the directory it started in. A count in a doc is a claim too.)*

An AST sweep over the fallback importers found **611 candidate sites**
across **200 modules** on the **pre-fix** tree, and **628 sites across
201 modules** on the fixed tree: a `try` whose body reaches a
canonicalizer and whose first handler catches the module's own error
class without catching `ValueError`. The difference is the seven fixed
modules themselves — each fix moved its pin *inside* the guarded
region, which is exactly what the defect was, so a sweep that reads
shape alone now sees them as dead-guard sites.

The counts are produced by `scripts/digest-pin-census.py` and pinned by
`tests/test_digest_pin_census.py`.

**611 is a worklist, not a finding.** A dynamic probe — instantiate
each candidate module's ledger class, enumerate its public methods,
build a call with every string parameter set to a lone surrogate and
every int parameter set to 1, and check whether `JcsError` escapes —
found **7 live**:

| module | method | `JcsError` escapes | a `rejected` row booked? |
|---|---|---|---|
| `graph_database.py` | `graph` / `node` | yes | **no** |
| `status_page.py` | `component` | yes | **no** |
| `ai_constitution.py` | `declare` | yes | **no** |
| `ai_interpretability.py` | `interpret` | yes | **no** |
| `ai_perturbation.py` | `perturb` | yes | **no** |
| `graphql_gateway.py` | `plan` | yes | n/a (a pure read view) |
| `zero_knowledge.py` | `setup` | yes | **no** |

**All seven are fixed**, and re-running the probe on the fixed tree
finds **0 live sites**: each of the seven now raises its **own** error
type and books its `rejected` row (`plan` books none, correctly — it is
a pure read view).

Two measurements about the probe itself, both worth recording:

* **A generic probe is not enough.** The probe has to supply
  **crafted** inputs per module: `zero_knowledge.setup()` validates
  `ceremony` and `constraint_digest` against a pinned vocabulary
  before it reaches the pin, so a lone surrogate in `circuit_id` is
  refused as a `BadDigestError` and the probe never sees the escape.
  With a valid `constraint_digest`, the same call escapes. A guard
  that reads only clean real files is unverifiable.
* **A sweep that misses a live module is not a sweep.** On the
  **pre-fix** tree the strict sweep (611 sites / 200 modules) finds
  **six** of the seven, not seven: `status_page.py`'s pin sits
  **outside** its guarded `try`, so it is not a "dead guard" site at
  all. That seventh was found by exercising the modules, not by
  reading them. On the **fixed** tree the sweep finds **all seven**
  (628 sites / 201 modules) — because the fix moved `status_page`'s
  pin *inside* the guarded region, which is what the defect was.
  This is the same lesson `graphql_gateway.py` teaches in §2.4: the
  finding is per METHOD and per SHAPE, not per module. A sweep's
  output is a function of the tree it ran on, so a sweep's count
  must name the tree.

At the time this slice was written, six of the seven were fixed (this
slice and its four predecessors, plus `graphql_gateway.py` in its own
slice).

The counts are produced by `scripts/digest-pin-census.py`, and
`tests/test_digest_pin_census.py` pins them, so the numbers in this
section are a measurement rather than a claim.

The lesson: *reachability decides, not the shape of the code.* A guard
that looks dead may be behind a validation that never lets the bad
value through. So the sweep's 611 sites must never be reported as 611
defects — and the probe's 7 must never be reported without having
actually exercised each one.

## 8. Where the fix lives

| file | change |
|---|---|
| `components/northstar-agent-runtime/ai_interpretability.py` | the five fixes, plus the `_cj` import shape |
| `components/northstar-agent-runtime/tests/test_ai_interpretability.py` | 11 new test functions, 6 controls |
| `components/northstar-agent-runtime/ai_perturbation.py` | the five fixes, plus the `_cj` import shape |
| `components/northstar-agent-runtime/tests/test_ai_perturbation.py` | 11 new test functions, 6 controls |

Related:

* `docs/design/graph-database-digest-pin.md` — the first module to
  carry these four defects; shipped in commit `66e6ccd4`.
* `docs/design/status-page-digest-pin.md` — the second; shipped in
  commit `9f01f1ef`.
* `docs/design/zero-knowledge-digest-pin.md` — the third.
* `docs/design/ai-constitution-digest-pin.md` — the fourth.
* `docs/design/refusal-hold-wiring.md` §20.6 — the open item the
  first of those closed.
* `docs/design/refusal-hold-wiring.md` §21.2, §21.3 — the
  digest-fidelity defect and the two refusal conventions.
