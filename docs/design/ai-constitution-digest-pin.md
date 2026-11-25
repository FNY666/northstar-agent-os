# ai_constitution: the same four pin defects, in the fourth module

**Date:** 2026-11-25
**From:** the submission window (session 728a716a)
**Status:** FIXED, with each defect measured before and after, and every
fix proved by a planted mutant.

## 1. The one-line finding

`components/northstar-agent-runtime/ai_constitution.py` carried **all
four** of the digest-pin defects that `graph_database.py` carried
first (commit `66e6ccd4`), `status_page.py` carried second (commit
`9f01f1ef`), and `zero_knowledge.py` carried third — the same four, in
the same places, with the same measurements.

This is the **house pattern** of the runtime: a module that pins a
digest over caller-supplied content inherits four obligations, and the
runtime's modules were written without them.

## 2. The four defects, measured

All four measured 2026-11-25 on the tree as it stood.

### 2.1 The canonicalizer's error escaped the module's taxonomy

```python
>>> AIConstitution().declare("\ud800", 1, principle_digest=GOOD)
canonical_json.JcsError: lone surrogate U+D800 is not JCS-serializable
```

`JcsError` is a `ValueError`; `AIConstitutionError` is **not** a
`ValueError` (it derives from `Exception`). So every guard in the
module (`except AIConstitutionError:`) was **dead** for that input, and
the caller got an exception type from a **different module's**
taxonomy.

### 2.2 The stdlib fallback accepted a lone surrogate

```python
>>> acm._canonical(["\ud800"])     # with the fallback installed
b'{"domain":"northstar.ai-constitution.v1","parts":["\\ud800"]}'
```

`json.dumps` escapes the surrogate as `\ud800` and emits bytes that are
**not JCS at all** — and RFC 8785 §3.2.2.3 requires a compliant
implementation to *terminate with an error*. So the fallback **pinned**
a form the shipped path refuses: the two configurations disagreed
about what is **legal**.

### 2.3 A tampered seq above the safe range verified `True`

`canonical_json` serializes an integer outside the safe range as an
IEEE-754 double (RFC 8785 Appendix B note (2)), so `2**53` and
`2**53+1` canonicalize to the **same bytes**. The seq rides in the
**declaration pin**, so the fail-open showed up directly on the
record:

```python
>>> d = acm._pin("declaration", "dec-1", "cai-1", ARTICLE_PUBLIC_SAFETY,
...              STANDING_ADOPTED, GOOD, 2**53)
>>> rec = acm.DeclarationRecord(..., seq=2**53 + 1, digest=d)
>>> rec.verify("dec-1", "cai-1", ARTICLE_PUBLIC_SAFETY,
...            STANDING_ADOPTED, GOOD)
True        # the seq was CHANGED; the digest was not
```

And `_check_seq` had **no** bound at all: it accepted `10**30`.

### 2.4 A failed pin booked no `rejected` row

`declare()`'s `_pin(...)` call sat **outside** the `try` that burns the
seq:

```python
>>> ac = AIConstitution()
>>> ac.declare("\ud800", 1, principle_digest=GOOD)
JcsError
>>> ac.audit_log()
()          # no row
```

So the trail could not tell **"the ledger refused this constitution"**
from **"the ledger never saw it"**.

### 2.5 A per-module nuance: the audit row carries NO pin

`ai_constitution_audit_event` builds an audit row with **no digest at
all** — `schema`, `module`, `kind`, `seq`, `detail`, and nothing else.
So unlike `zero_knowledge.py` (whose seq rides in the audit-event
pin), here the seq's fail-open shows up on the **record** pin.

That is a difference in where the defect lands, not in whether it
lands. The fix is the same.

### 2.6 A second per-module nuance: the fallback's shape

`ai_constitution.py`'s fallback was a bare `json.dumps` shim with **no
tagging at all** — not the `_tag`-style fallback that
`zero_knowledge.py` and `graph_database.py` use. So:

* it had no surrogate check (defect 2.2);
* it had **no integer bound at all**, so it accepted `2**53` exactly —
  where the tagged fallback refused it.

This slice replaces it with the tagged form, which is what the sibling
modules already use, so that the two configurations can agree about
**legality**.

## 3. The fixes

| # | fix | where |
|---|---|---|
| 1 | translate the sibling helper's `ValueError` into `AIConstitutionError` | `_canonical` |
| 2 | refuse a lone surrogate in the fallback's `_tag` | `_canonical` / `_tag` |
| 3 | refuse a seq above `_MAX_INT` | `_check_seq` |
| 3 | refuse an out-of-safe-range integer anywhere in a pin payload | `_canonical` / `_refuse_unsafe_int` |
| 4 | move every `_pin(...)` inside the guarded region | `declare`, `retire` |
| — | `verify()` answers instead of raising | `_verify_pin` + the four record types |

Every fix is the repo's **own pattern**, already shipped in
`graph_database.py`, `status_page.py` and `zero_knowledge.py`, and
before those in `job_queue.py`:

* the `ValueError` translation — `job_queue.py::_canonical`,
  `graph_database.py::_canonical`, `status_page.py::_canonical`,
  `zero_knowledge.py::_canonical`;
* the `2**53 - 1` bound — `job_queue.py::_check_seq`,
  `graph_database.py::_check_seq`, `status_page.py::_check_seq`,
  `zero_knowledge.py::_check_seq`, `grant_pin_ledger.py`
  (`_MAX_COUNTER`), `profiler.py` (`record_digest()`);
* the lone-surrogate refusal — required by RFC 8785 §3.2.2.3, already
  in `canonical_json.py` and now in every fallback.

### 3.1 The import shape

The module imported the sibling helper's **functions**:

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
the module — and a module that cannot be tested in both configurations
is a module whose second configuration is untested.

This slice changes it to the shape `status_page.py` and
`graph_database.py` already use:

```python
try:
    import canonical_json as _cj
except Exception:
    _cj = None
```

with a module-level `_canonical(payload)` that dispatches on `_cj` at
call time. That makes both configurations reachable from a test, which
is what lets the "both configurations must agree about legality" test
exist at all.

**The change is internal.** `jcs_canonical_json` and
`jcs_sha256_hex` were module-level *names* before; nothing outside the
module imported them (checked: only the module's own test file
references the module, and it does not use those two names).

### 3.2 The refusal's SHAPE

The repo has two conventions for a refused call, and they are not
interchangeable (`docs/design/refusal-hold-wiring.md` §21.3):

| the refusal is... | consumes the seq? | books a trail row? |
|---|---|---|
| a malformed **seq** (not an int, negative, oversized) | no | no |
| a malformed **argument** at a valid seq | yes | yes |

An oversized seq is a malformed **seq**: the call never reached the
ledger. Measured after the fix — an oversized seq books **no** row and
does **not** consume the seq, while a failed *pin* at a valid seq
books a row and consumes the seq. Both raise `AIConstitutionError`, so
the **shape** is what distinguishes them, and the tests assert it.

## 4. Why this is not a weakening

Every fix **narrows** what the module accepts:

* the surrogate refusal is required by RFC 8785 §3.2.2.3;
* the seq bound is the repo's own `_MAX_INT`, already used by six
  sibling modules;
* the pin refusal is the fallback's own bound, which the shipped path
  now matches;
* moving the pin inside the `try` changes **no** refusal's type — only
  that a failed pin now leaves a trace.

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

### 4.2 A test that changed its claim because the fix made it obsolete

The first draft of `test_a_tampered_seq_above_the_safe_range_cannot_verify`
minted a digest over `seq=2**53` and asserted that a record carrying
`seq=2**53 + 1` with that digest does **not** verify.

After the fix, minting that digest **raises** — `_refuse_unsafe_int`
refuses the out-of-range integer in the payload, so the pin cannot be
created at all. The test therefore changed to assert the *stronger*
property: the tampered record does not verify **and** the pin cannot be
minted over an out-of-range seq.

This is the same discipline as `status_page`'s §4.2, in a different
guise: *a test that passes for the wrong reason measures nothing*, and
a test whose premise the fix has invalidated must be rewritten, not
padded.

## 5. The measurements

### 5.1 Before and after

| property | before | after |
|---|---|---|
| `declare(constitution_id="\ud800", ...)` | raises `JcsError` | raises `AIConstitutionError` |
| `verify()` on an unencodable record | **raises** | answers `False` |
| fallback on a lone surrogate | **accepts** (non-JCS bytes) | refuses |
| shipped path on `2**53` | accepts (lossy) | refuses |
| a record whose seq was bumped above the safe range | **verifies `True`** | verifies `False` |
| failed pin books a `rejected` row | **no** | yes |
| failed mutation consumes its seq | yes | yes (unchanged) |

### 5.2 The mutants

Every fix was proved by planting the fault and re-running the suite.

| mutant | what it breaks | result |
|---|---|---|
| A | `except ValueError` → `except ZeroDivisionError` | **killed** — 4 failures |
| B | fallback's surrogate check → `if False` | **killed** — 1 failure |
| C | remove the seq bound | **killed** — 1 failure |
| D | drop the `_refuse_unsafe_int(payload)` call | **killed** — 2 failures |
| E | `_refuse_unsafe_int` checks only the top level | **killed** — 2 failures |
| F | `_verify_pin` returns `True` on an unencodable payload | **killed** — 2 failures |
| G | the pin moves back out of the guarded region (declare) | **killed** — 16 failures |
| H | the pin moves back out of the guarded region (retire) | **killed** — 3 failures |
| I | the fallback accepts a surrogate (no check at all) | **killed** — 1 failure |

### 5.3 Suites

* `tests/test_ai_constitution.py` — **26 passed** (12 new test
  functions).
* the repo suite — **462 passed**, 0 failed.
* the module's own self-check — `ai-constitution OK`.
* the full component suite — see §7.

## 6. What this does NOT change

* **The two configurations still disagree about the digest bytes.** The
  shipped path emits JCS; the fallback emits its own tagged form. This
  slice makes them agree about *legality*, not about *bytes*. A digest
  minted under the fallback does not verify under the shipped path,
  and that was true before.
* **The public API is unchanged.** No signature, no new error type in
  the happy path, no record shape. The refusals are the same
  `AIConstitutionError` subclasses the module already raised.
* **The audit row still carries no digest.** That is the module's
  design; this slice does not add one. The seq is pinned by the record
  pins, which is where it was already pinned.
* **The module still proves no constitutional fact.** It books
  declarations and derives posture by rule; the digests are pins over
  declared content, not a proof of provenance.

## 7. The general lesson, and the scope it leaves open

**A house pattern without a house guard is a defect in every house.**
The runtime has **1619** top-level modules (the helper `canonical_json.py`
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

At the time this slice was written, four of the seven were fixed (this
slice and its three predecessors) and the other three were the next
slices.

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
| `components/northstar-agent-runtime/ai_constitution.py` | the five fixes, plus the `_cj` import shape |
| `components/northstar-agent-runtime/tests/test_ai_constitution.py` | 12 new test functions, 6 controls |

Related:

* `docs/design/graph-database-digest-pin.md` — the first module to
  carry these four defects; shipped in commit `66e6ccd4`.
* `docs/design/status-page-digest-pin.md` — the second; shipped in
  commit `9f01f1ef`.
* `docs/design/zero-knowledge-digest-pin.md` — the third.
* `docs/design/refusal-hold-wiring.md` §20.6 — the open item the
  first of those closed.
* `docs/design/refusal-hold-wiring.md` §21.2, §21.3 — the
  digest-fidelity defect and the two refusal conventions.
