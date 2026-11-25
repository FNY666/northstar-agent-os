# graphql_gateway: the pin defects, in the seventh module

**Date:** 2026-11-25
**From:** the submission window (session 728a716a)
**Status:** FIXED, with each defect measured before and after, and every
fix proved by a planted mutant.

## 1. The one-line finding

`components/northstar-agent-runtime/graphql_gateway.py` carried **all
four** of the digest-pin defects that `graph_database.py` carried
first (commit `66e6ccd4`) and that five further modules carried after
it — the same four, in the same places, with the same measurements.

This module is the **seventh and last** of the seven the reachability
probe found live.

## 2. The four defects, measured

Measured 2026-11-25 on the tree as it stood.

### 2.1 The canonicalizer's error escaped the module's taxonomy

```python
>>> GraphQLGateway().plan("\ud800", 1)
canonical_json.JcsError: lone surrogate U+D800 is not JCS-serializable
```

`JcsError` is a `ValueError`; `GraphQLGatewayError` derives from
`Exception`, so it is **not** a `ValueError`. Every guard in the module
(`except GraphQLGatewayError as err:`) was **dead** for that input, and
the caller got an exception type from a **different module's**
taxonomy.

### 2.2 The stdlib fallback accepted a lone surrogate

```python
>>> gq._cj = None
>>> gq._canonical(["\ud800"])
b'{"t":"list","v":[{"t":"str","v":"\\ud800"}]}'
```

(The pre-fix fallback was a bare `json.dumps` shim, which escaped the
surrogate as `\ud800` and produced non-JCS bytes.) RFC 8785 §3.2.2.3
requires a compliant implementation to *terminate with an error*, so
the fallback **pinned** a form the shipped path refuses.

### 2.3 A tampered seq above the safe range verified `True`

`canonical_json` serializes an integer outside the safe range as an
IEEE-754 double (RFC 8785 Appendix B note (2)), so `2**53` and
`2**53+1` canonicalize to the **same bytes**. The seq rides in every
record payload (`created_at_seq`, `bound_at_seq`,
`federated_at_seq`, `planned_at_seq`), so the fail-open showed up
directly on the record:

```python
>>> rec = SchemaRecord(..., created_at_seq=2**53 + 1, digest=d)
>>> rec.verify_digest()
True        # the seq was CHANGED; the digest was not
```

And `_check_seq_kind` had **no** bound at all.

### 2.4 A failed pin booked no `rejected` row — and here that is CORRECT

**This is the one module where defect 4 is NOT a defect.**

`plan()` is a **pure read view**. The module's own comment says so:

```python
def plan(self, operation, seq, fields=()):
    """Shard ``fields`` across federated subgraphs deterministically.

    Pure read view: validates seq shape but does not consume it and
    writes no audit row of its own...
    """
```

A pure read consumes no seq and books no row. So "the failed pin left
no `rejected` row" is the **correct shape** for a read, not a missing
trail.

What *is* a defect here is that the pin **escaped** (defect 2.1) — the
caller got a foreign exception type out of a read view, and the read
view's own error taxonomy was bypassed.

**This is why the probe's finding is per METHOD and not per module.**
A module that looks broken in one place can be correct in the next, and
a claim written at module level would have been false.

The mutators (`schema`, `resolve`, `federate`, `defederate`) *do* book
a `rejected` row via `_fail(...)`, and they *do* catch
`GraphQLGatewayError` — so once the error is translated into the
module's own type, those paths book their row correctly. That is what
the new shape test asserts.

## 3. The fixes

| # | fix | where |
|---|---|---|
| 1 | translate the sibling helper's `ValueError` into `GraphQLGatewayError` | `_canonical` |
| 2 | refuse a lone surrogate in the fallback's `_tag` | `_canonical` / `_tag` |
| 3 | refuse a seq above `_MAX_INT` | `_check_seq_kind` |
| 3 | refuse an out-of-safe-range integer anywhere in a pin payload | `_canonical` / `_refuse_unsafe_int` |
| — | `verify_digest()` answers instead of raising | `_verify_digest` + the five record types |

Every fix is the repo's **own pattern**, already shipped in
`graph_database.py`, `status_page.py`, `zero_knowledge.py`,
`ai_constitution.py`, `ai_interpretability.py` and `ai_perturbation.py`,
and before those in `job_queue.py`:

* the `ValueError` translation — `job_queue.py::_canonical`,
  `graph_database.py::_canonical`, `status_page.py::_canonical`,
  `zero_knowledge.py::_canonical`, `ai_constitution.py::_canonical`,
  `ai_interpretability.py::_canonical`,
  `ai_perturbation.py::_canonical`;
* the `2**53 - 1` bound — `job_queue.py::_check_seq`,
  `graph_database.py::_check_seq`, `status_page.py::_check_seq`,
  `zero_knowledge.py::_check_seq`, `ai_constitution.py::_check_seq`,
  `ai_interpretability.py::_check_seq`,
  `ai_perturbation.py::_check_seq`, `grant_pin_ledger.py`
  (`_MAX_COUNTER`), `profiler.py` (`record_digest()`);
* the lone-surrogate refusal — required by RFC 8785 §3.2.2.3, already
  in `canonical_json.py` and now in every fallback.

### 3.1 The import shape

The module imported the sibling helper's **function**:

```python
try:
    from canonical_json import jcs_canonical_json
except ImportError:
    import json
    def jcs_canonical_json(obj): ...
```

Same defect as the `ai_*` modules: **there is no switch**, so the
fallback cannot be exercised from a test without reloading the module.

This slice changes it to the shape `status_page.py`,
`graph_database.py` and the `ai_*` modules now use:

```python
try:
    import canonical_json as _cj
except Exception:
    _cj = None
```

with a module-level `_canonical(payload)` that dispatches on `_cj` at
call time.

**The change is internal.** Nothing outside the module imported
`jcs_canonical_json` from it (checked).

### 3.2 The refusal's SHAPE

The repo has two conventions for a refused call, and they are not
interchangeable (`docs/design/refusal-hold-wiring.md` §21.3):

| the refusal is... | consumes the seq? | books a trail row? |
|---|---|---|
| a malformed **seq** (not an int, non-positive, oversized) | no | no |
| a malformed **argument** at a valid seq | yes | yes |

An oversized seq is a malformed **seq**: the call never reached the
ledger. Measured after the fix — an oversized seq books **no** row and
does **not** consume the seq, while a failed *digest* at a valid seq
consumes the seq and books a `rejected` row.

Both raise `GraphQLGatewayError`, so the **shape** is what
distinguishes them, and the tests assert it.

## 4. Why this is not a weakening

Every fix **narrows** what the module accepts:

* the surrogate refusal is required by RFC 8785 §3.2.2.3;
* the seq bound is the repo's own `_MAX_INT`, already used by eight
  sibling modules;
* the pin refusal is the fallback's own bound, which the shipped path
  now matches.

`verify_digest()` now answers `False` where it used to raise — that is
a **narrowing** of the claim "this record is intact", which is the
safe direction.

### 4.1 The controls

| control | what it would catch |
|---|---|
| `test_both_configurations_accept_a_value_both_can_canonicalize` | a fallback that refuses **everything** (vacuous agreement) |
| `test_the_safe_range_boundary_is_accepted` | a bound that over-refuses `2**53 - 1` |
| `test_an_oversized_seq_is_refused_as_a_malformed_seq` | the bound placed at the wrong layer |
| `test_an_oversized_seq_is_refused_before_the_digest_would` | the bound missing altogether |
| `test_a_pin_still_accepts_the_last_safe_integer` | a pin refusal that over-reaches |
| `test_a_tampered_seq_above_the_safe_range_cannot_verify` | a pin that does not pin what it claims |

### 4.2 A mutant that SURVIVED, and the test that killed it

Mutant C — replacing `if seq > _MAX_INT:` with `if False:` — **survived
the first attempt**. Every test still passed.

The reason is the repo's own `status_page` §4.2 lesson, in a third
guise: **both** the seq bound and the digest's own `_refuse_unsafe_int`
raise `GraphQLGatewayError`. So "the call raised" could not tell them
apart, and every test that only asserted "it raised" was satisfied by
either mechanism.

What distinguishes them is the refusal's **shape**: a seq refused at
the door books **no** `rejected` row and consumes no seq; a digest that
fails inside a mutation books a row and consumes the seq. The new test
`test_an_oversized_seq_is_refused_before_the_digest_would` asserts
that shape, and mutant C was then killed.

**Two details in that test had to be got right,** and the first
attempt got both wrong:

* the audit event's key is `"event"`, not `"kind"` — this module's
  audit rows use a different shape from the `ai_*` modules';
* with the wrong key, the test raised `KeyError` rather than failing
  its assertion. A `KeyError` is a failure, but it is not the failure
  the test was written to detect — the same "died for the wrong
  reason" trap the mutant probe exists to catch.

### 4.3 The RED check

Every new test was run against the **pristine** module before the fix:

| pristine | fixed |
|---|---|
| **10 failed**, 16 passed | 26 passed |

A test that has never failed against the broken code measures nothing.

## 5. The measurements

### 5.1 Before and after

| property | before | after |
|---|---|---|
| `plan(operation="\ud800", ...)` | raises `JcsError` | raises `GraphQLGatewayError` |
| `verify_digest()` on an unencodable record | **raises** | answers `False` |
| fallback on a lone surrogate | **accepts** (non-JCS bytes) | refuses |
| shipped path on `2**53` | accepts (lossy) | refuses |
| a record whose seq was bumped above the safe range | **verifies `True`** | verifies `False` |
| an oversized seq books a `rejected` row | **yes** | no (a malformed seq books nothing) |
| failed mutation consumes its seq | yes | yes (unchanged) |

### 5.2 The mutants

Every fix was proved by planting the fault and re-running the suite.

| mutant | what it breaks | result |
|---|---|---|
| A | `except ValueError` → `except ZeroDivisionError` | **killed** — 3 failures |
| B | fallback's surrogate check → `if False` | **killed** — 1 failure |
| C | remove the seq bound | **killed** — 1 failure (after §4.2) |
| D | drop the `_refuse_unsafe_int(payload)` call | **killed** — 2 failures |
| E | `_refuse_unsafe_int` checks only the top level | **killed** — 2 failures |
| F | `_verify_digest` returns `True` on an unencodable payload | **killed** — 2 failures |
| G | the fallback accepts a surrogate (no check at all) | **killed** — 1 failure |
| H | the digest helper goes back to the raw canonicalizer | **killed** — 3 failures |

### 5.3 Suites

* `tests/test_graphql_gateway.py` — **26 passed** (11 new test
  functions).
* the repo suite — **462 passed**, 0 failed.
* the module's own self-check — `graphql-gateway OK`.

## 6. What this does NOT change

* **The two configurations still disagree about the digest bytes.** The
  shipped path emits JCS; the fallback emits its own tagged form. This
  slice makes them agree about *legality*, not about *bytes*.
* **The public API is unchanged.** No signature, no new error type in
  the happy path, no record shape.
* **`plan()` still books no row of its own.** It is a pure read view;
  the shape of its refusals is unchanged, and the module's comment
  still says so.
* **The module still proves no GraphQL fact.** It books schemas,
  resolvers and federations; the digests are pins over declared
  content, not a proof of provenance.

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

This slice closed the class: all seven are now fixed.

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
| `components/northstar-agent-runtime/graphql_gateway.py` | the five fixes, plus the `_cj` import shape |
| `components/northstar-agent-runtime/tests/test_graphql_gateway.py` | 11 new test functions, 6 controls |

Related:

* `docs/design/graph-database-digest-pin.md` — the first module to
  carry these four defects; shipped in commit `66e6ccd4`.
* `docs/design/status-page-digest-pin.md` — the second.
* `docs/design/zero-knowledge-digest-pin.md` — the third.
* `docs/design/ai-constitution-digest-pin.md` — the fourth.
* `docs/design/ai-interpretability-perturbation-digest-pin.md` — the
  fifth and sixth.
* `docs/design/refusal-hold-wiring.md` §20.6 — the open item the
  first of those closed.
* `docs/design/refusal-hold-wiring.md` §21.2, §21.3 — the
  digest-fidelity defect and the two refusal conventions.
