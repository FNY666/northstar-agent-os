# status_page: the same four pin defects, in the second module

**Date:** 2026-11-25
**From:** the submission window (session 728a716a)
**Status:** FIXED, with each defect measured before and after, and every
fix proved by a planted mutant.

## 1. The one-line finding

`components/northstar-agent-runtime/status_page.py` carried **all four**
of the digest-pin defects that `graph_database.py` carried — the same
four, in the same places, with the same measurements.

This is not a coincidence and not a copy-paste error. It is the **house
pattern** of the runtime: a module that pins a digest over
caller-supplied content inherits four obligations, and the runtime's
modules were written without them.

The repo's own design doc already knew this and left it open on
purpose. `docs/design/refusal-hold-wiring.md` §20.6:

> `graph_database.py` has the **identical** clause — `except
> GraphDatabaseError` around its own `_pin()`, with the same
> `canonical_json` behind it. So the same `verify()`-raises bug is
> there. It is a separate module with its own scope, and the repo's
> house pattern is consistent, so it is left for a slice that owns
> `graph_database.py` rather than folded in here.

§21.2 left the **bigger** one open — the digest-fidelity defect above
`2**53`:

> The stdlib fallback *refuses* that integer outright
> (`JobQueueError: integer outside safe range`), so the two
> configurations also disagreed about whether a large seq was legal at
> all — the same divergence §20 found, one level deeper.

`status_page.py` was the next module to carry it.

## 2. The four defects, measured

All four measured 2026-11-25 on the tree as it stood.

### 2.1 The canonicalizer's error escaped the module's taxonomy

```python
>>> StatusPage().component(component_id="\ud800", name="n", seq=1)
canonical_json.JcsError: lone surrogate U+D800 is not JCS-serializable
```

`JcsError` is a `ValueError`; `StatusPageError` is a `ValueError` too —
but `JcsError` is **not** a `StatusPageError`. So every guard in the
module (`except StatusPageError as exc:`) was **dead** for that input.

Two consequences, both real:

* the caller asked the page to refuse a bad component id and got an
  exception type from a **different module's** taxonomy;
* because `JcsError` is a `ValueError`, a caller guarding on
  `except ValueError` treats a **refused mutation** as a **parse
  error** and moves on — the mutation was neither applied nor
  recorded.

`status_page.py`'s `verify()` methods were worse than `graph_database.py`'s:
they had **no `try` at all**, so `verify()` raised directly.

### 2.2 The stdlib fallback accepted a lone surrogate

```python
>>> sp._cj = None
>>> sp._canonical(["\ud800"])
b'{"t":"list","v":[{"t":"str","v":"\\ud800"}]}'
```

`json.dumps` escapes the surrogate as `\ud800` and emits bytes that are
**not JCS at all**. So the fallback **pinned** a form the shipped path
refuses — and the fallback also refused `2**53` while the shipped path
accepted it. The two configurations of one module disagreed about what
is **legal**.

### 2.3 A tampered seq above the safe range verified `True`

`canonical_json` serializes an integer outside the safe range as an
IEEE-754 double (RFC 8785 Appendix B note (2)), so `2**53` and
`2**53+1` canonicalize to the **same bytes**. `status_page._check_seq`
had **no** bound at all:

```python
>>> d = sp._pin(["component", "c", "n", "operational", "g", 2**53])
>>> sp.ComponentRecord(component_id="c", name="n", status="operational",
...                    group="g", seq=2**53 + 1, digest=d).verify()
True        # the seq was CHANGED; the digest was not
```

That is a **fail-OPEN integrity defect**. The digest *is* the tamper
pin, and above the safe range it silently stops pinning.

### 2.4 A failed pin booked no `rejected` row

The class docstring promises:

> Failed mutations consume their seq (ledger position stays total).

and the module books a `rejected` row for every refusal caught inside
the `try`. But the `_pin(...)` calls sat **outside** that `try`:

```python
>>> page = StatusPage()
>>> page.component(component_id="\ud800", name="n", seq=1)
StatusPageError
>>> page.audit_log()
()          # no row
```

So the trail could not tell **"the page refused this component"** from
**"the page never saw it"**.

## 3. The fixes

| # | fix | where |
|---|---|---|
| 1 | translate the sibling helper's `ValueError` into `StatusPageError` | `_canonical` |
| 2 | refuse a lone surrogate in the fallback's `_tag` | `_canonical` / `_tag` |
| 3 | refuse a seq above `_MAX_INT` | `_check_seq` |
| 3 | refuse an out-of-safe-range integer anywhere in a pin payload | `_canonical` / `_refuse_unsafe_int` |
| 4 | move every `_pin(...)` inside the guarded region | `component`, `set_status`, `incident`, `update`, `resolve` |
| — | `verify()` answers instead of raising | `_verify_pin` + the six record types |

Every fix is the repo's **own pattern**, already shipped in
`graph_database.py` (commit `66e6ccd4`) and, before that, in
`job_queue.py`:

* the `ValueError` translation — `job_queue.py::_canonical`,
  `graph_database.py::_canonical`;
* the `2**53 - 1` seq bound — `job_queue.py::_check_seq`,
  `graph_database.py::_check_seq`, `grant_pin_ledger.py`
  (`_MAX_COUNTER`), `profiler.py` (`record_digest()`);
* the lone-surrogate refusal — required by RFC 8785 §3.2.2.3, already
  in `canonical_json.py` and now in every fallback.

**No new numbers and no new rules.** `status_page.py` gained one
constant, `_MAX_INT = 2**53 - 1`, which is the value the sibling
modules already use.

### 3.1 The refusal's SHAPE

The repo has two conventions for a refused call, and they are not
interchangeable (`docs/design/refusal-hold-wiring.md` §21.3):

| the refusal is... | consumes the seq? | books a trail row? |
|---|---|---|
| a malformed **seq** (not an int, negative, oversized) | no | no |
| a malformed **argument** at a valid seq | yes | yes |

An oversized seq is a malformed **seq**: the call never reached the
ledger. Measured after the fix — an oversized seq books **no** row and
does **not** consume the seq, while a failed *pin* at a valid seq
books a row and consumes the seq. Both raise `StatusPageError`, so the
**shape** is what distinguishes them, and the tests assert it.

## 4. Why this is not a weakening

Every fix **narrows** what the module accepts:

* the surrogate refusal is required by RFC 8785 §3.2.2.3;
* the seq bound is the repo's own `_MAX_INT`, already used by four
  sibling modules;
* the pin refusal is the fallback's own bound (`abs(v) >= 2**53`),
  which the shipped path now matches;
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
| `test_the_seq_bound_refuses_before_the_pin_would` | the bound missing altogether |
| `test_a_pin_still_accepts_the_last_safe_integer` | a pin refusal that over-reaches |
| `test_a_failed_mutation_still_consumes_its_seq` | a fix that changes the seq semantics |

### 4.2 A mutant that SURVIVED, and the test that killed it

Mutant C — replacing `if value > _MAX_INT:` with `if False:` — **survived
the first attempt**. Every test still passed.

The reason: **both** the seq bound and the pin's own
`_refuse_unsafe_int` raise `StatusPageError`. So "the call raised" could
not tell them apart, and the test was satisfied by either mechanism.

What distinguishes them is the refusal's **shape**: a seq refused at
the door consumes nothing and books nothing; a pin that fails inside
the mutation consumes the seq and books a row. The two new tests assert
that shape, and mutant C was then killed.

This is the same lesson as §4.2 of
`docs/design/graph-database-digest-pin.md`, in a different guise: *a
test that passes for the wrong reason measures nothing*. And it is the
mirror of the guard's own lesson — a guard that asserts only that "the
call raised" cannot see **which layer** refused.

## 5. The measurements

### 5.1 Before and after

| property | before | after |
|---|---|---|
| `component(component_id="\ud800", ...)` | raises `JcsError` | raises `StatusPageError` |
| `verify()` on an unencodable record | **raises** | answers `False` |
| fallback on a lone surrogate | **accepts** (non-JCS bytes) | refuses |
| shipped path on `2**53` | accepts (lossy) | refuses |
| a tampered seq above the safe range | **verifies `True`** | refused at the door |
| failed pin books a `rejected` row | **no** | yes |
| failed mutation consumes its seq | yes | yes (unchanged) |

### 5.2 The mutants

Every fix was proved by planting the fault and re-running the suite.

| mutant | what it breaks | result |
|---|---|---|
| A | `except ValueError` → `except ZeroDivisionError` | **killed** — 5 failures |
| B | fallback's surrogate check → `if False` | **killed** — 1 failure |
| C | remove the seq bound | **killed** — 2 failures (after §4.2) |
| D | drop the `_refuse_unsafe_int(payload)` call | **killed** — 1 failure |
| E | `_refuse_unsafe_int` checks only the top level | **killed** — 1 failure |
| F | `verify()` raises instead of answering | **killed** — 2 failures |
| G | the pin moves back out of the guarded region | **killed** — 19 failures |
| H | `_verify_pin` returns `True` on an unencodable payload | **killed** — 2 failures |

### 5.3 Suites

* `tests/test_status_page.py` — **28 passed** (13 new test functions).
* the repo suite — **462 passed**, 0 failed.
* the full component suite — see §7.

## 6. What this does NOT change

* **The two configurations still disagree about the digest bytes.** The
  shipped path emits JCS; the fallback emits its own tagged form. This
  slice makes them agree about *legality*, not about *bytes*. A digest
  minted under the fallback does not verify under the shipped path, and
  that was true before.
* **The public API is unchanged.** No signature, no new error type in
  the happy path, no record shape. The refusals are the same
  `StatusPageError` subclasses the module already raised.
* **The module still proves no storage fact.** It books declared
  status; the digest is a pin over declared content, not a proof of
  provenance.
* **`page_status()` still pins outside a `try`.** It is a **pure read
  view** — it consumes no seq and books no row — so a pin failure there
  is a genuine exception about an unpinnable aggregate, not a silent
  refusal with a missing row. That is the correct shape for a read.

## 7. The general lesson, and the scope it leaves open

**A house pattern without a house guard is a defect in every house.**
The runtime has **672** modules that canonicalize through
`canonical_json` (measured 2026-11-25: `grep -rl jcs_dumps --include=*.py`,
excluding `build/` and the helper itself), and **189** of them import
the sibling helper behind a `try/except` fallback — the configuration
this defect lives in. An AST sweep over those found **165 candidate
sites** across **54 modules** (measured after this slice's fix, which
removed four of `status_page.py`'s own): a `try` whose body calls a
canonicalizer and whose handler catches the module's own error type
without catching `ValueError`.

**165 is a worklist, not a finding.** A dynamic probe — instantiate
each candidate module's ledger class, enumerate its public methods,
build a call with every string parameter set to a lone surrogate and
every int parameter set to 1, and check whether `JcsError` escapes —
was run over 50 candidate modules. It found **7 live**:

| module | method | `JcsError` escapes | a `rejected` row booked? |
|---|---|---|---|
| `graph_database.py` | `graph` / `node` | yes | **no** |
| `status_page.py` | `component` | yes | **no** |
| `ai_constitution.py` | `declare` | yes | **no** |
| `ai_interpretability.py` | `interpret` | yes | **no** |
| `ai_perturbation.py` | `perturb` | yes | **no** |
| `graphql_gateway.py` | `plan` | yes | **no** |
| `zero_knowledge.py` | `verify` | yes | **no** |

The first two are fixed by this slice and its predecessor. The other
**five are the next slices.** The other 43 probed modules were not
live — their public mutators validate their strings before reaching
the pin.

The lesson: *reachability decides, not the shape of the code.* A guard
that looks dead may be behind a validation that never lets the bad
value through. So the sweep's 165 sites must never be reported as 165
defects — and the probe's 7 must never be reported without having
actually exercised each one.

## 8. Where the fix lives

| file | change |
|---|---|
| `components/northstar-agent-runtime/status_page.py` | the five fixes |
| `components/northstar-agent-runtime/tests/test_status_page.py` | 13 new test functions, 6 controls |

Related:

* `docs/design/graph-database-digest-pin.md` — the first module to
  carry these four defects; the fixes shipped in commit `66e6ccd4`.
* `docs/design/refusal-hold-wiring.md` §20.6 — the open item this
  slice's predecessor closed, and the one naming `graph_database.py`.
* `docs/design/refusal-hold-wiring.md` §21.2, §21.3 — the
  digest-fidelity defect and the two refusal conventions.
