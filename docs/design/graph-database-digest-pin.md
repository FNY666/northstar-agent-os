# graph_database: the digest pin did not pin

**Date:** 2026-11-25
**From:** the submission window (session 728a716a)
**Status:** FIXED, with each defect measured before and after, and every
fix proved by a planted mutant.

## 1. The one-line finding

`components/northstar-agent-runtime/graph_database.py` had **four**
independent defects, all in the same narrow place: the layer between
"a value the caller supplied" and "a digest this module can stand
behind".

Each was found by asking a question the code's own docstrings already
answer:

* `verify()` answers a question — so it must **answer**, not raise.
* `verify()`'s answer is the tamper pin — so it must **pin** what it
  claims to pin.
* A failed mutation books a `rejected` row — so a failed **pin** must
  book one too.
* The stdlib fallback and the shipped path are the same module — so
  they must agree about what is **legal**.

## 2. The four defects

### 2.1 `verify()` raised instead of answering

`GraphRecord.verify()` guards its pin with `except GraphDatabaseError:
return False`. But `_canonical` delegates to the sibling helper
`canonical_json`, which refuses a lone surrogate with **its own** error
type — `canonical_json.JcsError`.

```
>>> JcsError.__mro__
(<class 'canonical_json.JcsError'>, <class 'ValueError'>, <class 'Exception'>, ...)
>>> issubclass(canonical_json.JcsError, GraphDatabaseError)
False
```

So the clause was **dead** for that input, and the measurement:

```
>>> GraphRecord(graph_name="\ud800", digest="sha256:"+"0"*64, seq=5).verify()
JcsError: lone surrogate U+D800 is not JCS-serializable
```

Two consequences, both measured:

* `verify()` **raised** instead of answering `False`, so a caller
  asking "is this record intact?" got an exception.
* `JcsError` is a `ValueError`, so a caller guarding with
  `except ValueError` treats a **tampered record** as a **parse error**
  and moves on — the record is neither verified nor rejected.

Four sites had the dead clause: `GraphRecord.verify` (:394),
`DropRecord.verify` (:420), `NodeRecord.verify` (:453),
`EdgeRecord.verify` (:491).

### 2.2 A seq above the safe range was accepted, and the digest stopped pinning it

`canonical_json` serializes an integer outside the safe range as an
IEEE-754 double (RFC 8785 Appendix B note (2)), so **2\*\*53 and
2\*\*53+1 canonicalize to the same bytes**:

```
>>> _canonical(2**53)   == b'9007199254740992'
>>> _canonical(2**53+1) == b'9007199254740992'   # identical
>>> _pin("graph", "g", 2**53) == _pin("graph", "g", 2**53+1)
True
```

`graph_database.py` declares `_MAX_INT = 2**53 - 1` — and **never uses
it**. `_check_seq` bounded the seq only below (`seq < 0`), so a seq
above the safe range was accepted, and the digest stopped pinning it.
The measurement:

```
>>> d = _pin("graph", "g", 2**53)
>>> GraphRecord(graph_name="g", digest=d, seq=2**53+1).verify()
True        # the seq was CHANGED; the digest was not
```

That is a **fail-OPEN integrity defect**. The digest *is* this module's
tamper pin, and above the safe range it silently stops pinning.

### 2.3 The stdlib fallback accepted what the shipped path refused

The fallback is reachable: `canonical_json` is imported inside a
`try/except Exception`. When it is absent, `_canonical` uses a local
`_tag`/`json.dumps` implementation.

The fallback's `_tag` passed a lone surrogate straight through to
`json.dumps`, which escapes it as `\ud800` and emits bytes that are
**not JCS at all**. Measured:

| input | shipped | fallback |
|---|---|---|
| lone surrogate | `GraphDatabaseError` | **OK, 49 bytes** |
| `2**53` | OK | `GraphDatabaseError` |
| NaN / Inf | `GraphDatabaseError` | `GraphDatabaseError` |

Both rows are defects. The fallback **accepted** a value the shipped
path refused, and it **refused** a value the shipped path accepted.
Either way the two configurations of the same module disagreed about
what is legal — so a digest pinned under one does not verify under the
other.

The second row is the same lossy-integer problem as §2.2, seen from
the other side.

### 2.4 A failed pin booked no `rejected` row

The class docstring promises:

> failed mutations consume their seq and book a `rejected` audit row

But the `_pin(...)` calls sat **outside** the `try` block that books
the row. Measured:

```
>>> db.graph("\ud800", 1)
GraphDatabaseError          # ... and books NO row
>>> db.node("g", "n", 2, properties={"p": "\ud800"})
GraphDatabaseError          # ... and books NO row
>>> db.node("g", "n", 2, properties={"p": object()})
BadPropertyError            # refused INSIDE the try -- books a row
```

So the trail could not tell **"the database refused this graph"** from
**"the database never saw it"** — the same defect shape the
refusal-hold wiring forbids for the queue (see
`docs/design/refusal-hold-wiring.md` §16.2: *a broken gate books no
row*).

## 3. The fixes

| # | fix | where |
|---|---|---|
| 1 | translate the sibling helper's `ValueError` into `GraphDatabaseError` | `_canonical` |
| 2 | refuse a seq above `_MAX_INT` | `_check_seq` |
| 2 | refuse an out-of-safe-range integer **anywhere in a pin payload** | `_canonical` / `_refuse_unsafe_int` |
| 3 | refuse a lone surrogate in the fallback's `_tag` | `_canonical` / `_tag` |
| 4 | move every `_pin(...)` call **inside** the guarded region | `graph`, `drop`, `node`, `edge` |

Fix 1 is the repo's **own established pattern**: `job_queue.py`'s
`_canonical` already translates `ValueError` from `_cj.jcs_dumps` into
`JobQueueError`, with the same reasoning in its comment. This slice
applies that pattern in the same repo, to the same defect class.

Fix 2 is the repo's **own house pattern**: `job_queue.py::_check_seq`
carries the identical rule with the identical reasoning (the same
`2**53` / `2**53+1` measurement in its comment), and
`grant_pin_ledger.py` (`_MAX_COUNTER`) and `profiler.py`
(`record_digest()`) enforce the same bound. `graph_database.py` was the
one module that declared `_MAX_INT` and forgot to use it.

Fix 2's second half is needed because `verify()` does **not** go
through `_check_seq` — it recomputes the pin from the record's own
fields, and the seq on that record may have been tampered with. So the
pin itself must refuse the lossy integer; otherwise no digest over it
can be minted in the first place.

Fix 4 is the shape the module already used for every *other* refusal:
the validation is inside the `try`, and the `except` books the row.
The pins were simply in the wrong place.

## 4. Why this is not a weakening

Every fix **narrows** what the module accepts; none relaxes a check.
The bounds are the repo's own, not new numbers:

* `_MAX_INT = 2**53 - 1` was already declared in this module.
* the seq bound and the lossy-integer refusal match `job_queue.py`,
  `grant_pin_ledger.py` and `profiler.py` exactly.

The refusal of a lone surrogate is **required by RFC 8785 §3.2.2.3**,
which the sibling helper already implemented and documented:

> lone surrogates "MUST cause a compliant JCS implementation to
> terminate with an appropriate error" — they break signatures silently.

The fallback now refuses it for the same reason the shipped path does.

### 4.1 The controls

Each fix has a control that could **fail**:

| control | what it would catch |
|---|---|
| `test_the_two_canonicalizer_configurations_agree` | the shipped path raising instead of answering |
| `test_both_configurations_accept_a_value_both_can_canonicalize` | a fallback that refuses **everything** (vacuous agreement) |
| `test_a_pin_still_accepts_the_last_safe_integer` | a bound that over-refuses `2**53 - 1` |
| `test_the_safe_range_boundary_is_accepted` | a bound that cuts off the last legal seq |
| `test_a_failed_mutation_still_consumes_its_seq` | a fix that changes the seq semantics |

### 4.2 A control that was WRONG, and was corrected

The first draft of `test_the_two_canonicalizer_configurations_agree`
asserted that **the fallback raises** for a lone surrogate. It did not:
the fallback accepted it and produced 49 bytes. The draft was passing
for the **wrong reason** — the digest mismatch, not an encode failure.

That is the same trap as the census false kill recorded in
`docs/design/refusal-hold-wiring.md` §26.6a: a test that passes for a
reason other than the one it names measures nothing. The control was
rewritten to assert the property that is actually true and actually
worth defending — **the two configurations must agree about what is
LEGAL** — and the docstring now records the false claim it used to
make, so the next reader does not repeat it.

Note the two configurations need **not** agree about the resulting
*digest*: the shipped path emits JCS bytes, the fallback emits its own
tagged form. They are different byte strings by construction. What
they must agree on is the *answer*.

## 5. The measurements

### 5.1 Before and after

| property | before | after |
|---|---|---|
| `verify()` on an unencodable record | **raises `JcsError`** | answers `False` |
| `_pin` over `2**53` and `2**53+1` | **same digest** | the pin **refuses** |
| tampered seq above the safe range | **verifies `True`** | refused at the door |
| fallback on a lone surrogate | **accepts** (49 bytes) | refuses |
| shipped path on `2**53` | accepts (lossy) | refuses |
| failed pin books a `rejected` row | **no** | yes |
| failed mutation consumes its seq | yes | yes (unchanged) |

### 5.2 The mutants

Every fix was proved by planting the fault and re-running the suite.
A fix that survives its mutant is not a fix.

| mutant | what it breaks | result |
|---|---|---|
| A | `except ValueError` → `except ZeroDivisionError` (drop the translation) | **killed** — 12 failures |
| B | fallback's surrogate check → `if False` | **killed** — 4 failures |
| C | `if seq > _MAX_INT:` → `if False:` | **killed** — 2 failures |
| D | drop the `_refuse_unsafe_int(payload)` call | **killed** — 1 failure |
| E | `_refuse_unsafe_int` checks only the top level | **killed** — 1 failure |

**Mutant D survived the first attempt** and that is worth recording.
The tests at that point passed, but for the wrong reason: the tampered
seq test asserted `verify() is False`, and it was false because the
digest did not match — not because the pin refused the lossy integer.
A digest over colliding bytes still *is* a digest; the test could not
see the collision. The fix was a test that asserts the **pin refuses**
the integer — the property that actually prevents the collision. Mutant
D was then killed.

This is the same lesson as §4.2, in a different guise: *a test that
cannot fail proves nothing*, and a test that passes for the wrong
reason is worse than no test, because it reports coverage that is not
there.

### 5.3 Suites

* `tests/test_graph_database.py` — **38 passed**.
* graph-adjacent suites (`test_graph_db`, `test_artifact_graph_probes`,
  `test_graphql_gateway`, `test_runtime_registration`) — **163 passed,
  18 subtests passed**.
* the full component suite — see §7.

## 6. What this does NOT change

* **The two configurations still disagree about the digest bytes.**
  The shipped path emits JCS; the fallback emits its own tagged form.
  This slice makes them agree about *legality*, not about *bytes*.
  A digest minted under the fallback does not verify under the shipped
  path, and that was true before. It is a property of the fallback
  being a *stand-in*, not a defect introduced or fixed here.
* **The module still stores no engine and proves no storage fact.**
  The digest is a pin over declared content, not a proof of
  provenance. That scope statement in the module docstring is
  unchanged.
* **No public API changed.** No method signature, no exception type in
  the happy path, no record shape. The refusals are the same
  `GraphDatabaseError` subclasses the module already raised; what
  changed is that they are now raised **consistently**, and that the
  seq bound uses the module's own already-declared `_MAX_INT`.

## 7. The general lesson

**A digest is only a pin if the encoding is injective.** Two of the
four defects here are the same defect seen twice: the canonical form
mapped two different logical values onto the same bytes (a lossy
float, and a lone surrogate encoded two ways). Whenever a module
computes a digest over a value, the question to ask is not *"does it
hash?"* but *"does the hash distinguish the values it must
distinguish?"* — and the second question needs a test that constructs
the two colliding values and shows the digests differ.

**A fallback is the same module, so it inherits the same law.** A
stdlib fallback that is "close enough" is worse than no fallback,
because the two paths disagree about which inputs are legal and the
disagreement is invisible until a deployment happens to take the other
path. The check for a fallback is not *"does it run?"* but *"does it
refuse the same set of inputs?"* — and the test for that is to run
**both** configurations against the same inputs and compare.

**A guard written for one error type catches only that error type.**
The four `except GraphDatabaseError:` clauses were not wrong in
intent; they were wrong about which error the callee actually
raises. When a helper is a **sibling module** rather than a local
function, its error taxonomy is not yours by default — you must
translate it, or the guard is decoration.

## 8. Where the fix lives

| file | change |
|---|---|
| `components/northstar-agent-runtime/graph_database.py` | the four fixes |
| `components/northstar-agent-runtime/tests/test_graph_database.py` | §15–§18: 8 new tests, 3 controls |

Related:

* `docs/design/refusal-hold-wiring.md` §26.6a — the census false kill:
  a test that passes for the wrong reason.
* `docs/design/refusal-hold-wiring.md` §16.2 — *a broken gate books no
  row*: the same trail-honesty requirement §2.4 violates.
* `components/northstar-agent-runtime/job_queue.py` — the sibling
  module whose `_canonical` and `_check_seq` already carry fixes 1 and
  2, with the same reasoning.
