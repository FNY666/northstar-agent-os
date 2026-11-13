# Refusal as a first-class row: the "no" is a record, not a log line

Module: `components/northstar-agent-runtime/refusal_row.py`
Tests: `components/northstar-agent-runtime/tests/test_refusal_row.py`
Absorption slice: B173 refusal-row (Moltbook post `abe9e16f`).

---

## 1. What the source says (verbatim)

**Source.** hermesagentj, "The most useful thing I built this month is a
check that refuses to run" (Moltbook post
`abe9e16f-21a4-4d38-a2b1-03fd84c3543c`, runners-up, frontier round already
read, `m/builds`).

**Verbatim — the mechanism the task book quotes from the frontier round:**

> refusal as a first-class row — verdict, evidence hash, ruleset hash,
> verifier key; "two instruments or none"; the missing population digest
> field.

**Verbatim — the source's own framing (the title):**

> "The most useful thing I built this month is a check that refuses to run."

**Verbatim — why the frontier round called this important:**

> Strong complement to item 18 (fieldnotes plant-the-fault) and to
> outcome_unknown. A refusal that leaves no record is indistinguishable
> from a check that never ran; a refusal recorded as a row (with verdict +
> hashes + verifier key) makes the "no" itself auditable.

Everything in §3 onward is **Northstar extension**, not source text, and is
marked as such.

---

## 2. What the repo says today (read before designing this)

This section reports what was read in the code. It is not a claim about how
good the code is.

### 2.1 How a failure is classified and recorded today

`components/northstar-agent-runtime/tool_failure.py` normalizes every tool
failure into a typed `tool_result`. Read from the source:

* A failure is never an exception, a crash, or a bare string. Every failure
  path produces a `tool_result` with `is_error: true`, the content wrapped
  in a `<tool_use_error>...</tool_use_error>` envelope, a plain-text summary,
  an optional **denial kind**, and an optional structured remedy.
* The denial-kind taxonomy is closed: `interrupted`, `user-rejected`,
  `permission-rule`, `cancelled` (transcribed verbatim from the Claude Code
  bundle). A denial may also end the turn — `ends_turn` is carried
  separately from the kind.
* The remedy kinds are closed too: `memory_paused`, `staged_for_review`,
  `sandbox_violation`, `auth_expired`, `auth_overridden` (Claude Code
  verbatim) plus `invalid_input`, `unknown_tool`, `compaction_required`
  (Northstar extension). A retryable provider fault is deliberately *not* a
  remedy kind: it is `retryable=True` plus a suggested wait on the record.
* The classification is closed and never guesses a kind: a validation
  failure and a provider fault carry an `error_code` and a remedy, with
  `denial_kind` explicitly `None` — "we could not tell" is not a denial.

**Is there a row for a refusal?** `tool_failure.py` records the *failure of
a tool call* — what went wrong with a call and what to do next. It does not
record "a check refused to run", and it does not carry evidence hashes,
ruleset hashes, or a population. So: **no row for a refusal.**

### 2.2 How a check's acceptance is booked today

`components/northstar-agent-runtime/planted_fault.py` answers the question
"did a check run, and did it catch the planted fault?" Read from the
source:

* `run_check(check_fn, faulted_input, checker_id)` calls the check blind
  against the *faulted mapping* only — the plant metadata is attributes, so
  a blind check cannot read which run was planted or what the true value is.
  The module does not change the check; it only records what the check said.
* Separation is enforced: a checker that is the same subject as the planter
  raises `SeparationError`. Identity is the subject id, not the process.
* The `EvidenceLedger` books rows: `record_pass`, `record_catch`,
  `record_miss`, `record_void_plant`, each with a monotonically allocated
  `seq`. A `reveal` unseals a note against a commitment posted beforehand;
  a mismatch, a missing commitment, or a reveal before the check ran is a
  `VOID_PLANT`.

**Can a check that never run be told apart from a check that ran and did
not pass?** Yes, and this is the sharpest thing in the file:
`record_check_run` stores the `CheckOutcome` by `plant_id`, and
`reveal` explicitly checks `ledger.check_run_for(plant_id)` — a reveal
*before* the check ran is a `VOID_PLANT`, and `void_back_to_last_catch` can
roll back passes. So the "check did not run" case is already a **distinct,
named** state.

**But**: the ledger's row is about a *plant* and a *check run*. It carries
`plant_id`, `run_index`, `check_scope`, `checker_id`, `caught`, `seq`. It
carries **no evidence hash, no ruleset hash, and no population digest** —
nothing that lets a reader re-derive *why* the check said no, over *which*
population, under *which* rules.

### 2.3 How "unknown" is represented today

The repo's word for "we could not tell" is `outcome_unknown`. Read from the
source:

* `scope_qualifier.py` defines `OUTCOME_UNKNOWN = "outcome_unknown"` and
  `BLOCKING_OUTCOMES = {OUTCOME_MISMATCH, OUTCOME_UNKNOWN, OUTCOME_EXPIRED}`.
  Its own docstring: "**Missing is a structured state.** When the gate
  cannot retrieve the source line or the refusal row, the outcome is
  `outcome_unknown` — never a clean read, never an allow."
* The `SourceStore` distinguishes *no such line* (`fetch` returns `None` —
  a mismatch) from *the store could not answer* (raises `ScopeSourceError` —
  `outcome_unknown`). The check itself not completing is a different state
  from the check completing and saying no.
* `grant_pin_ledger.py` and `endpoint_identity.py` use the same word for the
  same shape: dispatched, but the outcome is not yet resolvable.

**Can a "no result" be told apart from a "refused to give a result"?**
**Yes** — and this is the important prior art for this slice. `outcome_unknown`
is the *absence* of an answer. `scope_qualifier`'s `DenialRow` is the
*presence* of a refusal:

* `DenialRow` has exactly two kinds: `ROW_DENIED` ("the scope is refused")
  and `ROW_CLEAR` ("there is no denial, and here is a signed proof of it").
  A `clear` row **must carry a signature** — "an unsigned row is a claim,
  not a proof of no-denial".
* `DenialRowStore` answers exactly one question per scope, and the gate
  distinguishes all three answers: a denial row, a signed clear row, and
  *no row / unreadable store* — which is `outcome_unknown`, never a clean
  read.

So the repo already has the *shape* of the idea: a refusal is a row, and a
missing row is a different, named state. What it does **not** have is a
refusal row that carries the *evidence* behind the refusal.

### 2.4 The gap this slice fills

| | verdict | evidence hash | ruleset hash | verifier key | population digest |
| --- | --- | --- | --- | --- | --- |
| `tool_failure.py` failure record | kind + remedy | — | — | — | — |
| `planted_fault.py` evidence row | caught / seq | — | — | `checker_id` | — |
| `scope_qualifier.DenialRow` | `denied` / `clear` | — | — | — | — |
| `scope_qualifier` outcome | `outcome_unknown` | — | — | — | — |
| **this slice** | ✅ | ✅ | ✅ | ✅ | ✅ |

The source's own claim is the one this module encodes: *a refusal that
leaves no record is indistinguishable from a check that never ran*. Northstar
already answers "never ran" for plants (`VOID_PLANT`) and for scopes
(`outcome_unknown`); what it cannot yet do is make the refusal itself a
record a reader can re-verify.

---

## 3. The mechanism (Northstar extension)

Everything in this section is Northstar's own construction. The source
supplies the field list, the "two instruments or none" rule, and the
population-digest obligation; the *formats*, the *fail-closed validation*,
the *row self-digest*, and the *marker spelling* are ours.

### 3.1 The row

`RefusalRow` is a frozen dataclass — append-only, immutable after
creation.

| Field | Type | Source | Meaning |
| --- | --- | --- | --- |
| `verdict` | slug | source field | what was decided |
| `evidence_hash` | `sha256:<64 hex>` | source field | the evidence the "no" rests on |
| `ruleset_hash` | `sha256:<64 hex>` | source field | the rules that were applied |
| `verifier_key` | `<subject>@<version>` | source field | which instrument produced the verdict |
| `population_digest` | `sha256:<64 hex>` | source field | the population the refusal was taken over |
| `refused_at` | int | — (extension) | caller-supplied clock; no wall clock in a recorded row |
| `reason` | str | — (extension) | why |
| `instruments` | tuple of verifier keys | — (extension) | every distinct instrument, in call order |
| `single_instrument` | bool | — (extension) | the caller declared the weaker basis explicitly |
| `row_digest` | `sha256:<64 hex>` | — (extension) | the row's own digest over its content |

The four source-named hash/key fields are **mandatory**: a row missing any
one of them is refused at creation. The population digest is the field the
source names as *missing*, so it is the one with the strictest footing —
"a refusal without a population digest is an incomplete refusal".

### 3.2 The hash formats

Fixed in the module and checked at creation:

* **Digests** (`evidence_hash`, `ruleset_hash`, `population_digest`) must be
  `sha256:` followed by exactly 64 lowercase hex characters. The regex is
  `^sha256:[0-9a-f]{64}$` — uppercase hex, a truncated digest, a trailing
  character and a different algorithm prefix are all refused. This matches
  the repo's existing `sha256:` pin convention (`scope_qualifier._digest`).
* **Verifier keys** must be `<subject>@<version>`, regex
  `^[a-z0-9][a-z0-9._-]*@[a-z0-9][a-z0-9._+-]*$`. The source names the
  field but not its format; this is ours.
* **Verdicts** must be a non-empty lowercase slug, regex
  `^[a-z0-9][a-z0-9._-]*$`. The source fixes no verdict vocabulary, only
  that a refusal carries one; the *format* is ours.
* **`refused_at`** is an `int` — a caller-supplied clock. There is no
  wall-clock read inside the module, so a recorded row is reproducible.

`digest_of(value)` is public so callers can compute the digest fields the
same way the module does: `sha256:` + SHA-256 over canonical JSON (sorted
keys, compact separators, UTF-8).

### 3.3 The two-instrument rule

The source's rule is "two instruments or none". The module applies it to
the **distinct verifier keys** on the row:

| distinct instruments | what happens |
| --- | --- |
| ≥ 2 | recorded normally; `marker` is `""` |
| exactly 1 | the caller must pass `single_instrument=True` **and** give a `reason`; the row is marked `SINGLE_INSTRUMENT` |
| 0 | **refused** at creation |

Two details that matter:

* **The same key twice is one instrument.** `instruments=["a@v1", "a@v1"]`
  collapses to one distinct key, so it takes the single-instrument path.
  Two *distinct* keys are two instruments; one key listed twice is one.
* **Zero instruments is refused, not recorded.** A "refusal" with no
  instrument is an *absence*, and absence already has a name in this
  runtime: `outcome_unknown`. Recording it as a refusal would erase the
  distinction the source is trying to preserve.

The marker lives on the row (`row.marker`, `row.as_dict()["marker"]`), not
in a log line — that is the whole point of the slice.

### 3.4 Fail closed

Every illegal input raises `RefusalRowError` (a `ValueError`) at creation
rather than producing a plausible-looking row:

* any of the four mandatory fields missing or empty;
* a malformed digest, verifier key or verdict;
* `verifier_key` not among the recorded instruments;
* a single instrument without the explicit declaration;
* a single instrument declared without a reason;
* `single_instrument=True` contradicting two or more recorded instruments;
* zero instruments;
* a non-int `refused_at`.

### 3.5 Immutability and tamper detection

The row is frozen, and there is deliberately **no update function** — to
change a refusal you record another row. `refusal_row` exports no
`update_refusal` / `amend_refusal` / `replace_refusal` (the test asserts
their absence).

Tampering is caught by the row's own digest. `row_digest` is the digest of
`row.body()`; `verify_row(row)` recomputes it and compares. A row whose
`verdict` was rewritten from `denied` to `allowed`, or whose
`population_digest` was swapped, or whose second instrument was quietly
dropped, fails verification with
`row_digest does not match the row content (tampered)`.

Two layers, because `frozen=True` alone is not enough:

1. `__post_init__` **refuses a row that arrives with a `row_digest` that
   does not describe its content**. This closes `dataclasses.replace`:
   replacing a field on a frozen row carries the *old* digest, which no
   longer matches the new content, so the replacement is refused at
   construction rather than silently producing a forged row.
2. `verify_row` catches the forger who bypasses the constructor entirely
   with `object.__setattr__` — which is exactly what the tests do.

`row_errors(row)` returns the human-readable list of every reason a row is
not valid (empty tuple when it is), so a caller can report *why* rather
than just "no".

### 3.6 The public surface

| Function | Behaviour |
| --- | --- |
| `record_refusal(verdict, evidence_hash, ruleset_hash, verifier_key, population_digest, reason="", refused_at=0, instruments=None, single_instrument=False) -> RefusalRow` | validate everything and return the row; refuse otherwise |
| `verify_row(row) -> bool` | True iff the row is well-formed, self-consistent and untampered |
| `row_errors(row) -> tuple[str, ...]` | every reason the row is not valid; empty when it is |
| `digest_of(value) -> str` | `sha256:` digest of canonical JSON — how callers fill the hash fields |
| `RefusalRow` | the frozen row: `.body()`, `.content_digest()`, `.as_dict()`, `.marker`, `.instrument_count` |

`instruments` defaults to `[verifier_key]` — one instrument, which then
requires the explicit declaration.

### 3.7 What this module does **not** do

* It does not run a check. It records the refusal a check produced.
* It does not decide *whether* to refuse — that is the caller's gate.
* It does not store the evidence itself, only its digest. A reader with the
  evidence can recompute the digest; a reader without it cannot, and
  `verify_row` will not pretend otherwise (it checks the digest's *format*
  and the row's self-consistency, not the truth of the digest's referent).
* It does not prove the instruments were genuinely independent — it proves
  they were **distinct keys**. Deciding independence is the job of
  `evidence_independence.py`; this module only requires that the two keys
  differ.
* It does not observe a live run.

---

## 4. The driven path

`tests/test_refusal_row.py` drives the module end to end rather than
asserting each part in isolation:

* record a refusal on two distinct instruments → `verify_row` is True, the
  row carries every field, and `row.as_dict()` is self-describing;
* drop the population digest → creation is refused;
* drop the evidence hash / ruleset hash / verifier key / verdict → creation
  is refused;
* a malformed digest (wrong length, uppercase hex, wrong prefix, trailing
  character) → creation is refused;
* zero instruments → creation is refused;
* one instrument without the declaration → refused; with the declaration
  and a reason → recorded and marked `SINGLE_INSTRUMENT`;
* declare `single_instrument=True` while two instruments are present →
  refused (the marker may not contradict the row);
* tamper with the verdict / evidence hash / population digest / instrument
  count / row digest → `verify_row` is False and `row_errors` names the
  reason;
* mutate the frozen row → `FrozenInstanceError`; `dataclasses.replace` →
  refused.

---

## 5. Open items

* The digest fields are checked for **format** and **self-consistency**,
  not for truth: this module cannot tell whether `evidence_hash` really
  digests the evidence the caller had. That check belongs to the caller
  that holds the evidence.
* Independence of two instruments is decided by *distinctness of the key*,
  not by the independence analysis in `evidence_independence.py`. A caller
  wanting the stronger property should compose the two.
* There is no ledger of rows here: the module produces rows, and storing
  them append-only across a run is a separate concern (the repo's
  `forward_seal_ledger` / `sealed_audit_sink` are the candidates).
* `refused_at` is caller-supplied, so a caller that does not pass one gets
  `0` — a marker for "no clock", not a real timestamp.
