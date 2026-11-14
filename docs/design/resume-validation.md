# Resume validation — validating resume values before a step re-enters

Status: landed on `batch-173-moltbook-absorb`.
Module: `components/northstar-agent-runtime/resume_validation.py`
Tests: `components/northstar-agent-runtime/tests/test_resume_validation.py`

Every claim below is labelled either **[SOURCE]** (it comes from the LangGraph
Interrupts documentation, quoted or closely paraphrased) or **[NORTHSTAR]** (it
is a Northstar extension and is *not* in the source). The
[NORTHSTAR] items are the ones a reader must not mistake for the source's
behaviour.

---

## 1. The problem

`components/northstar-agent-runtime/durable_resume.py` defines the *semantics*
of a resume, and this slice does not change it. Read from the code:

| Behaviour | Where | What the code does |
|---|---|---|
| A resume is an explicit `Command(resume=...)` | `durable_resume.py:305` (`class Command`) | `runner.resume` refuses anything that is not a `Command`; re-sending the prompt is exactly what the module exists to stop being called a resume |
| The step re-enters at the head of the interrupted step | `durable_resume.py` `DurableRunner.resume` | the interrupted step is re-run from its beginning and the recorded answers are handed back by `interrupt_id` |
| Resume values are matched to interrupts in order | `durable_resume.py` `Interrupt.interrupt_id` (`f"{task_id}#{index}"`), `runner.interrupt` | a step that interrupts twice produces ids `#0` and `#1`; the runner answers by id |
| A retry clears pending writes first | `durable_resume.py` `_clear_pending` | a failed attempt's declared writes are dropped before the next attempt |

What is **missing** in that file, checked by grep on 2026-11-14: the string
`schema` occurs only in `SCHEMA_PIN` (the checkpoint's schema-version pin);
there is no `__interrupt__` and no pending-interrupt listing; and nothing
validates the *shape* of a resume value. A resume of
`{"approved": "yes"}` for a boolean field goes straight into the step.

The complementary module `components/northstar-agent-runtime/approval_sla.py`
answers a different question: *how long* may a human wait (SLA deadline in
sequence-number ticks), and it fails closed on silence — `poll` returns
`"expired"`, expiry is sticky, `decide` refuses non-pending requests, and
expiry never auto-approves. This slice is the other half: *what* is being
waited on, and whether the answer that came back is a legal answer.

---

## 2. The source

**[SOURCE]** LangGraph Interrupts, official documentation, sections
"Define an interrupt response schema" and "Rules of interrupts" (read in full
2026-11-14):
<https://docs.langchain.com/oss/javascript/langgraph/interrupts>

Quoted points that this slice acts on:

* **[SOURCE]** a `responseSchema` option describes the input expected when
  resuming; the client may use the schema to render a typed input form;
* **[SOURCE]** with a Zod schema, `interrupt()` returns the parsed value —
  the documentation's example is `{ approved: true, note: "" }`, where the
  empty-string `note` is the field's default — and invalid input raises a
  `ZodError`; the caller retries with a corrected
  `new Command({ resume: ... })` using the same thread ID;
* **[SOURCE]** a JSON Schema object may also be passed as `responseSchema`;
  LangGraph exposes that object unchanged but does **not** validate the
  resume value against it; omitting `responseSchema` means the interrupt has
  no `response_schema` field and the resume value passes through without
  validation;
* **[SOURCE]** when several interrupts are pending, a single invocation may
  resume several of them: map each interrupt ID to its resume value, so that
  every response is matched to the right interrupt;
* **[SOURCE]** rules of interrupts: an interrupt pauses by throwing a special
  exception, so a `try`/`catch` around it swallows the pause; multiple
  interrupts are matched strictly index-based, so the order of interrupts
  inside a node must stay deterministic; side effects before an interrupt
  must be idempotent, because the node re-runs.

**[SOURCE]** The source's retry story is therefore: *the value is wrong → the
call fails → the caller fixes the value and sends a new `Command` against the
same thread*. That is the shape this module enforces.

### What is deliberately **not** adopted from the source

* **[NORTHSTAR]** The source explicitly leaves a JSON Schema object
  *unvalidated*. This module does **not** adopt that behaviour: here, a
  declared schema is always enforced. Only an interrupt declared *without* a
  schema passes its value through untouched — which is the source's
  "omit `responseSchema`" case, kept as the Northstar default for interrupts
  that genuinely take free-form input.
* **[NORTHSTAR]** No Zod, no JavaScript, no `npm`: the schema is a plain
  declarative mapping, parsed with the standard library only
  (`required`, per-field `type`, numeric `minimum`/`maximum`, `enum`,
  optional `default`).
* **[NORTHSTAR]** The validation gate sits **before** the step re-enters and
  this module only validates and lists. It never re-runs a step; re-entry
  remains `durable_resume.py`'s job, and that file is not modified.
* **[NORTHSTAR]** The source's index-based matching is preserved by
  `durable_resume.py`'s `task_id#index` ids; this module keys the resume map
  by **interrupt id**, which is the source's own advice for resuming several
  interrupts in one invocation.

---

## 3. The module

`components/northstar-agent-runtime/resume_validation.py` — stdlib only.

### Records

* `InterruptDeclaration` (frozen): `interrupt_id`, `payload` (JSON-
  serializable), `response_schema` (`None` = pass through, otherwise a
  `ResponseSchema`), `seq`.
* `ResponseSchema` (frozen): `fields` (name → `FieldSpec`) and `required`.
* `FieldSpec` (frozen): `type` (one of `bool`, `int`, `float`, `number`,
  `str`, `list`, `dict`, `object`, `any`), optional `default`, optional
  `minimum` / `maximum`, optional `enum`.
* `ResolvedInterrupt` (frozen): `interrupt_id`, `value`, `seq`.

### API

| Call | Contract |
|---|---|
| `declare(interrupt_id, payload, response_schema, seq)` | Registers one pending interrupt. Refuses a non-JSON-serializable `payload` (`PayloadNotSerializableError`) and a duplicate id (`DuplicateInterruptError`). Registration *is* entering the pending list. |
| `pending()` | The `__interrupt__` equivalent: every pending interrupt with its id, payload and schema. An empty list means the run is waiting for nothing. |
| `validate_resume(resume_map)` | Validates the whole batch (`interrupt_id → value`). Returns the validated values with schema defaults filled in. All-or-nothing: an unknown id or a schema violation raises and **nothing is consumed**. |
| `resolve(interrupt_id, validated_value, seq)` | Consumes one interrupt, after re-checking the value against the schema. Refuses an unknown, already-resolved, or expired id. |
| `mark_expired(interrupt_id)` | The caller decides when an interrupt lapses. An expired interrupt leaves the pending list and can never be resolved: expiry never consents. |

### Schema enforcement

For a schema-bearing interrupt, a resume value must be a mapping. Each
`required` field must be present unless it carries a `default`; a defaulted
required field is filled with that default (this is the source's
`{ approved: true, note: "" }` shape — the `note` default is what the source's
example omits). Every declared field is then checked: type mismatch (with
`bool` explicitly *not* accepted as `int`), `enum` membership, and numeric
`minimum` / `maximum` bounds.

An interrupt declared **without** a schema passes its value through
unvalidated, which is the source's "omit `responseSchema`" behaviour
**[SOURCE]** — and the only place this module is permissive.

### Fail-closed rules

Every one of these refuses, and no refusal ever consumes an interrupt:

* unknown interrupt id in a resume map → `UnknownInterruptError`, the whole
  call is refused;
* value violating its schema (wrong type, missing required field, out of
  range, outside an enum) → `SchemaViolationError`, the whole call is
  refused;
* a duplicate interrupt id at declaration → `DuplicateInterruptError`;
* a non-JSON-serializable payload → `PayloadNotSerializableError`;
* resolving an already-resolved interrupt → `InterruptAlreadyResolvedError`;
* resolving an expired interrupt → `InterruptExpiredError` — expiry never
  auto-approves.

After a refusal, the caller retries with a corrected value against the same
run: the interrupts are still pending, and `pending()` still lists them.

### The gate's position

**[NORTHSTAR]** This module validates and lists. It does **not** re-run a
step, and it does not touch `durable_resume.py`. The intended wiring is:

```
caller
  │  pending()                      ← "what is this run waiting for?"
  ▼
ResumeValidator
  │  validate_resume(resume_map)    ← the gate: refused ⇒ nothing consumed
  ▼
durable_resume.Command(resume=...)  ← re-entry stays in durable_resume.py
```

---

## 4. The three driven paths

Driven end to end in `tests/test_resume_validation.py::RealPathTests`:

**(a) The approval interrupt.** `declare("approval#0", {"question": "approve?"},
schema)` puts one interrupt in the pending list; `validate_resume({"approval#0":
{"approved": True}})` returns `{"approved": True, "note": ""}` (the default
filled in); `resolve` consumes it and the pending list is empty.

**(b) The wrong type, then the correction.** `validate_resume({"approval#0":
{"approved": "yes"}})` raises `SchemaViolationError`; the interrupt is still
pending and nothing is resolved. The corrected value
`{"approved": False, "note": "too risky"}` is then retried against the same
run and passes; `resolve` consumes it.

**(c) Two interrupts, one bad.** Two pending interrupts with different
schemas are resumed together; the second value has the wrong type, so the
whole call is refused and **both** interrupts stay pending. The corrected
batch passes and both are resolved.

---

## 5. Source-to-code map

| Claim | Label | Where it lives |
|---|---|---|
| `responseSchema` describes the input expected when resuming | [SOURCE] | doc §2 |
| Zod schema → parsed value; invalid input raises; retry with a corrected `Command` on the same thread | [SOURCE] | doc §2; the retry contract in §3 "Fail-closed rules" |
| JSON Schema object is exposed but not validated | [SOURCE] | doc §2 — **not** adopted, see §2 |
| Omitting `responseSchema` ⇒ resume value passes through unvalidated | [SOURCE] | `ResumeValidator._validate_value` (schema `None` ⇒ pass through) |
| Several interrupts resumed in one invocation, each id mapped to its value | [SOURCE] | `validate_resume(resume_map)` keys by interrupt id; `RealPathTests.test_path_c_*` |
| Interrupt ids are index-based within a task | [SOURCE] | `durable_resume.py` `Interrupt.interrupt_id` = `task_id#index` |
| Declarative stdlib-only schema shape | [NORTHSTAR] | `ResponseSchema` / `FieldSpec` |
| A declared schema is always enforced | [NORTHSTAR] | `ResumeValidator._validate_value` |
| Validation gate before re-entry; no step re-run here | [NORTHSTAR] | §3 "The gate's position" |
| Whole-call refusal consumes nothing | [NORTHSTAR] | `validate_resume` (validate first, resolve later) |
| Expiry never consents; pending list is "what", SLA is "how long" | [NORTHSTAR] + repo | `mark_expired` / `InterruptExpiredError`; `approval_sla.py` `poll` / `decide` |

---

## 6. Scope

This module is a pure bookkeeping and validation library. It does not run a
loop, does not talk to a provider, and observes no live run.
`durable_resume.py` and `approval_sla.py` are read-only reuse: neither file
was modified.

