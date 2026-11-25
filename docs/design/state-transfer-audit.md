# State-transfer auditing — the failures happen *between* the boxes

**Slice:** `state-transfer-audit` (2026-11-25)
**Module:** `components/northstar-agent-runtime/state_transfer_audit.py`
**Tests:** `components/northstar-agent-runtime/tests/test_state_transfer_audit.py`
**Survey rank:** 3 of the frontier-expansion survey
(`docs/design/frontier-expansion-survey.md`)

**What this document is.** The survey's rank-3 source says that the
security and reliability failures of a long-horizon agent do not happen in
the model call or in the tool call — they happen in the moments where
state **moves** between the working context, the session history, the
persistent memory and the external environment. Northstar already records
actions and evidence; it does not record transfers. This slice adds the
transfer record, the rule that says when a transfer is allowed to count as
checked, and the gate that refuses to let an unchecked one downstream.

## How to read the citations

Three kinds of statement appear below, and they are never mixed:

| Marker | Meaning |
|---|---|
| **verbatim** | The text is quoted from the source, character for character. The URL is given. |
| **Northstar extension** | Northstar's own design. The source does **not** claim this. |
| **(this document's reasoning)** | The argument connecting the two. Check it against the linked source before relying on it. |

**Rule for the reader:** if a claim is not marked verbatim and not marked as
a Northstar extension, treat it as this document's own reasoning.

---

## 1. The sources

### 1.1 Source S5 — arXiv 2611.23346 (the primary source)

- **URL:** https://arxiv.org/html/2611.23346v1
- **Abstract page:** https://arxiv.org/abs/2611.23346
- **Category:** observability / auditability
- **Title (verbatim, the arXiv listing):** "Securing and Auditing Long-Horizon LLM Agents: State-Transfer Auditing and Controls in the Agent Harness"
- **Authors (verbatim, the arXiv listing):** "Deep Shah, Nehal Kathrotia"
- **Submitted (verbatim, the arXiv listing):** 17 Nov 2026
- **Verdict:** absorb-now (rank 3).

### 1.2 Source S6 — agentmem (the supporting source)

- **URL:** https://github.com/AgentMem/agentmem
- **Category:** memory / evidence
- **Verdict:** absorb-later (supporting; it supplies the "capture at the
  boundary, never scrape the agent's self-report" principle).

---

## 2. What the source claims (verbatim)

Every quotation in this section is **verbatim** from the sources named
above. Nothing here is Northstar's design.

### 2.1 The failure locus (arXiv 2611.23346, abstract)

> "While conventional execution traces log model prompts and tool calls, critical security and reliability failures occur during state transfers:"

> "a transfer can admit unchecked content (indirect prompt injections, unverified memory writes), rewrite state lossily (context compaction dropping user constraints, memory consolidation stripping source authority), or restore state incompletely (workspace rollbacks leaving aborted KV state active on the inference server)."

> "Because current traces omit what crosses these boundaries, failure attribution and runtime monitors fail on multi-step trajectories. We present a state-transfer audit architecture for the agent harness."

### 2.2 The harness moves state between four stores (arXiv 2611.23346, §II)

> "Observations bring environment state into the context,"

> "context assembly loads workspace rule files, tool schemas, and retrieved memories."

> "Compaction moves older turns to session history and leaves a condensed summary or placeholder"

> "memory writes and consolidation extract and merge entries from the working context or session history across runs."

> "Actions change the environment, and rollback restores prior state across the environment, working context, session history,"

> "Multi-agent harnesses add delegation, which passes a task and state slice to a sub-agent with its own context."

> "Each transfer gives the harness a concrete boundary to record and check what crosses."

### 2.3 The audit point and its record (arXiv 2611.23346, §II–III)

> "An audit point specifies, for one transfer, the record the harness emits and the check it enables."

> "At each transfer boundary, we define an audit point specifying the minimal hash-chained record the harness emits"

> "The rows of Table II share a structure, which suggests one hash-chained record type emitted at every transfer."

The record's fields, verbatim:

> "(i) the transfer type, step, session, previous-record hash, and a harness timestamp;"

> "(ii) the acting component (harness, model, sub-agent, or user), responsible principal, and active authorization state"

> "(iii) identifiers, content hashes, and integrity/confidentiality labels of the input segments;"

> "(iv) identifiers, content hashes, and assigned labels of the output segments,"

> "(v) the checks run and their results (each marked deterministic or model-based), active obligations or pinned user constraints,"

> "(vi) for actions and rollbacks, the environment, transcript, and memory snapshot IDs bound to the inference-server cache"

> "Fields (iii) and (iv) link records into a verified lineage graph across transfers,"

> "the same transfer records required for causal failure attribution supply the durable state needed by runtime security controls"

### 2.4 The source's own measurements (arXiv 2611.23346, §IV)

> "compactors kept on average only 17% of user constraints"

> "KV state retained after an aborted branch changed a protected decision in 25 of 63 audited cases"

> "across 240 multi-step fault-injection trajectories"

> "transfer records localize root causes and catch cross-transfer violations missed by lifecycle and tool-only logs"

The source's overhead figures, verbatim: "Seven transfers complete in 12.5–22.1 μs median latency (23.3–75.1 μs p99)", and the compaction transfer's median is "81.6" μs.

### 2.5 The supporting source (agentmem README)

> "its actions and their real effects are captured at the tool boundary"

> "never scraped from what the agent says about itself"

> "Every claim is checked against the repository and git, which decide."

> "The model never grades itself; anything the record cannot confirm is flagged, not quietly accepted."

> "every receipt is hash-chained to the last, so the record is an append-only audit trail"

---

## 3. What Northstar already had, and what was missing

This section is **(this document's reasoning)**, grounded in the code.

Read before this slice, in `components/northstar-agent-runtime/`:

| Module | What it records | Does it record a *transfer*? |
|---|---|---|
| `sealed_audit_sink.py` | every tool call and permission decision, sealed | no — it records the **action**, not the state it carried |
| `forward_seal_ledger.py` | a forward hash chain over sealed records, with checkpoints | no — the chain is over decisions, not over boundary crossings |
| `compaction.py` | a safe cut, an extractive or provider summary, a `compact_boundary` message | partly — it emits a boundary, but records **how many** messages it dropped, never **which constraints** |
| `context_budget.py` | thresholds, offload of large tool results, truncation of write-like calls | no — the offloaded pointer is returned to the caller, not recorded |
| `durable_resume.py` | checkpoints and **pending writes** kept apart, retry clears pending first | no — a pending write is durable state in flight, but its crossing is not an event |
| `checkpoints.py` | a turn boundary with a transcript digest, lineage checks | no — a checkpoint says where the run was, not what crossed into it |
| `agent_memory.py` | key-addressed memory slots, with an audit event per operation | no — it records the memory operation, not the transfer that caused it |
| `memory_provenance.py` (sibling slice) | a memory record's origin, a write gate, a revocation closure | partly — it governs the **memory-write** boundary only |

The gap, stated plainly: **Northstar could say what the agent did and could
prove what was written down, but could not say what crossed a boundary and
could not tell a downstream consumer whether a piece of state had been
checked.** The source names the consequence: "Because current traces omit
what crosses these boundaries, failure attribution and runtime monitors
fail on multi-step trajectories."

---

## 4. The invariants (Northstar extension)

These are Northstar's design. The source says a transfer boundary must be
auditable and that the record must be hash-chained; it does **not** say
which fields Northstar requires, and it does not say what "checked" means
for a Northstar runtime. Everything in this section is ours.

### INV-1 — Every transfer produces an event

A state transfer is not a side effect. It is an event, and it is recorded.
There is no transfer that leaves no record, and no record that is not a
transfer. (The source's "Each transfer gives the harness a concrete
boundary to record and check what crosses" is the closest verbatim
statement; the *enforcement* is ours.)

### INV-2 — Three questions, or the event is unverified

Every transfer event answers three questions:

1. **What moved** — `payload_digest`, a `sha256:` pin of the bytes that
   crossed.
2. **Where it came from** — `source_event_id`, the id of the event, tool
   call or user turn the content was taken from.
3. **Who approved it** — `approved_by`, where approval is required.

**An event that cannot answer all three applicable questions is
`unverified`, and carries a reason code naming what was missing.** It is
not discarded and it is not silently accepted — it is recorded, it is
marked, and downstream code must refuse it (§4, INV-6).

This mirrors the supporting source's discipline, verbatim: "anything the
record cannot confirm is flagged, not quietly accepted."

### INV-3 — A compaction must declare what it dropped

A `context_compact` event must carry `dropped_constraints`. The value may
be empty — *"I dropped nothing"* is a claim, and it is checkable. What is
not allowed is the *absence* of the declaration, because absence is
indistinguishable from silence, and silence is the failure the source
names: "context compaction dropping user constraints". The source measured
that "compactors kept on average only 17% of user constraints", so a
silent drop is not a hypothetical.

**The distinction between "declared empty" and "not declared" is
load-bearing and is preserved exactly in the code:** `()` and `None` are
different values and the rule table treats them differently.

### INV-4 — A restore must declare whether aborted in-flight state survived

A `workspace_restore` event must carry `residual_in_flight`. If it is
`True`, the event is `unverified`: aborted in-flight state survived the
restore, which is the source's "workspace rollbacks leaving aborted KV
state active on the inference server" and the source's measurement that
"KV state retained after an aborted branch changed a protected decision
in 25 of 63 audited cases". A restore that *declares* residual state is
not hiding it; it is reporting a real defect. The rule therefore does not
refuse to record it — it refuses to let it count as checked.

### INV-5 — A kind-specific field on the wrong kind is refused

`dropped_constraints` on a `memory_write` and `residual_in_flight` on a
`context_write` are both refused, with the reason code
`misplaced_field`. A field that means nothing in its context is a field
that will later be read as if it meant something, and this module exists
to stop state from being misread.

### INV-6 — `unverified` must not be treated as verified downstream

The `verified` flag is a **label**; `assert_verified()` is the **gate**.
It raises `UnverifiedTransferError` on an unverified event, and the
exception names the reason code, so a downstream consumer learns *which*
rule failed rather than merely that one did. A module that only marks
events would satisfy INV-2's letter while leaving the actual failure
unaddressed.

### INV-7 — The record is a forward hash chain

Each event is appended to a chain whose rows pin the event's full content,
so "which transfer brought this state in" has an answer that does not
depend on anybody's memory, and a later edit to a recorded event is a
chain break rather than a silent correction. `verify()` returns
`(ok, first_bad_index)` and names the first row that does not verify.

The source's own framing, verbatim: "the minimal hash-chained record the
harness emits". The chain's *shape* is ours.

---

## 5. The four transfer kinds (Northstar extension)

The source enumerates **eight** transfer classes (observation, context
assembly, compaction, memory write, consolidation, action, rollback,
delegation). Northstar collapses them onto the **four state boundaries
this runtime actually owns**, because this runtime has no inference-server
KV cache to bind and no delegation transfer of its own. This collapsing is
Northstar's design and is not claimed by the source.

| Kind | The boundary | Approval required? | Extra declaration |
|---|---|---|---|
| `context_write` | external content enters the working context | no | — |
| `context_compact` | the working context is compacted; older turns move to session history | no | `dropped_constraints` |
| `memory_write` | content enters persistent memory | **yes** | — |
| `workspace_restore` | the workspace is restored or rolled back | **yes** | `residual_in_flight` |

### 5.1 `context_write` — content entering the working context

**Allowed:** content whose source event id is known. The content itself is
screened by the runtime's existing output sanitizer and its
`scope_verbatim_compaction` rule; this module does not duplicate that
work, it only records that the crossing happened and where it came from.

**Refused (→ `unverified`):** an event with no `source_event_id`
(`missing_provenance`). A transfer that will not say where it came from is
not auditable, whatever else it says.

**Approval:** not required here. The content stays inside the current
context and does not outlive the turn.

### 5.2 `context_compact` — the context is compacted

**Allowed:** a compaction event that names its source event and declares
its dropped constraints — an explicit list, or an explicit empty tuple.

**Refused (→ `unverified`):**
* no `source_event_id` → `missing_provenance`;
* `dropped_constraints` absent → `undeclared_dropped_constraints`.

**Approval:** not required. Compaction is a routine host action; the
control is the *declaration*, not a signature.

### 5.3 `memory_write` — content entering persistent memory

**Allowed:** a memory write that names its source event **and** its
approver. This mirrors the sibling `memory-provenance` slice, which
quarantines tool output by default and charges a named approver for
promotion: a memory write is the same boundary, reached from the other
side.

**Refused (→ `unverified`):**
* no `source_event_id` → `missing_provenance`;
* no `approved_by` → `missing_approval`.

**Approval:** required. What outlives the turn needs a name attached to it.

### 5.4 `workspace_restore` — the workspace is restored or rolled back

**Allowed:** a restore that names its source event, its approver, and
declares `residual_in_flight=False` — meaning no aborted in-flight state
survived.

**Refused (→ `unverified`):**
* no `source_event_id` → `missing_provenance`;
* no `approved_by` → `missing_approval`;
* `residual_in_flight` absent → `undeclared_residual`;
* `residual_in_flight=True` → `residual_in_flight` — the restore left
  aborted state active, which is the source's incomplete-restore failure
  measured in 25 of 63 audited cases.

**Approval:** required. The world changes.

---

## 6. What this slice does **not** do

Stated up front, because a boundary audit that grows into a monitor stops
being a boundary audit.

* **No vector retrieval and no semantic search.** The module records a
  digest and an id. It does not find, rank or recall anything.
* **No LLM scoring.** No transfer is graded by a model. The source
  explicitly separates "low-overhead deterministic checks" from
  "model-based semantic checks"; this slice implements only the
  deterministic ones. The supporting source's rule is the reason:
  "The model never grades itself".
* **No cross-system tracing.** The chain is in-process. Writing it to a
  durable store, or binding it to the `forward_seal_ledger`, is the
  caller's job — this module reads and writes no files.
* **No wall clock.** `occurred_at` is supplied by the caller, exactly as
  `runtime_registration` does.
* **No inference-server KV cache binding.** The source's field (vi) binds
  snapshots to the inference server's cache; this runtime does not own
  that cache, so `residual_in_flight` is a *declaration by the caller*
  about aborted in-flight state, not a measurement of it. The module
  checks that the declaration is present and honest about its own state —
  it cannot verify it. **This is the one place where Northstar's record is
  weaker than the source's**, and it is a real limitation, not a
  simplification.
* **No enforcement inside the runtime's hot path.** The module is a
  library. `assert_verified()` is available to any downstream consumer;
  this slice does not wire it into `compaction.py`, `durable_resume.py` or
  any other existing module (those are out of scope for this slice, and
  touching them would break their pinned behaviour).
* **No new module beyond the one.** One module, one test file, one design
  document. Nothing else in the runtime changed except the two mandatory
  registration lines and one registry status.

---

## 7. The public surface

| Name | What it is |
|---|---|
| `TransferKind` | the four kinds |
| `TransferEvent` | the immutable event; `verified` and `reason` are **derived** |
| `TransferPolicy` / `POLICIES` | the rule table, one row per kind |
| `Verdict` | `(verified, reason, kind)` |
| `evaluate(event)` | the rule table applied to one event |
| `classify(event)` | the kind's name for one event |
| `assert_verified(event)` | the gate: raises `UnverifiedTransferError` |
| `TransferAuditor` | the forward hash chain: `record`, `verify`, `events`, `rows`, `unverified`, `head` |
| `TransferRow` | one chain row |
| `compute_row_hash(seq, event, prev_hash)` | the chain hash of one row |
| `REASON_CODES` | every reason code, in one tuple |

`verified` is **never** a constructor argument. It is a property derived by
`evaluate`, so an event cannot be constructed already-verified by
accident — the only way to get a verified event is to satisfy the rules.

### Reason codes and their precedence

`evaluate` checks in this order and the **first** failure wins:

1. `missing_provenance`
2. `missing_approval`
3. `undeclared_dropped_constraints`
4. `undeclared_residual`
5. `residual_in_flight`
6. `misplaced_field`

`ok` is the only code a verified event carries.

---

## 8. Honest limits of this slice

* **The digest is checked for shape, not for truth.** The module refuses a
  digest that could not be checked later (`sha256:` + 64 hex chars); it
  cannot know whether the digest matches the bytes it describes.
* **The approval is a name, not a signature.** `approved_by="user-1"` says
  somebody claimed to approve; this module does not verify that the name
  was real or that the approval was unrevoked. A future slice would bind
  this to the `agent_boundary` grant ledger.
* **The chain is in-process.** A crash loses it. Durable transfer records
  belong on the `forward_seal_ledger`, which is a different slice's work.
* **The rules are per-kind and static.** There is no per-session or
  per-tenant variation, and no obligation monitor — the source lists
  "obligation monitors" among the runtime controls its records enable, and
  Northstar has not built that yet.
* **The registry row is updated, not extended.** The survey's S5 row moves
  from `proposed` to `implemented`; no new survey row is added, because
  this slice implements an existing survey finding rather than making one.


