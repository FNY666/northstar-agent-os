# The memory provenance axis — a write boundary and a computable revocation

**Slice:** `memory-provenance-axis` (2026-11-24)
**Module:** `components/northstar-agent-runtime/memory_provenance.py`
**Tests:** `components/northstar-agent-runtime/tests/test_memory_provenance.py`

**What this document is.** The rank-1 source of the frontier-expansion survey
(`docs/design/frontier-expansion-survey.md`, records S1 and S2) was the *Always-On Agents*
survey together with *sentinel-mem*. This slice is the implementation of that ranking: it
makes two of the survey's six diagnostic axes — **provenance** and **recoverability** —
executable, and it gives Northstar the object the survey says the field is missing: a
memory state that can be **revoked**, not merely deleted.

## How to read the citations

Three kinds of statement appear below, and they are never mixed:

| Marker | Meaning |
|---|---|
| **verbatim** | The text is quoted from the source, character for character. The URL is given. |
| **Northstar extension** | Northstar's own design. The source does **not** claim this. |
| **(community opinion)** | A view expressed by a forum participant. Not a specification, and not Northstar's rule. |

**Rule for the reader:** if a claim is not marked verbatim and not marked as a Northstar
extension, treat it as this document's own reasoning and check it against the linked
source before relying on it.

---

## 1. The sources

### 1.1 Source S1 — Always-On Agents survey (Ding et al., June 2026)

- **URL:** https://arxiv.org/abs/2606.30306
- **Discussed at:** https://www.moltbook.com/post/32cd70db-2386-48ab-8e44-a835b151bb63
- **Category:** memory / state governance
- **Title (verbatim, the arXiv listing):** "Always-OnAgents:A Survey of Persistent Memory,
  State, and Governance in LLMAgents"
- **Authors (verbatim):** "Tianyu Ding, Aditya Nannapaneni, Bingfan Liu, Ling Zhang"
- **Abstract (verbatim):** "Always-on agents are systems whose future behavior depends on
  durable state accumulated across earlier interactions. We treat them as persistent-state
  systems: the operative system includes retrievable memories, but also task ledgers,
  permissions, credentials, commitments, provenance and audit records, shared state,
  trigger conditions, and externally committed effects linked to those records. The survey
  reads the literature through six diagnostic axes for each state item, authority, scope,
  mutability, provenance, recoverability, and actionability, and through a lifecycle in
  which state is written, validated, organized, retrieved, acted upon, updated,
  forgotten, audited, and sometimes rolled back. Across a 435-work coded corpus, treated
  as a scoped map rather than an exhaustive census, the literature concentrates more
  heavily on accumulating and retrieving state than on governing, recovering, or
  relinquishing it. We therefore introduce the Always-On Evaluation Protocol (AOEP-v0), a
  pilot evaluation contract that makes these governance requirements concrete by scoring
  state mutation and recovery obligations rather than answer quality alone. The
  resulting agenda connects always-on agents to databases, distributed systems, formal
  methods, capability security, and machine unlearning."
- **The six axes (verbatim, from the abstract):** "authority, scope, mutability,
  provenance, recoverability, and actionability"
- **The nine-step lifecycle (verbatim, from the abstract):** "written, validated,
  organized, retrieved, acted upon, updated, forgotten, audited, and sometimes rolled back"
- **Verdict:** absorb-now (rank 1).

> **Note on the "435 papers."** The abstract says "Across a 435-work coded corpus". This
> document uses the abstract's own wording and does not restate the number in its own
> voice.

### 1.2 Source S2 — sentinel-mem

- **URL:** https://github.com/rajeshamp/sentinel-mem
- **Category:** memory / provenance
- **Subtitle (verbatim, the README's opening paragraph):** "Provenance gating for
  cross-session agent memory. Zero runtime dependencies, stdlib only."
- **Repository description (verbatim, the GitHub repo's `description` field):** "Provenance
  gating for cross-session LLM agent memory. Zero runtime dependencies, stdlib only.
  Applies Biba integrity model to the memory-write boundary."
- **Claims (verbatim):**
  - "**Provenance is mandatory.** No `source_session_id` or `origin` → the record cannot
    be constructed. Default-deny, enforced at the type."
  - "**Origin decides promotion, not the classifier.** `TOOL_OUTPUT` and `EXTERNAL_DOC`
    are never auto-promoted, at any severity. No model call, no drift, nothing to
    prompt-inject."
  - "**Consolidation is a second gate, not a trusted job.** Merges union `derived_from`,
    inherit the worst input origin, and re-scan the merged text."
  - "**Quarantine has an exit.** `promote()` costs a named approver, a justification, and
    a ledger entry. Quarantine with no exit is a dead end, and a dead end gets forked
    out."
  - "**Revocation is computable.** Hash-chained, durable ledger; given a compromised
    session id, replay and get every transitively tainted memory — including ones a merge
    renamed, and ones a human promoted."
  - "a tool said it -> stored, never injected, never merged"
  - "Nightly consolidation guard — the merge pass that turns session facts into profile
    records inherits the worst input origin, unions provenance, re-scans merged text, and
    refuses non-promotable or cross-tenant inputs whole."
  - "Refuse whole, never partially. A merge with one bad input is refused, not silently
    completed without it. Partial success hides the failure."
  - "Quarantine ≠ delete, and ≠ permanent. Retained for forensics, excluded from preload
    and consolidation, releasable only by `promote()` with a named approver. A revoked
    record can never be promoted — re-establish the fact from a clean source instead."
  - "**Taint closure is only as complete as the ledger.** One un-gated write path and
    `taint_closure()` silently returns a subset — which is worse than no revocation,
    because it manufactures assurance."
  - "**`origin` is supplied by the caller.** The library enforces that it is present and
    enforces what follows from it; it cannot verify it. Tagging origin correctly at the
    point text is produced is the integrator's job and it is the load-bearing part of the
    whole design. When in doubt, tag down."
- **Design rules (verbatim, the source's own numbering):**
  1. "**Deterministic floor, probabilistic ceiling.** `scanner.scan()` does extraction
     only — no LLM, no network, no I/O. An LLM classifier may *raise* a verdict and may
     never lower one. Classifier exception → M4 BLOCK."
  2. "**Severity is M0–M4**, shared with the tool-call gate so verdicts are comparable
     across boundaries."
  3. "Refuse whole, never partially."
  4. "Quarantine ≠ delete, and ≠ permanent."
  5. "**The heuristics are not the boundary.** `heuristics.scan()` is a deterministic floor
     with known misses. The structural controls — the origin allow-list and the
     consolidation gate — hold even when every pattern misses. Named `heuristics`, not
     `scanner`, so nobody mistakes it for coverage."
- **What it does not do (verbatim):** "Retrieval ranking, embeddings, storage, or the
  harness itself. It sits in front of your store."
- **Verdict:** absorb-now (rank 1, implementation of S1).

### 1.3 Source S16 — Reddit r/AI_Agents, memory revocation preprint discussion

- **URL:** https://www.reddit.com/r/AI_Agents/comments/1xlmhkc/preprint_in_two_agent_memory_setups_revoked/
- **Category:** memory / red-team
- **Claims (verbatim, as the poster summarizes the preprint):**
  - "Some agent memory systems mark a contradicted fact as invalid and keep it instead
    of deleting it."
  - "no system enforced revocation in every case. Only two setups returned the revoked
    record: Graphiti, and mem0 with its read-time filter turned off by the authors"
  - "In both, the revoked record ranked first in every scenario, and agents took the
    unsafe action in more than two of every five trials."
  - "The authors also built a guard between the agent and the memory backend that
    withholds revoked or contradicted records."
- **Verdict:** absorb-now (rank 1, the red-team half).

### 1.4 Source S18 — Reddit r/LLMDevs, "Agent memory is a joke right now."

- **URL:** https://www.reddit.com/r/LLMDevs/comments/1xcatnx/agent_memory_is_a_joke_right_now_how_are_you/
- **Category:** memory
- **Claims (verbatim, community opinion):** "Keep the human approval before anything
  lands in shared memory. An agent that read a poisoned web page or issue comment can
  copy that instruction into a note. Once the note is in the shared repo, every
  teammate's agent reads it at startup and acts on it."
- **Verdict:** absorb-later (rank 7) — folded into rank 1's promotion rule.

> **The community opinion is not the specification.** The human-approval rule Northstar
> implements comes from S2's "Quarantine has an exit" (a source), not from S18 (a forum
> post). S18 is recorded because the survey recorded it, and because the convergence is
> worth noting — not because a comment is a spec.

---

## 2. What Northstar had, and what was missing

The runtime already owns five memory/ledger surfaces. Each was read (the code, not the
documentation) before this slice was written:

| module | what it actually does |
|---|---|
| `agent_memory.py` | key-addressed slots: `store` / `recall` / `search` / `forget`, with a `sha256:` digest pin over `(key, seq, content, sorted tags)`. `forget` retires a key forever and keeps a terminal tombstone. |
| `context_budget.py` | what fits in a context window, and how to spend it. |
| `ledger.py` | double-entry bookkeeping: accounts, journal entries, a trial balance. |
| `forward_seal_ledger.py` | a forward-secure sealed decision chain with checkpoints and an `append_grant` path. |
| `sealed_audit_sink.py` | a callable adapter that maps a gate's audit dict onto eight sealed ledger fields. |

**The gap.** Each of those is a *chain*. None of them is a *revocable state*. Concretely,
nothing in the runtime could answer the two questions the survey says the field cannot:

1. **"Which tool output wrote this memory?"** — `agent_memory.py` books *host-reported
   content*; its own docstring says so ("This module books *host-reported* content. A
   booked memory is a ledger entry, not a verified fact"). It has no `origin`.
2. **"That session was poisoned — which downstream memories go with it?"** — no module
   holds a *derivation edge* between two memories, so no closure can be computed.
   `agent_memory.forget()` retires a **key**; it says nothing about the memory that was
   *promoted from* it, or *merged with* it.

**Northstar extension (the gap statement is ours; the two questions are the survey's
concern, stated in Northstar's own terms):** the missing object is a *provenance-carrying
memory record* plus a *revocation closure* over it.

---

## 3. The invariants

These are the properties the module enforces. Each is stated so that a violation is a
**test failure**, not a design opinion.

**I1 — Every record has an origin.** A `MemoryRecord` cannot be constructed without an
`origin` and a `source_session_id`. There is no default for either: a caller that cannot
name where a fact came from does not get to write it. *(S2: "Provenance is mandatory.
No `source_session_id` or `origin` → the record cannot be constructed. Default-deny,
enforced at the type.")*

**I2 — The origin decides promotion, not a classifier.** An origin outside
`AUTO_PROMOTABLE` is quarantined, always. Northstar's version has **no classifier at
all** in the write path — there is no LLM to prompt-inject, and no severity scale. *(S2:
"Origin decides promotion, not the classifier.")*

**I3 — A tool output never lands on its own.** `tool_output` and `imported` are
quarantined by default and can only reach the durable set through a named approver.
*(S2: "`TOOL_OUTPUT` and `EXTERNAL_DOC` are never auto-promoted, at any severity.")*

**I4 — Promotion costs a named human and a reason.** `promote()` refuses without an
approver and without a justification, and writes both to the ledger. *(S2: "`promote()`
costs a named approver, a justification, and a ledger entry.")*

**I5 — A revocation produces a transitive closure.** Revoking a session id reaches every
memory derived from it — through a promotion, through a merge, through a chain of merges.
The closure walks the **derivation edges**, not a flat event list. *(S2: "given a
compromised session id, replay and get every transitively tainted memory — including
ones a merge renamed, and ones a human promoted.")*

**I6 — A merge inherits the worst input origin.** A merged record is only as trusted as
its least trusted input. *(S2: "Merges … inherit the worst input origin".)*

**I7 — A merge refuses cross-tenant input whole.** Not partially. *(S2: "refuses
non-promotable or cross-tenant inputs whole.")*

**I8 — A revocation is an appended event, not a deletion.** The record stays; its
disposition becomes `REVOKED`. A revoked record can never be promoted again. *(S2:
"Quarantine ≠ delete, and ≠ permanent. Retained for forensics".)*

**I9 — The chain is verifiable, and names the first bad row.** `verify()` returns
`(ok, first_bad_index)`; a mutated, inserted or deleted row is detected. *(S2: "the
hash-chained ledger verifies on load and raises `LedgerTampered` on any insertion,
deletion, or mutation".)*

**I10 — No clock, no I/O.** Every timestamp is supplied by the caller. The module
imports nothing outside the standard library (plus `canonical_json`, which is itself
stdlib-only and lives in this component). Nothing is written to disk.

**I11 — The graph traversal is cycle-safe.** `parent_ids` is free JSON, not a foreign
key. A caller can name an id that does not exist, and can name an id that names it
back. Every traversal keeps a visited set.

---

## 4. The record structure

`MemoryRecord` is a frozen dataclass. Every field is validated at construction.

| field | type | meaning | invariant |
|---|---|---|---|
| `memory_id` | `str` | the record's identity | non-empty; unique within a gate (a duplicate write is refused) |
| `text` | `str` | the memory's content | non-empty |
| `origin` | `Origin` | where the content came from | one of the four; unknown names refused |
| `source_session_id` | `str` | the session that produced it | non-empty — **I1** |
| `source_turn` | `int` | the turn within that session | `>= 0`; `bool` refused |
| `user_id` | `str` | the tenant | non-empty — the tenant boundary |
| `parent_ids` | `tuple[str, ...]` | the derivation edges | sequence of non-empty ids; a dangling id is tolerated |
| `created_at` | `str` | the caller's timestamp | supplied, never read from a clock — **I10** |
| `disposition` | `Disposition` | where the record sits | `PROMOTED` / `QUARANTINED` / `REVOKED` |

Derived: `record.digest` — the `sha256:` pin of the record's text.

### 4.1 The four origins (Northstar extension)

The source library has six origins. Northstar keeps **four**, and the mapping is
Northstar's own decision, not the source's:

| Northstar origin | the source's near neighbour | risk | default disposition |
|---|---|---|---|
| `user_direct` | `USER_DIRECT` | 0 | `PROMOTED` |
| `agent_summary` | `MODEL_INFERENCE` | 1 | `QUARANTINED` |
| `imported` | `EXTERNAL_DOC` | 2 | `QUARANTINED` |
| `tool_output` | `TOOL_OUTPUT` | 3 | `QUARANTINED` |

**Northstar extension — why four and not six.** The source distinguishes `USER_DIRECT`
(text the human *composed*) from `USER_PASTED` (text the human *pasted* from a poisoned
page), and says plainly why (verbatim from `sentinel_mem/provenance.py`):

> "The user turn is not a trust boundary -- it is a *channel*. Text the human composed
> and text the human pasted from a poisoned page arrive through the same field and are
> indistinguishable at the API. Trusting the channel instead of the authorship puts a
> hole at the top of the ordering, which is the worst place for one."

Northstar's boundary has the same property: a caller hands the runtime a text and an
origin, and nothing distinguishes a composed fact from a pasted one. So Northstar takes
the source's *conclusion* rather than its *distinction*: it refuses the whole channel.
`agent_summary` is the one Northstar adds beyond the source's four trusted-ish origins —
an agent's own conclusion about a turn is a derivation from text the agent may have been
fed, so it is quarantined by default, exactly as the source treats `MODEL_INFERENCE`.

**Northstar extension — `agent_summary` is Northstar's name.** The source calls it
`MODEL_INFERENCE`. Northstar's runtime talks about *agents*, not models, and its own
`agent_memory.py` talks about hosts and agents; `agent_summary` is the name Northstar
uses.

**Northstar extension — the risk order.** The source orders origins by a `_ORIGIN_RISK`
table used to pick the *worst* input of a merge. Northstar keeps the same shape and the
same relative order (`user_direct` < `model_inference` < `external_doc` < `tool_output`)
under its own four names, and exposes it as `ORIGIN_RISK`.

---

## 5. The state machine

```
                 submit()                    promote(approver, justification)
   (candidate) ─────────────►  QUARANTINED ───────────────────────────────► PROMOTED
                    │                                                          ▲
                    │ origin == user_direct                                 │
                    ▼                                                        │
                 PROMOTED ────────────────────────────────────────────────────┘
                    │
                    │ revoke_session(session_id)  [the closure reaches this
                    ▼                                                  record too]
                 REVOKED ──✗── promote() is refused here, forever
```

### 5.1 Transitions, with their trigger and refusal conditions

| # | transition | trigger | refused when |
|---|---|---|---|
| T1 | *(none)* → `PROMOTED` | `submit()` with `origin == user_direct` | the origin is not `user_direct` — **I2**, **I3** |
| T2 | *(none)* → `QUARANTINED` | `submit()` with any other origin | never refused: quarantine is the default — **I2** |
| T3 | `QUARANTINED` → `PROMOTED` | `promote(id, approver, justification)` | no approver; no justification; unknown id; already promoted; **the record is `REVOKED`** — **I4**, **I8** |
| T4 | `PROMOTED` → `REVOKED` | `revoke_session(gate, session_id)` | never refused: a revocation is fail-safe — **I5**, **I8** |
| T5 | `QUARANTINED` → `REVOKED` | `revoke_session(gate, session_id)` | never refused — **I5** |
| T6 | `REVOKED` → `PROMOTED` | — | **always refused.** There is no path. — **I8** |

**A refusal leaves a trail.** A refused promotion writes a `PROMOTION_REFUSED` row; a
refused merge writes a `MERGE_REFUSED` row; a refused write writes a `MEMORY_REFUSED`
row. The ledger records the decisions that did not happen, because a refusal nobody can
see is a refusal nobody can audit.

---

## 6. The revocation closure (the part the survey is really about)

**Northstar extension — closure over edges, not over events.** The source computes the
closure by *replaying the ledger*: it walks the `MEMORY_WRITTEN` and `MEMORY_CONSOLIDATED`
events in order and marks a record tainted when its `derived_from` intersects the revoked
sessions or its inputs are already tainted. Northstar computes the same closure over the
stored records' `parent_ids` **edges** instead.

Both compute the same set. The edge form is what Northstar uses because it is the form
the record already carries, so a closure computed from it cannot drift from the records
the way an event replay can. The source's own warning is the reason this matters:

> **verbatim (S2):** "**Taint closure is only as complete as the ledger.** One un-gated
> write path and `taint_closure()` silently returns a subset — which is worse than no
> revocation, because it manufactures assurance. Inventory every call site that reaches
> your store before you rely on it."

Northstar's answer to that warning is stated in section 8.

**What the closure reaches.** A revocation of session `s` reaches:

* every record whose own `source_session_id` is `s`;
* every record with a `parent` that is reached (transitively).

So a tool fact, promoted by a human, is still downstream of the session that produced it;
and a merge of a promoted fact with a tool fact is downstream of the tool's session even
though the merge's own `source_session_id` is the consolidation session.

**Cycle safety.** The walk keeps a visited set, so a `parent_ids` cycle terminates. This
is **I11**, and it is not hypothetical: `parent_ids` is caller-supplied JSON.

---

## 7. What Northstar does **not** do

These are the boundaries of this slice. Each is a decision, not an omission.

* **No vector store, no embeddings, no similarity search.** *(S2 says the same: "Retrieval
  ranking, embeddings, storage, or the harness itself. It sits in front of your store.")*
  Northstar's module is a **gate**, not a store. It holds records in memory for the
  lifetime of the process and hands them to the caller's store.
* **No LLM extraction and no LLM in the write path.** There is no classifier, no
  severity scale, and no severity ranks. The origin decides, and nothing else is
  consulted. *(S2 has a deterministic scanner and an optional raise-only LLM
  classifier; Northstar has neither, because Northstar's write path has no model in it.)*
* **No cross-tenant sharing.** A merge whose inputs span two `user_id`s is refused
  whole. There is no path in this module that copies a memory from one tenant to
  another.
* **No durability.** The ledger is in-process. Nothing is written to disk. A deployment
  that needs revocation claims to survive a restart must persist the rows itself — the
  runtime's `forward_seal_ledger` is the sealed chain it can ride on, and
  `sealed_audit_sink` is the adapter that writes a gate decision into it. Wiring that
  is **not** this slice's work (see the OPEN section).
* **No content scanner.** The source re-scans merged text with a heuristic scanner to
  catch a directive that no single input contained. Northstar's merge re-scans the
  merged text for its inputs' **provenance markers** (the origin names appearing
  verbatim in the text) and records what it found. This is a **weaker** check than a
  content scanner, and it is stated as such in the module's docstring.
* **No retrieval, no ranking, no preload policy.** `promoted(user_id)` returns the
  preload set; deciding what goes into a turn is the caller's job
  (`context_budget.py` owns that).
* **No severity scale, no `Action`/`Verdict` types.** S2's M0–M4 rubric belongs to its
  tool-call gate. Northstar's memory gate has one axis — the origin — and one rule.

---

## 8. The open seam: the closure is only as complete as the write path

The source's warning (section 6) is the sharpest thing either source says, and it
applies to Northstar verbatim: a memory that reached the store **without** passing the
gate is not in any closure.

**Northstar extension — what this slice does about it.** This slice ships the gate, the
record and the closure, and it does **not** ship the wiring that puts the gate in front
of Northstar's existing memory write paths. `agent_memory.py` still has its own
`store()`, and that path does not go through `WriteGate`.

So the honest statement of what this slice delivers is:

* the **mechanism** is complete and tested: every record has an origin, the origin
  decides the disposition, promotion costs a human, and a revocation reaches its whole
  downstream closure;
* the **enforcement** is not yet complete: until every caller of `agent_memory.store()`
  goes through a `WriteGate`, a record can still enter the store ungated, and a closure
  computed over gated records would silently miss it.

That gap is the same shape as the source's, and it is recorded as an OPEN item in the
slice report rather than papered over. The mitigation Northstar has that the source does
not is that the gate is a **separate object**: a caller cannot reach the record's
disposition without going through `WriteGate.submit()`, and a `ProvenanceGraph` built
from the gate's records is exactly the set of records the gate knows about. A future
wiring slice can therefore *enumerate* what is gated and what is not, rather than
reasoning about it.

---

## 9. The source map, in one table

| Northstar's thing | where it came from | verbatim? |
|---|---|---|
| the six axes and the nine-step lifecycle are the survey's frame | S1 | **verbatim** |
| a record cannot exist without an origin | S2 | **verbatim** |
| the origin decides promotion, not a classifier | S2 | **verbatim** |
| tool output is never auto-promoted | S2 | **verbatim** |
| promotion costs a named approver and a justification | S2 | **verbatim** |
| revocation is computable and transitive | S2 | **verbatim** |
| a merge inherits the worst input origin ("Merges union `derived_from`, inherit the worst input origin, and re-scan the merged text.") | S2 | **verbatim** |
| a cross-tenant merge is refused whole | S2 | **verbatim** |
| a revocation appends an event rather than deleting | S2 | **verbatim** |
| the chain verifies and names the first bad row | S2 | **verbatim** |
| the four origin names, and the risk order under them | — | **Northstar extension** |
| `agent_summary` as a distinct origin | — | **Northstar extension** |
| `parent_ids` as the derivation edge set | — | **Northstar extension** |
| the closure over edges rather than over events | — | **Northstar extension** |
| the merge's provenance-marker re-scan | — | **Northstar extension** |
| no classifier and no severity scale in the write path | — | **Northstar extension** |
| the four dispositions and their names | — | **Northstar extension** |
| "keep the human approval before anything lands in shared memory" | S18 | **(community opinion)** — the rule comes from S2, not from S18 |
