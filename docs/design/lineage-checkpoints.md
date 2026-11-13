# Lineage checkpoints, an atomic checkpoint store, and pair-preserving compaction

This document describes three mechanisms absorbed from Microsoft Agent Framework
(MSAF) into the Northstar agent runtime, and the rules each one enforces.

Honest scope: this is the *shape* of three MSAF mechanisms, not a port of MSAF.
The MSAF line numbers cited here were recorded by a frontier sweep on
2026-11-12 against `microsoft/agent-framework` (depth-1 clone, read-only at
`/tmp/agent-framework`); the star count and push date are the values seen at
that sweep, not a claim about today.

---

## 1. Lineage checkpoints (`components/northstar-agent-runtime/checkpoints.py`)

### 1.1 What Northstar had before

Read from the code before this change:

* **Ordering.** `select()` returned `found[-1]` - the *last checkpoint record in
  the transcript* - or the one at a named `record_index`. Both are positions in
  a transcript, not ancestry.
* **Resume verification.** `prepare_resume()` checked two things: the session
  id matched, and the transcript prefix hashed to `transcript_digest`. Nothing
  else.
* **Not verified.** Whether the checkpoint came from the *same run graph* as
  the run being resumed; whether the checkpoint's ancestry was intact.
* **Ordering caveat.** `turns` and `record_index` could not distinguish two
  checkpoints at the same boundary, and a fork could put a later record index
  on an earlier branch.

### 1.2 The lineage chain

Every checkpoint carries two new fields:

| field | type | meaning |
| --- | --- | --- |
| `previous_checkpoint_id` | `str \| None` | the checkpoint this one continues from; `None` is a **genesis** |
| `graph_signature_hash` | `str \| None` | hash of the run graph the checkpoint was taken under (64 lowercase hex) |

**Ordering rule.** Checkpoints are ordered by their `previous_checkpoint_id`
chain, and by nothing else. `turns` and `record_index` are positions in a
transcript, not lineage. `select()` walks the chain; it never sorts by turn
count or record index. The tie-break by `record_index` exists only to make the
choice stable between two checkpoints of the same depth - it is never the
primary ordering.

**Ancestor identity.** A previous id is recorded by the writer, and the
writer's naming convention is not fixed. `_find_ancestor()` therefore resolves
an ancestor by *identity* rather than by a naming convention: the lineage key
of every checkpoint in the record set (`record:<index>`), the raw previous id
as written, and - for a store-style id such as `ck-1` - the record index the
id's trailing number names. A checkpoint written by one tool stays readable by
another.

**Resume rules (fail closed).** `prepare_resume()` refuses when:

1. the checkpoint's `graph_signature_hash` is present and disagrees with the
   caller's `expected_graph_hash` - the checkpoint is from a different run
   graph;
2. the checkpoint's `previous_checkpoint_id` names a checkpoint that is not in
   the supplied `records` - the lineage is **dangling**, so the checkpoint's
   history cannot be verified.

A checkpoint with no previous id is a genesis and always passes the lineage
check. A checkpoint with no `graph_signature_hash` is not contradicted - only
unverifiable - so a resume proceeds when the caller does not know the current
graph hash. Both refusals are `CheckpointError`, the type every existing
caller already handles (`loop.py`, `run_setup.py`, `sdk.py`,
`session_replay.py`).

**Durable state.** `durable_state()` keeps its meaning unchanged: only
*committed* state travels in a checkpoint. The durable layer's pending writes
hang off the checkpoint as their own ordered records
(`durable_resume.put_writes`), and the test
`test_a_pending_write_never_travels_inside_a_lineage_checkpoint` proves a
pending write does not appear inside the lineage checkpoint's state.

### 1.3 The run graph hash

`run_graph_hash(*, steps, permission_mode, policy_revision)` hashes a
canonical JSON description of the run graph:

```json
{"steps": [...], "permission_mode": "...", "policy_revision": "..."}
```

* `steps` - the ordered loop / step configuration, each entry canonicalised.
* `permission_mode` - the authority ceiling the run runs under.
* `policy_revision` - the policy in force.

The hash is deliberately **not** the model name and **not** the transcript
digest. Two runs of the same graph with different prompts are the same graph,
and a checkpoint must survive a resumed run whose prompt was rewritten. What
must not change is the *shape*.

### 1.4 MSAF mapping

| MSAF | Northstar |
| --- | --- |
| `WorkflowCheckpoint.graph_signature_hash` | `Checkpoint.graph_signature_hash` |
| `WorkflowCheckpoint.previous_checkpoint_id` | `Checkpoint.previous_checkpoint_id` |
| "ordering is defined by the `previous_checkpoint_id` lineage chain ... do not use `iteration_count`" (`_workflows/_checkpoint.py`, docstring of `iteration_count`) | the ordering rule in `checkpoints.py`'s module docstring; `select()` walks the chain |
| `_select_latest_checkpoint` (resolves timestamp ties through the lineage) | `_latest_by_lineage` (resolves depth ties through the lineage) |
| "only committed state; pending state changes are not included in checkpoints" | `durable_state()`'s existing contract, unchanged |

MSAF's checkpoint also carries `pending_request_info_events` so a resumed run
re-delivers pending human responses. Northstar's equivalent is the approval
state in `approval_rules.py` (§4); it is **not** wired into the resume path
today (see §7, open item 3).

---

## 2. The atomic checkpoint store (`components/northstar-agent-runtime/checkpoint_store.py`)

### 2.1 What Northstar had before

Read from the code before this change: a checkpoint record is appended to the
session transcript (`sessions.py` `append()`, with `"checkpoint"` in
`RECORD_TYPES`), and `SessionStore.append` writes one JSONL line. There was no
file-level checkpoint store at all, so there was no atomicity discipline to
have: no temp file, no `os.replace`, no per-destination write queue, no
path validation for a checkpoint id, and no restricted loader.

### 2.2 The rules

**Path validation** (`_validate_file_path`). The id names a *file* inside the
store, never a path. Refused before it is joined: an empty id, an id with a
NUL, an id containing a path separator, an id equal to `.` or `..`, an
absolute path. After joining, the *resolved* path must still be inside the
resolved storage directory, so a symlink pointing out of the store is refused
too.

**Atomic write** (`_write_atomic`). The payload goes to a uniquely named
temporary file in the *destination directory* (`.northstar-ckpt-<uuid>.tmp`),
created with `O_CREAT | O_EXCL | O_WRONLY` so two writers can never share one,
written as UTF-8 JSON, flushed and `fsync`ed, and only then `os.replace`d over
the destination. The temp file lives in the destination directory so the
rename stays on one filesystem, which is what makes it atomic. A failure
removes the temp file; the destination is never seen half-written.

**One writer per destination** (`_WriteQueue`). Concurrent saves to the same id
are serialised in arrival order by a per-destination FIFO hand-off, so two
writers cannot interleave. Different ids do not contend.

**Restricted loading.** A payload is JSON. A value carrying a `__type__`
marker is only accepted when the type name (`"module:qualname"`) is on the
allowlist; otherwise the load is refused. `register_checkpoint_type(cls)`
extends the allowlist process-wide, and `allowed_types()` reports it.

**API.** `save(checkpoint_id, payload) -> str`, `load(checkpoint_id) -> dict`,
`list_ids() -> tuple[str, ...]`. The payload is the shape of
`Checkpoint.as_dict()`.

### 2.3 MSAF mapping

| MSAF (`_workflows/_checkpoint.py`) | Northstar (`checkpoint_store.py`) |
| --- | --- |
| `_validate_file_path` - refuses an id resolving outside the storage directory | `_validate_file_path` - plus a pre-join refusal of separators and parent segments |
| `_write_atomic` - unique temp file, `O_CREAT \| O_EXCL \| O_WRONLY`, `os.replace` | `_write_atomic` - same, plus an `fsync` before the rename |
| `_enqueue_write` / `_WriteTicket` - per-destination write queue | `_WriteQueue` - a per-destination FIFO hand-off of ownership |
| `register_checkpoint_type`, `"module:qualname"` allowlist, restricted unpickler | `register_checkpoint_type`, `"module:qualname"` allowlist, JSON with a `__type__` marker |

The difference in the loader is deliberate: MSAF's payload is JSON with a
pickled blob inside it, and it restricts *unpickling*. Northstar's payload is
plain JSON, so the restriction is on the type marker - an unregistered type is
refused rather than reconstructed.

---

## 3. Pair-preserving compaction (`components/northstar-agent-runtime/compaction.py`)

### 3.1 What Northstar had before

Read from the code before this change: `is_safe_cut()` refused a cut that left
a `tool_use` in the prefix whose `tool_result` was summarised away, or a
`tool_result` in the suffix whose `tool_use` was summarised away. Those are the
*orphan* rules. There was no notion of an atomic span, so a cut could land
between a tool call and its result whenever both messages happened to sit on
the same side of the orphan checks.

### 3.2 Atomic spans

`group_messages(messages) -> tuple[Span, ...]` groups a transcript into
spans. A span is a maximal run of messages that must be summarised together.

* `Span(start, end, kind)` - `kind` is `"pair"` for a linked pair and
  `"message"` for a lone message.
* `Span.contains(cut)` - true when the cut at position `k` (prefix
  `0..k-1`, suffix `k..n`) splits the span: `start < k <= end`.

**Pairing helpers.**

* `_unambiguous_tool_call_output_pairs(messages)` - pairs a `tool_use` with its
  `tool_result` **only when the call id appears exactly once** in the
  transcript. A call id that appears twice cannot say which occurrence the
  result belongs to, so no pair is claimed and the orphan rules still apply to
  it.
* `_unambiguous_approval_pairs(messages)` - pairs an approval request with its
  response by a shared `approval_id`, again only when the id appears once.

**Cut rules.** `is_safe_cut()` now refuses a cut that lands inside a span, on
top of the two orphan rules. `safe_cuts()` and `latest_safe_cut()` compute the
spans once and share them.

**`compact()`.** Keeps every existing rule. When the cut it would have taken
splits a span, the cut moves to the nearest legal boundary (the span's start
or end). When no legal cut exists, compaction is refused and the reason says
*which* rule refused it: "every candidate cut would split a tool call from its
result" versus "the transcript is mid tool exchange".

### 3.3 The approval pair, honestly

Northstar's transcript message types carry **no approval request/response
block**. The approval path lives in `permissions.py` -> `approval_chain.py`
-> a signed receipt -> the edge gate, and none of it becomes a transcript
message. So there is no approval message shape to pair, and inventing one
would be a shape nobody writes.

The pair rule is therefore implemented against the `data` mapping that
`SystemMessage` already carries, under the keys `approval_request` /
`approval_response` with a shared `approval_id` - the shape
`approval_rules.ToolApprovalState` serialises. No new message type is
introduced, and the tests exercise exactly that mapping. Wiring the approval
pair into a real transcript message shape is an open item (§7).

### 3.4 MSAF mapping

| MSAF (`_compaction.py`) | Northstar (`compaction.py`) |
| --- | --- |
| `group_messages()` - groups messages into spans, links non-contiguous call/result spans to one group | `group_messages()` - groups into `Span`s, links a call and its result into one span |
| `_unambiguous_tool_call_output_pairs()` | `_unambiguous_tool_call_output_pairs()` |
| `_unambiguous_approval_pairs()` | `_unambiguous_approval_pairs()` |
| a summary boundary never splits a linked group | a cut inside a span is refused; `compact()` moves the cut or refuses |

MSAF links *non-contiguous* spans (a declaration in one group, a result in
another) by union-find over group ids. Northstar's spans are contiguous runs,
so the union is a direct merge of the two messages' spans - the same rule, a
simpler shape.

---

## 4. Standing approval rules (`components/northstar-agent-runtime/approval_rules.py`)

### 4.1 What Northstar had before

Read from the code before this change: `permissions.py` keeps **no approval
state between calls** ("The engine keeps no approval state between calls: a
gated call always re-invokes the host callback"), and `approval_chain.py`
mints a signed receipt bound to one `(request_id, action)` pair that is
consumed on use. There was no *standing* rule - no "always approve this tool,
with these arguments" - and nothing that survived the process.

### 4.2 The rules

`ToolApprovalRule(tool_name, arguments=None, server_label=None)`:

* `arguments` pins a **subset** of a call's arguments. `None` means the rule
  matches every call to the tool.
* `server_label` bounds the rule to one server / host boundary.

`ToolApprovalState` holds the rules plus the open approval requests and the
collected answers, and serialises to a plain dict
(`northstar.approval-rules.v1`).

**Argument matching.** The polarity is the same as Claude Code's input
validation - **tolerate extra keys, require the pinned ones**:

* the call carries every pinned key with the right value -> match;
* a pinned key is **missing** -> no match;
* a pinned key holds a different value -> no match;
* a pinned key holds a different **type** -> no match (a pinned `1` must not
  match a call's `True`; `bool` is a subclass of `int`).

This is deliberately *not* MSAF's `_arguments_match`, which requires the two
argument sets to have the same size. A standing rule that only matched calls
with exactly those arguments would stop working the moment a tool grew a
parameter, and a rule that ignored extra keys would widen as the tool widened.
Pinning a subset keeps the rule narrow and stable.

**One rule per tool.** `add_rule()` replaces the earlier rule for the same
tool, so the state never carries two contradictory rules for one tool.

### 4.3 Where the rules can travel

`ToolApprovalState.as_dict()` is a plain dict, so it fits the `extra` field of
`checkpoints.durable_state()` (tested) or a session record.

### 4.4 MSAF mapping

| MSAF (`_harness/_tool_approval.py`) | Northstar (`approval_rules.py`) |
| --- | --- |
| `ToolApprovalRule(tool_name, arguments, server_label)` | `ToolApprovalRule(tool_name, arguments, server_label)` |
| `ToolApprovalState(rules, queued_approval_requests, collected_approval_responses)` | `ToolApprovalState(rules, queued_approval_requests, collected_approval_responses)` |
| `_arguments_match` - exact set match | `_arguments_match` - pinned-subset match (tolerate extra, require the pinned) |
| rules persisted in the session (`_get_state` / `_save_state`) | rules serialise to a plain dict, carried in a checkpoint's `extra` field or a session record |
| `ToolApprovalMiddleware` on the agent loop | **not wired** - §7, open item 3 |

---

## 5. How the pieces relate to the rest of the runtime

| module | relation |
| --- | --- |
| `sessions.py` | A checkpoint record is appended to the transcript (`RECORD_TYPES` holds `"checkpoint"`). The lineage fields ride along in that record; `sessions.py` was **not** changed. The atomic store in §2 is a *separate* destination - a checkpoint file - not a replacement for the transcript record. |
| `durable_resume.py` | `durable_state()` is the join between the two checkpoint layers: the turn boundary (how far the transcript got, what it cost) and the durable layer (a state it can hash, a run id it can be found under). The durable layer's pending writes stay out of it. `durable_resume.py` was **not** changed. |
| `forward_seal_ledger.py` | Its `Checkpoint` is a **different type with the same name**: a sealed checkpoint over a chain head (`seq`, `head_hash`, `records_sealed`, `seal`). The two are not interchangeable and are never mixed. The seal ledger was **not** changed. |
| `loop.py`, `run_setup.py`, `sdk.py`, `session_replay.py` | The existing resume call sites. They call `prepare_resume()` without the new keyword arguments, so their behaviour is unchanged: with no `expected_graph_hash` and no `records`, the new checks cannot fire. The new rules are opt-in at the call site. |

---

## 6. The paths the tests drive

**Path 1 - build -> atomic store -> lineage-checked resume**
(`tests/test_lineage_checkpoints.py::EndToEndPathTests`): two checkpoints are
built with a graph hash and a `previous_checkpoint_id`, stored atomically,
restored from the store, and the head of the lineage is selected. The resume
succeeds under the same graph. Then two resumes are refused: one under a
changed graph, one with the ancestor removed from the record set.

**Path 2 - a pair straddling the cut**
(`tests/test_pair_preserving_compaction.py::CompactPathTests`): a transcript
whose tool call and result straddle the position the old rules would have cut
at. The cut moves to the span boundary, or compaction is refused with the
reason that a pair would be split. The pair is never split.

---

## 7. Open items

1. **The resume call sites do not pass the new arguments.** `loop.py`,
   `run_setup.py` and `sdk.py` call `prepare_resume()` without
   `expected_graph_hash` or `records`, so the graph-mismatch and dangling-lineage
   rules cannot fire from the CLI today. They were left alone on purpose (they
   are outside this slice's writable file set), and the rules are available for
   the next slice that owns those files.
2. **`select()`'s tie-break.** Two checkpoints at the same lineage depth are
   ordered by `record_index`, for stability only. MSAF breaks the same tie by
   timestamp and then by checkpoint id. Northstar's checkpoint records carry an
   HLC timestamp (`sessions.py`), so the MSAF tie-break is available when the
   resume call sites are wired.
3. **The approval rules are not wired into the live approval gate.**
   `permissions.py` was not touched. The rules are data that can be built,
   matched, serialised and carried; connecting them to the host approval
   callback needs a seam that does not exist today.
4. **The approval pair shape.** The transcript carries no approval
   request/response block. The pair rule reads the `data` mapping; a real
   message shape has to be introduced before a live run's approval pair is
   protected by the cut rule.
5. **The atomic store is not the transcript's checkpoint path.** A checkpoint
   record still lands in the JSONL transcript through `sessions.py`. The store
   in §2 is an additional, atomic destination; making the transcript's
   checkpoint record itself atomic (or storing it *only* in the store) needs a
   decision about the audit chain in `sessions.py`.
