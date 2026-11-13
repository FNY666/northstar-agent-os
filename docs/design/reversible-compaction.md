# Reversible compaction — a ticket back to before the cut

Status: implemented (module + tests + this document). Slice: B173
`reversible-compaction`.

## What this slice is

A compaction in Northstar today is a one-way door. `compaction.compact()`
returns a `CompactionOutcome` whose `transcript` is `(boundary,) + kept`:
the summarised prefix is replaced by one summary string and is not
recoverable from the outcome. When a session dies on the compaction seam —
the last substantive event is the compaction, then a tool result, then
nothing — the only remedy the source offers is to re-dispatch the same
prompt and lose the thread that was carrying it.

This slice adds the ticket back: a compaction record that carries the hash
of the pre-compaction transcript and the hash of the prompt that was in
flight, plus an opaque revert token, so a seam death can be *reverted* to
before the cut instead of restarted from scratch.

Module: `components/northstar-agent-runtime/reversible_compaction.py`
Tests: `components/northstar-agent-runtime/tests/test_reversible_compaction.py`

## Source mapping — verbatim vs Northstar extension

### Verbatim from the source post (the excerpt carried by the slice brief)

The post itself is not in this repository and was not crawled; the excerpt
in the slice brief is the source.

* "Four of the five died on the seam. The compaction event was the last
  substantive thing in the file, and after it came a tool result and then
  nothing."
* "Now I check the log first. If the last event is a tool result and there
  is a compaction somewhere upstream, I do not rewrite the prompt. I
  re-dispatch the same prompt. The prompt was probably fine. What got lost
  was the thread that was carrying it."
* "617 sessions total; 522 with no compaction; 95 with one or more; 5 with
  no prose at all; All 5 failures were in compacted sessions."
* "1 compaction: 3 failures out of 64; 2 compactions: 2 failures out of 27;
  3 or more: 0 failures out of 4."

### Northstar extension (designed here, not quoted from the source)

* The **`CompactionRecord`** shape — `summary`, `transcript_hash`,
  `prompt_hash`, `revert_token` — is Northstar's. The source describes a
  *behaviour* (re-dispatch instead of rewrite) and a *loss* (the thread);
  it does not describe a record format.
* The **archive contract** (`archive.get(transcript_hash) -> transcript |
  None`) is Northstar's. The source says the thread was lost; it does not
  say how the bytes are kept.
* **Reverting** rather than re-dispatching is Northstar's. The source's
  remedy is to re-dispatch the same prompt; the source does not propose
  recovery of the dropped thread. This slice keeps the source's diagnosis
  ("the prompt was probably fine; the thread was lost") and answers it with
  a mechanism the source does not contain.
* **`rederive()` as a hash-consistency check** is Northstar's, and is
  explicitly *not* the semantic re-derivation discussed in the related
  thread (`vina`, "compaction re-derivation vs stored prompt hash"); that
  thread's full text was not retrieved, so nothing here is quoted from it.
* The **fail-closed discipline** (both hashes mandatory; revert by hash
  only; `None` rather than an approximation) is Northstar's house style,
  matching the sibling scope slice.

## What was read in this repository before designing (read, not assumed)

* `compaction.py` — `compact()` returns `CompactionOutcome(transcript=(boundary,) + kept, cut=…, summary=…)`.
  The outcome names no pre-compaction transcript and carries no hash of it.
  The summary is a single string (`extractive_summary`, clipped at 4000
  chars) that is concatenated with the tool-provenance ledger and the host
  instruction and then passed through `defensive_agent.sanitize_for_model`.
* `checkpoints.py` — `digest_transcript()` is a SHA-256 over the canonical
  JSON of the message list; `Checkpoint` carries `transcript_digest` and a
  lineage (`previous_checkpoint_id`), and `CheckpointStore` archives
  payloads under a **checkpoint id**. That is a resume mechanism keyed by
  lineage, not a revert mechanism keyed by content: nothing hands back the
  bytes a compaction dropped.
* `checkpoint_store.py` — `FileCheckpointStorage.save/load/list_ids`, keyed
  by checkpoint id, with type allow-listing and atomic writes.
* `scope_verbatim_compaction.py` — the sibling slice. It guarantees the
  *scope block* crosses a compaction verbatim (forward invariant). It says
  in its own docstring that re-deriving the scope from a stored source is
  "the reversible compaction slice's job". This slice and it do not
  overlap: scope loss is the scope slice's problem; seam death that cannot
  be undone is this slice's problem.

## API

```
compact_reversible(transcript, summary, prompt_hash, *, revert_token=None) -> CompactionRecord
can_revert(record, archive) -> bool
revert(record, archive) -> transcript | None
rederive(record, prompt_hash) -> bool
transcript_hash(transcript) -> "sha256:<hex>"
prompt_hash_for(prompt) -> "sha256:<hex>"
```

`CompactionRecord` is a frozen dataclass with fields `summary`,
`transcript_hash`, `prompt_hash`, `revert_token`, `schema`.

**Archive contract (defined here, implemented by the caller).** An archive
is any object with `get(transcript_hash) -> transcript | None` (a dict, a
host store) or any callable with the same signature. This module neither
stores nor retrieves transcripts; it consumes a content-addressed read
port.

## The rules, written down

1. A compaction without both a transcript hash and a prompt hash is not
   reversible. `compact_reversible()` refuses to mint such a record
   (`MissingHashError`); it never mints a half-record.
2. The record stores hashes and a token, never the transcript. Storing the
   transcript would defeat the compaction the record describes.
3. `revert()` accepts a candidate only when the candidate's canonical hash
   equals the record's `transcript_hash`. "Looks like the same
   conversation" is not a criterion.
4. `revert()` fails closed: absent archive, mismatched hash, or a record
   without hashes yields `None`. Never an exception, never an
   approximation, never a warning.
5. `can_revert()` is `True` only when the archive returns a transcript whose
   hash matches.
6. `rederive()` is hash consistency, not semantics: the record's
   `prompt_hash` must equal the caller's and the summary must be
   non-empty.

## The driven path

`tests/test_reversible_compaction.py::EndToEndPathTests::test_a_compaction_can_be_undone_after_the_session_dies_on_the_seam`
drives the whole path once, against the *real* `compaction.compact()`:

1. a transcript is compacted for real (`compaction_mod.compact(transcript, force=True)`),
2. the record is minted against the transcript as it was *before* the cut,
3. the archive holds the pre-compaction transcript → `can_revert` is `True`
   and `revert` returns the verbatim transcript,
4. the archive lost it → `can_revert` is `False`, `revert` is `None`,
5. the archive kept a corrupted copy (one character changed) →
   `can_revert` is `False`, `revert` is `None`,
6. the prompt was fine → `rederive` is `True` against the dispatched
   prompt hash.

## Honest residual

* This slice guarantees only that the pre-compaction transcript can be
  **recovered**. It does **not** guarantee that the session will not die
  again after the revert: the seam can kill the session twice, and a
  reverted session that dies on the next compaction is still a dead
  session.
* `rederive()` is a **hash-consistency** check, not a semantic
  re-derivation. It does not re-run a model, does not re-derive the
  summary from the prompt, and does not reconstruct the thread. The
  related thread's "re-derivation vs stored prompt hash" question is
  therefore *not* answered by this slice.
* The **archive** — the "fetch a transcript by hash" capability — is
  supplied by the caller and is **not** implemented here. Without an
  archive, `can_revert` is `False` and `revert` is `None`; the record on
  its own cannot restore anything.
* The record's `revert_token` is an opaque handle whose meaning is agreed
  with the archive. This module mints a derived default token; it does not
  authenticate it.
* Nothing in this module hooks itself into the live compaction path.
  `compaction.py` is untouched (it belongs to another slice); a host must
  call `compact_reversible()` itself and supply the archive.
* The hash covers the transcript's canonical JSON rendering, not the raw
  provider bytes. Two transcripts that render identically but were sent to
  the provider in different envelopes hash the same — this is the same
  canonicalisation `checkpoints.digest_transcript()` already uses, and it
  is a deliberate trade: content equality, not transport equality.
