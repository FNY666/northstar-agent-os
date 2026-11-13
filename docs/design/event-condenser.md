# event-condenser — condensation as a log event

*Status:* implemented (`components/northstar-agent-runtime/event_condenser.py`)
*Slice:* B173 event-condenser
*Source:* OpenHands context condensation (Moltbook round, rank 1), as quoted in
the slice taskbook. The quotes below are the source text; the taskbook's
quotes are the rule — no re-reading of the upstream repository.

---

## 1. The gap this slice closes

Northstar compresses context today, but compression is **not** an auditable
event. What was actually read in the repo (not assumed):

| Module | What it does | What it lacks |
| --- | --- | --- |
| `compaction.py` (625 lines) | Cuts the transcript at a *safe* boundary (no dangling `tool_use` / `tool_result`, never inside an atomic span), builds an extractive summary, and **rewrites the transcript in place** (`new_transcript = (boundary,) + kept`). | Nothing is written to the log. Once compaction runs, the summarised history is gone from the model-visible transcript — there is no record of *what* was dropped, so compression is neither auditable nor replayable. |
| `event_sourcing.py` (664 lines) | Append-only, hash-chained log (`Event`/`EventStore`), replay (`replay`, `replay_from_latest`), snapshots. | No notion of condensation. A compacted-away event cannot be brought back, because the transcript that held it was rewritten. |
| `summarization_guard.py` (23 lines) | `check_summary(original, summary, max_ratio=0.3)` — a summary-length ratio check. | No log entry, no view derivation, no per-source policy. |

So: **today compression is auditable only in the sense that the new transcript
shows a summary; it is not replayable.** There is no per-source throttling
(the `BrowserOutputCondenser` shape) and no reactive over-limit trigger.

A repo-wide grep for `CondensationAction` and `summary_offset` returned zero
hits before this slice. The word `forgotten` appeared only in
`agent_memory.py`, where it means *memory-key retirement* — unrelated to
compression.

---

## 2. Source mapping — verbatim vs Northstar extension

### 2.1 Verbatim from the source (OpenHands context condensation)

| Source text | Where it lands in this slice |
| --- | --- |
| `CondensationAction{forgotten: list[int], summary: str, summary_offset: int}` | `CondensationEvent` (`event_condenser.py`), fields `forgotten`, `summary`, `summary_offset`. The dataclass is frozen and stores `forgotten` as a tuple. |
| Compression is appended to the event log as a first-class event. | `append_condensation(log, forgotten, summary, offset)` appends one record of `type="condensation"` to the log. The log is never rewritten in place. |
| `View` (`openhands/memory/view.py` 13–93) derives the model-visible history from the complete log: drop forgotten events, drop the condensation meta-events, insert an `AgentCondensationObservation` at `summary_offset`. | `derive_view(log)` / `replay(log)`. The observation type here is `CondensationObservation` (`observation_type="agent_condensation_observation"`). |
| `BrowserOutputCondenser` keeps only the most recent 2 browser observations, `attention_window=2`. | `throttle_by_source(log, source, keep_last=ATTENTION_WINDOW)` with `ATTENTION_WINDOW = 2`. |
| `LLMSummarizingCondenser(keep_first=4, max_size=120)` summarises the middle events when over the limit. | `KEEP_FIRST = 4` and `MAX_SIZE = 120` are pinned constants. `keep_first` is the head that the middle summary never swallows. `max_size` is pinned as the source's window size; this slice does not implement a token-budget window (`MAX_SIZE` is asserted in the tests to keep the number honest, and is an open item below). |
| `ContextWindowExceededError` (`agent_controller.py` 845–873) can trigger condensation reactively. | `condense_on_limit(log, is_exceeded=...)`: condense the middle, then **retry once**. |
| Official self-report: cost per turn below half; SWE-bench subset 54% vs a 53% baseline. | Recorded here as a **self-report**, not a measurement, and not used as a claim about Northstar. |

### 2.2 Northstar extension (NOT source text)

| Extension | Where | Why it is an extension |
| --- | --- | --- |
| `condense_by_importance(log, scorer, keep=...)` — condense the *lowest-scored* events. | `event_condenser.py` | **OpenHands does not score events by importance.** It condenses **by position** (keep the first 4 + keep the most recent window). The scoring interface is opt-in, the scorer is the caller's, and the default paths (`condense_on_limit`, `throttle_by_source`) stay strictly positional. |
| The log record shape (`{"id", "type", "source", "payload"}`) and the id space shared with condensation records. | `event_condenser.py` | The source quote names the *action*, not Northstar's storage format. |
| Fail-closed rules: duplicate forgetting is refused, an out-of-range offset raises, a retry that still exceeds raises. | `event_condenser.py` | The source quote does not state these; they are Northstar's fail-closed house rules, written down below. |
| `audit_condensations(log)` — list every condensation's forgotten set and summary. | `event_condenser.py` | The source's `CondensationAction` carries the same information; the list function is Northstar's audit shape. |
| `KEEP_RECENT = 2` — how many trailing events the reactive path keeps verbatim. | `event_condenser.py` | The source quotes `keep_first=4` and `max_size=120`; the size of the *trailing* window in this slice is a Northstar choice and is labelled as such in the module docstring. |

### 2.3 Explicitly not implemented

* A token-budget window driven by `max_size=120`.
* A provider-written summary. The default summariser is deterministic and
  provider-free (`_extractive_summary`), following `compaction.py`'s existing
  house rule that condensation must not cost budget and must be reproducible.
  A host may pass its own `summarizer` callable.

---

## 3. The rules, written down

These are the rules the tests pin. Anything not here is not guaranteed.

### R1 — Appending is recording

`append_condensation` appends **one** record to the log. Every earlier record
is left byte-for-byte unchanged. The pre-condensation log stays in the log,
so the events a condensation removed are still auditable and the full
history can be replayed.

### R2 — Forgetting is idempotent-**refusing**

Naming an event id that an earlier condensation already forgot raises
`DuplicateCondensationError` and the log is left unchanged. (A silent no-op
would hide a caller bug that believes it removed something twice.)

Forgetting an id that is not in the log raises `InvalidCondensationError`.

### R3 — The view is derived, never stored

`derive_view(log)` replays the log in order:

1. an ordinary event whose id was forgotten by some condensation is skipped;
2. a condensation record inserts a `CondensationObservation` at its
   `summary_offset`;
3. everything else is copied through in log order.

The condensation meta-events are never in the view.

### R4 — Offsets fail closed

A `summary_offset` outside `[0, len(view)]` raises `ViewDerivationError`.
The view is never clamped, truncated or padded to fit a bad offset: a bad
offset means the log and the condensation disagree, and a caller that cannot
see the disagreement would act on a wrong view.

A **negative** offset is refused at *derivation* time, not at append time:
the log records what the caller asked for, and the refusal happens where a
wrong view would otherwise be handed out.

### R5 — Throttling is per source and is also an event

`throttle_by_source(log, source, keep_last=2)` keeps only the most recent
`keep_last` events of that source. Events of other sources are untouched.
The throttled events are not deleted: a condensation record naming them is
appended, exactly like any other condensation. The throttle therefore works
on what is *still in the view* (already-forgotten events are excluded).

### R6 — The reactive path condenses the middle, then retries exactly once

`condense_on_limit(log, is_exceeded=...)`:

* no signal → nothing is appended, `None` is returned;
* signal → the middle between the head (`keep_first`, default 4) and the
  trailing window (`keep_recent`) is condensed, and `is_exceeded` is called
  **once more** on the derived view;
* the retry still exceeds → `ContextStillExceededError`. The condensation
  that was appended stays in the log (it is a fact) and the error names what
  was forgotten. **Data is never dropped silently.**
* the log is too short to have a middle → `ContextStillExceededError` too.

### R7 — The head is never swallowed

The first `keep_first = 4` events are never named in a middle-summary's
`forgotten` set. The head is kept verbatim.

### R8 — Every condensation is auditable

`audit_condensations(log)` returns, for every condensation in the log, the
forgotten id list, the summary text and the summary offset.

---

## 4. API

Module: `components/northstar-agent-runtime/event_condenser.py`
(`VERSION = "event-condenser.v1"`, `SCHEMA_PIN = "northstar.event_condenser/v1"`).

### Data types

```python
@dataclass(frozen=True)
class CondensationEvent:
    forgotten: tuple[int, ...]
    summary: str
    summary_offset: int

@dataclass(frozen=True)
class CondensationObservation:
    summary: str
    summary_offset: int
    forgotten: tuple[int, ...]
```

### Functions

| Function | Purpose |
| --- | --- |
| `new_log() -> list[dict]` | An empty log. |
| `append_event(log, event_id, source, payload) -> dict` | Append one ordinary event (`type="event"`). Duplicate ids are refused. |
| `append_condensation(log, forgotten, summary, offset) -> CondensationEvent` | **Append** a condensation record (`type="condensation"`). Never rewrites the log. Rules R2, R4. |
| `derive_view(log) -> list[Any]` | The model-visible view derived from the log. Rule R3. |
| `replay(log) -> list[Any]` | Same derivation, named for the audit path. |
| `audit_condensations(log) -> list[dict]` | Every condensation: forgotten set, summary, offset. Rule R8. |
| `throttle_by_source(log, source, keep_last=2) -> CondensationEvent \| None` | Per-source throttle. Rule R5. |
| `condense_on_limit(log, *, is_exceeded, keep_first=4, keep_recent=2, summarizer=None) -> CondensationEvent \| None` | Reactive condensation + one retry. Rule R6. |
| `condense_by_importance(log, scorer, *, keep, summary=None, summary_offset=None) -> CondensationEvent \| None` | **Northstar extension.** Opt-in importance scoring. |

### Errors

| Error | Raised when |
| --- | --- |
| `InvalidCondensationError` | Malformed arguments: empty `forgotten`, a non-int id, a non-str summary, a non-int offset, an id that is not in the log, a duplicate event id. |
| `DuplicateCondensationError` | An id was already forgotten by an earlier condensation (R2). |
| `ViewDerivationError` | `summary_offset` outside `[0, len(view)]` (R4). |
| `ContextStillExceededError` | The reactive retry still exceeds the limit, or the log is too short to condense (R6). |

All four derive from `EventCondenserError`.

### Log record shapes

```python
# ordinary event
{"id": 0, "type": "event", "source": "browser", "payload": ...}
# condensation (a meta-event; not in the view)
{"id": 5, "type": "condensation", "forgotten": [1, 3],
 "summary": "...", "summary_offset": 2}
```

The condensation record takes the next free id in the same namespace as the
event ids, so the log is a single ordered id space.

---

## 5. How this relates to the existing compaction path

This slice is **additive**: it adds a new module and changes no existing
module. `compaction.py` still rewrites transcripts in place and still records
nothing in a log.

The two paths are complementary and the boundary is deliberate:

* `compaction.py` owns **where it is safe to cut** (tool-call pairing, atomic
  spans, orphan rules). A condensation of a run of events must not leave a
  dangling `tool_use`/`tool_result` pair either.
* `event_condenser.py` owns **the record and the derivation**: that the
  compression happened, what it dropped, and how the model-visible view is
  reconstructed from the log.

Open item: the eventual wiring should reuse `compaction.py`'s
`group_messages` / `is_safe_cut` when choosing the span to condense, so the
event-condenser path cannot produce a view that the Messages API would
reject. That wiring is not in this slice.

---

## 6. Open items

1. **`max_size=120` is pinned but not implemented as a window.** The source's
   `LLMSummarizingCondenser` summarises the middle when the event count
   exceeds `max_size`. This slice implements the *shape* (middle condensed,
   head kept) but not a `max_size`-driven trigger. The number is pinned in
   the module and asserted in the tests so it cannot drift silently.
2. **A provider-written summary** is supported via the `summarizer` callable
   but the default is extractive and deterministic.
3. **Wiring to the live transcript path** (see §5): safe-cut reuse, and
   emitting the condensation record into the same log the run's audit trail
   uses.
4. **`max_size` semantics**: the source quote does not say whether it counts
   events, messages or tokens. The taskbook quotes it as-is; this slice does
   not guess.
5. **Cost claims**: "cost per turn below half" is the source's official
   self-report and the "54% vs 53%" SWE-bench numbers are the source's
   numbers. Neither is a measurement of Northstar, and neither is used as
   one anywhere in this slice.
