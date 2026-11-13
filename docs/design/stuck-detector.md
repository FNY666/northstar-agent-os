# Stuck detector — design

A repetition-pattern detector for Northstar long-horizon runs.  It reads a
Northstar session event stream, recognises five patterns of getting stuck, and
returns a structured verdict.  It does **not** stop the run; the caller
decides.

Module: `components/northstar-agent-runtime/stuck_detector.py`
Tests: `components/northstar-agent-runtime/tests/test_stuck_detector.py`

## Why

A long-horizon Northstar run can loop forever: the same tool call, the same
failure, the same monologue, the same ping-pong between two tools.  Nothing in
the runtime stops it — the run ends when the budget or the context window is
exhausted.  The operations watchdog (`b173-watchdog.py`) watches the *session*
(compaction, no file changes, no commit); it cannot see a repetition pattern
*inside* a turn.  This module is the in-repo detector for that inner loop.

## Source of the thresholds

Everything below marked **OpenHands** comes from the OpenHands SDK guide
"Stuck Detector", <https://docs.openhands.dev/sdk/guides/agent-stuck-detector>,
read on 2026-11-14 (page last updated 2026-06-24).  The OpenHands V1 core has
moved to the `software-agent-sdk` repository; the guide is that SDK's official
documentation.

Everything marked **Northstar extension** is this implementation's own choice
and is *not* claimed to be OpenHands behaviour.

### The five patterns (OpenHands)

| # | Pattern | Threshold | Verbatim from the document |
|---|---------|-----------|---------------------------|
| 1 | `repeat_action_observation` | 4+ | "The same action produces the same observation repeatedly (4+ times)" |
| 2 | `repeat_action_error` | 3+ | "The same action repeatedly results in errors (3+ times)" |
| 3 | `monologue` | 3+ | "The agent sends multiple consecutive messages without user input or meaningful progress (3+ messages)" |
| 4 | `alternating` | 6+ cycles | "Two different action-observation pairs alternate in a ping-pong pattern (6+ cycles)" |
| 5 | `context_window_errors` | — | "Repeated context window errors that indicate memory management issues" (the document gives no number) |

The document also states that stuck detection "is enabled by default
(`stuck_detection=True`)" and that the status is queried with
`conversation.stuck_detector.is_stuck()`.

### Semantic comparison (OpenHands)

The document says the detector "compares events based on their semantic content
rather than object identity", and lists the keys:

* **Actions** — "compared by their tool name, action content, and thought (ignoring IDs and metrics)"
* **Observations** — "compared by their observation content and tool name"
* **Errors** — "compared by their error messages"
* **Messages** — "compared by their content and source"

This is what lets it find "truly repetitive behavior while ignoring superficial
differences like timestamps or event IDs".

### Scope (OpenHands)

The detector examines "the event history after the last user message".  A user
turn therefore resets the detection window.

### Halt (OpenHands, and where Northstar differs)

OpenHands: "the stuck detector monitors the conversation in real-time" and "can
automatically halt execution when stuck patterns are detected, preventing
infinite loops and wasted resources".

**Northstar extension:** this module never halts.  `StuckVerdict` is a
*report* — pattern name, evidence, evidence pointer — and the caller decides
whether to stop, warn, or ignore.  Stopping a run is a side effect that
belongs to whoever owns the run, not to a detector.

## Northstar extensions, one by one

1. **The input is Northstar's session event stream.**  OpenHands feeds its own
   `Event` objects to the detector.  Northstar has no such objects: the
   durable history is the JSONL transcript written by `sessions.py`
   (`SessionStore.append`), whose records are `assistant` (carrying `tool_use`
   and `text` blocks), `tool_result` (carrying the results), `user_prompt`,
   `denial`, and the rest of `RECORD_TYPES`.  The detector reads those records.
   See `sessions.py:374` (`SessionStore.append`) and
   `sessions.py:500` / `sessions.py:513` (the assistant and user record
   writers).

2. **The context-window-error threshold is 3.**  The OpenHands document names
   the pattern and gives no number.  3 is Northstar's choice, matching the
   3+ shape of the other "repeated" pattern (`repeat_action_error`).

3. **"6+ cycles" means 6 *complete* cycles.**  The OpenHands document says
   "6+ cycles" without defining a cycle.  Northstar reads one cycle as A+B —
   two steps — so 6 cycles is 12 steps (A-B-A-B-A-B-A-B-A-B-A-B).  11 steps is
   5 cycles and a half, and does not trip the detector.

4. **"Meaningful progress" is defined operationally.**  The OpenHands document
   names "meaningful progress" in the monologue pattern without defining it.
   Northstar reads it as: a *successful* tool result, or a file change, is
   progress; a failed tool call is not.  Progress resets a monologue run.

5. **The message source matters for the monologue count.**  The OpenHands
   message key is (content, source).  Northstar therefore counts the monologue
   run *per source*: two agents talking in turn are not one agent
   monologuing.

## Normalisation rules

Every event becomes one or more *comparison keys*.  A key is a tuple of
strings, so equality is the comparison.

| Event | Key | Built from |
|-------|-----|-----------|
| action | `(tool name, action content, thought)` | the `tool_use` block: `name`, `input` canonicalised to JSON with the volatile keys removed, and the thinking block's text |
| observation | `(observation content, tool name)` | the `tool_result` block's content flattened to text, and the tool name (taken from the paired action, because the transcript's `tool_result` block carries only the call id) |
| error | `(error message,)` | the error text of a failed `tool_result`, or a `denial` record's reason |
| message | `(content, source)` | the text blocks of an assistant record and the record's `agent` |

**Volatile keys** removed from a tool input before it is canonicalised:
`id`, `call_id`, `tool_call_id`, `tool_use_id`, `uuid`, `request_id`,
`metrics`, `usage`, `cost_usd`, `session_id`, `turn_index`, `index`,
`timestamp`, `ts`, `time`, `started_at`, `finished_at`, `duration_ms`,
`latency_ms`, `elapsed_ms`, `duration_s`.  This is the OpenHands "ignoring IDs
and metrics" rule, widened to the identity and timing fields a Northstar
transcript adds.

**Fail-closed.**  An event that cannot be normalised produces *no event at
all*: a `tool_use` block with no tool name, a `tool_result` block with no
content, a record that is not a dict.  Such an event does not participate in
any comparison, and — importantly — it is not silently counted as "not a
repeat" either.  It simply is not there.

## The five detectors

1. **`repeat_action_observation`** — the longest run of *consecutive* pairs
   with the same action key and the same observation key is at least 4.  Only
   successful observations count here: a repeated failure is the other
   pattern, and counting it twice would let one failure run masquerade as an
   observation loop.

2. **`repeat_action_error`** — the same action key produces at least 3 errors.
   The count is per action key; a success of the same action resets it.

3. **`monologue`** — at least 3 consecutive messages from one source, with no
   user input and no progress in between.

4. **`alternating`** — two *different* action-observation pairs alternate for
   at least 6 complete cycles.

5. **`context_window_errors`** — at least 3 errors whose message carries a
   context-window signal.  The signals are Northstar's:
   `context window`, `context_window`, `contextwindow`, `context length`,
   `context_length`, `maximum context`, `max context`, `context limit`,
   `context_limit`, `context overflow`, `too many tokens`, `prompt is too
   long`, `input is too long`, `exceeds the context`, `token limit`,
   `input length exceeds`.

The detectors run in the order the OpenHands document lists the patterns; the
first that trips is the verdict.  (So three context-window errors *from the
same action* are reported as `repeat_action_error` — the more specific
pattern — while three from different actions are reported as
`context_window_errors`.)

## The verdict

```python
@dataclass(frozen=True)
class StuckVerdict:
    is_stuck: bool = False
    pattern: str = ""
    summary: str = ""
    evidence: tuple[dict[str, Any], ...] = ()
    evidence_pointer: EvidencePointer | None = None
```

`evidence` holds the repeated keys themselves (the action key, the
observation key, the error key or the message keys).  `evidence_pointer` holds
the event index range of the repetition and how many events it spans:

```python
@dataclass(frozen=True)
class EvidencePointer:
    first_index: int = -1
    last_index: int = -1
    count: int = 0
```

`is_stuck()` is a **pure query**: it reads the history it is given, holds no
counters a call advances, writes nothing, and never halts.  Two calls over the
same history return the same verdict.

## Configuration

Every threshold is in one frozen record, `StuckThresholds`:

```python
@dataclass(frozen=True)
class StuckThresholds:
    repeat_action_observation: int = 4
    repeat_action_error: int = 3
    monologue: int = 3
    alternating_cycles: int = 6
    context_window_errors: int = 3
```

`DEFAULT_THRESHOLDS` holds the defaults.  A caller that wants a different
sensitivity passes its own record to `StuckDetector(thresholds=...)` or to
`detect(records, thresholds)`.

## Usage

```python
from stuck_detector import StuckDetector

detector = StuckDetector()
verdict = detector.is_stuck(records)
if verdict.is_stuck:
    # The caller decides.  The detector does not stop the run.
    halt_or_warn(verdict.pattern, verdict.evidence_pointer)
```

## Boundaries

* The detector reads a **history**, not a live stream.  OpenHands monitors in
  real time; Northstar's equivalent is a caller that re-reads the transcript
  and re-queries the detector, or a caller that holds the history in memory.
* The detector **does not** write to the transcript, does not kill a session,
  and does not touch `sessions.py`.
* A compaction boundary truncates the transcript the caller holds; the
  detector has no view of the events that were compacted away, and does not
  try to reconstruct them.
