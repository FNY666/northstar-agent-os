# Turn truncation — the recorded turn is the delivered prefix

## The gap

Northstar has two kinds of shortening, and they answer different questions:

* `components/northstar-agent-runtime/output_limits.py` truncates because a
  piece of output is **too long**. `OutputLimiter.truncate()` cuts the tail
  to satisfy `max_chars` / `max_lines`. The text that survives was still
  generated; it is dropped for size, not because it was never said.
* The shutdown unwind pass (`shutdown_unwind.py`, reached through
  `sessions.py:SessionStore.resume_transcript`) synthesises an `interrupted`
  result for a `tool_use` that never got one. A **call** was cut short.

Neither asks whether the words the model produced actually reached the user.
When a run is interrupted half-way through an assistant turn, the transcript
records the *complete generated text* — so a later resume, a compaction, or the
next turn reads words the user never heard as if they had been said. The model
then refers back to them: to an answer that was never delivered.

## The source

OpenAI Agents SDK, Realtime guide, **"Interruptions and playback tracking"**
section (read 2026-11-14):
<https://openai.github.io/openai-agents-python/realtime/guide/>

Verbatim, the two load-bearing paragraphs:

> "When the user interrupts the assistant, the session emits audio_interrupted
> and updates history so the server-side conversation stays aligned with what
> the user actually heard."

> "In low-latency local playback, the default playback tracker is often
> enough. In remote or delayed playback scenarios, especially telephony, use
> RealtimePlaybackTracker so the interrupted response is truncated at the
> actual playback position rather than assuming all generated audio has
> already been heard."

The second paragraph is the one Northstar imports: the fault is not that the
response was cut, it is that history keeps the *whole* response — "assuming
all generated audio has already been heard" is exactly the failure mode.

### The API-level mechanism

The Realtime API expresses the same idea as a `conversation.item.truncate`
event: the assistant audio item is truncated at `audio_end_ms`, and the
unplayed audio **and its transcript** are discarded.

> **Scope note.** The `conversation.item.truncate` semantics and the
> byte-level worked example below were read via the aicassindra deep article
> (<https://www.aicassindra.com/blogs/gpu/gpu_openai_realtime.html>), not from
> a Northstar code path. They are the source's barge-in example, quoted here
> because it fixes *which* number counts — the delivery position — and the
> Northstar module inherits only that idea.

The worked example spells out the barge-in case:

* the assistant starts a 6-second answer;
* the speaker had written **77,760 bytes** of 24 kHz 16-bit mono PCM to the
  output device — at 48,000 bytes per second that is **1.62 seconds**;
* when `speech_started` arrives, the client sends `audio_end_ms=1620`;
* the count that matters is the bytes that **left the output device**, not the
  bytes that were received — a 200 ms jitter buffer would otherwise make the
  model believe the user heard 0.2 s more than they did.

The failure mode the article names: the server generates audio faster than it
is played, so when the user interrupts, the conversation history already
contains the full assistant answer while the user heard only part of it. Do
nothing and "the model believes it said things the user never heard, and
refers back to them."

> **Scope note.** The 48,000 bytes/second figure and the 77,760-byte count
> are a speech example. They are **not** moved into the Northstar module
> (see "Northstar extensions" below).

## Northstar extensions (explicitly *not* from the source)

1. **Delivery position generalised.** The source's position is a *playback
   position* in audio. Northstar's is a **delivery position**
   `delivered_len`, measured in content units and **reported by the caller**
   (the delivery layer). The module performs no audio arithmetic and estimates
   no playback progress: the caller says what was delivered, and the module
   truncates to that (after validating the range). The worked example's
   1.62 s / 77,760 bytes / 48,000 B·s⁻¹ numbers stay in this document.
2. **Three states instead of two.** `DELIVERED` (the whole turn reached the
   user), `PARTIAL` (a prefix reached the user, the rest did not) and
   `UNKNOWN` (**no delivery report exists at all**). The source's default
   assumption — that generated audio has already been heard — is exactly what
   must not be assumed: with no report the state stays `UNKNOWN` and the
   history says so explicitly.
3. **Summary pin.** Every truncation record carries a digest pin of the item
   it truncated, so a record cannot be silently re-pointed at a different
   turn.

## The module

`components/northstar-agent-runtime/turn_truncation.py` — a pure, standard
-library-only bookkeeping module. It runs no loop, talks to no provider and
observes no live run. `sessions.py` and `output_limits.py` are **read-only**
reuse: this module decides what a resumed history may contain and never
writes the transcript itself.

### Records

* `TurnItem` (frozen): `item_id`, `role="assistant"`, `generated_text`,
  `generated_len`, `delivered_len` (`None` = no report), `status`.
  The constructor refuses a `status` that contradicts the report — an item
  with `delivered_len=None` cannot claim `DELIVERED`.
* `TruncationRecord` (frozen): `item_id`, `pin`, `delivered_len`,
  `truncated_len`, `seq`, `generated_len`.
* `HistoryEntry` (frozen): what a resumed turn may read — `text`, `status`,
  `delivered_len`, `truncated_len`, `marker`, and the `delivery_unknown`
  property.

### Operations

* `truncate(item, delivered_len, seq)` → `TruncationOutcome(item, record)`.
  Validates `0 <= delivered_len <= generated_len`; returns a `PARTIAL` item
  and a `TruncationRecord` when something was cut, or a `DELIVERED` item and
  **no record** when the whole turn was delivered.
* `delivered_prefix(item)` → the only text that may be treated as said: the
  whole text for `DELIVERED`, the delivered prefix for `PARTIAL`, the empty
  string for `UNKNOWN`.
* `history_for_resume(items)` → `list[HistoryEntry]`:
  * `PARTIAL` — the delivered prefix **plus** a truncation marker; the
    undelivered suffix is not in the entry at all.
  * `UNKNOWN` — no text, flagged `delivery_unknown` and a
    `[delivery-unknown: …]` marker: a reader must not assume the turn was
    delivered.
  * `DELIVERED` — the text as recorded.
* `verify_record(item, record)` → refuses a record whose summary pin does
  not match its item.
* `item_pin(item)`, `delivery_status(delivered_len, generated_len)`,
  `make_item(...)`, `stdlib_only()`.

### Fail-closed rules

| Situation | Behaviour |
|---|---|
| `delivered_len > generated_len` or `delivered_len < 0` | `DeliveryRangeError` |
| Re-extending an already truncated item (claiming the undelivered suffix was said) | `ReextendRefusedError` |
| Shortening an already truncated item to a smaller reported position | `DeliveryRangeError` |
| A record whose `pin` / `item_id` / lengths do not match the item | `PinMismatchError` |
| No delivery report | status stays `UNKNOWN`; never silently `DELIVERED` |

## The three driven paths

The module's tests drive the three paths end to end.

**(a) Interrupted mid-answer.** A 6-second answer whose speaker had written
77,760 bytes (1.62 s at 48,000 B·s⁻¹) is interrupted. The caller reports
the delivered position; the module truncates to the delivered prefix. The
record carries `delivered_len`, `truncated_len` and the item's summary pin.
`history_for_resume` returns the prefix plus a `[truncated: …]` marker; the
undelivered remainder is absent from the entry and from the marker, so the
model cannot refer back to what the user never heard.

**(b) Interrupted before anything was delivered.** `delivered_len=0`:
`delivered_prefix` is empty, the history entry's text is empty, and the only
thing left of that turn in the history is the truncation marker. No "said"
text survives.

**(c) No interruption.** `delivered_len == generated_len`: status `DELIVERED`,
**no** truncation record, and the history entry is the text as recorded.

## What is deliberately absent

* No audio arithmetic, no playback-progress estimation, no byte-rate
  constants in the module.
* No estimation of the delivery position: the module never guesses. It
  truncates to the number the caller reports, and refuses a number outside
  the range.
* No writing to the transcript: `sessions.py` is untouched.

## Tests

`components/northstar-agent-runtime/tests/test_turn_truncation.py` — 34 test
methods covering: truncation to the delivered prefix (prefix correct,
suffix unreachable), the record's pin / lengths / seq, zero delivery, full
delivery with no record, out-of-range refusal, re-extend refusal, shortened
re-truncation refusal, mismatched and tampered summary pins, a status that
contradicts the report, non-int / boolean delivery positions refused at both
the constructor and `truncate()`, the three delivery states,
`history_for_resume` per state (partial prefix + marker, unknown flagged,
delivered unchanged), the three driven paths, and the "no audio arithmetic
in the code" check.

The mutant probe (`b173-mutant.sh turn-truncation`) reports **3/3 killed**:
the `status`/`expected` comparison, the delivery-position type guard, and the
negative-bound check each break the suite when mutated.

