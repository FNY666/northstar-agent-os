# Session memory: a four-operation conversation-memory protocol

Status: implemented for B173 slice "session-memory". Northstar had
JSONL session transcripts (`sessions.py`) and auth session management
(`session_manager.py`), but no *conversation memory* protocol.

Module: `components/northstar-agent-runtime/session_memory.py`
Tests: `components/northstar-agent-runtime/tests/test_session_memory.py`

## Source of the mechanism

OpenAI Agents SDK, official sessions documentation
<https://openai.github.io/openai-agents-python/sessions/>, read in full
on 2026-11-14.

Throughout this document:

* **[OpenAI]** marks a rule transcribed from that source.
* **[Northstar]** marks an extension of this repo that is **not** OpenAI
  content.

## What the code said before this slice

Read from the code, not assumed:

* **`sessions.py`** is the *transcript* recorder: append-only JSONL
  writes with an HLC timestamp, a hash chain, and a fixed record-type
  vocabulary (`RECORD_TYPES`, lines 38-64): `session_start`,
  `user_prompt`, `assistant`, `tool_result`, `hook`, `denial`,
  `defensive_assessment`, `compact_boundary`, `informational`,
  `postconditions`, `checkpoint`, `subagent`, `result`, `session_end`,
  `cancellation`. It records *what happened*; it does not retrieve a
  conversation for the next run and it has no notion of a session item
  with a stable sequence number.
* **`session_manager.py`** holds *auth* tokens — login, logout, refresh.
  The word "session" there means an authenticated principal, not a
  conversation.
* **`session_lease.py`**, **`session_replay.py`** — lease and replay
  machinery for runs, again not a conversation-memory protocol.

A grep of the repository for `pop_item` and `get_items` returned no
implementation anywhere in the tree (only an unrelated research script
under `research/`): **no session protocol existed**.

## The four operations

**[OpenAI]** The session protocol is four operations: `get_items`,
`add_items`, `pop_item`, `clear_session`.

`SessionStore` in `session_memory.py` implements exactly these four,
over a pluggable `SessionBackend`:

| Operation | Semantics | Northstar notes |
|---|---|---|
| `get_items(limit=None)` | Returns the stored items in insertion order | Fail-closed digest verification, see below |
| `add_items(items)` | Appends a batch | Assigns a monotonic `seq` to every row |
| `pop_item()` | Removes and returns the most recent item | Refuses on an empty session instead of returning `None` |
| `clear_session()` | Removes every stored item | — |

Two Northstar decisions ride on top of the four operations:

* **A monotonic `seq`.** The store assigns the sequence number itself,
  on every `add_items` call. A caller cannot choose a `seq`, so a stale
  or reused `seq` can never make an old row look like a new one. This
  is what implements the source's promise that a merge callback cannot
  cause an old item to be re-saved.
* **`pop_item` refuses on an empty session.** It raises
  `SessionEmptyError` instead of answering `None`, because `None` would
  be indistinguishable from a stored item whose content is `None`. The
  popped item's `seq` is retired for good: a later item can never
  reuse it.

`SessionItem` is a frozen record with `role` (`user`, `assistant`,
`tool_call`, `tool_result`), `content` (any JSON-serializable value),
`seq` and `digest`. The role vocabulary mirrors the transcript record
vocabulary of `sessions.py` without importing it: `sessions.py` owns
the JSONL transcript, this module owns the conversation memory, and the
two subsystems share no state.

## The runner contract

**[OpenAI]** With session memory enabled, the runner retrieves the
session history before each run and prepends it to the input; after the
run it stores every item produced during that run (user input,
assistant responses, tool calls). The next run on the same session
therefore contains the full history.

The module implements this as two functions plus a convenience wrapper:

```python
model_input = begin_turn(session, new_input)          # retrieve + prepend
stored      = end_turn(session, new_items)            # store this turn only
result      = run_session(session, new_input, new_items=...)   # both, in order
```

`run_session` fixes the order: the history is retrieved **before** the
new items are booked, so the model input can never contain the current
turn's own output, and the current turn's items are booked exactly
once.

The only way an item is ever booked is a call to `end_turn` /
`run_session` with that item in `new_items`. The history is never
re-booked, because `begin_turn` does not write. A two-turn
conversation therefore ends with exactly four stored items, not six.

## The merge callback

**[OpenAI]** `RunConfig.session_input_callback` is a merge callback. It
receives the retrieved history (normalized to input-item form) and the
new input as two lists, and returns the final list of input items for
the model. The callback receives copies and may modify them safely.
The returned list controls the model input only: the SDK still persists
only the items belonging to the current turn, so reordering or
filtering old history never re-saves old items as new input.

`begin_turn(..., merge_callback=fn)` implements this. The callback is
called as `fn(list(history), list(new_input))` — the two lists are
fresh copies, so a callback that clears or mutates them cannot affect
the store.

The persistence guarantee is enforced structurally, not by convention:
the merge callback runs inside `begin_turn`, which performs no write
at all. Whatever the callback returns, the store is untouched. The
only writer is `end_turn`, and it books exactly the items it was
handed. Reordering or filtering old history therefore cannot re-book
anything — the old rows keep their original `seq`, and a booked row
always receives a fresh one.

A callback that returns `None` is refused (`SessionConfigError`): a
`None` return would silently drop the whole turn's input.

## The most-recent-N limit

**[OpenAI]** `SessionSettings(limit=N)` caps how much history is
retrieved before each run; `limit=None` retrieves everything and
`limit=N` retrieves only the most recent N items.
`RunConfig.session_settings` overrides the session default per run.

`SessionSettings(limit=N)` holds the setting. `limit=None` means "the
whole history"; `limit=N` takes the last N rows. A limit that is not a
non-negative integer is refused at construction (`SessionConfigError`).

The per-run override follows the source rule that a per-run
`session_settings` replaces the session default — but only when the
override's own limit is not `None`, so a default of `limit=2` is not
silently turned into "everything" by an override that simply did not
specify a limit.

## The exclusion rule

**[OpenAI]** In the same run a session may not be combined with the
run-level continuation options `conversation_id`, `previous_response_id`
or `auto_previous_response_id`. To continue server-side, use those
mechanisms instead of stacking them on a session.

**[Northstar]** The refusal is fail-closed. Passing a session together
with any of the three raises `SessionExclusionError` naming the
offending option. The module never silently picks one of the two
mechanisms, and it never picks a "winner" and continues. The refusal
happens before any storage, so a refused run stores nothing.

The check is applied in all three entry points (`begin_turn`,
`end_turn`, `run_session`), so a run cannot be half-executed.

## The correction path (`pop_item`)

**[OpenAI]** `pop_item` supports corrections: pop the assistant reply,
then pop the user question, then ask the corrected question.

`pop_item` removes and returns the most recent item. Two consecutive
pops undo a whole turn: the first pop takes the assistant reply, the
second takes the user question. The session is then empty of that turn,
and the next turn starts from the corrected question only. The popped
items do not come back: they are removed from the backend, their `seq`
values are retired, and the new turn receives fresh ones.

## Digest-pinned history (Northstar extension)

**[OpenAI]** The source's trust boundary: `SQLiteSession` assumes the
application trusts the database and the storage. The backend does not
authenticate stored rows, does not detect external edits, deletions,
reorderings or replays. `get_items` selects rows by session ID, orders
them by insertion ID and decodes each row's `message_data` as JSON;
**rows that fail to decode are skipped without an integrity error**.
The application must authorize access to each session itself and
restrict access to the database file.

**[Northstar]** The skip-undecodable-rows behavior is the weakness this
slice deliberately does not adopt. Every stored row carries a `sha256:`
digest pin over its exact stored bytes (its `seq`, its `role` and the
canonical JSON rendering of its `content`). `get_items` verifies every
pin and **refuses the whole call** with `SessionIntegrityError` when
any row fails to decode or any pin does not match. A caller is never
handed a silently shortened history: either it gets the whole history
it stored, or it gets an exception.

The pin also covers the *order*: each row's pin covers its own `seq`,
so a row that travels on its own stays internally consistent. The
strictly-increasing `seq` run is what pins the order, so an external
reordering of the rows is refused rather than returned.

**The extension's limit, stated so it is not overclaimed.** A digest
pin can only prove that a row the module can *see* is unchanged. It
cannot detect a row that was deleted outright: a deleted row leaves no
trace to verify against, and the remaining rows still verify. The
source's statement that a backend "does not detect external ... deletions"
therefore still holds for the Northstar implementation as well. What
Northstar closes is the *silent skip* — a row that is present but
tampered with, mis-ordered, or undecodable now stops the read instead
of being dropped from the history.

### Why the module-level `Session` type exists

`Session` bundles a session ID, a backend and the settings, and
`Session.store` builds the `SessionStore` over them. The ID is
validated against the same shape `sessions.SESSION_ID_PATTERN` uses
(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`), so one identifier never has two
spellings across the two subsystems.

## The trust boundary (Northstar extension)

**[OpenAI]** A session ID selects history but never authenticates or
authorizes; the application must authorize access to each session
itself.

**[Northstar]** The module enforces the *shape* of that boundary and
nothing more:

* There is **no identity parameter anywhere in the public API**.
  `begin_turn`, `end_turn` and `run_session` take no user, principal,
  token or auth argument, so there is no place for the module to appear
  to have authorized anything. Authorization is the caller's job,
  before the session ID is handed to this module.
* Two stores with the same ID are two separate histories. The ID
  selects; it never grants.
* The module performs no identity check and no access decision. It is a
  store, not a gate.

## What this slice does not implement

The source lists a family of built-in backends — `SQLiteSession`,
`AsyncSQLiteSession`, `RedisSession`, `SQLAlchemySession`,
`MongoDBSession`, `DaprSession`, `OpenAIConversationsSession`,
`OpenAIResponsesCompactionSession`, `AdvancedSQLiteSession`,
`EncryptedSession`. They are **background, not scope**. This slice
implements the protocol, the runner contract, the merge callback, the
limit, the exclusion rule and the digest pin; the storage backends it
ships are `MemorySessionBackend` and the pluggable `SessionBackend`
interface a durable backend would implement.

`EncryptedSession` is noted for one reason: the source states it
encrypts but **does not verify the completeness or the order** of the
history and does not refuse unencrypted entries. The Northstar digest
pin addresses the order and the tamper question; it is not encryption
and does not claim to be.

## Test coverage map

`components/northstar-agent-runtime/tests/test_session_memory.py`,
74 test methods:

| Rule | Test class |
|---|---|
| Four operations, insertion order, monotonic `seq`, empty-pop refusal | `FourOperationProtocolTests` |
| Runner contract: prepend, store-only-new, no re-store | `RunnerContractTests` |
| Merge callback: copies, input-only effect, no re-book on reorder/filter | `MergeCallbackTests` |
| Limit: `None`, `N`, `0`, invalid, per-run override | `LimitTests` |
| Exclusion: each of the three continuation options | `ExclusionTests` |
| Correction: two pops, no revival of popped items | `PopCorrectionTests` |
| Digest pin: mismatch, decode failure, missing pin, reorder | `DigestPinnedHistoryTests` |
| The three real paths end to end | `RealPathTests` |
| Trust boundary: the ID grants nothing | `TrustBoundaryTests` |
| Pluggable backend | `BackendInterfaceTests` |
