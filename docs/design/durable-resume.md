# Durable checkpoints, retry-clears-writes, and an explicit resume

What this document is: the shape Northstar gives to four mechanisms it read
out of LangGraph, and the rules those mechanisms obey here.

What it is not: a port of LangGraph. LangGraph is a graph/state-machine agent
framework; Northstar is a run-loop runtime with a sealed ledger. The mapping
below is a mapping of *shapes*, not of code.

All LangGraph line numbers and quotes are from the depth-1 clone of
`langchain-ai/langgraph` (`main` @ `3183e90eca59850a607d8a4c1b24fa8c5c8a2b69`,
2026-11-12), read on 2026-11-13.

---

## 1. The gap this closes

Before this slice, Northstar had:

| Concern | Where it lived | What was missing |
|---|---|---|
| run state | `checkpoints.Checkpoint` (turn boundary: transcript length, digest, counters) | no place for a *pending* write |
| resume | `sessions.SessionStore.resume_transcript` + `shutdown_unwind.unwind` | a re-sent prompt, not a command |
| retry | `retry_contract.RetryContract` (one outbound call) | no "clear the writes first" rule |

Three facts about the runtime as it stood, read out of the code:

1. **State lived in the transcript.** A checkpoint was a record *in* the
   append-only session file. A step's in-flight side effect had nowhere to
   live, because a transcript records what happened, and an effect that has
   not happened is not a fact.
2. **Nobody cleared pending writes on a retry.** `retry_contract` governs one
   outbound call: it decides whether the call may be repeated and refuses when
   it may not (`Operation.replay_safe`). But there was no notion of a *step*
   whose body declares writes and is then retried — the writes of the first
   attempt had no record at all, so "the effect happened once" was a hope.
3. **Resume was a re-sent prompt.** `resume_transcript` rebuilds the transcript
   and the unwind pass synthesises an `interrupted` result for every
   `tool_use` that never got one. That is right about the *turn*; it is not a
   command. Nothing could say "resume *this* step with *this* value", and
   nothing could distinguish a resume from a restart.

---

## 2. The checkpoint record

`durable_resume.DurableCheckpoint` holds the **committed** state of a run at a
boundary. The writes a step declared are **not** in it: they hang off the
checkpoint as their own ordered records.

```
DurableCheckpoint
  run_id            the primary key — required
  checkpoint_id     ck-000001
  seq               1-based, monotonic
  state             the committed state (hashable, digest-pinned)
  state_digest      sha256 of the canonical state
  parent_checkpoint_id
  interrupted_task  the task that was interrupted here, if any
  interrupt_value   what it asked for
  interrupt_answers resume answers already given, by interrupt id
```

`DurableStore` is the log. Four record kinds, all appends:

| kind | meaning |
|---|---|
| `checkpoint` | the committed state at a boundary |
| `pending_writes` | writes a step declared, under a checkpoint, in order |
| `cleared_writes` | writes that were dropped (reason recorded) |
| `committed_writes` | writes that were applied |

The log is never rewritten. "The write was dropped" and "the write never
happened" are therefore distinguishable after the fact — which is the whole
point of an append-only record.

### The run id is mandatory

`DurableStore.put_checkpoint` raises `MissingRunIdError` without one. This is
LangGraph's rule, quoted:

> The `thread_id` is the primary key used to store and retrieve checkpoints.
> Without it, the checkpointer cannot save state, resume from interrupts, or
> enable time-travel debugging.
> — `libs/checkpoint/langgraph/checkpoint/base/__init__.py`, `BaseCheckpointSaver`

Northstar's `checkpoints.Checkpoint` has an *optional* `run_id`, because a
turn-boundary checkpoint in a transcript file is found by its record index. The
durable layer is different: a durable checkpoint is found by its run, and the
run id is what makes it findable. So the durable layer fails closed where the
transcript layer can afford not to.

### Writes are ordered

`PendingWrite.sort_key` is `(task_path, task_id, idx)` — LangGraph's
`writes_sort_key`:

> Live execution applies a super-step's tasks in this order, so a saver that
> replays stored writes … must sort them by it too, or an order-sensitive
> reducer rebuilds a different value than the run produced.
> — `libs/checkpoint/langgraph/checkpoint/base/__init__.py`

---

## 3. The retry rule: clear the writes, then try again

`DurableRunner.run` wraps a step. The rule, in LangGraph's own words:

```python
try:
    # clear any writes from previous attempts
    task.writes.clear()
    # run the task
    return task.proc.invoke(task.input, config)
```
— `libs/langgraph/langgraph/pregel/_retry.py`, `run_with_retry`

Northstar's version keeps the ordering and adds the accounting:

1. the step runs;
2. if it fails, its **pending writes are cleared first** (`DurableStore.clear_writes`
   appends a `cleared_writes` record);
3. only then is the failure classified;
4. if it is retryable, the policy waits and the step runs again.

Because the applier is only ever called from `DurableStore.commit_writes`, and
a cleared write is never committed, **the effect is applied once**. The test
proves it with a counter, not with a claim: `test_a_retry_clears_the_pending_writes_so_the_effect_lands_once`
collects the applied effect keys into a list and asserts `["tool:only-once"]`
after a step that declared it twice.

`commit_writes` also refuses to apply a write whose `effect_key` was already
committed, so a re-entry into an existing checkpoint cannot double-apply
either.

### The policy

`durable_resume.RetryPolicy` carries LangGraph's five fields with the same
meanings (`libs/langgraph/langgraph/types.py`, `RetryPolicy`, line 428):

| field | default | meaning |
|---|---|---|
| `initial_interval` | 0.5 | seconds before the first retry |
| `backoff_factor` | 2.0 | multiplier per retry |
| `max_interval` | 128.0 | ceiling on the wait |
| `max_attempts` | 3 | total attempts **including** the first |
| `jitter` | True | randomize the wait |

`max_attempts` counts the first attempt. Northstar's `run` raises
`RetryExhaustedError` when the budget is spent — it never returns the last
failure as if it were a result, because a silent pass is the failure mode
that matters.

### The `retry_on` predicate

`retry_on` is a **callable predicate** — `Callable[[BaseException], bool]` —
exactly as LangGraph allows (`type[Exception] | Sequence[type[Exception]] |
Callable[[Exception], bool]`). Northstar uses the callable form because "is
this failure transient" is a question about the failure, not about its type.

`default_retry_on` decides:

| failure | retried? | why |
|---|---|---|
| 429 (throttle), 503 | **yes** | the peer's load, not our mistake |
| 5xx (500, 502, 504, 507, 508) | **yes** | the server failed |
| `ConnectionRefusedError`, DNS, connect timeout | **yes** | no request byte reached the peer |
| 401 / 403 / 407 | **no** | a retry cannot fix a credential |
| other 4xx | **no** | the request is wrong; repeating it is rude |
| post-write drop (`ECONNRESET`, `EPIPE`) | **no** | the peer may already have executed it |

**Alignment with `retry_contract`.** The post-write rule is `retry_contract`'s,
not invented here: `retry_contract.classify_exception` returns
`FailureClass.NON_RETRYABLE` with `phase=POST_WRITE` and
`may_have_executed=True` for `ConnectionResetError`/`BrokenPipeError` and the
`POST_WRITE_ERROR_CODES`, and `FailureClass.RETRYABLE` for the
pre-write connection errors. `default_retry_on` delegates to
`classify_exception` rather than re-deriving the classification, so the two
modules cannot drift.

**Where they deliberately differ.** `retry_contract` is about *one outbound
call*, and it adds two gates LangGraph has no concept of: the call must be
replay-safe (`Operation.replay_safe` — idempotent method or an idempotency
key, never a streamed body), and the retry must be the same operation
(same idempotency key, same payload digest). `durable_resume`'s predicate
answers only the *transience* question, because the replay-safety question
here is answered differently: a step's effect is protected by the
clear-then-commit rule, not by an idempotency key. Both modules' rules are
kept; they answer different questions.

**The one deliberate hardening.** `retry_contract.classify_response` treats a
404/410 as "confirmed absent" (`NON_RETRYABLE`) and a 429/502/503/504 as
retryable when no `Should-Retry` header is present. `default_retry_on` treats
*all* 5xx as retryable and all other 4xx as not — a slightly wider net on the
server-error side, because a step that is retried after a clear cannot
double-apply. This is a documented divergence, not an accident.

**Unclassifiable failures are not retried.** `default_retry_on` returns
`False` for anything it cannot place. "We could not tell" is not "transient",
and treating it as transient turns every bug into a request storm against the
thing that is already failing. (LangGraph's own `default_retry_on` returns
`True` as its final fallback; Northstar does not, and the difference is
deliberate and stated here.)

---

## 4. Interrupt and resume

### Interrupt

`DurableRunner.interrupt(value)` raises `GraphInterrupt` on the first call in
a step, after recording the interrupt against the current checkpoint. Without
a store it raises `InterruptRequiresCheckpointError` — an interrupt with
nothing to resume from is a pause nobody can leave.

This is LangGraph's rule:

> To use an `interrupt`, you must enable a checkpointer, as the feature relies
> on persisting the graph state.
> — `libs/langgraph/langgraph/types.py`, `interrupt()` (line 913)

### Resume is a command

`DurableRunner.resume(command, …)` takes a `Command`. Anything else raises
`ResumeRequiresCommandError`. **Re-sending the prompt is refused**, and that
is the point of the whole slice: the prompt is what the run already had; the
command is what the operator has.

```python
@dataclass(frozen=True)
class Command:
    resume: Any = None
    graph: str | None = None
    update: Mapping[str, Any] | None = None
```
— mirroring `langgraph.types.Command` (line 843), which carries `graph`,
`update`, `resume`, `goto`.

### The step restarts

> The graph resumes from the start of the node, **re-executing** all logic.
> — `libs/langgraph/langgraph/types.py`, `interrupt()` docstring

Northstar does the same, and says so out loud: `resume()` calls `run()`, which
calls the step body from its first line. The test
`test_a_resume_re_enters_the_step_from_its_start` counts the "before" marker
and asserts it ran **twice**.

What differs is what the re-run may commit. Before re-entering, the runner
clears the checkpoint's pending writes:

```python
self.store.clear_writes(checkpoint.checkpoint_id, reason="the step was resumed")
```

so the interrupted attempt's declarations are dropped and the re-run's
declarations are the only ones that can commit. The state that was already
committed stays committed — a resume replays committed state and drops
uncommitted writes, never the other way round.

### Resume values match by interrupt, in order

> If a node contains multiple `interrupt` calls, LangGraph matches resume
> values to interrupts based on their order in the node. This list of resume
> values is scoped to the specific task executing the node and is not shared
> across tasks.
> — `libs/langgraph/langgraph/types.py`, `interrupt()` docstring

Northstar's `_match_answer`:

| the command carries | it answers |
|---|---|
| a mapping `{interrupt_id: value}` | the interrupt with that id |
| a sequence `[v0, v1, …]` | the *n*-th interrupt, in order |
| a single value | the task's next unanswered interrupt |

A mapping key that does not belong to the task raises
`ResumeValueMismatchError`. The scope is per-task: `interrupt_id` is
`"{task_id}#{index}"`, so a value minted for one task cannot answer another's
interrupt.

---

## 5. The seams

### `sessions.py` — the unwind verdict

`SessionStore.unwound_calls()` is a new, small method: it returns the calls
the shutdown unwind pass says never ran.

```python
def unwound_calls(self, session_id=None) -> tuple[tuple[str, str], ...]:
    from shutdown_unwind import pending_tool_uses
    transcript = self.transcript(session_id)
    return pending_tool_uses(transcript)
```

It delegates to `shutdown_unwind.pending_tool_uses` rather than re-deriving
"which calls never ran" — the unwind pass is the runtime's own verdict on that
question, and a second implementation of it would eventually disagree with the
first.

`durable_resume.drop_unwound_writes(store, checkpoint_id, transcript)` maps
that verdict onto the durable layer: a write whose `effect_key` belongs to an
interrupted call is dropped, and never replayed as a success.

The unwound result is *never* a success anywhere in the runtime — that is
`shutdown_unwind`'s own rule ("A synthetic result never counts as success"),
and this layer sits on top of it rather than beside it.

### `checkpoints.py` — the join

`checkpoints.durable_state(checkpoint, extra=…)` returns the committed part of
a turn boundary: the counters, the transcript digest, and whatever the caller
adds. The pending writes are **not** in it — a write that has not landed
cannot travel inside the state as if it had.

### `long_horizon.py` — only verified progress

`LongHorizonLoop` takes an optional `durable_store`. On the auditor's **pass**
path only, `_write_durable_checkpoint` writes a durable checkpoint whose state
is built by `durable_resume.checkpoint_from_verified`.

That function takes the verified progress and has **no parameter for the
executor's summary** — the same structural argument `long_horizon`'s Manager
rebuild makes. An executor's self-report cannot reach a durable checkpoint
even by accident, because there is nowhere to put it.

The write happens on the pass path, next to `_write_session_checkpoint`, so
the two checkpoint layers agree about *when* a checkpoint exists.

### The forward seal ledger

The durable store is **not** sealed by `forward_seal_ledger`. The ledger seals
the *action* record — the eight-field event with its triple fingerprints — and
this layer writes run state and write intents, which are not actions. The
seam that exists is the digest: `DurableCheckpoint.state_digest` is a
`sha256:` pin in the same shape the ledger's fingerprints use, so a durable
checkpoint can be *about* a sealed event without being part of the chain.

This is a deliberate non-connection, and it is listed as an open item below.

---

## 6. The mapping, in one table

| LangGraph | Northstar | file:line (LangGraph) |
|---|---|---|
| `BaseCheckpointSaver` | `DurableStore` | `libs/checkpoint/langgraph/checkpoint/base/__init__.py:199` |
| `put()` | `DurableStore.put_checkpoint` | same |
| `put_writes()` | `DurableStore.put_writes` | same |
| `get_tuple()` | `DurableStore.get_checkpoint` / `latest_checkpoint` | same |
| `list()` | `DurableStore.list_checkpoints` | same |
| `delete_thread()` | `DurableStore.delete_thread` | same |
| `PendingWrite` = `tuple[str, str, Any]` | `PendingWrite` (dataclass) | base/`__init__.py:32` |
| `writes_sort_key` = `(task_path, task_id, idx)` | `PendingWrite.sort_key` | base/`__init__.py:182` |
| `thread_id` required | `run_id` required (`MissingRunIdError`) | base/`__init__.py:215` |
| `RetryPolicy` | `RetryPolicy` | `libs/langgraph/langgraph/types.py:428` |
| `default_retry_on` | `default_retry_on` (narrower fallback) | `libs/langgraph/langgraph/_internal/_retry.py:1` |
| `run_with_retry` / `task.writes.clear()` | `DurableRunner.run` / `DurableStore.clear_writes` | `libs/langgraph/langgraph/pregel/_retry.py:593` |
| `node_attempt` (1-indexed) | `Attempt.index` (1-indexed) | `pregel/_retry.py:640` |
| `interrupt()` | `DurableRunner.interrupt` / `GraphInterrupt` | `libs/langgraph/langgraph/types.py:913` |
| `Command(resume=…)` | `durable_resume.Command` | `libs/langgraph/langgraph/types.py:843` |
| resume values matched by order, scoped per task | `_match_answer` | `types.py:930` (docstring) |
| resume re-executes the node | resume re-enters the step from its start | `types.py:926` (docstring) |
