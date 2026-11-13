# Retry clears writes: discard pending writes before re-invoking a retried node

Status: implemented (`components/northstar-agent-runtime/retry_clears_writes.py`).
Version pin: `retry-clears-writes.v1`. Schema pin: `northstar.retry-clears-writes.v1`.

Source: LangGraph, `libs/langgraph/langgraph/pregel/_retry.py` and
`libs/langgraph/langgraph/types.py`, **main branch, read 2026-11-14**.
<https://github.com/langchain-ai/langgraph/blob/main/libs/langgraph/langgraph/pregel/_retry.py>

**Line-number note.** The line numbers quoted below are the ones verified by
re-reading the file from the URL above on 2026-11-14 (874 lines;
`md5 1d3b3f37e06f5cde49bac7a847e8391a`).  The task brief quoted the same
rules at lines 929 / 603 / 1107, which are the numbers of a *different*
revision of that file (the brief's numbers fall outside the 874-line file
read here).  The **rules** are identical -- the clearing is the first line of
the attempt's `try` block, the same clearing appears on the timeout path, and
`_should_retry_on` has the three shapes described -- but the numbers are
quoted here from the file that was actually read, so that every citation can
be checked against the source as fetched.

## 1. The problem this slice solves

Northstar's retry story answers three questions and not a fourth:

| layer | question it answers | where it lives |
| --- | --- | --- |
| budget | how many attempts, how long to wait | `retry_config.py`, `retry_contract.py` |
| trigger | does this failure become a retry | `retry_config.RetryGate`, `intent_bound_retry.py` |
| ledger | will this operation be applied twice | `idempotency_manager.py` |
| **clearing** | **what happens to the half-finished work of the failed attempt** | **this module** |

The missing fourth layer is the *effect* question. A node that writes state
and then fails leaves those writes behind. If the retry runs with the old
writes still in place, the effect is applied **twice**: once by the attempt
that failed, once by the attempt that succeeded. The idempotency ledger
cannot catch this, because the two applications are not two *calls* -- they
are one call and one half-finished write.

LangGraph closes the hole in one line.

## 2. The mechanism, as in the source

### 2.1 The clearing rule (verbatim behaviour)

`run_with_retry` in `libs/langgraph/langgraph/pregel/_retry.py` (main branch,
read 2026-11-14), sync path (the function starts at line 593; the clearing is
at line 635):

```python
while True:
    ...
    try:
        # clear any writes from previous attempts
        task.writes.clear()
        # run the task
        return task.proc.invoke(task.input, config)
```

Three facts about this line, all of which the implementation copies:

1. It is the **first line of the `try` block** -- the clearing happens *before*
   the node runs, not after it fails.
2. It is inside the retry loop, so it runs **before every attempt**, including
   the first. The first attempt's clearing is what makes a stale write from
   an earlier phase disappear.
3. The clearing is unconditional. It is not "clear on retry" -- it is "clear,
   then try".

The same rule appears twice more in the same file:

* the timeout path -- line 496: `scope.close()`, `task.writes.clear()`,
  `bg.cancel()`, then `raise NodeTimeoutError(...)`;
* the async path (`arun_with_retry`, line 706) -- `task.writes.clear()` at
  line 752, the first statement of its `try` block, before
  `await task.proc.ainvoke(...)`.

Why clearing is the right rule: in LangGraph the task's writes are the
**only outlet** of the node's work. `_return_value(task)` (same file, line
855) reads the result out of `task.writes` on the `RETURN` channel. A write
that is not cleared is therefore not a log line -- it is an effect that will
be applied.

### 2.2 The retry loop around it

Same file, sync path (line numbers as read on 2026-11-14):

* a matching policy is chosen by walking the policy list and taking the first
  whose `retry_on` matches (line 670); **no match means the exception is
  raised as-is**;
* `attempts` counts **failed attempts only** -- it is incremented at line 678,
  *after* a failure, never on the success path;
* `if attempts >= matching_policy.max_attempts: raise` (line 680) -- the last
  exception is re-raised, the loop gives up;
* the wait is (line 685)
  `min(max_interval, initial_interval * backoff_factor ** (attempts - 1))`,
  and **with jitter** `interval + random.uniform(0, 1)` (line 692);
* before the next attempt the config is marked as resuming (line 702):
  `config = patch_configurable(config, {CONFIG_KEY_RESUMING: True})`.

### 2.3 `RetryPolicy` defaults (verbatim)

`libs/langgraph/langgraph/types.py`, main branch, read 2026-11-14:

```python
class RetryPolicy(NamedTuple):
    initial_interval: float = 0.5
    backoff_factor: float = 2.0
    max_interval: float = 128.0
    max_attempts: int = 3
    jitter: bool = True
    retry_on: ... = default_retry_on
```

`retry_on` accepts three shapes, and `_should_retry_on` (same file, line 861)
decides between them:

| shape | rule |
| --- | --- |
| a sequence of exception classes | `isinstance(exc, tuple(retry_on))` |
| a single exception class | `issubclass(retry_on, Exception)` then `isinstance(exc, retry_on)` |
| a callable | `retry_on(exc)` |

Anything else raises `TypeError`.

The default predicate `default_retry_on` lives in
`libs/langgraph/langgraph/_internal/_retry.py` (read 2026-11-14): a
`ConnectionError` retries; an `httpx`/`requests` HTTP error retries on a 5xx
status; a fixed list of programming errors (`ValueError`, `TypeError`,
`ArithmeticError`, `ImportError`, `LookupError`, `NameError`, `SyntaxError`,
`RuntimeError`, `ReferenceError`, `StopIteration`, `StopAsyncIteration`,
`OSError`) never retries; everything else retries.

### 2.4 The two shapes of cancellation (verbatim)

From the async path of the same file:

1. The runtime cancelled the task because **a sibling failed**
   (`asyncio.Task.cancelling() >= 1`). The cancellation **propagates
   untouched** -- the framework already knows the run is failing.
2. The **node body itself** raised `asyncio.CancelledError`
   (`cancelling() == 0`). The runner would otherwise treat this as a silent
   tear-down and the run would report `success` even though the node failed.
   It is converted into a `NodeCancelledError` and follows the ordinary
   failure path.

The distinction matters because the two must not be treated alike: an
external cancellation is not the node's failure and must not consume
attempts; a self-cancellation is the node's failure and must not be reported
as success.

## 3. What is a Northstar extension (not LangGraph)

Everything in this section is Northstar's own, and is **not** presented as
LangGraph's.

1. **"Pending writes" are Northstar's writes.**  In LangGraph a write is a
   Pregel channel write held by the task (`task.writes`).  Here a write is a
   node's write to the ledger / checkpoint layer: a **key**, a **value** and a
   **write sequence number** (`PendingWrite`).  The clearing therefore means
   *discard this attempt's uncommitted writes*; the committed writes are not
   in the pending set and are never touched.
2. **The write set is its own object** (`PendingWrites`) rather than a field
   on the task, so the rule can be driven without a Pregel executor.  The
   distinction is not invented: `durable_resume.py` models it from the other
   side -- `put_writes` / `pending_writes`, where "a write is *pending* --
   declared, not committed -- so nothing has happened yet", and
   `checkpoints.durable_state` keeps the pending writes **out** of the
   committed state for the same reason.
3. **The committed writes live beside the pending ones** in the same object,
   so the acceptance test can show that clearing pending writes leaves the
   committed ones alone.
4. **The timeout path is thread-based.**  A synchronous node cannot be
   interrupted, so the attempt runs in a worker thread; on expiry the pending
   writes are cleared and the write set is **sealed**, so a late write from
   the abandoned worker cannot slip into the next attempt.
5. **The external cancellation is its own exception type**
   (`ExternalCancelledError`) rather than an `asyncio` cancelling count, so
   the split can be driven synchronously and read in an audit record.
6. **The attempt records** (`AttemptRecord`, `RetryOutcome`) are Northstar's
   audit trail: attempt number, whether the attempt was a resuming one, how
   many writes the clearing discarded, and the error type.  LangGraph logs
   the retry; it does not keep a record of what the clearing discarded.

What this module does **not** implement: LangGraph's Pregel executor, its
checkpointing, its interrupt machinery, its streaming, its `ParentCommand`
handling.  Only the "clear before a retry" rule and the retry loop around it
are implemented.

## 4. The Northstar surface

| name | role |
| --- | --- |
| `PendingWrite` | one uncommitted write: `key`, `value`, `seq` |
| `PendingWrites` | the write set: `write()`, `clear()`, `commit()`, `seal()`, `pending()`, `committed()` |
| `RetryPolicy` | the policy, with LangGraph's defaults and its three `retry_on` shapes |
| `run_with_retry` | the runner: clear, try, match, count, wait, mark resuming |
| `NodeCancelledError` | the node body cancelled itself |
| `ExternalCancelledError` | the runtime cancelled the attempt (sibling failed) |
| `NodeTimeoutError` | the attempt exceeded its timeout |
| `patch_configurable` | LangGraph's config patching, reused for the resuming flag |

## 5. The three real paths this slice drives

| path | what happens | proven by |
| --- | --- | --- |
| (a) write-then-fail, retried | the first attempt's write is discarded; only the second attempt's write survives | `RealPathTests.test_path_a_...` |
| (b) fails past `max_attempts` | the loop gives up, the last exception is raised, the pending writes are cleared | `RealPathTests.test_path_b_...` |
| (c) an exception no policy matches | the first failure raises at once, no retry, no write survives | `RealPathTests.test_path_c_...` |

## 6. Verbatim, and where it comes from

| claim | source |
| --- | --- |
| the clearing is the first line of every attempt | LangGraph `pregel/_retry.py` line 635 (sync `run_with_retry`: `task.writes.clear()` then `task.proc.invoke`), read 2026-11-14 |
| the clearing also happens on the timeout path | LangGraph `pregel/_retry.py` line 496 (`scope.close()`, `task.writes.clear()`, `bg.cancel()`, then `NodeTimeoutError`), read 2026-11-14 |
| the async twin clears the same way | LangGraph `pregel/_retry.py` line 752 (`arun_with_retry`), read 2026-11-14 |
| writes are the node's only outlet | LangGraph `pregel/_retry.py` line 855 (`_return_value(task)` reads the `RETURN` channel out of `task.writes`), read 2026-11-14 |
| no matching policy means the exception is raised | LangGraph `pregel/_retry.py` line 670, read 2026-11-14 |
| `attempts` counts failures only | LangGraph `pregel/_retry.py` line 678 ("attempts tracks failed tries only"), read 2026-11-14 |
| the give-up rule | LangGraph `pregel/_retry.py` line 680 (`if attempts >= matching_policy.max_attempts: raise`), read 2026-11-14 |
| the backoff formula and the jitter | LangGraph `pregel/_retry.py` lines 685 and 692, read 2026-11-14 |
| the resuming marker | LangGraph `pregel/_retry.py` line 702 (`patch_configurable(config, {CONFIG_KEY_RESUMING: True})`), read 2026-11-14 |
| the policy defaults | LangGraph `types.py` `RetryPolicy` (line 428), read 2026-11-14 |
| the three `retry_on` shapes | LangGraph `pregel/_retry.py` `_should_retry_on`, line 861, read 2026-11-14 |
| the default predicate | LangGraph `_internal/_retry.py` `default_retry_on`, read 2026-11-14 |
| the cancellation split | LangGraph `pregel/_retry.py`, async path (lines 790-805), read 2026-11-14 |
| pending vs committed writes | Northstar `durable_resume.py` (`put_writes` / `pending_writes`) and `checkpoints.durable_state` |
| the write object shape | Northstar extension (this module) |
| the thread-based timeout | Northstar extension (this module) |
| the attempt records | Northstar extension (this module) |

## 7. Open items

* The rule is implemented as a standalone module; the runtime's own node
  execution path (`long_horizon.py`, `durable_resume.py`) does **not** call
  `run_with_retry` yet.  Wiring it in is a separate change and would touch
  files this slice is not allowed to touch.
* The timeout path is thread-based, so a node that ignores the timeout keeps
  running in the background until it returns.  Its writes are sealed out, but
  the thread itself is not killed -- a synchronous Python thread cannot be.
* `default_retry_on` imports `httpx` and `requests` lazily, as LangGraph's
  own function does; when they are absent the HTTP arms are skipped.
