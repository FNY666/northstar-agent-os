# Declarative retry configuration and call-kind classification

Status: implemented. Module: `components/northstar-agent-runtime/retry_config.py`.
Tests: `components/northstar-agent-runtime/tests/test_retry_config.py`.

This document separates two kinds of statement, and labels every one of them:

- **Verbatim from Dynamiq** — the upstream source, read at commit `acc30e5`
  (2026-11-11), quoted or copied exactly.
- **Northstar extension** — a rule this repository adds on top, which upstream
  does not state.
- **Unverified** — a claim that the code supports but that was *not* exercised
  against a live provider.

---

## 1. The problem

Northstar's relay retries and fails over blindly. `retry_contract.py` already
classifies failures (`FailureClass`) and describes a single call's replay
safety (`Operation.body_replayable`), and `retry_policy.py` already computes a
bounded backoff. What was missing was the thing between them:

1. **The call itself was never classified.** Nothing in the code said "this
   particular call may be repeated" or "this one may not". The information
   existed in `Operation`, per call site, but the *kind* of call — session
   lifecycle versus code execution — was nowhere in the code, so it lived in
   the head of whoever wrote the call site.
2. **The retry parameters were constants spread across modules.**
   `provider_retry.py` alone carries `DEFAULT_MAX_ATTEMPTS = 3`,
   `DEFAULT_BASE_DELAY_MS = 250`, `DEFAULT_MULTIPLIER = 2.0`,
   `DEFAULT_MAX_DELAY_MS = 20_000`, `DEFAULT_DEADLINE_MS = 60_000`; and
   `retry_contract.py` carries its own `RetryContractConfig` defaults
   (`max_retries=2`, `initial_wait_ms=100`, `max_wait_ms=10_000`). None of them
   was a single declarative object that a caller could pass around.

## 2. The source rule (verbatim from Dynamiq)

From `dynamiq/connections/agentcore.py`, lines 105–108 (commit `acc30e5`):

> ```
> # Disable botocore's built-in retries: the default legacy mode silently re-sends
> # failed requests up to 5 times, which for the non-idempotent InvokeCodeInterpreter
> # (executeCode/executeCommand carry no idempotency token) could execute user code
> # multiple times on a transient socket error. Transient throttling on the idempotent
> # session-lifecycle calls is instead retried at the application level via tenacity.
> ```

Two sentences in that comment carry the whole rule:

- the non-idempotent call must not be re-sent, **even on a transient error**,
  and **even when the transport's own retry is "only" five attempts**;
- the throttle retry applies to the **idempotent session-lifecycle calls**.

The same file's `_translate_error` maps the provider's throttling error onto a
typed `AgentCoreThrottlingError` — "so callers can retry on a typed exception"
— and `dynamiq/sandboxes/bedrock_agentcore.py` retries **only** that type:

> ```python
> @retry(
>     retry=retry_if_exception_type(AgentCoreThrottlingError),
>     stop=stop_after_attempt(cfg.max_retries),
>     wait=wait_exponential_jitter(
>         initial=cfg.initial_wait_seconds,
>         max=cfg.max_wait_seconds,
>         exp_base=cfg.exponential_base,
>         jitter=cfg.jitter,
>     ),
>     reraise=True,
> )
> ```

## 3. Call-kind classification

The classification lives in code (`CallKind`), not in a runbook.

| Kind | Idempotent? | May be retried? | Source |
| --- | --- | --- | --- |
| `SESSION_LIFECYCLE` (session create, reconnect) | yes | yes, on a retryable failure | Verbatim: the AgentCore comment ("the idempotent session-lifecycle calls"). |
| `EXECUTION` (running user code) | no | **never** — not even on a throttle | Verbatim: the AgentCore comment ("the non-idempotent InvokeCodeInterpreter … could execute user code multiple times"). |
| `UNKNOWN` (we cannot tell) | treated as **no** | **never** | Northstar extension: fail-closed. |

`CallKind.UNKNOWN` exists because "we could not tell" is not permission to
repeat a side effect. `classify_call` treats it exactly as `EXECUTION`.

### The gate order

`classify_call(kind, failure, attempt=..., config=...)` decides in this order,
and the order is load-bearing:

1. **Indeterminate first.** A post-write failure, or one carrying
   `may_have_executed`, is `INDETERMINATE`: the peer may already have executed
   the call. Never retried, never reported as success. This is
   `retry_contract`'s rule (`_terminal_error` raises
   `TargetUnreachableError(may_have_executed=True)`), reused — not restated.
2. **Idempotency next.** A non-idempotent kind is `NEVER_RETRY` for *any*
   failure, throttling included.
3. **Classification next.** A failure that is not `FailureClass.RETRYABLE` is
   `NEVER_RETRY`.
4. **Budget last.** A retryable, idempotent failure with the budget spent is
   `NEVER_RETRY`.

The failure vocabulary is not copied: `classify_call` accepts a
`retry_contract.Failure`, a bare `retry_contract.FailureClass`, or an
exception, and an exception is classified by `retry_contract.classify_exception`.

### Decisions

| Decision | Meaning |
| --- | --- |
| `RETRY` | The call may be tried again; the budget allows it; a wait window is declared. |
| `NEVER_RETRY` | The call must not be tried again. The outcome is definite, or at least not repeatable. |
| `INDETERMINATE` | The call must not be tried again **and** the outcome is unknown: the peer may already have run it. |

## 4. The declarative configuration object

`RetryConfig` is a frozen dataclass. Its defaults are **verbatim from
Dynamiq**, copied from `dynamiq/nodes/tools/code_interpreter.py` line 322:

> ```python
> class SandboxCreationErrorHandling(BaseModel):
>     max_retries: int = Field(default=5, description="Maximum number of creation attempts on rate-limit.")
>     initial_wait_seconds: float = Field(default=2.0, description="Initial wait before retry.")
>     max_wait_seconds: float = Field(default=32.0, description="Max wait used by exponential jitter backoff.")
>     exponential_base: float = Field(
>         default=2.0, description="Exponential base for backoff (2.0 means doubling each time)."
>     )
>     jitter: float = Field(default=1.0, description="Jitter factor to add randomness to retry timing.")
> ```

So `RetryConfig()` is `max_retries=5, initial_wait_seconds=2.0,
max_wait_seconds=32.0, exponential_base=2.0, jitter=1.0` — Dynamiq's numbers,
not Northstar's. The module says so at the point of use.

### Fail-closed validation

A configuration that does not make sense is refused at construction, not
repaired at call time:

| Field | Rule |
| --- | --- |
| `max_retries` | integer, `>= 0` |
| `initial_wait_seconds` | number, `> 0` |
| `max_wait_seconds` | number, `> 0`, and `>= initial_wait_seconds` |
| `exponential_base` | number, in `[1.0, 4.0]` |
| `jitter` | number, in `[0.0, 1.0]` |

`from_dict` / `to_dict` round-trip, and `from_dict` refuses an unknown key — a
typo in a retry table looks exactly like a working retry table.

### The wait schedule is deterministic

> **Northstar extension.** Upstream uses tenacity's `wait_exponential_jitter`,
> which draws from an RNG. A Northstar run must be replayable from its audit
> record (the rule `retry_policy.py` already follows: "the same policy and
> attempt number always yield the same delay, so a run is replayable from the
> audit record"). So jitter here is **declared as a window**, not sampled.

`config.schedule()` returns one `WaitWindow` per retry step:

- `nominal = min(initial_wait_seconds * exponential_base ** i, max_wait_seconds)`
  — the same shape as upstream's `wait_exponential_jitter(initial, max,
  exp_base)`, minus the sampling;
- `low = nominal * (1 - jitter)`, `high = nominal` — the interval a jittering
  scheduler may pick from. `jitter = 0` declares an exact wait; `jitter = 1`
  declares "anywhere up to the nominal".

With the defaults the nominal waits are `2.0, 4.0, 8.0, 16.0, 32.0` — five
windows for five retries. The nominal is already capped at `max_wait_seconds`,
so no window can promise more than the configured ceiling.

No RNG, no wall-clock: the same configuration always yields the same
schedule, and the sleeper is injectable so a test asserts the exact sequence
without waiting.

## 5. The session guard

> **Verbatim from Dynamiq** (`dynamiq/sandboxes/bedrock_agentcore.py`,
> `_ensure_sandbox()`): "Uses double-checked locking so concurrent threads
> never create duplicate sessions."

`SessionGuard` implements that shape with a plain `threading.Lock`:

- the fast path reads the cached session without taking the lock;
- the slow path takes the lock, re-checks the cache, and creates;
- concurrent callers share the one created session;
- a **failed** creation releases the guard — no half-made session is cached —
  so the next caller may try again. Creating a session is an idempotent
  lifecycle call, so retrying it is safe.

`SessionGuard.create_calls` is the proof that the guard works; the test
asserts it is `1` after eight concurrent callers.

## 6. The exit-124 timeout convention

> **Verbatim from Dynamiq** (`dynamiq/sandboxes/bedrock_agentcore.py`,
> `run_command_shell()`): the command is wrapped in the `timeout` coreutils
> command "since AgentCore has no per-invocation timeout parameter", and "a
> non-zero exit, e.g. 124, surfaces as a failed result".

`run_with_timeout(call, timeout_seconds)` is the in-process equivalent: the
call runs on its own thread and the caller waits at most the timeout.

| Outcome | Result |
| --- | --- |
| finished in time | `ok=True`, `exit_code=0`, the value |
| timed out | `ok=False`, `exit_code=124`, `timed_out=True` |
| raised | `ok=False`, `exit_code=1`, the error text |

A timeout is a **failed result**, never a silent hang and never a success. The
result records *what* happened, not *when*: no wall-clock time is stored, so
the record is replayable. The test uses an injected callable that blocks on an
event — no subprocess is spawned.

## 7. Relation to the existing modules

| Module | Relationship | Change |
| --- | --- | --- |
| `retry_contract.py` | Supplies the failure vocabulary (`FailureClass`, `Failure`, `classify_exception`, `classify_response`) and the indeterminate rule. Imported read-only. | **none** |
| `retry_policy.py` | The scheduling *shape* this module mirrors: bounded attempts, deterministic schedule, injectable sleeper, no wall-clock in the policy. Imported read-only in spirit; no code dependency. | **none** |
| `provider_retry.py` | The provider-side fault vocabulary (`rate_limited`, `overloaded`, …). This module does not extend it; it reuses `retry_contract`'s classification so there is exactly one vocabulary. Read-only. | **none** |
| `idempotency_manager.py` | The payload-bound idempotency ledger. A call carrying an idempotency key can be replayed as the same operation; a call carrying none cannot — which is why `EXECUTION` is never retried. Read-only. | **none** |
| `retry_config.py` | **New.** The declarative config, the call kinds, the gate, the guard, the timeout wrapper. | new file |

## 8. What is *not* verified

> **Unverified claim.** The AWS Bedrock AgentCore sandbox was **not run live**
> (it needs AWS credentials). The retry/idempotency *code* is verified — the
> upstream source was read verbatim, and this module's behaviour is exercised
> by 31 tests against injected callables — but the **live-provider behaviour**
> is not. Specifically, that upstream's `tenacity` jitter, its botocore
> `total_max_attempts: 1` setting and its `timeout(1)` wrapping behave as
> described on a real AgentCore endpoint was not observed.

Also out of scope for this slice, and deliberately not touched: checkpoint
lineage, the sandbox backends themselves, and any change to the modules listed
in the table above.

## 9. The driven path

One end-to-end test (`EndToEndPathTests`) drives all three cases through the
gate, because the parts having their own tests is not the same as the *gate*
being proven:

1. a throttled **idempotent** session create is retried, and the waits follow
   the declared schedule;
2. the same throttle on a **non-idempotent** execution is refused — the user's
   code ran exactly once, a counter proves it, and no wait was declared;
3. a hung invocation returns a failed result with `exit_code == 124`.
