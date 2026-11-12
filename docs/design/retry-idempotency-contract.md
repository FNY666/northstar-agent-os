# Retry / Idempotency Contract

How E2B's client retry contract maps onto Northstar's egress sidecar, and
what Northstar does that E2B does not.

Source read: [E2B](https://github.com/e2b-dev/E2B), Apache-2.0, at commit
`main` on 2026-11-12. The two files that matter are
`packages/js-sdk/src/retry.ts` and `packages/js-sdk/src/errors.ts`; the
idempotency key is used in `packages/js-sdk/src/sandbox/sandboxApi.ts`.

## The problem this solves

Northstar's egress sidecar is the only process that opens outbound network
connections. Every connection it opens carries a call whose side effect may
already have landed on the far side. Two failure modes follow:

* **Blind retry** of a call that landed re-executes it — a deploy posted
  twice, a payment captured twice.
* **Blind non-retry** of a call that never landed loses the work and strands
  the run.

The contract separates those cases by *classification*, before any retry
decision is made.

## Where the contract lives

| Piece | Location |
|---|---|
| The contract (classification, keys, config, executor) | `components/northstar-agent-runtime/retry_contract.py` |
| The sidecar's seam onto it | `components/northstar-egress-sidecar/retry_contract_egress.py` |
| The governed call site | `components/northstar-egress-sidecar/egress_sidecar.py` (`_run_one_inner` → `_perform_http`) |
| The agent-facing key field | `components/northstar-agent-runtime/egress_client.py` |

The contract lives in the runtime component because the runtime already
owns `egress_enforcer.py`, `egress_client.py`, `retry_policy.py` and
`http_client.py`; the sidecar already imports the runtime's engine modules
(`from egress_enforcer import ...`). Putting the contract there keeps the
dependency direction the same as it already is — sidecar depends on runtime,
never the reverse.

## The classification rules

A failure is classified before anything else happens to it.

### Responses (`classify_response`)

E2B's `retryDelayMs` reads the `Should-Retry` header. A **present** header is
authoritative — including an explicit `false`, which forbids the retry. Only
when the header is **absent** does the status matrix apply.

| Condition | Class | E2B source |
|---|---|---|
| `Should-Retry: true` | retryable | `retryDelayMs` |
| `Should-Retry: false` | non-retryable | `retryDelayMs` — "a present header is authoritative, including explicit `false`" |
| header absent, status ∈ {429, 502, 503, 504} | retryable | `RETRYABLE_STATUSES` |
| header absent, any other status | non-retryable | same |
| status ∈ {404, 410} | non-retryable, **confirmed absent** | Northstar addition (see below) |

The header name and its value are both matched case-insensitively. A
present-but-empty header counts as *present*, so it forbids the retry — the
alternative (treating empty as absent) would let a malformed header fall
through to the status matrix.

### Transport failures (`classify_exception`)

E2B's `isRetryableFetchError` / `isConnectionError` distinguish failures to
*establish* a connection from failures *after* the request was written.

| Condition | Class | Phase | E2B source |
|---|---|---|---|
| `ECONNREFUSED`, `ENOTFOUND`, `EAI_AGAIN`, `EHOSTUNREACH`, `ENETUNREACH`, `ENETDOWN`, `EHOSTDOWN` | retryable | pre-write | `CONNECTION_ERROR_CODES` |
| `ECONNRESET`, `EPIPE`, `ESHUTDOWN` | non-retryable | **post-write** | E2B's exclusion: "Post-write failures such as `ECONNRESET` are excluded: the server may have received the request" |
| connect-phase timeout | retryable | pre-write | E2B's `UND_ERR_CONNECT_TIMEOUT` |
| anything else | **unknown** | unknown | — |

A post-write failure is the important one. It is not merely "a failure" — the
peer may already have executed the operation. It is therefore never retried,
and the caller is told so explicitly (`may_have_executed=True`).

The sidecar raises `IndeterminateError` for the post-write cases it can
detect itself — a read timeout, a response cut short, a malformed status
line — because by then the request bytes were certainly written.

### Replay safety (`Operation.replay_safe`)

A failure being *retryable* is necessary but not sufficient. The call must
also be *safe to repeat*:

* an idempotent HTTP method (`GET`, `HEAD`, `OPTIONS`, `TRACE`, `DELETE`)
  may always be repeated;
* any other method may be repeated **only** with an idempotency key, so the
  upstream can collapse the duplicate;
* a streamed request body may never be repeated — E2B: "Streaming bodies
  would be consumed by the first attempt and cannot be replayed without
  buffering them, so they get a single attempt."

This property is decided **in code, at the call site**, not in a runbook.

## Idempotency keys

`resolve_idempotency_key` transcribes E2B's `resolveIdempotencyKey`: a key
must match `^[a-z0-9-]{1,255}$`. A malformed key is refused loudly rather
than dropped — silently dropping it would turn a replay-safe call into a
replay-unsafe one without anybody noticing.

The key travels as a **wire field** (`idempotency_key`), not as a header the
agent sets. The sidecar owns the upstream `Idempotency-Key` header, and
`idempotency-key` is therefore in `FORBIDDEN_EGRESS_HEADERS`: an agent that
could set the header directly could pin a *different* key than the sidecar
records, and the upstream would then collapse the wrong call.

Every attempt of one operation carries the **same** key and the **same**
payload digest. `assert_same_operation` refuses a retry whose key, digest or
method changed — resending a different operation under the first operation's
name is worse than not resending at all.

The digest is computed once, before the first attempt, from the method, the
path and the request body. It pins "this is the same operation" without
requiring the body to be buffered again.

## Dead versus unknown

Two different error types, never one vague one. This is E2B's
`SandboxNotRunningError` (confirmed stopped) versus `SandboxUnreachableError`
(might still be running).

| Error | Means | Caller should |
|---|---|---|
| `TargetGoneError` | the target is confirmed absent (HTTP 404/410) | **recreate** it |
| `TargetUnreachableError` | the target could not be reached and may still be running | **resume** or probe it |

`TargetUnreachableError` carries `may_have_executed`, so the caller can tell
"the request never landed" from "the request may have landed".

Collapsing these into a single "network error" would force the caller to
guess, and a wrong guess is expensive in both directions: recreating a target
that is still running loses its state, and resuming a target that is gone
wastes a retry budget on a corpse.

## Fail-closed

An indeterminate outcome is neither retried nor reported as a success. It
comes back as an independent result (`RetryOutcome`) with `ok=False`, so the
layer above decides — the brief's "以独立的结果返回，让上层决定".

`RetryContract.execute` returns the outcome; `RetryContract.execute_strict`
raises the terminal error for callers that prefer exceptions. Both exist
because different callers want different things, and the *classification*
is identical either way.

## Retry configuration

Declarative, validated, and declared once — no constants scattered at call
sites:

```python
DEFAULT_EGRESS_RETRY_CONFIG = RetryContractConfig(
    max_retries=2, initial_wait_ms=100, max_wait_ms=2_000,
    exponential_base=2.0, jitter=0.5,
)
```

`RetryContractConfig` refuses out-of-range values at construction: negative
counts, `max_wait_ms < initial_wait_ms`, `exponential_base < 1.0`, jitter
outside `[0, 1]`.

E2B's backoff is `min(100 * 2**attempt, 10_000)`, jittered to between 50%
and 100% of the computed delay. Northstar keeps that shape; the sidecar caps
the wait lower (2 s) because a sidecar retry is on the latency path of a
run, not a background poll.

## Where it is wired

The governed path is the sidecar's real outbound call:

```
agent → EgressClient.request()        (runtime)
      → Unix socket
      → egress_sidecar.run_one()       (sidecar)
      → _run_one_inner()
          authorize (enforcer)          ← unchanged
          persist the allow receipt     ← unchanged
          build the Operation          ← NEW: key + payload digest, once
          governed_egress_call(...)     ← NEW: the contract decides
              → _perform_http()         ← the real socket write
```

`_perform_http` was split so that the *phase* of a failure is visible: a
connect-phase failure is raised as-is (the contract classifies it by errno),
while a read-phase failure — the request was written — is raised as
`IndeterminateError`.

The wire response gained four fields, on both the success and the failure
path:

| Field | Meaning |
|---|---|
| `target_state` | `ok` \| `gone` \| `unreachable` |
| `may_have_executed` | the peer may already have done it |
| `attempts` | how many attempts were made |
| `retry_classification` | `retryable` \| `non_retryable` \| `unknown` \| `none` |

## What Northstar does that E2B does not

1. **A retryable status is not enough.** E2B retries a 502/503 whenever the
   caller asked for retries. Northstar additionally requires the operation to
   be replay-safe (idempotent method, or an idempotency key) and refuses the
   retry otherwise. "The server answered 502" is not proof that the origin
   never saw the request.

2. **The idempotency key is enforced end to end.** E2B validates the key and
   sends it; it does not check that a retry carries the *same* key or the
   same payload. Northstar pins the digest and refuses a mismatched retry.

3. **Confirmed-gone is a first-class answer.** E2B distinguishes
   "not running" from "unreachable" for sandboxes. Northstar does the same
   for HTTP targets, via the 404/410 → `TargetGoneError` mapping.

4. **The phase of a transport failure is explicit.** E2B infers it from the
   error code; Northstar's sidecar knows whether it had written the request
   and says so.

## Open items

These could not be resolved from the E2B source or the Northstar code, and
are recorded rather than invented:

* **Should a 429 be retried for a non-idempotent operation?** E2B says yes
  (429 is in `RETRYABLE_STATUSES`). Northstar currently says no, because the
  operation may have landed. A rate-limit response is normally generated
  *before* the operation runs, so E2B's position is defensible — but the
  general rule cannot be derived from the source, and the safer answer was
  taken. If a future upstream proves it rejects before executing, the rule
  could be narrowed to "429 with a rate-limit body".

* **How long should the sidecar wait between retries?** E2B caps at 10 s;
  Northstar's sidecar uses 2 s. The right value depends on the run's
  latency budget, which is not expressed anywhere in the repo. The number is
  a declared default in one place, so it is cheap to change.

* **Should the `Should-Retry` header be forwarded upstream?** The contract
  reads it, but the sidecar does not forward it to the next hop. E2B's header
  is an API-specific signal from the *upstream* to *E2B*, not a hop-by-hop
  header. Leaving it out of the forwarded set is the conservative reading.

* **Does the upstream actually honour `Idempotency-Key`?** The contract
  guarantees the key is *sent* and *stable*. Whether a given upstream
  collapses duplicates is outside Northstar's control and outside E2B's
  source. The `ServiceBusyError` precedent ("Nothing was changed by the
  refused call… so the same call can be retried") shows that the guarantee
  is service-specific, not universal.

* **Should a 5xx response body be included in the receipt?** The contract
  records the classification but not the upstream body, because the body may
  contain credential reflections and the scrubber runs after the contract
  returns. A future version could scrub first and record a digest.
