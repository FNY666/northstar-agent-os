# Cross-system evidence-window schema and continuity acceptance — S11

**Access date:** 2026-09-22 UTC. **Scope:** official first-party public documentation only. This slice addresses retry/redelivery, idempotency, activity partial completion, and why platform workflow semantics cannot be promoted to external-effect continuity.

## Verified evidence

- Stripe documents idempotency keys as a way to safely retry requests after connection errors without creating a second object/update twice; the request parameters must remain consistent with the key's original request.
- Stripe webhook documentation says deliveries can be retried, event IDs should identify duplicate deliveries, and event order must not be inferred from creation time. A fast 2xx response is recommended before complex processing.
- Temporal documents that Activities may execute multiple times or partially complete during retry, even though the workflow observes one completed Activity result. Activity code should therefore be idempotent and granular.
- Temporal documents retries, timeouts and heartbeats as platform execution mechanisms; workflow replay does not re-execute completed Activities.
- AWS Step Functions documents Retry/Catch, task errors/timeouts, and redrive behavior. Workflow retry/redrive is orchestration evidence, not an external target read-back.

## Schema additions

```json
{
  "operation": {"id":"...","target_fingerprint":"...","normalized_args_hash":"...","idempotency_key":"..."},
  "attempts": [{"attempt":1,"started_at":"...","ended_at":"...","platform_status":"...","target_receipt":"..."}],
  "redelivery": {"event_id":"...","delivery_count":2,"ordering_authoritative":false},
  "reconciliation": {"query_required":true,"query_performed":false,"target_state":"unknown"},
  "verdict":"UNKNOWN"
}
```

An idempotency key must be bound to target identity and normalized arguments. A platform success/retry result cannot substitute for target receipt or independent read-back.

## Deterministic acceptance vectors

| ID | Fixture facts | Expected verdict | Forbidden upgrade |
|---|---|---|---|
| S11-1 | Same idempotency key, same target/args; authoritative target read-back shows one committed object | `VERIFIED_CONTINUITY` | None |
| S11-2 | Connection error after request; no target query/read-back | `UNKNOWN` | Do not assume not committed or safe to retry without idempotency |
| S11-3 | Same key reused with changed normalized args | `UNKNOWN`/`QUERY_GAP` and hard policy error | Do not treat as same operation |
| S11-4 | Webhook event ID delivered twice; one target commit and duplicate suppressed | `VERIFIED_CONTINUITY` with duplicate annotation | Delivery count is not commit count |
| S11-5 | Webhook event received; processing timed out; target state not queried | `UNKNOWN` | 2xx/receipt does not prove business effect |
| S11-6 | Temporal Activity retry; first attempt may have partially completed; final attempt returns success; no target read-back | `UNKNOWN` | Workflow success is not external uniqueness/completion |
| S11-7 | Activity retry plus target idempotency key and independent read-back shows exactly one target result | `VERIFIED_CONTINUITY` | None |
| S11-8 | Step Functions task timed out and was retried; target query unavailable | `UNKNOWN` | Retry success cannot erase prior ambiguity |
| S11-9 | Step Functions execution history says succeeded; required target postcondition absent | `UNKNOWN` | Platform completion is not external effect |
| S11-10 | Explicit target query says operation ID absent after a timeout, but target consistency is not proven | `UNKNOWN` | A transient absence is not definitive not-committed |

## State discipline

Keep `platform_status`, `delivery_status`, `target_commit_status`, and `reconciliation_status` separate. After timeout, disconnect, worker failure, or redelivery, default the target status to `UNKNOWN` until an authoritative query/postcondition resolves it. Retrying is permitted only when the target contract supplies idempotency/fencing or the operation is read-only; it does not itself change the verdict.

## Cannot prove

The cited sources do not prove that any particular deployment uses keys correctly, that a target honors idempotency, that retries are lossless, or that a platform success means an external business commit. Production acceptance requires target-side receipts/read-back and a documented consistency/reconciliation policy.
