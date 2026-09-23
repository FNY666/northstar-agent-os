# S16 Continuity verdict state machine

**Access date:** 2026-09-22 UTC. Official first-party public documentation only.

## Verified boundaries
Temporal event history is a durable workflow record, but an event-history entry is not itself proof that a third-party effect committed. Temporal Activities can retry and must account for repeated execution. AWS Step Functions redrive/retry and execution history are platform execution mechanisms, not proof that an external target has one effect. Stripe idempotency stores/replays request results subject to its documented key/parameter lifecycle; it is not a universal cross-system exactly-once mechanism.

## Deterministic state machine

`NOT_SEEN -> ACCEPTED -> IN_FLIGHT -> {VERIFIED_CONTINUITY, DELAYED, DROPPED, EXPORTER_FAILURE, QUERY_GAP, RETENTION_EXPIRED, UNKNOWN}`.

Transitions are permitted only with explicit evidence predicates:

- `VERIFIED_CONTINUITY`: source identity/sequence, target read-back/postcondition, and coverage all agree.
- `DELAYED`: retry/queue remains live and deadline has not expired; no contradictory target result.
- `DROPPED`: authoritative source/exporter says loss/rejection and no replay receipt exists.
- `EXPORTER_FAILURE`: exporter/transport failure is observed and coverage/read-back is incomplete.
- `QUERY_GAP`: query cannot cover the required source interval or pagination/revision continuity is broken.
- `RETENTION_EXPIRED`: authoritative record is no longer retrievable under declared retention, before proof completed.
- `UNKNOWN`: conflicting or insufficient evidence; never inferred as absence.
- `NO_EVENT`: allowed only from a source-native absence query with valid coverage, not from a missing telemetry row.

## Vectors

1. `ACCEPTED` only, no target read-back -> `UNKNOWN`.
2. Activity retry succeeds, first attempt may have side-effect -> `UNKNOWN` until idempotent read-back.
3. Redrive succeeds, external target query absent -> `UNKNOWN`.
4. Idempotency key reused with changed normalized parameters -> `CONFLICT_REJECTED`.
5. Retry live before deadline and no target contradiction -> `DELAYED`.
6. History exists but retention makes target evidence unavailable -> `RETENTION_EXPIRED`.
7. Source and target receipts agree on operation identity, args hash and postcondition -> `VERIFIED_CONTINUITY`.
8. Cancel/timeout/disconnect without target read-back -> `UNKNOWN`, not `DROPPED`.

## Cannot prove
Platform histories, retries, redrives, idempotency responses and logs do not independently prove external commit, no duplicate side effect, or production-wide continuity.
