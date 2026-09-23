# S18 Cross-signal continuity patterns

Access date: 2026-09-22; official first-party public documents only.

## Verified observations

- OpenTelemetry logs, metrics, traces and OTLP define different signal/data-model and transport concerns. A signal record's existence is not proof that other signals for the same operation exist.
- Collector resiliency features such as queues/retries can improve delivery behavior, but a queue or exporter result is not the target's business commit.
- OTLP transport response/partial success semantics are transport evidence, not universal proof of backend retention or query completeness.

## State-machine rule

Maintain independent axes: `source_emitted`, `transport_accepted`, `exporter_persisted`, `backend_queryable`, `target_postcondition`, and `coverage_complete`. Compute the public status as:

- `VERIFIED_CONTINUITY` only when the operation identity matches, all required evidence windows are covered, the target postcondition is independently read back, and no exporter/query/retention gap exists.
- `NO_EVENT` only when an authoritative source scope says the event was not emitted; an empty query result is not enough.
- `DELAYED` when source/transport evidence exists but the event is inside an explicitly allowed convergence window.
- `DROPPED` when an authoritative drop counter/negative acknowledgement identifies the event or batch as discarded.
- `EXPORTER_FAILURE` when export failed and no authoritative downstream receipt exists.
- `QUERY_GAP` when the source may contain the event but the query is incomplete, paginated incompletely, interrupted, or otherwise cannot establish absence.
- `RETENTION_EXPIRED` when the requested interval is outside the documented retention window.
- `UNKNOWN` for all remaining ambiguity, including conflicting signals.

## Deterministic vectors

S18-1 source-only log + absent metric/trace: `UNKNOWN`, not `NO_EVENT`.
S18-2 transport accepted + exporter error: `EXPORTER_FAILURE`.
S18-3 exporter receipt + missing backend read-back: `UNKNOWN`.
S18-4 explicit dropped batch counter covering operation: `DROPPED`.
S18-5 query page interrupted or continuation token not exhausted: `QUERY_GAP`.
S18-6 interval beyond retention: `RETENTION_EXPIRED`.
S18-7 all required signals, complete coverage, target read-back and matching identity: `VERIFIED_CONTINUITY`.
S18-8 conflicting authoritative statuses: `UNKNOWN` with conflict reason.

## Cannot prove

The sources cannot prove lossless multi-signal capture, universal ordering, exactly-once external effects, absence from an empty query, or production continuity without system-specific evidence and an independent verifier.
