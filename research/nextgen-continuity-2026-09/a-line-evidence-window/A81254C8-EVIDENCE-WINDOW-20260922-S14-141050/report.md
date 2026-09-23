# S14 Event identity and deduplication

**Access date:** 2026-09-22 UTC. **Scope:** official first-party public documentation only.

## Verified
- OpenTelemetry log records have identifying fields and timestamps, but the data model does not make an arbitrary log record a globally unique business event.
- OpenTelemetry spans have trace/span identity and parent context; these identify telemetry relationships, not exactly-once external effects.
- Kubernetes Events expose metadata such as name, UID, creation time and series/count fields; this supports cautious identity handling but does not prove complete observation of all cluster activity.
- GitHub workflow runs have run identity and API-visible states, but a run record is not the same as every job, step, log, artifact, or external side effect.

## Cross-system schema
`event_id`, `source_id`, `run_id`, `attempt`, `operation_id`, `target_fingerprint`, `args_hash`, `policy_revision`, `event_time`, `observed_time`, `sequence`, `source_revision`, `first_seen`, `last_seen`, `evidence_kind`, `coverage`, `verdict`.

`operation_id` must be bound to target and normalized arguments before deduplication. A trace ID alone is insufficient. Retries with the same operation identity are candidates for reconciliation, not proof of duplicate-free execution.

## Deterministic vectors
- S14-1 same source/event identity, same payload: `DUPLICATE_SUPPRESSED` (not a second effect).
- S14-2 same identity, changed args hash: `CONFLICT_REJECTED`.
- S14-3 different attempts, same operation identity, no authoritative target read-back: `UNKNOWN`.
- S14-4 trace correlation exists but sampling/coverage is unknown: `QUERY_GAP` or `UNKNOWN`, never `NO_EVENT`.
- S14-5 Kubernetes event count increases but no stable target read-back: `UNKNOWN`.
- S14-6 GitHub run is successful but artifact/job/external read-back is absent: `UNKNOWN`.
- S14-7 event identity is absent and timestamps overlap: `QUERY_GAP`, not deduplicated success.

## Cannot prove
Public schemas do not prove global uniqueness, complete sampling, exactly-once external effect, or production continuity. These require target-side idempotency/read-back and independent coverage evidence.
