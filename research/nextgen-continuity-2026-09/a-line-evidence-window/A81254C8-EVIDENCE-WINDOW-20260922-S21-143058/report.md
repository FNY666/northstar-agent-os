# S21 report — exporter partial success and state classification

**Access date:** 2026-09-22. **Evidence level:** verified for the cited protocol/documentation semantics; inferred for the cross-system schema; unknown for any production deployment.

## Findings

1. OTLP and collector resiliency documentation distinguish transport/export outcomes from application delivery. A request accepted by a protocol or queued for retry is not proof that the destination received, persisted, or applied the record.
2. Partial success must be represented explicitly: preserve accepted count, rejected count, retryability, exporter/queue status, and the source sequence or event IDs. Do not convert a partial success response into `VERIFIED_CONTINUITY`.
3. `DROPPED` requires authoritative loss evidence (producer sequence/counter, explicit rejection, exhausted durable retry, or equivalent). A missing query result alone is `QUERY_GAP` or `UNKNOWN`.
4. `EXPORTER_FAILURE` is a pipeline state, not proof of external non-effect. If the external target cannot be read back, retain `UNKNOWN`.
5. A deterministic evidence record should include: `window_id`, `source_system`, `operation_id`, `event_id`, `event_time`, `observed_at`, `ingest_time`, `query_start/end`, `page_complete`, `retention_valid`, `integrity_status`, `exporter_status`, `accepted_count`, `rejected_count`, `retryable`, `loss_proof`, `postcondition_status`, and `state`.

## Acceptance vectors

- **S21-1 NO_EVENT:** complete query, valid retention, exporter healthy, no errors, and zero matching IDs. Pass only when every predicate is true.
- **S21-2 DELAYED:** later read-back finds the ID after the latency bound. Earlier absence is not NO_EVENT.
- **S21-3 DROPPED:** explicit loss proof plus expected predecessor/successor or counter gap. Without proof, use UNKNOWN.
- **S21-4 EXPORTER_FAILURE:** exporter reports terminal failure or exhausted retry; target read-back absent. Result is EXPORTER_FAILURE plus unresolved UNKNOWN effect, not `not committed`.
- **S21-5 QUERY_GAP:** partial page, API error, cursor invalidation, permission filter, or incomplete interval. Empty response cannot pass NO_EVENT.
- **S21-6 RETENTION_EXPIRED:** interval outside the source retention guarantee. Absence cannot pass NO_EVENT.
- **S21-7 VERIFIED_CONTINUITY:** complete query, valid retention, integrity verified, exporter health proven, matching IDs/sequences, and independent target postcondition. Any missing predicate fails closed.
- **S21-8 UNKNOWN:** timeout, cancellation, conflicting evidence, partial success without reconciliation, or any unclassified condition.

## Cannot prove

The sources do not prove universal exactly-once external effects, complete event generation, absence of sampling, production coverage, or correctness of an implementation that merely records platform receipts.
