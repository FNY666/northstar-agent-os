# Cross-system evidence-window schema and continuity acceptance — S10

**Access date:** 2026-09-22 UTC. **Scope:** official first-party public documentation only. This slice adds multi-signal, exporter, and explicit negative-counter semantics.

## Verified evidence

- OpenTelemetry OTLP distinguishes full success, partial success, retryable failure, and non-retryable failure. For non-retryable bad data, the client must not retry and must drop the data; clients should count dropped data. A timeout while waiting for acknowledgement is not delivery proof.
- OpenTelemetry Collector documents in-memory queue overflow, retry-duration expiry, backend unavailability, collector crash without persistence, and persistent WAL limitations as distinct loss/failure mechanisms. Queue/retry metrics can expose potential issues but are not proof of zero loss.
- Kubernetes auditing documents `apiserver_audit_event_total` as exported events and `apiserver_audit_error_total` as events dropped due to export errors; webhook buffers can overflow and drop events; failed webhook requests are retried with backoff.
- OpenTelemetry Metrics documents temporality, resets/gaps, and missing timestamps as semantic conditions. A metric point is not interchangeable with a log/span event.
- GitHub artifact API exposes `expired`, `expires_at`, and digest; artifact retention is separate from workflow-run/log queryability.

## Cross-signal schema

```json
{
  "window": {"start":"...","end":"...","semantics":"[start,end)"},
  "source": {"system":"...","signal":"logs|metrics|traces|audit|workflow","partition":"...","config_fingerprint":"..."},
  "emission": {"event_id":"...","source_sequence":"...","producer_receipt":"..."},
  "transport": {"request_id":"...","ack":"full|partial|none|timeout","retryable":null,"rejected_count":0,"dropped_count":0},
  "buffer": {"queue_capacity":0,"queue_high_watermark":0,"overflow_count":0,"retry_deadline":"...","wal":"enabled|disabled|unknown"},
  "query": {"pages":0,"continuation_complete":false,"cursor_errors":[],"partitions_expected":[],"partitions_read":[]},
  "retention": {"available":true,"expires_at":"...","checked_at":"..."},
  "integrity": {"digest_valid":null,"digest_scope":"..."},
  "verdict":"UNKNOWN"
}
```

Counts must be scoped by source, signal, partition, and window. An exporter error counter is not a count of business effects; a successful export counter is not a destination read-back.

## Deterministic acceptance vectors

| ID | Authoritative fixture | Expected verdict | Reason |
|---|---|---|---|
| S10-1 | OTLP full success; destination read-back contains every source ID/sequence; all pages/partitions complete; no gaps | `VERIFIED_CONTINUITY` | Positive evidence across transport and query planes |
| S10-2 | OTLP non-retryable rejection names `rejected=3`; those source IDs absent at destination | `DROPPED` | Explicit protocol-level rejection |
| S10-3 | Collector queue overflow count > 0 | `DROPPED` | Collector documents overflow loss |
| S10-4 | Retry deadline expires while destination unavailable; no later read-back | `EXPORTER_FAILURE` | Export path failed; external effect unresolved |
| S10-5 | Ack timeout; producer receipt exists; destination read-back absent | `UNKNOWN` | Receipt is not delivery/commit proof |
| S10-6 | Kubernetes export-error counter increases and matching audit IDs absent | `DROPPED` | Explicit audit export loss |
| S10-7 | Exporter error counter increases but authoritative destination read-back contains all IDs | `VERIFIED_CONTINUITY` for this window, with exporter incident annotation | Counter alone does not prove event loss |
| S10-8 | Metric cumulative stream has reset/gap or missing timestamp and no documented reset boundary | `QUERY_GAP` | Metric continuity cannot be reconstructed |
| S10-9 | Logs complete but metrics query is empty | `NO_EVENT` only for metrics if metrics source active, coverage complete, retention valid, and no export/query errors; otherwise `UNKNOWN` | Signal separation |
| S10-10 | Artifact digest valid but workflow logs/jobs/run query is incomplete | `UNKNOWN` | Artifact integrity does not establish cross-signal completeness |

## Precedence

1. `RETENTION_EXPIRED` when required evidence is outside a verified retention boundary.
2. `QUERY_GAP` when pagination, cursor, partition, sequence, or metric continuity is incomplete.
3. `DROPPED` when authoritative producer/exporter evidence explicitly identifies discarded records.
4. `EXPORTER_FAILURE` when export did not complete and no explicit per-record drop is established.
5. `DELAYED` when a documented retry/queue path remains active within its deadline and no terminal loss is established.
6. `NO_EVENT` only after source activation, complete query, valid retention, complete partition scope, and no loss/error indicators.
7. `VERIFIED_CONTINUITY` only after authoritative source identity/sequence and independent destination read-back cover the full window.
8. Otherwise `UNKNOWN`.

This ordering is a proposed deterministic harness policy, not an official vendor classification.

## Cannot prove

These sources do not prove any specific deployment is lossless, correctly configured, fully retained, or externally committed. Counters and acknowledgements are bounded evidence; they must not be inflated into end-to-end continuity claims.
