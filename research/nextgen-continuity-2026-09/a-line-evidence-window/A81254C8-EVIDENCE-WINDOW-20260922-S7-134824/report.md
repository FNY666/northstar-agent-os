# Cross-system evidence-window schema and continuity acceptance

**Slice:** S7  
**Access date:** 2026-09-22 (UTC; Asia/Shanghai session date)  
**Scope:** official first-party documentation only; no production systems, credentials, protected local trees, or private data.

## Conclusion

A cross-system evidence window must separate at least: event time (`event_time`), observation/ingest time (`observed_time`), export/transport time (`export_time`), query time (`queried_at`), source identity, operation/event identity, attempt, sequence/cursor, and retention/coverage metadata. OpenTelemetry explicitly distinguishes event `Timestamp` from `ObservedTimestamp`; OTLP describes request/response delivery only between one client and one server, not end-to-end final-destination continuity. Therefore an event-window result is not a binary “logs exist” flag.

The deterministic acceptance rule proposed here is:

* `VERIFIED_CONTINUITY` only when every required source has authoritative coverage for the requested window, its records are queryable and integrity-checked, expected identity/sequence or an explicit authoritative no-event proof is present, and no exporter, retention, or query gap overlaps the window.
* `NO_EVENT` only when the source is known to have been active and query-complete for the window and the authoritative result is empty; an empty result with an unknown query/retention/export state is not NO_EVENT.
* `DELAYED` when the source/export path is known and records are expected but their observation/export time is beyond the declared bound, without evidence of loss.
* `DROPPED` when an authoritative producer/exporter reports rejection, discard, queue overflow, non-retryable failure, or retention eviction for the event/window.
* `EXPORTER_FAILURE` when the export path failed and the outcome for the requested event is not independently resolved. It must not be collapsed into DROPPED unless discard is explicitly evidenced.
* `QUERY_GAP` when the query cannot cover the requested interval, cursor/page, region, tenant, signal, or source; an empty partial query is UNKNOWN, not NO_EVENT.
* `RETENTION_EXPIRED` when the source's documented/attested retention boundary makes the requested window unavailable; this is a coverage failure, not proof that no event occurred.
* `UNKNOWN` for conflicting, missing, stale, or insufficient evidence, including a transport acknowledgement without destination read-back.

## Proposed evidence-window record

```json
{
  "schema_version": "ew-1",
  "window": {"start": "...", "end": "...", "boundary": "[start,end)"},
  "source": {"system": "...", "region": "...", "tenant": "...", "signal": "..."},
  "query": {"queried_at": "...", "cursor_start": "...", "cursor_end": "...", "complete": true},
  "event": {"event_id": "...", "operation_id": "...", "event_time": "...", "observed_time": "..."},
  "transport": {"export_time": "...", "attempt": 1, "receipt": "...", "status": "..."},
  "coverage": {"source_active": true, "retention_valid": true, "integrity_valid": true, "gap_intervals": []},
  "verdict": "VERIFIED_CONTINUITY",
  "evidence_refs": ["url-or-immutable-record-id"],
  "limitations": []
}
```

`receipt` is deliberately not equivalent to `verdict`: OTLP's documented reliability boundary is the client/server pair, and Collector queues/WALs have explicit overflow, retry-timeout, disk-space, and endpoint-unavailable loss boundaries.

## Deterministic acceptance vectors

Each vector is evaluated against a fixed requested window `[t0,t1)`, source identity, and policy revision. The harness must reject missing required fields and must not infer a positive state from absent data.

| ID | Fixture facts | Expected verdict | Forbidden upgrade |
|---|---|---|---|
| V1 | Source active; complete authoritative query; event identity and integrity valid; no gaps; destination read-back contains all expected records | `VERIFIED_CONTINUITY` | none |
| V2 | Source active; complete query; authoritative query says zero matching events; retention and integrity valid; no transport/export gap | `NO_EVENT` | Do not call it VERIFIED_CONTINUITY for an event that was never expected |
| V3 | Event produced at `t`; export/observation at `t+Δ`, Δ exceeds policy bound; later authoritative read-back finds it; no loss evidence | `DELAYED` | Do not call it VERIFIED_CONTINUITY within the original SLA window |
| V4 | Exporter queue full or retry deadline expires and exporter explicitly reports data dropped | `DROPPED` | Do not relabel as exporter failure or no-event |
| V5 | Exporter unavailable; retries exhausted/failed; no explicit discard and no destination read-back | `EXPORTER_FAILURE` | Do not infer DROPPED or NO_EVENT |
| V6 | OTLP non-retryable response / partial failure identifies rejected records; rejected count is authoritative | `DROPPED` | Do not retry blindly or mark continuity |
| V7 | Query covers only `[t0,tq)` with `tq<t1`, page/cursor/region missing or API returned an incomplete result | `QUERY_GAP` | Do not call empty result NO_EVENT |
| V8 | Requested window older than authoritative retention; records unavailable solely because retention expired | `RETENTION_EXPIRED` | Do not infer NO_EVENT or DROPPED |
| V9 | Producer/export receipt exists but destination read-back is absent and query completeness is unknown | `UNKNOWN` | Receipt alone cannot prove continuity |
| V10 | Conflicting sources: one says empty, another reports dropped/gap for overlapping interval | `UNKNOWN` | Do not choose the favorable source silently |
| V11 | No source heartbeat/activation proof for the requested interval; query returns empty | `UNKNOWN` | Empty is not NO_EVENT |
| V12 | All source partitions/regions are explicitly queried; each reports authoritative zero; no gap/retention issue | `NO_EVENT` | Do not upgrade merely because all queries succeeded |

## State precedence

For deterministic evaluation, apply failure/coverage gates before positive results:

`RETENTION_EXPIRED` / `QUERY_GAP` / conflicting evidence → `UNKNOWN` or the explicit coverage state; `DROPPED` → `DROPPED`; unresolved exporter failure → `EXPORTER_FAILURE`; known late arrival → `DELAYED`; only then evaluate complete empty (`NO_EVENT`) or complete positive (`VERIFIED_CONTINUITY`). A deployment may choose a precedence table, but it must publish it and retain the raw facts; it must not silently overwrite contradictions.

## Source-specific verified boundaries

* **OpenTelemetry Logs data model:** `Timestamp` is when the event occurred; `ObservedTimestamp` is when it was observed. This supports separating event and observation windows, but the data model does not itself prove ingestion completeness.
* **OTLP specification:** export is a sequence of requests with responses and discusses reliability between one client/server pair. Partial success and non-retryable failures require rejected data to be dropped; the protocol boundary does not prove final backend persistence.
* **OpenTelemetry Collector resiliency:** in-memory queues can drop on full queue or retry timeout; WAL improves restart resilience but can still lose data on disk exhaustion or prolonged unavailability. These are direct reasons to classify gaps rather than treating exporter acknowledgement as continuity.
* **AWS CloudTrail Event History:** the default searchable event history is limited to the past 90 days and is regional and management-event scoped. Outside that scope or age, absence is not NO_EVENT.
* **AWS CloudTrail digest validation:** signed digest files can validate delivered log-file integrity and detect modification/deletion after delivery; integrity validation does not establish that the service recorded every business event.
* **Kubernetes auditing:** audit records are chronological records of activities generated by users, applications using the API, and the control plane; the audit subsystem and configured backend determine what is actually retained/available.
* **Temporal Event History:** a Workflow Execution is a sequence of events created by the Temporal Service. This is platform history, not a universal proof that an external side effect committed; external postcondition/read-back remains a separate field in this schema.

## Cannot prove

This slice does not prove any production deployment is lossless, complete, exactly-once, continuously queryable, or configured according to these rules. Official documentation defines component semantics and limits; it does not attest to a particular installation's exporter configuration, clocks, queue capacity, retention, permissions, backend durability, cross-region coverage, or external business state. A signed log/digest, platform event history, successful export response, or non-empty query proves only its documented boundary. Determining `VERIFIED_CONTINUITY` requires deployment-specific independent evidence for all required sources and the complete requested window.
