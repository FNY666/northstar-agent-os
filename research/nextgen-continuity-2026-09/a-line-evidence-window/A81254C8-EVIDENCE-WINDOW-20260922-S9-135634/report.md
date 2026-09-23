# Cross-system evidence-window schema and continuity acceptance — S9

**Access date:** 2026-09-22 UTC. **Scope:** official first-party public documentation only. This slice addresses correlation identity, sampling/propagation loss, event ordering, and why correlation cannot by itself establish continuity.

## Verified evidence

1. W3C Trace Context standardizes `traceparent` request identity and propagation, but explicitly notes that intermediaries/providers cannot guarantee propagation support. A missing downstream trace context is therefore not automatically `NO_EVENT`; it can be `QUERY_GAP` or `UNKNOWN` unless an independent source proves the gap.
2. W3C Baggage is application metadata, not an authorization or evidence proof. The specification permits intermediaries/platforms to drop members to meet size limits, and propagated values must be treated as potentially untrusted. Baggage may be a correlation hint only.
3. OpenTelemetry trace sampling can omit spans/events. `IsRecording`/sampling state does not establish complete trace capture. A sampled trace is therefore not a complete evidence window.
4. OpenTelemetry Logs distinguishes event timestamp from observed timestamp and carries optional trace/span identifiers. Trace linkage is useful for joining records, but optional linkage cannot prove that an unlinked record did not occur.
5. OpenTelemetry span events preserve recording order, but custom timestamps can be out of order and the API does not require timestamp ordering. Sequence/order must therefore be represented separately from wall-clock time.
6. CloudTrail digest files hash and sign delivered log files. This can prove integrity of delivered files after delivery; it cannot prove the files contain every event or that a business effect occurred.

## Proposed schema additions

```json
{
  "identity": {
    "operation_id": "...",
    "trace_id": "...",
    "span_id": "...",
    "source_event_id": "...",
    "propagation_status": "present|absent|invalid|unknown",
    "identity_trust": "authoritative|correlation_only|untrusted"
  },
  "ordering": {
    "source_sequence": "...",
    "observed_sequence": "...",
    "ordering_basis": "source_sequence|event_time|observed_time|none",
    "ordering_complete": false
  },
  "sampling": {"sampled": false, "coverage_known": false},
  "integrity": {"digest_valid": false, "scope": "delivered_file_only"}
}
```

`trace_id`, `span_id`, and baggage must never be treated as the sole authoritative event identity. A `trace_id` join is evidence of association only. `source_event_id`/source sequence, complete query coverage, and independent destination read-back are required for positive continuity.

## Deterministic S9 acceptance vectors

| ID | Fixture facts | Expected verdict | Forbidden upgrade |
|---|---|---|---|
| S9-1 | Authoritative source event ID and monotonic source sequence present; all records in `[t0,t1)` read back; digest/integrity valid; no gaps | `VERIFIED_CONTINUITY` | None |
| S9-2 | Trace ID present on producer and consumer records, but no authoritative source event ID/sequence or complete query proof | `UNKNOWN` | Trace join is not continuity |
| S9-3 | Trace context absent downstream; source/export/query coverage otherwise not independently complete | `QUERY_GAP` or `UNKNOWN` per published precedence | Missing propagation is not `NO_EVENT` |
| S9-4 | Baggage member is missing because propagation size limit/intermediary drop is documented; authoritative event records remain complete | `UNKNOWN` for baggage continuity, not event absence | Baggage absence is not `DROPPED` event evidence |
| S9-5 | Sampling flag says not sampled or coverage is unknown; query is empty | `UNKNOWN` | Empty sampled trace is not `NO_EVENT` |
| S9-6 | Source sequence has a gap `[101,103]` and no authoritative explanation | `QUERY_GAP` | Wall-clock adjacency cannot fill sequence gap |
| S9-7 | Event timestamps are out of order but source sequence and complete read-back are valid | `VERIFIED_CONTINUITY` | Do not classify solely from timestamp ordering |
| S9-8 | Digest validates delivered files, but source coverage is unknown | `UNKNOWN` | Digest integrity is not capture completeness |
| S9-9 | Export rejection explicitly names event IDs; source receipt exists but destination lacks those IDs | `DROPPED` | Receipt does not override explicit rejection |
| S9-10 | Producer receipt exists; no destination read-back; identity and query coverage incomplete | `UNKNOWN` | Transport receipt is not final continuity |

## Deterministic procedure

1. Validate `operation_id`/source identity syntax and bind records to a fixed source, region, signal, policy revision and half-open time window.
2. Prefer authoritative source IDs and source sequence/cursor. Use trace/span/baggage only as correlation fields with explicit trust labels.
3. Evaluate sampling and propagation coverage before accepting empty results.
4. Evaluate explicit rejection/drop/exporter failure and sequence/query gaps.
5. Validate integrity only within its stated scope (for example, delivered-file bytes).
6. Require complete destination read-back and all required source partitions before `VERIFIED_CONTINUITY`.
7. Preserve raw contradictory evidence; unresolved cases remain `UNKNOWN`.

## Cannot prove

This slice does not prove that trace context propagates through a particular deployment, that sampling is disabled, that all records share a trace, that a valid digest covers all expected events, or that a correlated event caused an external business commit. Official standards define formats and boundaries; deployment attestations and independent read-back remain necessary.
