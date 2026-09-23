# Summary

## Verified from official sources

- Event time and observation time are distinct in OpenTelemetry Logs.
- OTLP has explicit request/response, partial-success, retryable, and non-retryable failure semantics; protocol success is a bounded transport fact.
- Collector queues can overflow/drop; retry windows can expire; WAL improves restart behavior but does not remove all loss conditions.
- CloudTrail Event History is regional, management-event scoped, and limited to 90 days; CloudTrail digests support integrity validation after delivery.
- Kubernetes auditing records activity subject to configured policy/backend; Temporal Event History is platform-created workflow event history.

## Inferred design

Use a typed evidence-window record with separate event, observation, export, query, identity, sequence/cursor, retention, integrity, gap, and verdict fields. Evaluate coverage/failure gates before positive results. Treat an empty result as `NO_EVENT` only after proving active source, complete query, valid retention, and integrity/coverage; otherwise use `UNKNOWN`, `QUERY_GAP`, or `RETENTION_EXPIRED`.

## Deterministic acceptance labels

`NO_EVENT`, `DELAYED`, `DROPPED`, `EXPORTER_FAILURE`, `QUERY_GAP`, `RETENTION_EXPIRED`, `VERIFIED_CONTINUITY`, and `UNKNOWN` are mutually explicit outcomes in the S7 vectors. Raw facts must be retained so a later reconciliation can distinguish “not observed” from “not emitted” and “not retained.”

## Boundary

This is a design and evidence-semantic result, not production validation. No official source inspected here proves that any particular deployment is lossless, complete, exactly-once, or externally committed.
