# Summary

S10 adds cross-signal evidence and negative counters. OTLP acknowledgement, Collector queue/retry metrics, Kubernetes audit export counters, metric temporality, and artifact digests each prove only their bounded layer. The schema must keep transport, buffer, query, retention, integrity, and destination read-back separate.

## Verified

- OTLP explicitly distinguishes full/partial/retryable/non-retryable outcomes and drop behavior.
- Collector and Kubernetes official docs describe retry, overflow, exporter errors, and loss counters.
- Metrics have stream semantics (temporality/resets/gaps) distinct from event records.
- Artifact expiry and digest are separate from workflow/log coverage.

## Inferred

Use the proposed precedence and vectors to classify `NO_EVENT`, `DELAYED`, `DROPPED`, `EXPORTER_FAILURE`, `QUERY_GAP`, `RETENTION_EXPIRED`, `VERIFIED_CONTINUITY`, and `UNKNOWN` deterministically. Require complete source partitions plus independent destination read-back for a positive verdict.

## Boundary

No production system was accessed. No source proves a particular deployment is lossless, complete, exactly-once, or externally committed.
