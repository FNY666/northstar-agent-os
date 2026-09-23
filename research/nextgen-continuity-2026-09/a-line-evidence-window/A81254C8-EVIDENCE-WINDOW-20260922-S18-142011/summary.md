# S18 summary

S18 consolidates a cross-signal state machine. The key rule is that each of emission, transport, exporter persistence, query visibility, target postcondition and coverage completeness is an independent axis. It supplies deterministic classification vectors for all requested states: `NO_EVENT`, `DELAYED`, `DROPPED`, `EXPORTER_FAILURE`, `QUERY_GAP`, `RETENTION_EXPIRED`, `VERIFIED_CONTINUITY`, and `UNKNOWN`. Empty results, exporter receipts and platform success must not be upgraded into continuity without authoritative scope and target read-back.
