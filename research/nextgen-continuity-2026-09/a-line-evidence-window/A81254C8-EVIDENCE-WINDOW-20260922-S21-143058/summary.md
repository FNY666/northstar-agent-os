# S21 summary

S21 isolates partial-success and exporter-failure semantics. Protocol acceptance, queue admission, or retry scheduling is not `VERIFIED_CONTINUITY`; it must be paired with complete query, retention/integrity checks, ID/sequence reconciliation, and independent postcondition. `DROPPED` requires explicit loss evidence. Otherwise classify as `QUERY_GAP`, `EXPORTER_FAILURE`, or `UNKNOWN` according to the observed predicate.

- verified: cited OTLP/Collector/OTel Logs semantics.
- inferred: cross-system evidence schema and deterministic vectors S21-1..S21-8.
- unknown: production completeness, exactly-once external effects, sampling, and target state.
