# S17 summary

- Verified: trace context/baggage are correlation carriers, OTel logs expose event fields, DSSE authenticates signed payloads.
- Inferred: identity, correlation and authenticity must be separate from delivery, retention and target-effect evidence.
- Unknown: complete propagation, lossless export, global uniqueness, external commit and production continuity.
- Six deterministic vectors are in `report.md`, including duplicate, conflict, exporter failure, query gap, retention expiry and authenticated-but-uncommitted states.
