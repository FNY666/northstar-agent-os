# S14 summary

- **Verified:** telemetry and workflow systems expose different identities and status layers; no one ID is a universal exactly-once proof.
- **Inferred:** bind deduplication to `operation_id + target_fingerprint + args_hash + policy_revision`; distinguish duplicate, conflict, query gap and unknown.
- **Unknown:** global uniqueness, full sampling, external commit and production continuity.
- **Vectors:** S14-1 through S14-7 in `report.md`.
