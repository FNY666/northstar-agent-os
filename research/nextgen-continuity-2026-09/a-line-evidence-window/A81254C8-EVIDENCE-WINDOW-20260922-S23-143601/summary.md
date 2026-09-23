# S23 summary

Separate syntax (`event_time`), observation (`observed_at`), source/query windows, coverage, retention, completeness and postcondition. Schema validation is necessary but never sufficient for continuity. Fail closed: incomplete query/expired retention/absent attestation cannot yield `NO_EVENT` or `VERIFIED_CONTINUITY`.
