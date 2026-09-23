# S23 — evidence-window schema structure

## Scope
Official IETF RFC 3339 and JSON Schema 2020-12 documentation, accessed 2026-09-22. This is a schema-design slice, not a production audit.

## Deterministic record shape
A record SHOULD carry: `schema_version`, `operation_id`, `source_id`, `event_time`, `observed_at`, `source_window`, `query_window`, `status`, `evidence_hash`, `coverage`, `query_completeness`, `retention_valid`, `cannot_prove`. Timestamps MUST be syntactically valid RFC 3339 values; they do not establish causal order.

## Acceptance vectors
1. Valid RFC3339 `event_time` + complete query + valid retention + matching hash + independent postcondition => eligible for `VERIFIED_CONTINUITY`.
2. Invalid timestamp => reject schema, never downgrade to `NO_EVENT`.
3. Empty result with `query_completeness=false` => `QUERY_GAP`, not `NO_EVENT`.
4. Empty result outside retention => `RETENTION_EXPIRED`, not `NO_EVENT`.
5. Valid schema with missing source attestation => `UNKNOWN`.
6. Structural JSON validation passing without read-back => not `VERIFIED_CONTINUITY`.

## Boundaries
Verified: timestamp and structural validation semantics. Inferred: the proposed field separation and fail-closed mapping. Unknown: clock synchronization, event-generation completeness, sampling, delivery and external business effects.
