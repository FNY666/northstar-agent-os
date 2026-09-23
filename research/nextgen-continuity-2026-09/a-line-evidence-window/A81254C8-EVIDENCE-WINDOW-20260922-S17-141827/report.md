# S17 Evidence envelope and correlation

Access date: 2026-09-22. Sources are official/public first-party material only.

## Findings

1. **Verified / W3C Trace Context:** trace context provides propagation fields and processing rules for distributed tracing. A trace identifier is a correlation handle, not proof that every event was emitted, retained, exported, queried, or that an external effect committed.
2. **Verified / W3C Baggage:** baggage is application-defined propagated context. It may be changed or removed in transit and is not an authorization or integrity proof. It must not be treated as durable evidence.
3. **Verified / OpenTelemetry logs:** log records have timestamps and optional trace/span correlation fields, but the data model does not guarantee complete collection, delivery, retention, or query visibility.
4. **Verified / DSSE:** an envelope can bind a payload to signatures, but signature verification authenticates the signed statement; it does not prove the underlying operation was correct, complete, or externally committed.

## Deterministic acceptance vectors

- S17-1: same `operation_id`, same target fingerprint, same normalized-args hash, same policy revision, two records -> classify `DUPLICATE`, not two successful effects.
- S17-2: same operation ID but different target or args hash -> `CONFLICT`; never merge.
- S17-3: trace/span ID present in target log but exporter receipt absent -> `UNKNOWN` or `EXPORTER_FAILURE`, never `VERIFIED_CONTINUITY`.
- S17-4: baggage differs between hops -> correlation uncertainty; preserve the independently authenticated event ID and classify `QUERY_GAP` if no authoritative read-back exists.
- S17-5: valid signature over an event whose target postcondition is absent -> authenticated evidence only; effect remains `UNKNOWN`.
- S17-6: complete source-side events but a retention/query window excludes the target interval -> `RETENTION_EXPIRED` or `QUERY_GAP`, not `NO_EVENT`.

## Boundaries

These sources support correlation, propagation, and authenticated-envelope design. They do not establish global uniqueness, lossless sampling, complete retention, exactly-once external effects, or production continuity. Those remain `inferred` design rules or `unknown` until independently verified by target read-back and coverage accounting.
