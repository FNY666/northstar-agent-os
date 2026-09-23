# S15 Exporter health and evidence-window verdicts

**Access date:** 2026-09-22 UTC. Official first-party public documentation only.

## Verified
- OpenTelemetry Collector resiliency documentation describes queues, retry and persistent storage/WAL-style mechanisms as configuration choices; these mechanisms improve delivery behavior but do not turn an exporter into an omniscient source ledger.
- OTLP defines transport/protocol response semantics and partial-success concepts; a transport response is not equivalent to complete source coverage or business commit.
- GitHub workflow logs and artifacts are separate queryable resources with their own availability/retention behavior; a run status does not prove both are complete or present.

## Deterministic export-state vectors
- S15-1 source sequence complete; exporter queue drained; destination read-back contains every expected sequence: `VERIFIED_CONTINUITY`.
- S15-2 exporter retry active before declared deadline; destination missing expected sequence: `DELAYED`.
- S15-3 exporter reports permanent drop/rejection with no durable retry and no source replay: `DROPPED`.
- S15-4 exporter process/transport failure and no queue/read-back evidence: `EXPORTER_FAILURE` (not `NO_EVENT`).
- S15-5 OTLP partial success or ambiguous response with absent per-item reconciliation: `UNKNOWN`.
- S15-6 queue drained but source coverage interval itself is unknown: `QUERY_GAP`.
- S15-7 logs unavailable due retention while event time is within requested historical window: `RETENTION_EXPIRED`.
- S15-8 run is successful but logs/artifacts cannot be independently read back: `UNKNOWN`.

## Acceptance record
Record `source_expected_count`, `source_sequence_range`, `queue_depth`, `retry_state`, `drop_count`, `export_attempts`, `destination_query_range`, `destination_count`, `read_back_at`, and `retention_deadline`. Verdict computation must fail closed when any required counter is absent or inconsistent.

## Cannot prove
Vendor queue/retry/transport documentation cannot prove a particular deployment's queue durability, source completeness, absence of drops, or external side effect. These need independent counters, source replay/read-back and reconciliation.
