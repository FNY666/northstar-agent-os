# Cross-system evidence-window schema and continuity acceptance — S13

**Access date:** 2026-09-22 UTC. **Scope:** official first-party public documentation only. This slice addresses event-time versus observation-time, clock uncertainty, ordering, metric temporality, and deterministic delayed/no-event classification.

## Verified evidence

- OpenTelemetry Logs distinguish `Timestamp` (event occurrence) from `ObservedTimestamp` (observation by the collection system); either can be absent or have different semantics.
- OpenTelemetry common time guidance uses nanosecond Unix time and requires implementations to account for timestamp semantics rather than silently treating all timestamps as one clock.
- OpenTelemetry Metrics model distinguishes data-point time fields and temporality/resets; metrics are stream observations, not an ordered event ledger.
- W3C Trace Context defines propagation identifiers and interoperability fields, but it does not establish global event ordering or effect completion.
- AWS CloudWatch metric publishing documentation describes timestamp bounds/acceptance rules for published metric data; acceptance by a metric service is not a proof of source event completeness.

## Schema fields

```json
{"event_time":"...","observed_time":"...","ingest_time":"...","export_time":"...","query_time":"...","clock_basis":"UTC/monotonic/source-clock","uncertainty_ms":0,"ordering":"source-sequence|timestamp-only|unknown","temporality":"delta|cumulative|gauge|unknown","late_arrival_deadline":"...","verdict":"UNKNOWN"}
```

## Deterministic vectors

| ID | Fixture facts | Expected |
|---|---|---|
| S13-1 | Event timestamp is inside window; observed/export/query times valid; source sequence contiguous and read-back matches | `VERIFIED_CONTINUITY` |
| S13-2 | Event is outside observation cutoff but inside retention/retry deadline; exporter has not yet delivered it | `DELAYED` |
| S13-3 | Event has old event time but observation arrives inside window; policy uses observation time | `DELAYED` or in-window according to declared policy, never implicit |
| S13-4 | Timestamp differs across systems beyond declared clock uncertainty; no authoritative sequence | `UNKNOWN` |
| S13-5 | Cumulative metric resets with no reset marker or restart metadata | `UNKNOWN`/`QUERY_GAP`, not a zero event count |
| S13-6 | Gauge has no event identity/sequence and reads zero during window | `NO_EVENT` forbidden; use `UNKNOWN` unless source contract proves absence |
| S13-7 | Trace identifier correlates records but sample decision is unknown | `UNKNOWN`/`QUERY_GAP`, not `NO_EVENT` |
| S13-8 | Source sequence has missing interval and no explicit drop/retention explanation | `QUERY_GAP` |
| S13-9 | All timestamps satisfy declared bounds but destination read-back absent | `UNKNOWN` |
| S13-10 | Valid late arrival is observed after initial empty query and before deadline | initial `DELAYED`; after complete read-back `VERIFIED_CONTINUITY` |

## Status rule

A window must declare which time axis controls inclusion. Never use a timestamp alone to infer absence across unsynchronized clocks. `NO_EVENT` requires an authoritative source absence result plus valid coverage; an empty metric/gauge/trace query is insufficient. `DELAYED` is a temporal state, not success.

## Cannot prove

No cited source proves clock synchronization, universal ordering, complete sampling, or deployment-wide absence. No source turns a metric acceptance or trace correlation into external-effect continuity.
