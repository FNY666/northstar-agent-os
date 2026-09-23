# S20 report — deterministic evidence-window acceptance vectors

**Date/access:** 2026-09-22, official AWS/Kubernetes/GitHub pages fetched and read. **Evidence level:** verified for documented mechanisms; inferred for the cross-system schema; unknown for production completeness.

## Schema
Each evidence window should carry: `window_id`, `source_system`, `event_id` (or explicit `NO_EVENT` basis), `operation_id`, `target_fingerprint`, `policy_revision`, `observed_at`, `event_time`, `ingest_time`, `query_started_at`, `query_completed_at`, `cursor/resource_version`, `page_complete`, `retention_valid`, `integrity_status`, `exporter_status`, `postcondition_status`, and `state`.

A state is accepted only if its predicate is satisfied; missing predicates force `UNKNOWN`.

## Deterministic vectors
1. `NO_EVENT`: query complete; all pages/cursors consumed; retention valid; no authorization/consistency error; independent source health OK; zero matching event IDs. Otherwise not NO_EVENT.
2. `DELAYED`: event ID is later observed with event/ingest time after the query window or outside the expected latency bound; do not classify the earlier empty result as NO_EVENT.
3. `DROPPED`: authoritative producer/exporter counter or sequence proves an expected record was not delivered; retain predecessor/successor and loss reason. A mere query gap is not DROPPED.
4. `EXPORTER_FAILURE`: exporter/queue/WAL reports failed, exhausted, or irrecoverable delivery; absent target event remains UNKNOWN unless loss is explicitly proven.
5. `QUERY_GAP`: pagination incomplete, cursor/resourceVersion invalidated, API error, permission filter, or query boundary not fully covered. Empty result is UNKNOWN/QUERY_GAP.
6. `RETENTION_EXPIRED`: requested interval exceeds documented/observed retention, or source says records are unavailable due to expiry. Absence is not NO_EVENT.
7. `VERIFIED_CONTINUITY`: complete query + valid retention + integrity checks + producer/exporter health + matching event IDs/sequence + independent target postcondition. Platform receipt alone fails.
8. `UNKNOWN`: any conflicting, missing, delayed-without-readback, timeout/cancel, or unclassified condition.

## Cross-system invariants
- `event_time` is not `ingest_time`; preserve both and report clock uncertainty.
- Trace/baggage correlation is a join aid, not authorization or proof of delivery.
- CloudTrail digest validation proves log-file integrity after delivery, not business completion; Kubernetes/GitHub/Temporal query success is not universal completeness.
- Never downgrade UNKNOWN to NO_EVENT because a dashboard is empty.

## Cannot prove
These official mechanisms do not establish a universal exactly-once external effect, complete production coverage, absence of sampling, or recovery of a missing record without source-specific authoritative evidence.
