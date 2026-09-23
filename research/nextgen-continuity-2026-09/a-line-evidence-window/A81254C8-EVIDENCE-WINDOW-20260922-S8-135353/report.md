# Cross-system evidence-window schema and deterministic continuity acceptance — S8

**Access date:** 2026-09-22 UTC. **Scope:** official first-party public documentation only. This slice focuses on query completeness, pagination/cursors, resource versions, retention and platform-history boundaries.

## New verified evidence

1. **Kubernetes list/watch query gaps are observable, not empty results.** Official API Concepts documents paginated list continuation tokens, token expiry, and HTTP 410 `Gone` when a continuation cannot be used; it also documents resource-version availability and possible timeout/retry behavior. Therefore a failed/expired cursor or unavailable resource version must be represented as `QUERY_GAP` (or `UNKNOWN` if the cause cannot be established), not as `NO_EVENT`.
2. **Kubernetes audit buffering can drop events.** The official Auditing page documents bounded webhook buffering and that events are dropped when incoming rate overflows the buffer. An audit backend configuration must therefore expose `DROPPED` evidence rather than silently treating the queried stream as complete.
3. **GitHub Actions artifacts have explicit expiry metadata.** The official REST Artifacts documentation exposes `expired`, `expires_at`, and `digest` fields. An artifact unavailable because it is expired is `RETENTION_EXPIRED`; an available artifact with matching digest is an integrity fact, not proof that every run/job/log existed.
4. **CloudTrail Event History is scoped.** AWS documents the viewable/searchable/downloadable/immutable record of the past 90 days of management events in an AWS Region. A query outside that age, region, or event class is a coverage failure, not `NO_EVENT`.
5. **Temporal history and visibility are different evidence planes.** Temporal documents a Workflow Execution as a sequence of service-created Events and documents history limits/continue-as-new; Visibility is a separate search/list plane. A visibility query result cannot silently substitute for complete event history.

## Deterministic S8 acceptance vectors

All fixtures use half-open window `[t0,t1)`, fixed source/region/signal identity, and policy revision. Missing required metadata is a failing fixture, not a default false.

| ID | Fixture | Expected | Prohibited interpretation |
|---|---|---|---|
| S8-1 | Kubernetes paginated list returns a continuation token; token expires and next request returns 410; no authoritative restart-from-beginning query | `QUERY_GAP` | Empty/partial page is not `NO_EVENT` |
| S8-2 | Kubernetes watch uses a resourceVersion no longer available; server returns 410; restart/read-back not completed | `QUERY_GAP` | 410 is not no events |
| S8-3 | Kubernetes audit webhook buffer overflows and official audit status/metrics identify dropped events overlapping window | `DROPPED` | Do not label `EXPORTER_FAILURE` without discard evidence |
| S8-4 | GitHub artifact has `expired=true` or current time ≥ `expires_at`; artifact is required evidence for window | `RETENTION_EXPIRED` | Do not infer `NO_EVENT` |
| S8-5 | GitHub artifact is available and digest matches, but run/job/log/artifact coverage is not complete | `UNKNOWN` | Digest match is not continuity |
| S8-6 | CloudTrail lookup is restricted to one region while requested scope is multi-region | `QUERY_GAP` | Regional empty result is not global `NO_EVENT` |
| S8-7 | CloudTrail requested event is older than 90-day Event History scope and no retained trail/event-data-store evidence exists | `RETENTION_EXPIRED` | Absence from Event History is not no event |
| S8-8 | Temporal Visibility says no matching workflow; authoritative Event History/read-back is unavailable or history was continued-as-new without linked coverage | `UNKNOWN` | Visibility empty is not complete history |
| S8-9 | Every partition/page/region is queried; cursors terminate normally; retention valid; integrity and source-active proofs valid; expected IDs and destination read-back match | `VERIFIED_CONTINUITY` | No upgrade if any hidden partition or page remains |
| S8-10 | Same as S8-9 except an event is observed after the declared bound but later read-back confirms it | `DELAYED` | Do not call it within-window continuity |

## State decision procedure

1. Validate schema, identity, boundary, policy revision, clocks and raw evidence references.
2. Check retention and query coverage: expired/unsupported window → `RETENTION_EXPIRED`; incomplete page/cursor/region/partition/resource-version → `QUERY_GAP`.
3. Check explicit discard/rejection/overflow → `DROPPED`; exporter failure without discard and without read-back → `EXPORTER_FAILURE`.
4. Check known late observation → `DELAYED`.
5. Check complete authoritative empty result with active source, valid retention, complete query and no gaps → `NO_EVENT`.
6. Check complete positive records plus integrity and independent destination read-back → `VERIFIED_CONTINUITY`.
7. Any conflict or missing proof → `UNKNOWN`.

These are design rules inferred from documented boundaries, not a universal vendor-mandated schema. Raw facts must remain immutable so a later reconciliation can revise an `UNKNOWN` without rewriting history.

## Cannot prove

This slice does not prove any deployment has complete pagination, valid resource versions, sufficient audit buffers, configured retention, complete cross-region coverage, or durable external effects. Official APIs/documentation define behavior and limits; only deployment-specific read-back and independent coverage evidence can support `VERIFIED_CONTINUITY`.
