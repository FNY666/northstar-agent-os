# Cross-system evidence-window schema and continuity acceptance — S12

**Access date:** 2026-09-22 UTC. **Scope:** official first-party public documentation only. This slice focuses on temporal boundaries, exporter buffering, audit overflow, integrity chains, and multi-signal acceptance.

## Verified evidence

- OpenTelemetry Collector resiliency documentation distinguishes in-memory sending queues, persistent WAL, retry backoff/maximum elapsed time, queue capacity, and data-loss scenarios when queues overflow or a collector crashes without persistence.
- Kubernetes auditing documents chronological audit records, configurable audit policy, webhook retries/backoff, batching, and explicit event dropping when the batch buffer overflows.
- AWS CloudTrail digest documentation says digest files reference and hash delivered log files and chain signatures; validation supports detecting modification/deletion of delivered files. This is file integrity evidence, not proof that all source activity was logged.
- GitHub Actions workflow-run API documents paginated results with a maximum page size, while artifact API records include `expires_at` and `digest`; these fields separate query completeness and retained-file integrity.
- OpenTelemetry configuration and signal-model documentation distinguish pipeline components and signal data-model semantics; metric streams and log/event records cannot be treated as interchangeable event evidence.

## Evidence-window fields reinforced

```json
{
  "window": {"start":"...","end":"...","timezone":"UTC","clock_basis":"..."},
  "source_scope": {"region":"...","partition":"...","tenant":"...","policy_revision":"..."},
  "export": {"attempts":[],"queue_depth_samples":[],"retry_deadline":"...","overflow_count":0,"wal_or_durable":false},
  "query": {"pages":[],"cursor_chain":[],"page_limit":100,"complete":false},
  "retention": {"available_from":"...","expires_at":"...","checked_at":"..."},
  "integrity": {"artifact_digest":"...","chain_valid":false,"scope":"delivered_files_only"},
  "signals": {"logs":{},"metrics":{},"audit":{},"workflow":{}},
  "verdict":"UNKNOWN"
}
```

## Deterministic acceptance vectors

| ID | Fixture facts | Expected verdict | Reason |
|---|---|---|---|
| S12-1 | Collector export retry succeeds before deadline; no overflow; destination query complete; independent event count/hash read-back matches source | `VERIFIED_CONTINUITY` | All layers covered |
| S12-2 | Downstream unavailable until retry deadline; queue reaches capacity; official counter says new data dropped | `DROPPED` | Explicit loss evidence |
| S12-3 | Collector crashes with only in-memory queue and unflushed batch | `EXPORTER_FAILURE` or `DROPPED` | Export failure plus loss fact; retain both raw facts |
| S12-4 | Collector has WAL, restarts, replays all queued batches, destination read-back complete and matches | `VERIFIED_CONTINUITY` | Durable replay independently verified |
| S12-5 | Kubernetes audit webhook batch buffer overflow counter >0 during window | `DROPPED` | Audit docs explicitly define overflow drop |
| S12-6 | CloudTrail digest chain validates delivered files, but trail coverage/policy window is unknown | `UNKNOWN` | Integrity is not completeness |
| S12-7 | GitHub workflow-run query returns first page only; total may exceed page limit and no next-page proof | `QUERY_GAP` | Incomplete query |
| S12-8 | Artifact `expires_at` precedes requested evidence window; no alternate retained copy | `RETENTION_EXPIRED` | Evidence unavailable |
| S12-9 | Logs show no record, metrics show no matching count, but source sampling/policy/export coverage is unknown | `UNKNOWN` | Absence is unproven |
| S12-10 | Logs and metrics agree, but one region/partition was not queried | `QUERY_GAP` | Scope incomplete |
| S12-11 | Export receipt is successful, but destination read-back is absent after timeout | `UNKNOWN` | Receipt is not target continuity |
| S12-12 | All source partitions have contiguous sequence/cursor coverage, no drop/error counters, retention valid, destination digest/read-back matches | `VERIFIED_CONTINUITY` | Positive gate satisfied |

## Status precedence

Evaluate hard negative/coverage gates before interpreting absence: `RETENTION_EXPIRED` and `QUERY_GAP` when evidence is unavailable/incomplete; `DROPPED` when explicit loss is recorded; `EXPORTER_FAILURE` when export failed but loss is not established; `DELAYED` when the item is outside the observation point but inside a valid retry/retention window; `NO_EVENT` only when source coverage, export, query, retention, and integrity gates pass and the authoritative source reports no event; `VERIFIED_CONTINUITY` only for a complete positive read-back; otherwise `UNKNOWN`.

## Cannot prove

No source proves that a particular deployment has complete policy coverage, synchronized clocks, lossless export, complete page traversal, valid retention, or exactly-once external effects. S12 is an official-source design/fixture result, not production validation.
