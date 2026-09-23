# Next-slice dispatch

- dispatch_id: `A81254C8-NEXT-IDEMPOTENCY-20260922`
- dispatched_at: `2026-09-22T03:18:00+08:00`
- status: `ready-for-independent-execution`
- scope: public first-party sources only; no private accounts, credentials, real services, shared targets, prior-slice directories, or restricted paths.

## Narrow next research question (non-overlapping)

**Agent runtime idempotency-key lifecycle and crash-safe deduplication: how to make business side effects retry-safe across worker crash, broker redelivery, timeout ambiguity, and multi-step tool calls.**

## Explicit non-overlap boundary

Do **not** research queue admission, backpressure, rate limiting, visibility timeout, retention, expiry, publisher/consumer receipts, or overload rejection as primary topics. Those are covered by the current slice. Only mention them as trigger conditions for retries when necessary.

## Required first-party evidence targets

Compare official specifications/docs/source for at least two of: Stripe idempotency keys, HTTP Idempotency-Key RFC (IETF), Temporal workflow/activity retry/idempotency docs, AWS Powertools idempotency docs/source, PostgreSQL transactional outbox docs/source if official. Verify key scope, persistence, replay response, conflict handling, TTL/pruning, crash windows, atomicity, and limits. Separate platform deduplication from business-side effect idempotency; do not claim exactly-once external effects unless explicitly proved.

## Required outputs

Create a new timestamped isolated directory under `/tmp/` (not this directory), containing `report.md`, `sources.md`, `summary.md`, `research-manifest.json`, `SHA256SUMS`, and its own `next-slice-dispatch.md`. Record URL, access date 2026-09-22, verified/inferred/unknown, proof/non-proof boundary, versions and freshness limits. Validate existence, nonzero sizes, SHA256, and manifest parse/artifact match.