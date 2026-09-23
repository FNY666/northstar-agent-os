# Next-slice dispatch

- dispatch_id: `A81254C8-NEXT-RECONCILIATION-20260922`
- dispatched_at: `2026-09-22T03:50:00+08:00`
- status: `ready-for-independent-execution`
- scope: public first-party sources only; no private accounts, credentials, real services, shared targets, prior-slice directories, or restricted paths.

## Narrow next question

How should an Agent runtime implement durable reconciliation and manual-review gates when authoritative target queries are eventually consistent, incomplete, or unavailable, without turning UNKNOWN into false success or unsafe compensation?

## Non-overlap boundary

Do not repeat transactional outbox atomicity, CDC routing, generic inbox deduplication, or basic idempotency-key lifecycle. Focus on reconciliation evidence freshness, read-after-write uncertainty, authoritative versus advisory receipts, bounded polling, conflict states, manual review, and compensations only after confirmed commit.

## Required outputs

Use a new isolated `/tmp/A81254C8-RECONCILIATION-20260922-<timestamp>/` directory. Include `report.md`, `sources.md`, `summary.md`, `research-manifest.json`, `SHA256SUMS`, and this file. Validate existence, nonzero sizes, SHA256, and manifest schema. Official sources only; record URL, access date, evidence level, proof/non-proof boundary, versions, and freshness limits.