# Next-slice dispatch

- Dispatch ID: A81254C8-NEXT-20260922
- Parent slice: A81254C8-RECOVERY-EVIDENCE-20260922
- Dispatch time: 2026-09-22
- Scope: public official first-party documentation only; no private accounts, credentials, real service calls, shared targets, or shared directories.
- Non-overlap constraint: do **not** repeat recovery evidence/reconciliation, Temporal Event History, Kubernetes Job/Pod status/events, AWS Step Functions history/redrive/logging, lease expiry, heartbeat, or fencing-token lines.

## Selected independent narrow question
**Agent runtime reliability: durable backpressure and admission control semantics—what official queue/workflow platforms record when work is accepted, rejected, delayed, rate-limited, or expired, and how to distinguish admission receipt from execution receipt?**

## Why this is distinct and useful
The completed slice studies post-dispatch recovery evidence and ambiguous external effects. This slice instead studies the earlier boundary: whether work entered a runtime at all, queue acceptance versus rejection, queue delay/visibility/expiration, and overload behavior. It serves reliable Agents by preventing false claims that a client-side enqueue return means work ran, without reusing the prior recovery evidence topics.

## Suggested official primary sources
1. Apache Kafka official producer delivery/acks/idempotence and record metadata docs (accepted by broker vs consumed/processed).
2. Amazon SQS official SendMessage/ReceiveMessage visibility and FIFO deduplication docs (send receipt vs consumer processing).
3. NATS JetStream official publish acknowledgements/consumer ack/retention docs, if accessible.
4. One additional official queue with explicit admission semantics, e.g. RabbitMQ publisher confirms (official docs).

## Required evidence ledger fields
For every source: complete URL; access date 2026-09-22; verified/inferred/unknown; direct proof; cannot-prove boundary; version/retention/freshness caveat. Do not treat producer/broker acknowledgement as downstream business commit, and do not use benchmark results as production evidence.

## Deliverables
Write to a new isolated `/tmp/A81254C8-<TOPIC>-20260922-<timestamp>/`: `report.md`, `sources.md`, `summary.md`, `research-manifest.json` when applicable, `SHA256SUMS`, and this dispatch record. Validate existence, nonzero size, SHA256, and manifest schema before reporting.
