# Next slice dispatch

- Time: 2026-09-22
- Status: dispatched immediately after first slice validation
- Topic: cancellation/timeout/disconnect UNKNOWN, retry idempotency, compensation
- Scope: public official sources only; isolated /tmp output only; no shared/P0/production/credentials
- Required distinctions: cancellation vs termination; retry may duplicate external effects; idempotency key lifetime and argument binding; compensation is not proof of undo; UNKNOWN requires authoritative query/reconciliation.
