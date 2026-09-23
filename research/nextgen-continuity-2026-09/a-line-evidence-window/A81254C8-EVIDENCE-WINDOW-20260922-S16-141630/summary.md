# S16 summary

- **Verified:** Temporal/AWS/Stripe provide different execution-history, retry/redrive and idempotency semantics; none alone proves external exactly-once.
- **Inferred:** use fail-closed state transitions and require target read-back/postcondition for `VERIFIED_CONTINUITY`.
- **Unknown:** timeout/cancel/retry/redrive outcomes without authoritative target evidence.
- **Vectors:** 1–8 in `report.md`; states cover all requested continuity labels and keep `NO_EVENT` narrowly gated.
