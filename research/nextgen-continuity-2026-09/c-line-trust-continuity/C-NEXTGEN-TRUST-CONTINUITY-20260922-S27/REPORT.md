# S27 trust-continuity research report

## Scope and guardrails

This is a **synthetic-only, offline** research slice (`synthetic_only=true`, `production_verified=false`). No network, real service, SDK, credential, production input, or external effect was used. Inputs are fixtures and the deterministic evaluator in this directory. The prohibited paths and S1–S26 were not read or written.

## Question

When may an observer quorum and revocation watermark jointly close continuity during a recovery window that includes retention boundaries and crash/restart uncertainty?

## Model

The mutually exclusive output states are `RECOVERED`, `UNKNOWN`, and `REJECT`.

`RECOVERED` is emitted only when all gates are true: (1) threshold quorum is present, including both 2-of-3 and 3-of-5 forms; (2) observer IDs are independent, so repeating one observer never raises the count; (3) watermark samples are nondecreasing across and within epochs and have reached the revocation watermark; (4) crash/restart reconciliation is closed; (5) platform receipt, durable log, and external-effect confirmation each exist exactly once in the fixture and carry the same commit digest; and (6) retention and query coverage are closed.

Missing/split quorum, partition-stale quorum, a lagging revocation watermark, cross-epoch rollback, duplicate observer, unknown post-crash commit, duplicate receipt, retention expiry, query gap, missing evidence, or inconsistent evidence cannot upgrade to `RECOVERED`; they remain `UNKNOWN` unless an explicit irreconcilable hard conflict is designated, which is `REJECT`.

## Synthetic observations

There are 13 cases: one recovered 2-of-3 case; missing 3-of-5 quorum; duplicate observer; stale partition quorum; cross-epoch watermark regression; crash/post-commit unknown; crash/restart duplicate receipt; expired retention; query gap; missing evidence; explicit hard conflict; and inconsistent 3-of-5 split evidence; plus a separate cross-epoch rollback case. Classification fixtures cover `NO_EVENT`, `DELAYED`, `DROPPED`, `EXPORTER_FAILURE`, `QUERY_GAP`, `RETENTION_EXPIRED`, `VERIFIED_CONTINUITY`, and `UNKNOWN`.

## Verification

`harness.py` runs a deterministic 256-combination property sweep over eight gates. The property is: no `RECOVERED` result is possible if any required gate is false. A one-gate minimizer identifies each individual gate as a smallest non-recovery witness. The harness is run twice and output bytes are compared with `cmp`; local validators, the official offline `validate_research.py`, and SHA256 verification are run after final hash refresh.

## Findings and limits

The result is a finite model invariant, not an empirical production result. It cannot prove production durability, exactly-once behavior, rollback safety, real external effects, or production readiness. In particular, matching synthetic evidence classes do not establish that a real platform receipt, durable write, or external effect occurred. Completion of this slice does not mean stop-line; future work must remain independently scoped.

## Next independent slice suggestion

Run a separately named offline slice on **evidence provenance equivocation under observer membership churn**: model observer add/remove epochs, signed-but-conflicting receipts, delayed revocation acknowledgements, and bounded query replay. Keep the same three-state fail-closed contract, but do not reuse this directory's fixtures or infer production behavior.
