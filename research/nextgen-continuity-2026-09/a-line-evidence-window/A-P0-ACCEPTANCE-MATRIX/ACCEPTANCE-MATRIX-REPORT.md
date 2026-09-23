# A-P0 Acceptance Matrix

## Scope

This is an isolated, offline, synthetic continuation of the A line. It reads no production target and performs no network, service, systemd, credential, canonical, tri-line, or shared-P0 operation.

## Decision

The matrix has ten acceptance items and 1024 combinations of evidence flags. It is a decision-rule test, not production evidence.

- Items 1, 4, and 9 can be decided from direct contract/negative evidence: malformed or unauthorized contract rejection, target mismatch rejection, and complete rollback coverage.
- Items 2, 3, 7, and 8 require E3 evidence: independent authoritative readback/postcondition. A request, receipt, audit row, or producer report is insufficient.
- Items 5 and 6 remain `UNKNOWN`: a send without response and an audit/receipt without business-state readback do not establish effect.
- Item 10 is only `CONDITIONAL`: a hash binds bytes, not semantic correctness, authorization, or proof that the runtime used those bytes.

## Evidence levels

- `E1`: direct contract or explicit negative proof.
- `E2`: request, platform receipt, audit, or producer evidence; useful for correlation but not effect proof.
- `E3`: independent external readback/postcondition from the authoritative target.

## D1 and production front door

A D1 opt-in is necessary but not sufficient. Before any real effect may be classified as eligible, the gate must independently close: schema, D1 opt-in, authority, authenticated producer/verifier, durable registry/CAS/idempotency, independent readback, target-side fencing, trusted time, secret boundary, target authorization/acceptance, audit persistence, and crash/reconcile behavior. Missing or unknown evidence must produce `UNKNOWN` or `NO_GO`, never `VERIFIED`.

The executable matrix intentionally uses only local synthetic fixtures. Its successful assertions prove the decision rules and their fail-closed behavior, not production completion.
