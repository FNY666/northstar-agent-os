# S29 Duplicate delivery / idempotency permutations

- `synthetic_only`: `true`
- `production_verified`: `false`
- Worker: one local worker (`worker-s29-1`)
- Operation: one local operation ID (`op-s29-001`)
- Fixtures: 16 deterministic cases in `fixtures/cases.json`.

## Scope and method

This is an offline, local model only. The harness computes a canonical payload fingerprint (SHA-256 over canonical JSON) and classifies each delivery sequence using only fixture data. `accepted` means the local model treats the delivery or retry as equivalent to the locally observed canonical payload; `rejected` means a fully observable payload conflicts with that local canonical payload; `UNKNOWN` means the fixture withholds evidence or payload needed to prove equivalence or conflict. `UNKNOWN` is intentionally a third value and is never converted to `rejected`.

The model uses one worker and one operation ID. It does not contact Gemini, a real CLI, an external service, a network, a credential store, or any durable state. It cannot establish durability, remote state, exactly-once processing, rollback, or production safety.

## Coverage

The fixtures cover same-event duplicate delivery, same and different payloads, reversed order, lost acknowledgements, conflicting retries, inaccessible evidence/payload, and a conflict-then-canonical sequence. Expected deterministic distribution is 6 accepted, 5 rejected, and 5 `UNKNOWN`.

## Results

The executable result record is `outputs/results.json`. Run output is reproducible with:

```text
$ python3 harness.py
{"UNKNOWN": 5, "accepted": 6, "all_match": true, "cases": 16, "matches": 16, "production_verified": false, "rejected": 5, "synthetic_only": true}
$ python3 validator.py
PASS: 16 deterministic fixtures; classifications valid; UNKNOWN distinct from rejected; synthetic_only=true; production_verified=false
```

## Interpretation and limitations

Idempotency here is a local model rule, not observed Gemini behavior and not a claim about any external service. In particular, an accepted fixture does not prove remote acceptance, deduplication, durability, exactly-once effects, rollback, or safety. An inaccessible-evidence fixture is `UNKNOWN`, not `rejected`; absence of evidence is not evidence of rejection.

No network, real CLI/service, credentials, shared/P0, incident directories, D10/L12/D14, canonical/staging/140/tri-line/systemd, or prior S27/S28/other research artifacts were read or used. The next slice should independently test a new synthetic permutation family (for example, explicit acknowledgement-state permutations) while preserving the same three-valued distinction; do not stop the line.
