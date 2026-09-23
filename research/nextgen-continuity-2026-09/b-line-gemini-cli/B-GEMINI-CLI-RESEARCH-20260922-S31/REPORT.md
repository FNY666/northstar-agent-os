# S31 Report — multi-operation interleavings

- `synthetic_only=true`
- `production_verified=false`
- Execution is strictly local and offline.
- Scope: 20 deterministic fixtures, two operation IDs (`A`, `B`), one worker.
- Model dimensions: acknowledgement precedence, interleaved event order, same/different payloads, late/lost/conflicting acknowledgement, missing/inaccessible evidence, and cross-operation contamination resistance.

## Classification contract

Each operation is classified independently as exactly one of `accepted`, `rejected`, or `UNKNOWN`. `UNKNOWN` is not `rejected`. An accepted acknowledgement only qualifies its own operation, only when it follows accessible matching evidence. A rejection/conflicting acknowledgement matching that operation is terminally `rejected`. Missing, inaccessible, mismatched, or absent evidence/ack leaves the operation `UNKNOWN`. No operation may use another operation’s accepted status as evidence.

## Reproducible commands

```sh
python3 harness.py
python3 validator.py
python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py research-manifest.json
sha256sum -c SHA256SUMS
```

## Boundaries

This synthetic slice does **not** prove durability, remote state, exactly-once behavior, rollback, or production readiness. It also does not test concurrency: the model intentionally uses one worker and deterministic serialized traces. “Late” means later in the supplied trace, not a wall-clock or distributed-system guarantee. Evidence accessibility is a fixture attribute, not a storage or authorization test.

## Results

The harness output and per-event traces are in `outputs/results.json`. The manifest claims are local inferred observations only; no external claim is marked confirmed.

## Next slice

Proceed without stopping the line to a next independent synthetic slice, preferably expanding operation cardinality beyond two and adding duplicate/reordered evidence, stale acknowledgements, explicit operation epochs, and adversarial unknown operation IDs while preserving per-operation evidence isolation. Keep the same offline-only and non-production-verified boundary.
