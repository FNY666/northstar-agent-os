# S27 — Offline synthetic crash-window permutation slice

## Conclusion

This is an **offline, deterministic simulation only**. Across 18 fixtures, with one worker and one `op_id`, the model classified **4 accepted, 3 rejected, and 11 UNKNOWN** outcomes. In this model, `accepted` means the record append is observed before durable-reference emission; `rejected` means the cut occurs before any modeled observable side effect; `UNKNOWN` means partial or order-invalid evidence cannot decide.

## Research contract and scope

- Question: how do crash cuts before/after record append, response emission, and durable-reference emission classify under several stage permutations?
- Included: three permutations of the three modeled stages; before/after cut at every stage; 18 fixtures; local execution.
- Constraints: one worker, one `op_id`, no network, no real Gemini CLI, no real service, no credentials, no external research sources.
- Explicit flags in every artifact: `synthetic_only=true`, `production_verified=false`.

## Evidence and results

| Classification | Count |
|---|---:|
| accepted | 4 |
| rejected | 3 |
| UNKNOWN | 11 |
| Total | 18 |

The complete machine-readable output is `outputs/results.json`. Fixture definitions are in `fixtures/cases.json`; the simulator and self-validator are in `harness.py`.

The harness was run successfully, then its self-validator checked all 18 fixtures. The official evidence-first validator also passed the manifest, and SHA-256 verification passed for all listed files.

## Interpretation

The result is a permutation/cut-point table for a deliberately narrow state machine, not an operational finding. `UNKNOWN` is intentionally conservative: seeing an append without a durable reference, or seeing a reference before append in a permutation, does not prove either acceptance or rejection outside this model.

## Non-claims / limitations

This slice **does not prove** real crash durability, remote state, exactly-once semantics, rollback behavior, or production safety. It does not model process scheduling, actual filesystem/database fsync semantics, transport buffering, retries, concurrent workers, server reconciliation, or a real Gemini CLI implementation. No confirmed claims are asserted; local execution facts are marked `inferred` in `research-manifest.json`.

## Verification commands and outcomes

```text
python3 harness.py
=> result_count=18; counts={UNKNOWN: 11, accepted: 4, rejected: 3}

python3 harness.py --validate
=> PASS: self-validator checked 18 deterministic fixtures

python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py research-manifest.json
=> PASS: 4 claims; manifest schema is valid (2026-09-22)

sha256sum -c SHA256SUMS
=> all files OK
```

## Next independent slice (proposed, not executed)

S28: offline synthetic **retry/reconciliation permutation slice**, still isolated and synthetic-only, with one operation but explicit retry attempts and a local reconciliation pass. It should independently vary retry-before/after-reference and reconciliation-before/after-response, classify accepted/rejected/UNKNOWN, and preserve the same non-claims. It must use a new directory and must not reuse S27 outputs as input.
