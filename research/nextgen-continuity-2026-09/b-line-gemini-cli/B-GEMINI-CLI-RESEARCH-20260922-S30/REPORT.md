# S30 synthetic acknowledgement-state research

- `synthetic_only=true`; `production_verified=false` in every artifact.
- This is a fully offline, deterministic, single-worker/single-`op_id` fixture study. It does not read or depend on S27-S29 or any prior research artifact.
- The harness evaluates explicit states: acknowledgement received/lost, duplicate retry, late acknowledgement, conflicting late acknowledgement, and unavailable evidence.
- Classification is exactly one of `accepted`, `rejected`, or `UNKNOWN`.
- `UNKNOWN` is intentionally distinct from `rejected`: absent, unavailable, incomplete, or contradictory evidence is not evidence of rejection.
- A verified fact has precedence over a late acknowledgement. A late acknowledgement cannot overwrite a conflicting verified fact.
- Duplicate identical retries/acks do not alter the result in the synthetic rule set.

## Non-claims / boundaries

This work does **not** prove durability, remote state, exactly-once behavior, rollback, or production readiness. It does not access the network, a real Gemini CLI/service, credentials, shared/P0, incident directories, D10/L12/D14, canonical/staging/140/tri-line/systemd, or any production system.

## Verification commands and expected outputs

```text
python3 harness.py
HARNESS_PASS: 16 fixtures; accepted/rejected/UNKNOWN classification deterministic
python3 validator.py
VALIDATOR_PASS: 16 results; UNKNOWN distinct from rejected; late conflict and evidence gates hold
python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py research-manifest.json
PASS: 5 claims; manifest schema is valid (2026-09-22)
sha256sum -c SHA256SUMS
...: OK (all 7 listed artifacts)
```

## Next slice

Propose the next slice: **S31 — synthetic-only multi-operation interleavings** (still offline), varying two `op_id`s while retaining explicit acknowledgement permutations, to test whether the same precedence and UNKNOWN rules remain separable across operations. This proposal does not authorize production access or take any system offline.
