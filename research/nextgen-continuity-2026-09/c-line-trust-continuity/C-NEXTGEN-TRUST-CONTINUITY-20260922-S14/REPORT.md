# S14 offline synthetic evidence-provenance matrix extension

## Conclusion

The local deterministic model passes 16/16 fixtures. `UNKNOWN`, `RECOVERED`, and `REJECT` are mutually exclusive. Clock drift, same event IDs with changed sequence numbers, duplicate event IDs, sequence gaps, budget truncation without completeness proof, and source-independence self-labels do **not** silently upgrade `UNKNOWN` to `RECOVERED`. In the absence of explicit verifiable contradiction, the model does not convert `UNKNOWN` to `REJECT`. Explicit verifiable contradiction produces `REJECT`. Two independently verified candidates can produce `RECOVERED` only when the model's completeness, sequence, clock, and independence gates pass.

These are inferred results of a deliberately local synthetic rule model, not externally confirmed facts.

## Reproducibility

```sh
cd /tmp/C-NEXTGEN-TRUST-CONTINUITY-20260922-S14
python3 harness.py
python3 validator.py
python3 manifest_validator.py
python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py research-manifest.json
sha256sum -c SHA256SUMS
```

Expected outcome: harness `case_count=16`, `all_pass=true`; all validators PASS; checksum verification PASS.

## Matrix

| Dimension | Fixtures | Expected behavior | Observed |
|---|---|---|---|
| Clock drift | S14-01, S14-11 | Hold UNKNOWN | Pass |
| Same event, different seq | S14-02 | Deduplicate; hold UNKNOWN | Pass |
| Duplicate event ID | S14-03, S14-12 | Never counts as independent; valid independent pair remains RECOVERED | Pass |
| Budget truncation | S14-04, S14-05, S14-15 | Hold UNKNOWN absent explicit completeness proof | Pass |
| Independence mislabel | S14-06 | Self-label is insufficient; hold UNKNOWN | Pass |
| Explicit verifiable contradiction | S14-09, S14-13 | REJECT | Pass |
| Unverified/non-contradictory conflict | S14-07, S14-10, S14-14, S14-16 | No erroneous REJECT | Pass |
| Valid recovery gate | S14-08, S14-12 | RECOVERED | Pass |

## State transition policy and provenance

1. Every case begins `UNKNOWN`; this transition is recorded with `initial_state_conservative`.
2. Canonicalization deduplicates by `event_id`; later copies are recorded with input index and canonical index. Sequence differences do not create a new event.
3. `REJECT` requires a contradiction event with `kind=contradiction`, `verifiable=true`, and `independence_verified=true`. Recovery evidence cannot override that explicit contradiction.
4. Candidate recovery requires at least two verified candidates from distinct verified source IDs, contiguous sequence values, no clock anomaly, and no budget truncation unless completeness is explicitly proven. Failure records blockers and remains `UNKNOWN`.
5. All output states are asserted to belong to exactly one of the three states.

## Provenance and limitations

Each output records fixture ID, expected and observed state, pass/fail, canonical event IDs, raw/unique event counts, dropped duplicate details, ordered transition records, evidence IDs, blockers, deterministic model name, and SHA-256 of normalized fixture input. Package files are marked `synthetic_only=true` and `production_verified=false` where applicable.

No public source was consulted; there are no confirmed claims. This work cannot prove real durability, remote state, exactly-once delivery, rollback, or production readiness. It also cannot establish that this policy is suitable for deployment, because no live system, SDK, credential, service, or production artifact was accessed. No prior S1–S13 or other restricted artifact was read.

## Continuation

This S14 slice is complete and offline. Next slice may be proposed only as a separate, similarly isolated synthetic experiment; this result does not authorize stopping any operational line or making production changes.
