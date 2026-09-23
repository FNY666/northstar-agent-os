<!-- synthetic_only=true; production_verified=false -->
# S28 Offline Synthetic Retry/Reconciliation Permutation Slice

## Conclusion

S28 is a **local synthetic execution only**. It does not establish Gemini CLI, service, or production behavior. Under the explicit deterministic oracle in `harness.py`, 16 fixtures produce **4 accepted, 4 rejected, and 8 UNKNOWN** outcomes. `UNKNOWN` is a third state and is **not equivalent to REJECTED**.

## Question and scope

The slice varies two independent axes: retry **before vs. after reference** and reconciliation **before vs. after response**. It uses one worker (`worker-1`), one operation id (`s28-op-0001`), and a fresh directory. The 16-case matrix is the Cartesian product of four position permutations and four synthetic scenarios: `valid_match`, `response_mismatch`, `missing_response`, and `invalid_reference`.

Explicit exclusions: network; real Gemini CLI or service; credentials; shared/P0; accident directories; D10/L12/D14; canonical/staging/140/tri-line/systemd; S27 and all other prior research products.

## Complete observed output

Harness stdout:

```text
{"case_count": 16, "counts": {"UNKNOWN": 8, "accepted": 4, "rejected": 4}, "sha256": "f3775395d9894ed0add32dac261cdb520ca835a840a836c9b024e40481b7bd17"}
```

The generated `outputs/results.json` contains all 16 rows. By scenario, each of the four position permutations yields:

| Scenario | Count | Verdict | Synthetic reason |
|---|---:|---|---|
| `valid_match` | 4 | accepted | reference and response match |
| `response_mismatch` | 4 | rejected | response differs from reference |
| `missing_response` | 4 | UNKNOWN | response unavailable |
| `invalid_reference` | 4 | UNKNOWN | reference unavailable |

Thus, position changes are represented in the fixture matrix but do not, by themselves, change the deliberately simple synthetic oracle. This is a fixture result, not a production claim.

## Verification

Executed from the fresh S28 directory:

1. `python3 harness.py` — PASS; 16 cases, counts above.
2. `python3 validator.py` — PASS; confirms one worker/op_id, complete fixture coverage, allowed verdicts, all artifact flags, both retry positions, both reconciliation positions, and `UNKNOWN != REJECT`.
3. `python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py research-manifest.json` — PASS; generic manifest schema valid.
4. `(cd /tmp/B-GEMINI-CLI-RESEARCH-20260922-S28 && sha256sum -c SHA256SUMS)` — run after checksum creation; expected PASS for every listed artifact.

## Evidence and limitations

There are no external sources: `sources.md` records that this was offline synthetic work. Manifest claims are `inferred`, `unverified`, or otherwise non-confirmed; no claim is marked `confirmed`. `synthetic_only=true` and `production_verified=false` are present in the manifest, result, and each result row. The local oracle intentionally treats unavailable response/reference evidence as UNKNOWN rather than rejection. It does not model retry timing side effects, duplicate delivery, idempotency, concurrency, transport errors, durability, real reconciliation protocols, or any service-specific behavior.

## Next slice

Proceed with **S29**, a separately isolated offline synthetic slice for duplicate delivery and idempotency permutations. Preserve the same boundaries, single-worker/single-op discipline, explicit UNKNOWN state, and no-stop-line posture; do not infer production behavior without production evidence.
