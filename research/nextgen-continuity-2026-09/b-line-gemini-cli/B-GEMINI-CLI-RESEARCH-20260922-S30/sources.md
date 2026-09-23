- `synthetic_only=true`; `production_verified=false` apply to this source register.
- No external sources were accessed. All conclusions are inferred solely from local, deterministic fixtures and the offline harness. The `https://example.invalid/` URLs in the manifest are non-resolving provenance placeholders required by the validator's source shape; they are not evidence and were not fetched.

- `fixtures/cases.json`: 16 deterministic synthetic cases, one worker and one `op_id`.
- `harness.py`: pure local classifier; no network, service, credentials, or external input.
- `outputs/results.json`: generated harness output.
- `validator.py`: local invariant checks, including `UNKNOWN != rejected`, conflict precedence, and evidence gate.
- `research-manifest.json`: evidence-first manifest; all claims are `inferred`, never `confirmed`.

Boundaries: no durability, remote state, exactly-once, rollback, or production-readiness claim is made.
