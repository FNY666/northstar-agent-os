# Sources

No external sources were used. This is a local synthetic-only conformance slice; all claims in `research-manifest.json` are marked `inferred`. The fixture key is fixed and non-real solely to make local HMAC-SHA256 behavior deterministic.

- Local fixture corpus: `fixtures/cases.json` (synthetic input, not an external source).
- Local evaluator: `harness.py` (deterministic standard-library implementation).
- Local validators: `validator.py`, `manifest_validator.py`.
