# S31 sources

- `synthetic_only=true`
- `production_verified=false`

This slice is synthetic-only and offline. No external sources, network access, Gemini CLI/service, credentials, or prior research artifacts were used. The only evidence is the deterministic local fixture set and the harness execution recorded in `outputs/results.json`; local observations are therefore classified as `inferred`, not `confirmed`.

- `local-fixture-spec`: `fixtures/cases.json`; deterministic two-op (A/B), one-worker event traces.
- `local-harness`: `harness.py`; implementation under test and emitted traces.
- `local-validator`: `validator.py`; invariant checks.

No URL sources are applicable. The manifest uses an empty source list for inferred claims.
