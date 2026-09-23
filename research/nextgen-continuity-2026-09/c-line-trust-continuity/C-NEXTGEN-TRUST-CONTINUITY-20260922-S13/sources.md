# Sources

This S13 slice is an **offline synthetic model only**. It uses no external sources, network, real service, SDK, credential, or production artifact. Therefore the manifest claims are `inferred`, not `confirmed`; an empty source list is intentional. Fixture records in `fixtures/cases.json` are generated test inputs, not evidence about any deployed system.

Provenance convention used by the model:

- `source_id`, `event_id`, `seq`, `event_time`, `observed_at`, decision, accessibility, freshness age, and input index are retained per observation.
- Freshness is synthetic and inclusive: `freshness_age_seconds <= 3600`.
- Independence is approximated by distinct `source_id` values.
- Only records within the observation budget, accessible, and fresh are usable evidence.
- A `RECOVERED` result requires at least two independent usable observations agreeing on `(event_id, seq)` with `decision=RECOVERED`.
- A `REJECT` result requires an explicit same-version conflict between independent usable observations, with both terminal decisions represented.
- Otherwise the result is `UNKNOWN`, including missing, inaccessible, stale, duplicate-only, and budget-exhausted paths.

No source can establish real durability, remote state, exactly-once behavior, rollback behavior, or production readiness.

synthetic_only=true  
production_verified=false
