# Sources

synthetic_only=true
production_verified=false

No external or production sources were consulted. This slice is an original deterministic local simulation. The only inputs are `fixtures/cases.json` and the executable semantics in `harness.py`.

| ID | Source / artifact | Classification | Access |
|---|---|---|---|
| SRC-S11-LOCAL-01 | `fixtures/cases.json` | confirmed fixture input | accessible locally |
| SRC-S11-LOCAL-02 | `harness.py` | confirmed executable model | accessible locally |
| SRC-S11-LOCAL-03 | `outputs/results.json` | confirmed generated output | accessible locally |
| SRC-S11-NONE-01 | filesystem durability evidence | inaccessible / not consulted | intentionally out of scope |
| SRC-S11-NONE-02 | remote service state | inaccessible / not consulted | intentionally out of scope |
| SRC-S11-NONE-03 | production logs, SDKs, credentials, or canonical artifacts | inaccessible / not consulted | intentionally prohibited |

No claims in this slice should be interpreted as production verification.
