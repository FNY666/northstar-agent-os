# S23 sources

- **S23-local-policy** — `harness.py` and `fixtures/cases.json` in this directory. Deterministic synthetic inputs and an explicit local classification policy; directly supports only the generated run outputs. `synthetic_only=true`; `production_verified=false`.
- **External/production sources intentionally not consulted** — scope forbids Gemini CLI, real services, credentials, pre-existing research artifacts, and remote state. Therefore no external source is claimed as evidence for implementation or production behavior.

Evidence labels used in the report: `confirmed` means directly observed in this deterministic harness run; `inferred` means a narrow implication of the local policy; `unverified` means not tested or not established; `conflicting` means contradictory synthetic records; `inaccessible` means outside the permitted offline scope.
