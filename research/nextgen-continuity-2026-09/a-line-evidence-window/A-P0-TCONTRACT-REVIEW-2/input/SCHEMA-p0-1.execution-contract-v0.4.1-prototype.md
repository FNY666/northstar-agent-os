# p0-1.execution-contract/v0.4.1-prototype

## Purpose and boundary

This is a **tree-external prototype schema** for T-Contract-0. It defines offline, pure structural validation and a projection of the five contract phases. It is not a production contract, adapter, canonical schema, registry, authority, executor, producer, clock, audit log, or readback implementation. `verified` means only that the supplied offline declarations are structurally mutually consistent under this prototype; it is never authority or ground truth.

## Input schema

- `schema_version`: exact string `p0-1.execution-contract/v0.4.1-prototype`.
- Top-level required objects: `run`, `operation`, `decision`, `execution`, `observation`, `postconditions` (non-empty array), `effect`, `receipt`, `trusted_binding`; `expected` is one of `verified|failed|unknown|invalid`; optional `dedupe`.
- Unknown fields are rejected at every object level.
- `run`: `task_id`, `run_id`, `idempotency_key`, `operation_fingerprint`, `artifact_owner`, `artifact_identity`, `read_at`, integer `attempt` 1..1,000,000.
- `operation`: `operation_id`, `kind`, `target`, object `args`. Its canonical fingerprint is `sha256:` plus SHA-256 of recursively NFC-normalized, sorted, compact JSON. Numbers must be finite integers in `[-10^18,10^18]`.
- `decision`: status `accepted`, `policy_id`, `authority`, `decided_at`.
- `trusted_binding`: identity mirror, operation and decision mirror, owner/identity/read time, `expiry`, `policy_revision`, nonempty offline `signature` declaration. No signature is treated as a real authority proof.
- `execution`: status `not_started|started|succeeded|failed|timeout|cancelled`, operation/idempotency identity, `started_at`, and `ended_at` iff terminal.
- `observation`: status `returned|error|missing|timeout|cancelled`, source/channel/read time; returned requires `groundtruth_health=healthy` and opaque `raw_ref` matching `evidence://sha256/` plus 64 lowercase hex characters. This validates shape only and does not dereference content.
- Each postcondition: `name`, `status` `verified|failed|unknown`, `source`, `channel`, `read_at`, `evidence_strength`, `evidence_id`; names and evidence IDs must be unique.
- `effect`: status `verified|failed|unknown`, reason/source/read time. `receipt`: run/operation identity, status in the defined receipt set, read time, producer.
- Time strings are UTC `YYYY-MM-DDTHH:MM:SSZ`, years 2000..2099. Events must be ordered and not future to supplied `trusted_now`; run read time is within the configured window.
- Strict JSON rejects exact duplicate keys, NFC-normalization key collisions, NaN/Infinity, malformed JSON, non-object input, and invalid canonical numbers.

## Output schema

JSON object fields: `prototype=true`, `tree_external=true`, `fixture`, `valid` boolean, `verdict` (`verified|failed|unknown|invalid`), `expected` or null, `match` boolean, `errors` array, `warnings` (always says offline structural result), `state_trace` array, `projection`, `identity`, `authority_asserted=false`, `groundtruth_asserted=false`, and `replay` with `action=none`, `side_effect_replayed=false`, `evidence_level=declaration_only`.

The projection contains only `decision`, `execution`, `observation`, `effect`, and `receipt` declarations. No output writes state or creates authority. Any parser/validator exception is converted into structured `invalid` or `unknown`; callers do not receive an unhandled exception. The expected field is an assertion for fixture matching only and cannot upgrade a safety verdict.

## Verdict rules

`verified` requires structurally valid input, observed healthy opaque reference, succeeded execution, all postconditions verified, verified effect, and `ok` receipt, with no conflict. `failed` requires observed healthy shape and a failed execution/effect/postcondition or terminal negative receipt. Conflicting effect/receipt/postcondition evidence is not verified and is classified invalid/unknown according to structural error context. Missing or insufficient evidence is unknown. This is not a claim about external reality.
