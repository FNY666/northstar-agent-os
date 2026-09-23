# S25 — Offline synthetic restart-window slice

## Scope and safety boundary

This is an **offline synthetic** experiment with one worker (`worker-s25-01`) and one operation (`op-s25-0001`). It deterministically simulates a crash/restart boundary around a local write and records only simulated local journal state. It does **not** test or establish real crash durability, remote state, exactly-once behavior, rollback, or production safety.

Flags: `synthetic_only=true`; `production_verified=false`.

No network, real Gemini CLI, real service, credential, shared/P0, accident directory, D10, L12, D14, canonical, staging, 140, tri-line, or systemd was accessed. No S24 or other prior research artifact was read.

## Design

Each fixture has exactly attempts 1 and 2, the same worker/op identifiers, one of three local-write positions, same/different values, and response/durable reference relationships. The deterministic classifier uses only the fixture's local simulated journal:

- **before-record**: attempt 1 has neither response nor record; attempt 2 can be accepted only when its response and durable references are equal.
- **record-before-response**: an attempt-1 local record is an anchor. A same-value retry with unchanged durable reference and equal attempt-2 references is accepted; a different value is rejected; reference changes remain UNKNOWN.
- **response-before-record**: an attempt-1 response exists without a local record, so the result remains UNKNOWN rather than asserting recovery or deduplication.

These are harness classification rules, not claims about any real implementation.

## Results

The harness generated 12 deterministic fixtures:

| Fixture | Boundary | Values | Refs | Classification | Evidence label |
|---|---|---|---|---|---|
| S25-01 | before-record | same | equal | accepted | confirmed (within synthetic fixture/rule) |
| S25-02 | before-record | different | equal | accepted | confirmed (within synthetic fixture/rule) |
| S25-03 | before-record | same | changed | UNKNOWN | confirmed (within synthetic fixture/rule) |
| S25-04 | before-record | different | changed | UNKNOWN | confirmed (within synthetic fixture/rule) |
| S25-05 | record-before-response | same | equal | accepted | confirmed (within synthetic fixture/rule) |
| S25-06 | record-before-response | different | equal | rejected | confirmed (within synthetic fixture/rule) |
| S25-07 | record-before-response | same | changed | UNKNOWN | confirmed (within synthetic fixture/rule) |
| S25-08 | record-before-response | different | changed | rejected | confirmed (within synthetic fixture/rule) |
| S25-09 | response-before-record | same | equal | UNKNOWN | confirmed (within synthetic fixture/rule) |
| S25-10 | response-before-record | different | equal | UNKNOWN | confirmed (within synthetic fixture/rule) |
| S25-11 | response-before-record | same | changed | UNKNOWN | confirmed (within synthetic fixture/rule) |
| S25-12 | response-before-record | different | changed | UNKNOWN | confirmed (within synthetic fixture/rule) |

Counts: **accepted=3, rejected=2, UNKNOWN=7**. Every generated classification matched its declared fixture expectation. The labels above mean confirmed only as deterministic replay of authored synthetic input under authored local rules; they are not production evidence.

## Evidence status taxonomy

- **confirmed**: directly present and replay-checked in the local fixture/result, under the harness rule.
- **inferred**: none used for a production claim; any intuitive interpretation beyond the local rule is intentionally withheld.
- **unverified**: real crash timing, filesystem durability, process death semantics, service behavior, remote state, and recovery behavior.
- **conflicting**: none in this synthetic dataset; reference changes are represented as UNKNOWN, not treated as conflict resolution.
- **inaccessible**: all prohibited external systems/artifacts and any production environment by design.

## Reproduction and validation

From this directory:

```sh
python3 harness.py run
python3 harness.py validate
python3 harness.py manifest-validate
(cd /tmp/B-GEMINI-CLI-RESEARCH-20260922-S25 && sha256sum -c SHA256SUMS)
```

The generated result is `outputs/results.json`; the complete machine-readable local journal projection is there. `sources.md` documents the absence of external sources.

## Next independent slice (keep the line running)

Proceed with **S26: offline synthetic journal replay permutation slice** in a new directory, still one worker and one op_id, varying deterministic event ordering around record/response visibility and adding explicit missing/duplicate journal-entry fixtures. Keep it synthetic-only, do not read S25 outputs, classify only local simulated states, and preserve the same prohibition against production durability, remote-state, exactly-once, rollback, and safety conclusions.
