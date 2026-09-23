# S26 — Offline synthetic journal replay permutation slice
synthetic_only=true
production_verified=false

## Scope and isolation
This is a single-worker, single-`op_id` deterministic local simulation. It uses only the files in `/tmp/B-GEMINI-CLI-RESEARCH-20260922-S26/`. It does not read S25 or any other prior research artifact, and does not access network, real Gemini CLI, real services, credentials, shared/P0, incident directories, D10, L12, D14, canonical, staging, 140, tri-line, or systemd.

Worker count: 1  
`op_id`: `synthetic-op-S26-0001`  
Fixture count: 14  

## Replay policy
The harness normalizes visibility events by their synthetic `journal_seq`, rather than trusting arrival order. A case is **accepted** only when exactly one attempt has one record visibility, one response visibility, and one durable-reference visibility; all three values are identical; and `response.durable_ref == durable_ref.ref`. It is **rejected** for duplicate/misidentified entries, sequence collisions, reference mismatch, or different values. It is **UNKNOWN** for missing, inaccessible, unknown, or ambiguous evidence (including multiple complete attempts).

The evidence-status labels are intentionally separate from the classification: `confirmed`, `inferred`, `unverified`, `conflicting`, and `inaccessible`. They describe the status of the synthetic observation under this model, not a production fact.

## Results
The authoritative per-fixture output is `outputs/results.json`. The deterministic run produced:

| Fixture | Classification | Evidence status | Local observation |
|---|---|---|---|
| S26-01 ordered attempt 1, same value | accepted | confirmed | coherent record/response/durable reference |
| S26-02 response arrives first, same value | accepted | inferred | normalized by journal sequence |
| S26-03 missing record | UNKNOWN | unverified | no complete attempt |
| S26-04 missing response | UNKNOWN | unverified | no complete attempt |
| S26-05 inaccessible durable reference | UNKNOWN | inaccessible | visibility is inaccessible |
| S26-06 duplicate record | rejected | conflicting | duplicate entry identity |
| S26-07 reordered same-value entries | accepted | inferred | normalized by journal sequence |
| S26-08 different values | rejected | conflicting | record/response/durable values differ |
| S26-09 response/durable reference mismatch | rejected | conflicting | references disagree |
| S26-10 attempt 1 incomplete, attempt 2 complete | accepted | inferred | complete attempt 2 is selected by expected hint |
| S26-11 attempts 1 and 2 both complete | UNKNOWN | inferred | attempt choice is ambiguous |
| S26-12 unknown entry kind | UNKNOWN | unverified | event kind is not interpretable |
| S26-13 complete attempt 1 conflicts with expected attempt 2 hint | UNKNOWN | inferred | selection hint mismatch |
| S26-14 journal sequence collision | rejected | conflicting | sequence is duplicated |

Expected/generated totals: **accepted=4, rejected=4, UNKNOWN=6**.

## What this does not establish
A local journal replay cannot prove real crash durability, remote state, exactly-once behavior, rollback, immutable auditability, or production safety. It also cannot establish that a real service emits these event types, preserves these sequence semantics, or honors this classification policy. `production_verified=false` is therefore mandatory.

## Reproduction and verification
From the slice directory:

```sh
python3 harness.py
python3 - <<'PY'
import json
p='outputs/results.json'
x=json.load(open(p))
assert x['synthetic_only'] is True and x['production_verified'] is False
assert x['result_count'] == 14
assert x['summary'] == {'accepted': 4, 'rejected': 4, 'UNKNOWN': 6}
assert {r['classification'] for r in x['results']} == {'accepted','rejected','UNKNOWN'}
print('validator: PASS')
PY
python3 - <<'PY'
import json
p='research-manifest.json'; x=json.load(open(p))
assert x['synthetic_only'] is True and x['production_verified'] is False
assert x['worker_count']==1 and x['op_id']=='synthetic-op-S26-0001'
assert len(x['files'])==7
print('research manifest validator: PASS')
PY
(cd /tmp/B-GEMINI-CLI-RESEARCH-20260922-S26 && sha256sum -c SHA256SUMS)
```

## Next independent slice suggestion — keep the line moving
Run **S27: offline synthetic crash-window permutation slice** in a fresh directory and a fresh single `op_id`. Vary crash cut points before/after record append, response emission, and durable-reference emission; retain the same explicit evidence labels and UNKNOWN policy. It must remain local-only and must not be interpreted as proof of real crash durability or remote state.

## File flags
Every deliverable in this slice explicitly contains `synthetic_only=true` and `production_verified=false` (JSON booleans are used in JSON files).
