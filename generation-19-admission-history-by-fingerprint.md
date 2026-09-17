# Generation 19: Admission history query by fingerprint

## Gap

`AdmissionLedger.query()` only filters by `session_id`, but never by the goal fingerprint. A host wanting to answer "what admission decisions were made for this specific goal across all sessions?" has no direct query path, forcing it to manually derive fingerprints from each admission's checkpoint and filter post-query.

## Goal

Add `query_by_fingerprint()` method to AdmissionLedger that returns admission history for a specific goal fingerprint, with optional session filtering and time windowing.

## Current state

- `AdmissionLedger` has `query(session_id)` returning all admissions for a session
- `derive_fingerprint(goal)` exists for computing goal fingerprints
- `AdmissionRecord` stores `checkpoint_digest` but not the derived fingerprint
- No cross-session fingerprint indexing

## Expected state after completion

- `AdmissionLedger` has `query_by_fingerprint(fingerprint, *, session_id=None, since=None, until=None)` 
- Method returns chronologically ordered `list[AdmissionRecord]`
- Optionally filter by session_id (for single-session queries)
- Optionally filter by time window (since/until timestamps)
- Fingerprint derived on-demand from checkpoint (no schema change)
- Runtime adapter method `query_admission_history_by_goal(ledger, goal, ...)` for convenience

## Test requirements

1. **Empty ledger**: Returns empty list
2. **No matches**: Returns empty list when fingerprint has no admissions
3. **Single match**: Returns one record for matching fingerprint
4. **Multiple sessions**: Returns records from all sessions with same fingerprint
5. **Session filter**: Returns only matching session when `session_id` provided
6. **Time window**: `since` and `until` filter correctly
7. **Chronological order**: Results sorted by `observed_at`
8. **Invalid inputs**: Rejects invalid fingerprint format

## Implementation notes

- Fingerprint must be derived from checkpoint on each query (no denormalization)
- Fingerprint extraction requires reading checkpoint from store or admission metadata
- For now, store checkpoint goal in admission metadata (backward compatible extension)
- Fail-closed on corrupted records (consistent with existing behavior)

## Success criteria

- [ ] 8+ focused tests (RED → GREEN)
- [ ] Runtime adapter method added
- [ ] All 504+ runtime tests pass
- [ ] No schema breaking changes
- [ ] Commit message follows conventions

## Verification

```bash
cd components/northstar-agent-runtime
python3 -m pytest tests/test_admission_history_query.py -v
python3 -m pytest tests/ -q
```
