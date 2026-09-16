# Admission Conflict Detection

**Goal**: Identify contradictory admission decisions for the same task, indicating policy inconsistency or bugs.

**Current gap**: 
- AdmissionLedger records decisions but doesn't detect conflicts
- Cannot answer: "Did we block Task-X at 10:00 but admit it at 10:05 with same stats?"
- Policy bugs or inconsistent human overrides go unnoticed

**Problem scenarios**:
1. **Same statistics, different verdicts**: Task-X blocked at 20% success_rate, then admitted at 20% (policy bug?)
2. **Flip-flop**: Admitted → Blocked → Admitted in short time window (unstable policy?)
3. **Human override**: Blocked by policy, then manually admitted (legitimate but needs audit trail)

**Proposed API**:

```python
@dataclass(frozen=True)
class AdmissionConflict:
    """One detected conflict between two decisions."""
    earlier: AdmissionRecord
    later: AdmissionRecord
    conflict_type: str  # "admit-vs-block" / "block-vs-admit" / "state-change"
    time_delta: int  # seconds between decisions

def detect_conflicts(
    ledger: AdmissionLedger,
    *,
    window_seconds: int | None = None,  # Only check recent conflicts
) -> tuple[AdmissionConflict, ...]:
    """Find contradictory decisions for the same fingerprint."""
```

**Conflict types**:
1. **admit-vs-block**: Earlier admitted, later blocked (severity: high)
2. **block-vs-admit**: Earlier blocked, later admitted (could be policy relaxation or override)
3. **state-change**: Any verdict state change (admitted ↔ caution, etc.)

**Detection logic**:
- Group records by fingerprint
- For each fingerprint, compare consecutive decisions
- Flag if:
  - Verdict state changed (admitted → blocked or vice versa)
  - Statistics similar (±10% success_rate) but verdict different
  - Time delta < threshold (e.g., < 1 hour = suspicious)

**Use cases**:
1. **Policy debugging**: "Why did we admit Task-X after blocking it 5 mins ago?"
2. **Audit human overrides**: "Show all blocked→admitted changes in last 24h"
3. **Stability check**: "Are we flip-flopping on borderline tasks?"
4. **Regression detection**: "Did new policy version introduce conflicts?"

**Testing**:
- No conflicts → returns empty tuple
- Same task admitted then blocked → conflict detected
- Same task blocked then admitted → conflict detected
- Different tasks → no conflict
- Window filter works (only recent conflicts returned)

**Non-goals** (defer):
- Automatic conflict resolution
- Policy version diffing
- Cross-fingerprint similarity conflicts

**Timeline**: ~1.5 hours (conflict detection logic + tests)

---
**Author**: 96942423  
**Date**: 2026-09-16 深夜  
**Status**: 代际 5 (after admission ledger)
