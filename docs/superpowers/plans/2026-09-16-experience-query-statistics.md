# Experience Query API: Standing Statistics

**Goal**: Let callers query "how well does this fingerprint perform historically?" without manually parsing recall results.

**Current gap**: 
- `standing(fingerprint)` returns verdict (consistent-success/failure/contradicted/etc)
- Callers wanting **statistics** (success rate, sample size, trend) must call `recall()` and count manually
- No API for "show me the last N runs" or "what's the recent trend?"

**Proposed API**:
```python
@dataclass(frozen=True)
class ExperienceStatistics:
    fingerprint: str
    total_runs: int
    successes: int
    failures: int
    success_rate: float | None  # None if total_runs == 0
    recent_trend: str  # "improving" / "declining" / "stable" / "insufficient-data"
    last_n_outcomes: tuple[str, ...]  # ["verified", "failed", ...] (recent first)
    execution_authorized: bool = False

def query_statistics(fingerprint: str, *, recent_window: int = 5) -> ExperienceStatistics:
    """Compute actionable statistics from experience history."""
```

**Use cases**:
1. Admission policy: "Block if success_rate < 0.3 and total_runs >= 3"
2. Forecast confidence: "likely-success with 80% historical rate"
3. UI/monitoring: "Show task health dashboard"

**Non-goals**:
- Time-series analysis (keep it simple: just counts + recent window)
- Cross-fingerprint similarity (future work)

**Testing strategy**:
- Empty ledger → total_runs=0, success_rate=None, recent_trend="insufficient-data"
- All success → success_rate=1.0, trend="stable"
- All failure → success_rate=0.0, trend="stable"
- Mixed history → compute correct rate
- Recent improvement (3 fail → 2 success) → trend="improving"
- Recent decline (3 success → 2 fail) → trend="declining"
- Tampered ledger → raise or return unverifiable statistics

**Timeline**: ~1.5 hours (TDD + implementation + full suite)

---
**Author**: 96942423  
**Date**: 2026-09-16 深夜  
**Status**: Next independent research slice
