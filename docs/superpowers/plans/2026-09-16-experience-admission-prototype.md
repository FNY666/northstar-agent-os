# Experience-Aware Admission Policy (Prototype)

**Goal**: Demonstrate how experience statistics enable risk-informed admission decisions.

**Revised approach**: 
- Don't search for runtime admission integration point (that's in the other session's domain)
- Build a **standalone admission policy prototype** in experience_ledger module
- Show the API contract for future integration

**API design**:

```python
@dataclass(frozen=True)
class AdmissionVerdict:
    """Risk-informed admission decision based on experience."""
    state: str  # "admitted" / "blocked" / "admitted-with-caution"
    reason: str
    confidence: float  # 0.0-1.0, based on sample size
    execution_authorized: bool

def evaluate_admission(
    statistics: ExperienceStatistics,
    *,
    min_success_rate: float = 0.3,
    min_sample_size: int = 3,
    decline_is_blocking: bool = True,
) -> AdmissionVerdict:
    """Decide whether to admit a task based on its track record."""
```

**Policy logic**:
1. **Insufficient data** (total_runs < min_sample_size) → admitted-with-caution
2. **Consistent failure** (success_rate < min_success_rate AND enough samples) → blocked
3. **Declining trend** (recent_trend == "declining" AND enough samples) → blocked or warned
4. **Good standing** (success_rate >= min_success_rate) → admitted
5. **Excellent standing** (success_rate >= 0.9 AND improving/stable) → admitted (high confidence)

**Confidence scoring**:
- Based on sample size: `min(1.0, total_runs / 10)` (10+ runs = full confidence)
- Insufficient data → low confidence (0.1-0.3)

**Testing**:
- Empty history → admitted-with-caution, low confidence
- 5 failures → blocked, reason="consistent-failure"
- 8 success + 2 fail (80%) → admitted
- Recent decline (3 success → 3 fail) → blocked if flag set
- 10 successes, improving → admitted, confidence=1.0

**Non-integration**:
- This is a **demonstrator**, not runtime integration
- Real integration waits for Phase 3 coordination with 616C93DD
- Shows the API contract: `(statistics) → verdict`

**Timeline**: ~1.5 hours (policy function + tests + examples)

---
**Author**: 96942423  
**Date**: 2026-09-16 深夜  
**Status**: Revised approach (standalone prototype, not runtime integration)
