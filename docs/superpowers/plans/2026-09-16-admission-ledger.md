# Admission Ledger: Persistent Decision History

**Goal**: Persist admission decisions for audit, retrospective analysis, and policy tuning.

**Current gap**: 
- `evaluate_admission()` makes decisions but doesn't record them
- Cannot answer: "Why was task-X blocked last week?" or "Is our policy too strict?"
- No audit trail for regulatory/debugging purposes

**Proposed API**:

```python
@dataclass(frozen=True)
class AdmissionRecord:
    """One recorded admission decision."""
    fingerprint: str
    verdict_state: str  # "admitted" / "blocked" / "admitted-with-caution"
    verdict_reason: str
    verdict_confidence: float
    statistics_snapshot: dict[str, Any]  # Frozen statistics at decision time
    decided_at: int  # Unix timestamp
    policy_config: dict[str, Any]  # min_success_rate, min_sample_size, etc.
    record_digest: str
    sequence: int

class AdmissionLedger:
    def __init__(self, path: Path):
        ...
    
    def record(
        self,
        fingerprint: str,
        verdict: AdmissionVerdict,
        statistics: ExperienceStatistics,
        *,
        policy_config: dict[str, Any],
        decided_at: int,
    ) -> AdmissionRecord:
        """Append admission decision to ledger (append-only, flock, fsync)."""
    
    def query(self, fingerprint: str) -> tuple[AdmissionRecord, ...]:
        """Retrieve all decisions for a fingerprint (oldest first)."""
    
    def summary(self) -> dict[str, Any]:
        """Global stats: total decisions, block rate, caution rate."""
```

**Persistence design**:
- Append-only JSONL (same pattern as experience/settlements)
- flock for concurrency safety
- Digest chain (each record references prev_record_digest)
- fsync after write

**Use cases**:
1. **Audit**: "Show me all blocked tasks in the last 7 days"
2. **Policy tuning**: "What % of decisions are 'admitted-with-caution'? Too many?"
3. **Retrospective**: "Task-X was blocked with 20% success_rate, but now it's 80% — unblock?"
4. **Compliance**: Regulatory requirement for access control decision logs

**Testing**:
- Record decision → read back, verify digest chain
- Multiple decisions for same fingerprint → query returns all
- Concurrent appends → no corruption
- Summary computes correct block/caution rates
- Tampered ledger → unverifiable digest chain

**Non-goals** (defer):
- Decision rollback / policy override
- Real-time alerts on policy violations
- Cross-fingerprint correlation

**Timeline**: ~2 hours (ledger class + record/query + digest chain + tests)

---
**Author**: 96942423  
**Date**: 2026-09-16 深夜  
**Status**: Next slice (代际 4, after admission policy prototype)
