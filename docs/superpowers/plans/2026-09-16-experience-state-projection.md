# Experience State Projection

**Goal**: Project experience evidence into a unified state representation for integration with broader evidence layers.

**Current gap**: 
- Experience exists in isolation (ledger, statistics, admission)
- No bridge to route causality, graph store, or other evidence layers
- External systems can't ask: "What's the evidence state for checkpoint-X?"

**Problem**: 
Experience has rich internal structure (settlements, statistics, conflicts), but external systems need a **simplified, stable interface** to integrate experience into larger state machines.

**Proposed API**:

```python
@dataclass(frozen=True)
class ExperienceState:
    """Projected experience state for a checkpoint/fingerprint."""
    fingerprint: str
    standing: str  # consistent-success / consistent-failure / contradicted / etc.
    confidence: float  # Based on sample size
    recent_trend: str  # improving / declining / stable / insufficient-data
    last_admission: str | None  # "admitted" / "blocked" / "admitted-with-caution"
    conflict_count: int  # Number of detected conflicts
    data_quality: str  # "verified" / "insufficient-data" / "unverifiable"

def project_state(
    ledger: ExperienceLedger,
    fingerprint: str,
    *,
    admission_ledger: AdmissionLedger | None = None,
) -> ExperienceState:
    """Project all experience evidence into a unified state."""
```

**Projection logic**:
1. Query statistics → get standing, trend, confidence
2. Query admission ledger (if provided) → get last admission verdict
3. Detect conflicts → count conflicts
4. Assess data quality:
   - verified: sufficient samples, no conflicts
   - insufficient-data: < min samples
   - unverifiable: conflicts detected or contradicted standing

**Use cases**:
1. **Integration with causality**: "Experience state at this node is 'consistent-failure'"
2. **Unified dashboard**: Show all evidence types in one view
3. **Decision context**: Admission gate queries "experience state" without knowing internal structure
4. **Audit trail**: "At decision time, experience state was X"

**Testing**:
- Empty experience → insufficient-data, confidence=0
- Consistent success → verified, confidence high
- Contradicted → unverifiable
- Has conflicts → data_quality reflects conflicts
- With admission ledger → last_admission populated
- Without admission ledger → last_admission=None

**Non-goals** (defer):
- Cross-evidence correlation (experience + route causality)
- Real-time state change notifications
- State versioning / time-travel

**Timeline**: ~1.5 hours (projection function + tests)

---
**Author**: 96942423  
**Date**: 2026-09-16 深夜  
**Status**: 代际 6 (final slice for 5+ gap target)
