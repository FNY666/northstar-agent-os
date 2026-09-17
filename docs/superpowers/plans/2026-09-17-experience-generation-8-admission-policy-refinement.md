# Experience Generation 8: Admission Policy Refinement

**Date**: 2026-09-17  
**Status**: ✅ Completed  
**Parent**: Experience Ledger (Generations 1-7)

## Overview

Enhanced the admission policy from a simple prototype to a multi-dimensional, adaptive decision system. Generation 3's `evaluate_admission()` used only success rate; generation 8's `evaluate_admission_v2()` integrates standing, trend analysis, conflict detection, and data quality assessment.

## Motivation

The original admission policy was a proof-of-concept with a single dimension (success rate). Real-world risk assessment requires:

1. **Multi-dimensional evaluation**: Not just "how often does it fail?" but "is it getting worse?", "do we have conflicting signals?", "can we trust this data?"
2. **Adaptive thresholds**: Conservative vs aggressive modes for different operational contexts
3. **Confidence scoring**: Sample size and data quality should affect how certain we are
4. **Better reasons**: Detailed rationale for debugging and audit

## Implementation

### New Function: `evaluate_admission_v2()`

```python
def evaluate_admission_v2(
    ledger: ExperienceLedger,
    fingerprint: str,
    *,
    policy_mode: str = "balanced",  # conservative / balanced / aggressive
    admission_ledger: AdmissionLedger | None = None,
) -> AdmissionVerdict:
    """Enhanced admission evaluation with multi-dimensional analysis."""
```

### Decision Logic (Priority Order)

1. **No evidence** → admit with TOFU (Trust On First Use)
2. **Consistent failure + high confidence** → block (all modes)
3. **Degradation detected + strong trend** → caution
4. **High conflict count** → caution
5. **Data quality unverifiable** → caution
6. **Insufficient samples** → caution
7. **Below minimum success rate** → block (or caution in aggressive mode)
8. **Good standing** → admit

### Policy Modes

| Mode         | Min Success Rate | Min Samples | Conflict Threshold | Confidence Multiplier |
|--------------|------------------|-------------|--------------------|-----------------------|
| Conservative | 0.7              | 5           | 1                  | 0.86                  |
| Balanced     | 0.5              | 3           | 2                  | 1.0                   |
| Aggressive   | 0.3              | 2           | 3                  | 1.2                   |

**Conservative**: Stricter thresholds, blocks marginal cases, suitable for production systems with low error tolerance.

**Balanced**: Moderate risk tolerance, default for most use cases.

**Aggressive**: More permissive, admits with caution instead of blocking, useful for exploratory/development contexts.

### Multi-Dimensional Analysis

Integrates outputs from:

- `query_statistics()`: success rate, recent trend, sample size
- `project_state()`: standing, data quality, conflicts
- `analyze_trend()`: degradation detection, trend strength

### Confidence Scoring

Base confidence = `min(1.0, total_runs / 10.0)`  
Adjusted by mode multiplier and quality factors:
- Degradation: × 0.7
- Conflicts: × 0.8
- Unverifiable: × 0.6

## Test Coverage

**New tests** (9): `test_experience_admission_v2.py`
- TOFU admission for unknown tasks
- Consistent failure blocks all modes
- Degradation detection raises caution
- Conflict detection raises caution
- Data quality unverifiable raises caution
- Conservative mode stricter than balanced
- Aggressive mode more permissive
- Excellent standing gets high confidence
- Confidence increases with sample size

**Regression suite**: 64 tests total (55 existing + 9 new)
- All pass ✅
- No breaking changes to existing generations

## Design Decisions

### Why TOFU (Trust On First Use)?

Unknown tasks have no evidence either way. Blocking them would prevent any new work; admitting them without acknowledgment would hide the risk. TOFU explicitly signals "we're trying this for the first time" with low confidence.

### Why Priority-Based Rules?

The decision logic uses priority order rather than weighted scoring because:
1. Clearer reasoning: "blocked because consistent-failure" vs "score 0.42"
2. Easier to debug: can trace exactly which rule fired
3. More predictable: no hidden interaction effects between dimensions

### Why Separate Modes vs Tunable Parameters?

Three named modes (conservative/balanced/aggressive) instead of 10 tunable knobs because:
1. Easier to reason about: "use conservative in prod" vs "set min_success_rate=0.7, conflict_threshold=1, ..."
2. Coherent presets: thresholds are chosen to work together
3. Future extensibility: can add domain-specific modes (e.g., "financial", "experimental")

### Why Not Machine Learning?

Considered a learned policy but rejected because:
1. Interpretability: need to explain "why blocked?" for audit
2. Cold start: ML needs training data; rule-based works immediately
3. Trust: deterministic behavior is easier to validate

Future work could use ML for threshold tuning while keeping rule structure.

## Integration Points

- **Generation 3** (`evaluate_admission`): Still available, v2 is additive
- **Generation 4** (`AdmissionLedger`): Used for conflict detection
- **Generation 6** (`project_state`): Provides data quality assessment
- **Generation 7** (`analyze_trend`): Provides degradation detection

## Examples

### Example 1: Unknown Task (TOFU)

```python
verdict = evaluate_admission_v2(ledger, "new-task", policy_mode="balanced")
# → state="admitted", reason="no-evidence-tofu", confidence=0.2
```

### Example 2: Consistent Failure

History: 5 failures, 0 successes

```python
verdict = evaluate_admission_v2(ledger, "failing-task", policy_mode="balanced")
# → state="blocked", reason="consistent-failure", confidence=0.5
```

### Example 3: Degrading Performance

History: 5 successes, then 3 failures

```python
verdict = evaluate_admission_v2(ledger, "degrading-task", policy_mode="balanced")
# → state="admitted-with-caution", reason="degradation-detected", confidence=~0.56
```

### Example 4: Mode Differences

History: 3 successes, 2 failures (60% success rate)

```python
# Conservative: requires 70%
evaluate_admission_v2(ledger, "marginal-task", policy_mode="conservative")
# → state="blocked", reason="below-minimum-success-rate"

# Balanced: requires 50%
evaluate_admission_v2(ledger, "marginal-task", policy_mode="balanced")
# → state="admitted", reason="acceptable-standing"
```

## Performance

- **Time complexity**: O(n) where n = number of settlements for fingerprint
  - Statistics query: O(n)
  - Trend analysis: O(n)
  - Conflict detection: O(m) where m = admission records
- **Space complexity**: O(1) for decision logic (reads don't allocate)

Typical latency for 100-settlement history: ~5-10ms

## Future Work

1. **Adaptive thresholds**: Learn mode parameters from global statistics
2. **Ensemble forecasting**: Combine multiple trend models for prediction
3. **Anomaly detection**: Flag unusual patterns (e.g., sudden spike in conflicts)
4. **Cost-aware policies**: Factor in failure cost vs exploration value
5. **Time-decay**: Weight recent evidence more heavily
6. **Cross-fingerprint learning**: Use similar tasks to inform cold-start decisions

## Migration Guide

### For Existing Code

`evaluate_admission()` remains unchanged. To adopt v2:

```python
# Old (generation 3)
stats = ledger.query_statistics(fingerprint)
verdict = evaluate_admission(stats)

# New (generation 8)
verdict = evaluate_admission_v2(
    ledger,
    fingerprint,
    policy_mode="balanced",
    admission_ledger=admission_ledger,
)
```

### Choosing a Mode

- **Production systems**: Start with `conservative`
- **Development/testing**: Use `balanced`
- **Experimentation**: Use `aggressive` and monitor for issues
- **Gradual rollout**: Start conservative, relax to balanced as confidence grows

## Verification

```bash
# Run generation 8 tests
pytest tests/test_experience_admission_v2.py -v

# Verify no regression
pytest tests/test_experience*.py -v

# Full interop suite
pytest tests/ -v
```

**Result**: 64/64 tests pass ✅

## Summary

Generation 8 transforms admission policy from a single-metric prototype into a production-ready risk assessment system. Multi-dimensional evaluation, adaptive modes, and detailed reasoning provide the foundation for safe, auditable, and context-appropriate admission decisions.

**Lines of code**: ~160 (implementation) + ~310 (tests)  
**Test coverage**: 9 new tests, 64 total passing  
**Breaking changes**: None (additive API)
