#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','question_bound','claim_bound','evidence_bound',
    'counterfactual_defined','counterfactual_tested','alternative_explanation_checked',
    'negative_evidence_bound','contradiction_search_done','conflict_preserved',
    'status_grade_bound','inference_boundary_bound','unknown_explicit',
    'open_question_bound','open_question_owner_bound','next_test_defined',
    'source_tier_bound','evidence_class_bound','scope_limit_bound','migration_reason_bound',
    'resolution_readback','research_conflict','unknown_research_state'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['research_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['question_bound'] or not f['claim_bound'] or
        not f['evidence_bound'] or not f['counterfactual_defined'] or not f['counterfactual_tested'] or
        not f['alternative_explanation_checked'] or not f['negative_evidence_bound'] or
        not f['contradiction_search_done'] or not f['conflict_preserved'] or
        not f['status_grade_bound'] or not f['inference_boundary_bound'] or not f['unknown_explicit'] or
        not f['open_question_bound'] or not f['open_question_owner_bound'] or not f['next_test_defined'] or
        not f['source_tier_bound'] or not f['evidence_class_bound'] or not f['scope_limit_bound'] or
        not f['migration_reason_bound'] or not f['resolution_readback'] or f['unknown_research_state']):
        return 'UNKNOWN'
    return 'RECOVERED'

def main():
    data = json.loads((ROOT / 'fixtures' / 'cases.json').read_text())
    rows = []
    for case in data['cases']:
        got = classify(case['flags'])
        rows.append({'id': case['id'], 'status': got, 'expected': case['status'], 'match': got == case['status'], 'evidence_count': len(case['evidence'])})
    counts = {s: sum(r['status'] == s for r in rows) for s in ('RECOVERED', 'UNKNOWN', 'REJECT')}
    combinations = 1 << len(FIELDS)
    identity_conflict_bit = 1 << FIELDS.index('identity_conflict')
    research_conflict_bit = 1 << FIELDS.index('research_conflict')
    unknown_research_state_bit = 1 << FIELDS.index('unknown_research_state')
    required_names = [
        'same_identity','question_bound','claim_bound','evidence_bound','counterfactual_defined',
        'counterfactual_tested','alternative_explanation_checked','negative_evidence_bound',
        'contradiction_search_done','conflict_preserved','status_grade_bound','inference_boundary_bound',
        'unknown_explicit','open_question_bound','open_question_owner_bound','next_test_defined',
        'source_tier_bound','evidence_class_bound','scope_limit_bound','migration_reason_bound',
        'resolution_readback'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | research_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_research_state_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S59-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['QUESTION', 'CLAIM', 'EVIDENCE_WINDOW', 'COUNTERFACTUAL', 'ALTERNATIVE_EXPLANATION', 'NEGATIVE_EVIDENCE', 'CONTRADICTION', 'STATUS_GRADE', 'INFERENCE_BOUNDARY', 'OPEN_QUESTION', 'OWNER', 'NEXT_TEST', 'SOURCE_TIER', 'EVIDENCE_CLASS', 'SCOPE_LIMIT', 'MIGRATION_REASON', 'RESOLUTION', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
