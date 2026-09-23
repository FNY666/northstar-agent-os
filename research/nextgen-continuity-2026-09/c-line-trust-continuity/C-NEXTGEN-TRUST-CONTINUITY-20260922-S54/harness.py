#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','model_source_declared','model_precedence_known',
    'provider_route_readback','token_cache_scope_bound','token_cache_expiry_known',
    'token_cache_key_bound','cache_invalidation_attested','auto_memory_scope_bound',
    'memory_write_policy_known','memory_read_policy_known','memory_retention_bound',
    'memory_export_bound','worktree_identity_bound','worktree_path_bound',
    'worktree_branch_bound','worktree_dirty_state_known','worktree_cleanup_attested',
    'cross_worktree_isolation_closed','route_conflict','unknown_state'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['route_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['model_source_declared'] or not f['model_precedence_known'] or
        not f['provider_route_readback'] or not f['token_cache_scope_bound'] or
        not f['token_cache_expiry_known'] or not f['token_cache_key_bound'] or
        not f['cache_invalidation_attested'] or not f['auto_memory_scope_bound'] or
        not f['memory_write_policy_known'] or not f['memory_read_policy_known'] or
        not f['memory_retention_bound'] or not f['memory_export_bound'] or
        not f['worktree_identity_bound'] or not f['worktree_path_bound'] or
        not f['worktree_branch_bound'] or not f['worktree_dirty_state_known'] or
        not f['worktree_cleanup_attested'] or not f['cross_worktree_isolation_closed'] or
        f['unknown_state']):
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
    route_conflict_bit = 1 << FIELDS.index('route_conflict')
    unknown_state_bit = 1 << FIELDS.index('unknown_state')
    required_names = [
        'same_identity','model_source_declared','model_precedence_known','provider_route_readback',
        'token_cache_scope_bound','token_cache_expiry_known','token_cache_key_bound','cache_invalidation_attested',
        'auto_memory_scope_bound','memory_write_policy_known','memory_read_policy_known','memory_retention_bound',
        'memory_export_bound','worktree_identity_bound','worktree_path_bound','worktree_branch_bound',
        'worktree_dirty_state_known','worktree_cleanup_attested','cross_worktree_isolation_closed'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | route_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_state_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S54-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['MODEL_ROUTE', 'TOKEN_CACHE', 'AUTO_MEMORY', 'RETENTION', 'EXPORT', 'WORKTREE', 'BRANCH', 'DIRTY_STATE', 'CLEANUP', 'ISOLATION', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
