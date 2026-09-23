#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','server_declared','server_trusted',
    'tool_allowlist_closed','resource_allowlist_closed','include_exclude_consistent',
    'transport_authenticated','request_context_bound','argument_schema_valid',
    'resource_uri_bound','resource_version_closed','result_captured',
    'error_state_captured','timeout_semantics_known','side_effect_class_known',
    'approval_boundary_known','source_attribution_closed','pagination_closed',
    'retry_state_reconciled','permission_conflict','unknown_remote_state'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['permission_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['server_declared'] or not f['server_trusted'] or
        not f['tool_allowlist_closed'] or not f['resource_allowlist_closed'] or
        not f['include_exclude_consistent'] or not f['transport_authenticated'] or
        not f['request_context_bound'] or not f['argument_schema_valid'] or
        not f['resource_uri_bound'] or not f['resource_version_closed'] or
        not f['result_captured'] or not f['error_state_captured'] or
        not f['timeout_semantics_known'] or not f['side_effect_class_known'] or
        not f['approval_boundary_known'] or not f['source_attribution_closed'] or
        not f['pagination_closed'] or not f['retry_state_reconciled'] or f['unknown_remote_state']):
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
    # Evaluate the exact boolean truth table using integer masks to keep the
    # 22-dimensional sweep bounded on iSH.
    identity_conflict_bit = 1 << FIELDS.index('identity_conflict')
    permission_conflict_bit = 1 << FIELDS.index('permission_conflict')
    unknown_remote_state_bit = 1 << FIELDS.index('unknown_remote_state')
    required_names = [
        'same_identity','server_declared','server_trusted','tool_allowlist_closed',
        'resource_allowlist_closed','include_exclude_consistent','transport_authenticated',
        'request_context_bound','argument_schema_valid','resource_uri_bound',
        'resource_version_closed','result_captured','error_state_captured',
        'timeout_semantics_known','side_effect_class_known','approval_boundary_known',
        'source_attribution_closed','pagination_closed','retry_state_reconciled'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | permission_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_remote_state_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S44-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['MCP_SERVER', 'MCP_TOOL', 'MCP_RESOURCE', 'WEB_TOOL', 'ALLOWLIST', 'TRANSPORT', 'CONTEXT', 'SCHEMA', 'URI', 'VERSION', 'RESULT', 'ERROR', 'TIMEOUT', 'APPROVAL', 'ATTRIBUTION', 'PAGINATION', 'RETRY', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
