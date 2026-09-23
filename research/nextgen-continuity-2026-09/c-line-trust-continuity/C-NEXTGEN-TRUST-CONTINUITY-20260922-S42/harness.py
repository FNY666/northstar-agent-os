#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','source_declared','schema_valid','default_defined',
    'user_override_loaded','workspace_override_loaded','env_override_loaded',
    'cli_override_loaded','precedence_order_known','effective_value_readback',
    'restart_boundary_closed','scope_boundary_closed','secret_redaction_closed',
    'unknown_key_policy_known','type_validation_passed','version_compatible',
    'source_file_stable','runtime_snapshot_attested','override_conflict','unknown_effective'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['override_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['source_declared'] or not f['schema_valid'] or
        not f['default_defined'] or not f['user_override_loaded'] or
        not f['workspace_override_loaded'] or not f['env_override_loaded'] or
        not f['cli_override_loaded'] or not f['precedence_order_known'] or
        not f['effective_value_readback'] or not f['restart_boundary_closed'] or
        not f['scope_boundary_closed'] or not f['secret_redaction_closed'] or
        not f['unknown_key_policy_known'] or not f['type_validation_passed'] or
        not f['version_compatible'] or not f['source_file_stable'] or
        not f['runtime_snapshot_attested'] or f['unknown_effective']):
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
    # Bit-mask sweep avoids allocating one dictionary per combination.
    identity_conflict_bit = 1 << FIELDS.index('identity_conflict')
    override_conflict_bit = 1 << FIELDS.index('override_conflict')
    unknown_effective_bit = 1 << FIELDS.index('unknown_effective')
    required_names = [
        'same_identity','source_declared','schema_valid','default_defined',
        'user_override_loaded','workspace_override_loaded','env_override_loaded',
        'cli_override_loaded','precedence_order_known','effective_value_readback',
        'restart_boundary_closed','scope_boundary_closed','secret_redaction_closed',
        'unknown_key_policy_known','type_validation_passed','version_compatible',
        'source_file_stable','runtime_snapshot_attested'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | override_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_effective_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S42-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['DEFAULTS', 'USER', 'WORKSPACE', 'ENV', 'CLI', 'PRECEDENCE', 'RUNTIME_READBACK', 'RESTART', 'SCOPE', 'SECRET_REDACTION', 'SCHEMA', 'UNKNOWN_KEY', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
