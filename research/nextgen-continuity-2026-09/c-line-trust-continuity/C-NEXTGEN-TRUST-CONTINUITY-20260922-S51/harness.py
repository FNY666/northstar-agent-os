#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','auth_context_declared','terms_scope_bound',
    'privacy_policy_bound','data_region_bound','telemetry_setting_bound','telemetry_optout_observed',
    'prompt_data_classified','tool_data_classified','session_data_classified','file_event_classified',
    'redaction_policy_bound','config_precedence_known','workspace_config_bound',
    'user_config_bound','env_config_bound','runtime_setting_readback','retention_bound',
    'exporter_destination_bound','access_control_bound','privacy_conflict','unknown_data_path'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['privacy_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['auth_context_declared'] or not f['terms_scope_bound'] or
        not f['privacy_policy_bound'] or not f['data_region_bound'] or not f['telemetry_setting_bound'] or
        not f['telemetry_optout_observed'] or not f['prompt_data_classified'] or
        not f['tool_data_classified'] or not f['session_data_classified'] or
        not f['file_event_classified'] or not f['redaction_policy_bound'] or
        not f['config_precedence_known'] or not f['workspace_config_bound'] or
        not f['user_config_bound'] or not f['env_config_bound'] or
        not f['runtime_setting_readback'] or not f['retention_bound'] or
        not f['exporter_destination_bound'] or not f['access_control_bound'] or
        f['unknown_data_path']):
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
    privacy_conflict_bit = 1 << FIELDS.index('privacy_conflict')
    unknown_data_path_bit = 1 << FIELDS.index('unknown_data_path')
    required_names = [
        'same_identity','auth_context_declared','terms_scope_bound','privacy_policy_bound','data_region_bound',
        'telemetry_setting_bound','telemetry_optout_observed','prompt_data_classified','tool_data_classified',
        'session_data_classified','file_event_classified','redaction_policy_bound','config_precedence_known',
        'workspace_config_bound','user_config_bound','env_config_bound','runtime_setting_readback',
        'retention_bound','exporter_destination_bound','access_control_bound'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | privacy_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_data_path_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S51-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['TERMS', 'PRIVACY_POLICY', 'REGION', 'TELEMETRY', 'OPTOUT', 'PROMPT', 'TOOL', 'SESSION', 'FILE_EVENT', 'REDACTION', 'PRECEDENCE', 'RETENTION', 'EXPORT', 'ACCESS_CONTROL', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
