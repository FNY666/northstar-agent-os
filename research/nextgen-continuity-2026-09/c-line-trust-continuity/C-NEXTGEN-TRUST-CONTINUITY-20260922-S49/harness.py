#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','mode_declared','event_schema_valid',
    'json_or_jsonl_framing_closed','message_event_bound','tool_use_event_bound',
    'tool_result_event_bound','error_event_bound','exit_code_semantics_known',
    'plan_mode_declared','plan_scope_closed','write_boundary_closed',
    'approval_request_bound','approval_obtained','cancel_signal_bound',
    'cancel_state_observed','headless_input_bound','stream_order_closed',
    'final_state_readback','external_effect_not_claimed','mode_conflict','unknown_final_state'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['mode_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['mode_declared'] or not f['event_schema_valid'] or
        not f['json_or_jsonl_framing_closed'] or not f['message_event_bound'] or
        not f['tool_use_event_bound'] or not f['tool_result_event_bound'] or
        not f['error_event_bound'] or not f['exit_code_semantics_known'] or
        not f['plan_mode_declared'] or not f['plan_scope_closed'] or
        not f['write_boundary_closed'] or not f['approval_request_bound'] or
        not f['approval_obtained'] or not f['cancel_signal_bound'] or
        not f['cancel_state_observed'] or not f['headless_input_bound'] or
        not f['stream_order_closed'] or not f['final_state_readback'] or
        not f['external_effect_not_claimed'] or f['unknown_final_state']):
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
    mode_conflict_bit = 1 << FIELDS.index('mode_conflict')
    unknown_final_state_bit = 1 << FIELDS.index('unknown_final_state')
    required_names = [
        'same_identity','mode_declared','event_schema_valid','json_or_jsonl_framing_closed',
        'message_event_bound','tool_use_event_bound','tool_result_event_bound','error_event_bound',
        'exit_code_semantics_known','plan_mode_declared','plan_scope_closed','write_boundary_closed',
        'approval_request_bound','approval_obtained','cancel_signal_bound','cancel_state_observed',
        'headless_input_bound','stream_order_closed','final_state_readback','external_effect_not_claimed'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | mode_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_final_state_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S49-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['HEADLESS', 'JSON', 'JSONL', 'MESSAGE', 'TOOL_USE', 'TOOL_RESULT', 'ERROR', 'EXIT_CODE', 'PLAN_MODE', 'APPROVAL', 'CANCEL', 'STREAM', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
