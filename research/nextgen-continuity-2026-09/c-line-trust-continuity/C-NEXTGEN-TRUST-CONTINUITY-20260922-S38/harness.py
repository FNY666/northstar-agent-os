#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','trace_context_valid','log_present',
    'metric_present','trace_present','signal_correlation_closed','sequence_complete',
    'export_attempt_attested','export_ack_attested','exporter_queue_closed',
    'drop_counter_reconciled','retry_history_complete','otlp_scope_consistent',
    'resource_identity_bound','time_window_closed','sampling_known','duplicate_dedup_attested',
    'signal_conflict','unknown_export_state'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['signal_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['trace_context_valid'] or not f['log_present'] or
        not f['metric_present'] or not f['trace_present'] or not f['signal_correlation_closed'] or
        not f['sequence_complete'] or not f['export_attempt_attested'] or not f['export_ack_attested'] or
        not f['exporter_queue_closed'] or not f['drop_counter_reconciled'] or
        not f['retry_history_complete'] or not f['otlp_scope_consistent'] or
        not f['resource_identity_bound'] or not f['time_window_closed'] or
        not f['sampling_known'] or not f['duplicate_dedup_attested'] or f['unknown_export_state']):
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
    sweep_counts = {s: 0 for s in ('RECOVERED', 'UNKNOWN', 'REJECT')}
    minimizers = []
    found = set()
    for mask in range(combinations):
        flags = {name: bool(mask & (1 << i)) for i, name in enumerate(FIELDS)}
        status = classify(flags)
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S38-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['LOGS', 'METRICS', 'TRACES', 'OTLP', 'SAMPLING', 'EXPORT_ATTEMPT', 'EXPORT_ACK', 'QUEUE', 'DROP_COUNTER', 'RETRY', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
