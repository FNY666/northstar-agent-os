#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','window_declared','window_bounds_closed',
    'source_scope_complete','platform_receipt_attested','durable_log_attested',
    'external_effect_attested','event_time_closed','ingest_time_closed',
    'watermark_closed','retention_closed','pagination_closed','query_gap_absent',
    'export_attempt_closed','exporter_failure_absent','delay_explained',
    'drop_explained','no_event_contract_known','state_conflict','unknown_commit'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['state_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['window_declared'] or not f['window_bounds_closed'] or
        not f['source_scope_complete'] or not f['platform_receipt_attested'] or
        not f['durable_log_attested'] or not f['external_effect_attested'] or
        not f['event_time_closed'] or not f['ingest_time_closed'] or not f['watermark_closed'] or
        not f['retention_closed'] or not f['pagination_closed'] or not f['query_gap_absent'] or
        not f['export_attempt_closed'] or not f['exporter_failure_absent'] or
        not f['delay_explained'] or not f['drop_explained'] or
        not f['no_event_contract_known'] or f['unknown_commit']):
        return 'UNKNOWN'
    return 'RECOVERED'

def main():
    data = json.loads((ROOT / 'fixtures' / 'cases.json').read_text())
    rows = []
    for case in data['cases']:
        got = classify(case['flags'])
        rows.append({'id': case['id'], 'class': case['class'], 'status': got, 'expected': case['status'], 'match': got == case['status'], 'evidence_count': len(case['evidence'])})
    counts = {s: sum(r['status'] == s for r in rows) for s in ('RECOVERED', 'UNKNOWN', 'REJECT')}
    class_counts = {c: sum(r['class'] == c for r in rows) for c in ('NO_EVENT', 'DELAYED', 'DROPPED', 'EXPORTER_FAILURE', 'QUERY_GAP', 'RETENTION_EXPIRED', 'VERIFIED_CONTINUITY')}
    combinations = 1 << len(FIELDS)
    # The 21-dimensional sweep is evaluated as bit masks: this preserves the
    # exact boolean classifier while avoiding millions of temporary dicts.
    identity_conflict_bit = 1 << FIELDS.index('identity_conflict')
    state_conflict_bit = 1 << FIELDS.index('state_conflict')
    unknown_commit_bit = 1 << FIELDS.index('unknown_commit')
    required_names = [
        'same_identity','window_declared','window_bounds_closed',
        'source_scope_complete','platform_receipt_attested','durable_log_attested',
        'external_effect_attested','event_time_closed','ingest_time_closed',
        'watermark_closed','retention_closed','pagination_closed','query_gap_absent',
        'export_attempt_closed','exporter_failure_absent','delay_explained',
        'drop_explained','no_event_contract_known'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | state_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & unknown_commit_bit) or (mask & required_mask) != required_mask:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S40-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'class_distribution': class_counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['NO_EVENT', 'DELAYED', 'DROPPED', 'EXPORTER_FAILURE', 'QUERY_GAP', 'RETENTION_EXPIRED', 'VERIFIED_CONTINUITY', 'PLATFORM_RECEIPT', 'DURABLE_LOG', 'EXTERNAL_EFFECT'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
