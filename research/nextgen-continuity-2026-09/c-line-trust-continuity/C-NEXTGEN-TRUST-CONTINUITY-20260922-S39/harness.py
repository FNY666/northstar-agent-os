#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','query_scope_fixed','time_window_fixed',
    'page_cursor_chain_complete','page_terminal_attested','resource_version_monotonic',
    'snapshot_consistent','watermark_closed','retention_window_open',
    'retention_boundary_attested','no_event_semantics_known','gap_absent',
    'pagination_limit_known','filter_semantics_known','cross_region_complete',
    'query_retry_reconciled','duplicate_page_deduped','query_conflict','retention_expired'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['query_conflict'] or (f['retention_expired'] and not f['retention_window_open']):
        return 'REJECT'
    if (not f['same_identity'] or not f['query_scope_fixed'] or not f['time_window_fixed'] or
        not f['page_cursor_chain_complete'] or not f['page_terminal_attested'] or
        not f['resource_version_monotonic'] or not f['snapshot_consistent'] or
        not f['watermark_closed'] or f['retention_window_open'] or
        not f['retention_boundary_attested'] or not f['no_event_semantics_known'] or
        not f['gap_absent'] or not f['pagination_limit_known'] or
        not f['filter_semantics_known'] or not f['cross_region_complete'] or
        not f['query_retry_reconciled'] or not f['duplicate_page_deduped'] or f['retention_expired']):
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
        'schema_version': 'S39-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['QUERY_SCOPE', 'TIME_WINDOW', 'PAGE_CURSOR', 'RESOURCE_VERSION', 'SNAPSHOT', 'WATERMARK', 'RETENTION', 'NO_EVENT', 'QUERY_GAP', 'CROSS_REGION', 'RETRY', 'PAGINATION_LIMIT', 'FILTER_SEMANTICS'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
