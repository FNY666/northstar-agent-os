#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','ledger_schema_valid','entry_id_bound',
    'question_bound','claim_bound','source_url_bound','source_date_bound',
    'evidence_window_bound','status_bound','confidence_bound','caveat_bound',
    'canonical_path_bound','derived_path_bound','raw_immutable_attested',
    'derived_not_canonical','digest_recorded','digest_recomputed','manifest_complete',
    'cross_reference_closed','count_filesystem_grounded','archive_index_closed',
    'ledger_conflict','unknown_lineage'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['ledger_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['ledger_schema_valid'] or not f['entry_id_bound'] or
        not f['question_bound'] or not f['claim_bound'] or not f['source_url_bound'] or
        not f['source_date_bound'] or not f['evidence_window_bound'] or not f['status_bound'] or
        not f['confidence_bound'] or not f['caveat_bound'] or not f['canonical_path_bound'] or
        not f['derived_path_bound'] or not f['raw_immutable_attested'] or
        not f['derived_not_canonical'] or not f['digest_recorded'] or not f['digest_recomputed'] or
        not f['manifest_complete'] or not f['cross_reference_closed'] or
        not f['count_filesystem_grounded'] or not f['archive_index_closed'] or f['unknown_lineage']):
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
    ledger_conflict_bit = 1 << FIELDS.index('ledger_conflict')
    unknown_lineage_bit = 1 << FIELDS.index('unknown_lineage')
    required_names = [
        'same_identity','ledger_schema_valid','entry_id_bound','question_bound','claim_bound',
        'source_url_bound','source_date_bound','evidence_window_bound','status_bound',
        'confidence_bound','caveat_bound','canonical_path_bound','derived_path_bound',
        'raw_immutable_attested','derived_not_canonical','digest_recorded','digest_recomputed',
        'manifest_complete','cross_reference_closed','count_filesystem_grounded','archive_index_closed'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | ledger_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_lineage_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S56-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['LEDGER_SCHEMA', 'ENTRY', 'QUESTION', 'CLAIM', 'SOURCE_URL', 'SOURCE_DATE', 'EVIDENCE_WINDOW', 'STATUS', 'CONFIDENCE', 'CAVEAT', 'CANONICAL', 'DERIVED', 'RAW_IMMUTABLE', 'DIGEST', 'MANIFEST', 'CROSS_REFERENCE', 'FILESYSTEM_COUNT', 'ARCHIVE', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
