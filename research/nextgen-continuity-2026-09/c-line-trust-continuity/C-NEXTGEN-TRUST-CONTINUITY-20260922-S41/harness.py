#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','origin_attested','derivation_link_complete',
    'parent_digest_bound','transform_declared','transform_authorized','transform_deterministic',
    'export_mapping_complete','import_mapping_complete','resign_scope_valid',
    'redaction_provenance_complete','canonicalization_version_bound','algorithm_version_bound',
    'timestamp_chain_closed','actor_identity_bound','evidence_location_bound',
    'lineage_order_complete','duplicate_lineage_deduped','lineage_conflict','unknown_transform'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['lineage_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['origin_attested'] or not f['derivation_link_complete'] or
        not f['parent_digest_bound'] or not f['transform_declared'] or not f['transform_authorized'] or
        not f['transform_deterministic'] or not f['export_mapping_complete'] or
        not f['import_mapping_complete'] or not f['resign_scope_valid'] or
        not f['redaction_provenance_complete'] or not f['canonicalization_version_bound'] or
        not f['algorithm_version_bound'] or not f['timestamp_chain_closed'] or
        not f['actor_identity_bound'] or not f['evidence_location_bound'] or
        not f['lineage_order_complete'] or not f['duplicate_lineage_deduped'] or
        f['unknown_transform']):
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
    # Evaluate the boolean sweep with bit masks rather than allocating one
    # dictionary per combination; the truth table is unchanged.
    identity_conflict_bit = 1 << FIELDS.index('identity_conflict')
    lineage_conflict_bit = 1 << FIELDS.index('lineage_conflict')
    unknown_transform_bit = 1 << FIELDS.index('unknown_transform')
    required_names = [
        'same_identity','origin_attested','derivation_link_complete',
        'parent_digest_bound','transform_declared','transform_authorized',
        'transform_deterministic','export_mapping_complete','import_mapping_complete',
        'resign_scope_valid','redaction_provenance_complete',
        'canonicalization_version_bound','algorithm_version_bound',
        'timestamp_chain_closed','actor_identity_bound','evidence_location_bound',
        'lineage_order_complete','duplicate_lineage_deduped'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | lineage_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_transform_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S41-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['ORIGIN', 'DERIVATION', 'PARENT_DIGEST', 'TRANSFORM', 'EXPORT', 'IMPORT', 'RESIGN', 'REDACTION', 'CANONICALIZATION', 'ALGORITHM', 'TIMESTAMP', 'ACTOR', 'LOCATION', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
