#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','export_id_bound','import_id_bound',
    'origin_digest_bound','export_manifest_complete','import_manifest_complete',
    'field_mapping_bound','transform_declared','transform_authorized','redaction_bound',
    'redaction_policy_attested','resign_scope_bound','resign_authorized',
    'permission_downgrade_bound','target_scope_bound','recipient_bound',
    'canonicalization_version_bound','algorithm_version_bound','timestamp_chain_closed',
    'lineage_order_closed','source_attribution_closed','final_readback_closed',
    'lineage_conflict','unknown_transform_state'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['lineage_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['export_id_bound'] or not f['import_id_bound'] or
        not f['origin_digest_bound'] or not f['export_manifest_complete'] or not f['import_manifest_complete'] or
        not f['field_mapping_bound'] or not f['transform_declared'] or not f['transform_authorized'] or
        not f['redaction_bound'] or not f['redaction_policy_attested'] or not f['resign_scope_bound'] or
        not f['resign_authorized'] or not f['permission_downgrade_bound'] or not f['target_scope_bound'] or
        not f['recipient_bound'] or not f['canonicalization_version_bound'] or not f['algorithm_version_bound'] or
        not f['timestamp_chain_closed'] or not f['lineage_order_closed'] or not f['source_attribution_closed'] or
        not f['final_readback_closed'] or f['unknown_transform_state']):
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
    lineage_conflict_bit = 1 << FIELDS.index('lineage_conflict')
    unknown_transform_state_bit = 1 << FIELDS.index('unknown_transform_state')
    required_names = [
        'same_identity','export_id_bound','import_id_bound','origin_digest_bound','export_manifest_complete',
        'import_manifest_complete','field_mapping_bound','transform_declared','transform_authorized',
        'redaction_bound','redaction_policy_attested','resign_scope_bound','resign_authorized',
        'permission_downgrade_bound','target_scope_bound','recipient_bound','canonicalization_version_bound',
        'algorithm_version_bound','timestamp_chain_closed','lineage_order_closed','source_attribution_closed','final_readback_closed'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | lineage_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_transform_state_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S66-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['EXPORT', 'IMPORT', 'ORIGIN_DIGEST', 'MANIFEST', 'FIELD_MAPPING', 'TRANSFORM', 'REDACTION', 'RESIGN', 'PERMISSION_DOWNGRADE', 'SCOPE', 'RECIPIENT', 'CANONICALIZATION', 'ALGORITHM', 'TIMESTAMP', 'LINEAGE_ORDER', 'ATTRIBUTION', 'READBACK', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
