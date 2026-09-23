#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','document_id_bound','digest_bound',
    'title_bound','topic_bound','claim_summary_bound','source_link_bound',
    'evidence_status_bound','freshness_bound','attention_score_bound',
    'retrieval_scope_bound','top_k_rule_known','rank_stable','tie_break_known',
    'citation_anchor_bound','citation_target_resolvable','citation_version_bound',
    'missing_citation_detected','duplicate_document_deduped','index_recomputed',
    'cross_platform_normalized','retrieval_conflict','unknown_index_state'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['retrieval_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['document_id_bound'] or not f['digest_bound'] or
        not f['title_bound'] or not f['topic_bound'] or not f['claim_summary_bound'] or
        not f['source_link_bound'] or not f['evidence_status_bound'] or not f['freshness_bound'] or
        not f['attention_score_bound'] or not f['retrieval_scope_bound'] or
        not f['top_k_rule_known'] or not f['rank_stable'] or not f['tie_break_known'] or
        not f['citation_anchor_bound'] or not f['citation_target_resolvable'] or
        not f['citation_version_bound'] or not f['missing_citation_detected'] or
        not f['duplicate_document_deduped'] or not f['index_recomputed'] or
        not f['cross_platform_normalized'] or f['unknown_index_state']):
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
    retrieval_conflict_bit = 1 << FIELDS.index('retrieval_conflict')
    unknown_index_state_bit = 1 << FIELDS.index('unknown_index_state')
    required_names = [
        'same_identity','document_id_bound','digest_bound','title_bound','topic_bound','claim_summary_bound',
        'source_link_bound','evidence_status_bound','freshness_bound','attention_score_bound',
        'retrieval_scope_bound','top_k_rule_known','rank_stable','tie_break_known','citation_anchor_bound',
        'citation_target_resolvable','citation_version_bound','missing_citation_detected',
        'duplicate_document_deduped','index_recomputed','cross_platform_normalized'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | retrieval_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_index_state_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S58-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['DOCUMENT_ID', 'DIGEST', 'TOPIC', 'CLAIM_SUMMARY', 'SOURCE_LINK', 'EVIDENCE_STATUS', 'FRESHNESS', 'ATTENTION_SCORE', 'SCOPE', 'TOP_K', 'RANK', 'TIE_BREAK', 'CITATION_ANCHOR', 'CITATION_TARGET', 'DEDUP', 'NORMALIZATION', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
