#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','document_id_bound','digest_bound',
    'title_bound','topic_bound','claim_summary_bound','source_link_bound',
    'evidence_status_bound','freshness_bound','attention_score_bound',
    'retrieval_scope_bound','top_k_rule_known','rank_stable','tie_break_known',
    'citation_anchor_bound','citation_target_resolvable','citation_version_bound',
    'missing_citation_detected','duplicate_document_deduped','index_recomputed',
    'cross_platform_normalized','retrieval_conflict','unknown_index_state'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'retrieval_conflict': False, 'unknown_index_state': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('digest-index-closed', 'digest/attention索引闭合', 'RECOVERED', ['document identity/digest/topic/claim完整','attention score和retrieval scope可重算']),
    make('top-k-stable-closed', 'Top-K排序闭合', 'RECOVERED', ['top-k rule/rank/tie-break固定','重复文档已去重']),
    make('citation-anchor-closed', '引用锚点闭合', 'RECOVERED', ['citation anchor可解析到版本化target','missing citation检查通过']),
    make('cross-platform-normalized', '跨平台归一化闭合', 'RECOVERED', ['不同平台字段/URL/版本归一化','digest和source identity保持一致']),
    make('freshness-attention-closed', 'freshness与attention闭合', 'RECOVERED', ['freshness影响score/排序有明确规则','index已重算']),
    make('evidence-status-retrieval-closed', 'evidence status检索闭合', 'RECOVERED', ['verified/inferred/unknown在检索中可区分','scope与引用一致']),
    make('document-id-missing', 'document id缺失', 'UNKNOWN', ['无法稳定去重或引用'], document_id_bound=False),
    make('digest-missing', 'digest缺失', 'UNKNOWN', ['内容变化无法检测'], digest_bound=False),
    make('topic-missing', 'topic缺失', 'UNKNOWN', ['无法按主题检索'], topic_bound=False),
    make('claim-summary-missing', 'claim summary缺失', 'UNKNOWN', ['结果只能看到文档名不能看到结论'], claim_summary_bound=False),
    make('source-link-missing', 'source link缺失', 'UNKNOWN', ['检索结果无法回到来源'], source_link_bound=False),
    make('status-missing', 'evidence status缺失', 'UNKNOWN', ['verified/inferred/unknown边界丢失'], evidence_status_bound=False),
    make('freshness-unknown', 'freshness未知', 'UNKNOWN', ['旧证据可能被当成最新'], freshness_bound=False),
    make('attention-score-open', 'attention score未绑定', 'UNKNOWN', ['排序规则不可解释'], attention_score_bound=False),
    make('scope-open', 'retrieval scope未绑定', 'UNKNOWN', ['Top-K覆盖语料不明'], retrieval_scope_bound=False),
    make('top-k-rule-unknown', 'Top-K规则未知', 'UNKNOWN', ['不同查询结果不可复现'], top_k_rule_known=False),
    make('rank-unstable', 'rank不稳定', 'UNKNOWN', ['同一输入排序漂移'], rank_stable=False),
    make('tie-break-unknown', 'tie-break未知', 'UNKNOWN', ['相同score结果不可复现'], tie_break_known=False),
    make('citation-anchor-open', '引用anchor未绑定', 'UNKNOWN', ['结论不能定位到原文'], citation_anchor_bound=False),
    make('citation-target-missing', '引用target不可解析', 'UNKNOWN', ['链接/版本/文件不存在'], citation_target_resolvable=False),
    make('citation-version-open', '引用版本未绑定', 'UNKNOWN', ['同URL内容可能变化'], citation_version_bound=False),
    make('missing-citation-unchecked', 'missing citation未检测', 'UNKNOWN', ['无来源claim可能进入结论'], missing_citation_detected=False),
    make('duplicate-unproven', '重复文档未去重', 'UNKNOWN', ['同一事实可能重复占据Top-K'], duplicate_document_deduped=False),
    make('index-stale', '索引未重算', 'UNKNOWN', ['源文档变化后排序/摘要过期'], index_recomputed=False, unknown_index_state=True),
    make('platform-schema-open', '跨平台schema未归一化', 'UNKNOWN', ['不同平台字段不能直接比较'], cross_platform_normalized=False),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['project/document/query字段不完整'], same_identity=False),
    make('identity-conflict', '跨项目文档合并', 'REJECT', ['不同project的document被错误合并'], same_identity=False, identity_conflict=True),
    make('retrieval-conflict', '检索结论冲突', 'REJECT', ['同一query/version出现不可调和Top-K/引用状态'], retrieval_conflict=True),
]

assert len(cases) == 28
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S58-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['project', 'document_id', 'digest', 'query_id', 'source_url', 'source_version'],
    'retrieval_domain': ['title', 'topic', 'claim_summary', 'evidence_status', 'freshness', 'attention_score', 'scope', 'top_k', 'rank', 'tie_break', 'citation_anchor', 'citation_target', 'dedup', 'normalization'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')
