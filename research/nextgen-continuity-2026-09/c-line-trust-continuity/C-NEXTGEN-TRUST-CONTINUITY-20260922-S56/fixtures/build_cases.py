#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','ledger_schema_valid','entry_id_bound',
    'question_bound','claim_bound','source_url_bound','source_date_bound',
    'evidence_window_bound','status_bound','confidence_bound','caveat_bound',
    'canonical_path_bound','derived_path_bound','raw_immutable_attested',
    'derived_not_canonical','digest_recorded','digest_recomputed','manifest_complete',
    'cross_reference_closed','count_filesystem_grounded','archive_index_closed',
    'ledger_conflict','unknown_lineage'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'ledger_conflict': False, 'unknown_lineage': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('ledger-entry-complete', '账本entry schema完整', 'RECOVERED', ['question/claim/source/window/status/confidence/caveat完整','entry id和digest可重算']),
    make('canonical-derived-separated', 'canonical/derived隔离闭合', 'RECOVERED', ['raw/canonical不可变','derived不能覆盖canonical']),
    make('manifest-digest-closed', 'manifest/digest闭合', 'RECOVERED', ['required files和SHA256可独立验证','manifest与产物对应']),
    make('filesystem-count-grounded', '文件系统计数闭合', 'RECOVERED', ['计数来自文件系统','digest不携带硬编码计数']),
    make('cross-reference-closed', '跨文档引用闭合', 'RECOVERED', ['raw/wiki/experiment/question引用可追溯','archive index完整']),
    make('archive-index-closed', '归档索引闭合', 'RECOVERED', ['归档路径、版本和digest绑定','恢复后状态可读回']),
    make('schema-invalid', '账本schema无效', 'UNKNOWN', ['entry字段不完整或类型错误'], ledger_schema_valid=False),
    make('entry-id-unbound', 'entry id未绑定', 'UNKNOWN', ['记录无法稳定去重/引用'], entry_id_bound=False),
    make('question-unbound', 'question未绑定', 'UNKNOWN', ['研究产物不能对应决策问题'], question_bound=False),
    make('claim-unbound', 'claim未绑定', 'UNKNOWN', ['来源证据不能映射到结论'], claim_bound=False),
    make('source-url-missing', 'source URL缺失', 'UNKNOWN', ['公开证据不可追溯'], source_url_bound=False),
    make('source-date-missing', '访问日期缺失', 'UNKNOWN', ['时效性和版本窗口未知'], source_date_bound=False),
    make('evidence-window-missing', '证据窗口缺失', 'UNKNOWN', ['无法知道claim由哪段原文支持'], evidence_window_bound=False),
    make('status-missing', 'status缺失', 'UNKNOWN', ['verified/inferred/unknown级别不明'], status_bound=False),
    make('confidence-missing', 'confidence缺失', 'UNKNOWN', ['结论强度不明'], confidence_bound=False),
    make('caveat-missing', 'caveat缺失', 'UNKNOWN', ['不能看到不能证明的边界'], caveat_bound=False),
    make('canonical-path-open', 'canonical路径未绑定', 'UNKNOWN', ['多个副本可能被误认为权威'], canonical_path_bound=False),
    make('derived-overwrite-risk', 'derived/canonical隔离未证明', 'UNKNOWN', ['派生摘要可能覆盖原始事实'], derived_not_canonical=False),
    make('raw-immutable-unknown', 'raw不可变未证明', 'UNKNOWN', ['源料可能被静默修改'], raw_immutable_attested=False),
    make('digest-missing', 'digest未记录', 'UNKNOWN', ['内容变化无法检测'], digest_recorded=False),
    make('digest-recompute-missing', 'digest未重算', 'UNKNOWN', ['记录的hash未经当前文件验证'], digest_recomputed=False),
    make('manifest-incomplete', 'manifest不完整', 'UNKNOWN', ['required files缺失或未声明'], manifest_complete=False),
    make('cross-reference-gap', '跨引用缺口', 'UNKNOWN', ['wiki/experiment/question无法追溯raw'], cross_reference_closed=False),
    make('filesystem-count-missing', '文件系统计数缺失', 'UNKNOWN', ['账本计数可能硬编码过期'], count_filesystem_grounded=False),
    make('archive-index-gap', '归档索引缺口', 'UNKNOWN', ['归档后无法恢复原状态'], archive_index_closed=False),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['project/slice/entry字段不完整'], same_identity=False),
    make('identity-conflict', '跨项目账本合并', 'REJECT', ['不同project/slice事实被错误合并'], same_identity=False, identity_conflict=True),
    make('ledger-conflict', '账本状态冲突', 'REJECT', ['同一entry出现不可调和的canonical/status/digest'], ledger_conflict=True),
]

assert len(cases) == 28
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S56-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['project', 'slice', 'entry_id', 'question', 'claim', 'source', 'canonical_path', 'derived_path'],
    'ledger_domain': ['schema', 'manifest', 'digest', 'raw', 'wiki', 'experiment', 'question', 'archive', 'filesystem_count', 'cross_reference'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')
