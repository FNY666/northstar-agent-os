#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','question_bound','claim_bound','evidence_bound',
    'counterfactual_defined','counterfactual_tested','alternative_explanation_checked',
    'negative_evidence_bound','contradiction_search_done','conflict_preserved',
    'status_grade_bound','inference_boundary_bound','unknown_explicit',
    'open_question_bound','open_question_owner_bound','next_test_defined',
    'source_tier_bound','evidence_class_bound','scope_limit_bound','migration_reason_bound',
    'resolution_readback','research_conflict','unknown_research_state'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'research_conflict': False, 'unknown_research_state': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('claim-evidence-closed', 'claim/evidence边界闭合', 'RECOVERED', ['claim对应明确证据窗口','inferred与confirmed边界可读回']),
    make('counterfactual-closed', '反事实与替代解释闭合', 'RECOVERED', ['counterfactual/test和alternative explanation均记录','负证据不被过度解释']),
    make('conflict-preserved-closed', '矛盾证据保留闭合', 'RECOVERED', ['冲突来源同时保留','结论显式标注不确定性与范围']),
    make('open-question-closed', '开放问题责任与下一实验闭合', 'RECOVERED', ['owner/next test/decision threshold绑定','resolution可读回']),
    make('evidence-grade-migration-closed', '证据等级迁移闭合', 'RECOVERED', ['source tier/evidence class/scope limit完整','status迁移有理由']),
    make('negative-evidence-closed', '负证据边界闭合', 'RECOVERED', ['未找到与未搜索/不可访问严格区分','反事实测试结果可追溯']),
    make('question-unbound', 'research question未绑定', 'UNKNOWN', ['结论无法对应明确问题'], question_bound=False),
    make('claim-unbound', 'claim未绑定', 'UNKNOWN', ['证据无法对应具体结论'], claim_bound=False),
    make('evidence-window-open', 'evidence window未绑定', 'UNKNOWN', ['原文支持范围不明'], evidence_bound=False),
    make('counterfactual-undefined', '反事实未定义', 'UNKNOWN', ['无法判断结论是否经过反事实检验'], counterfactual_defined=False),
    make('counterfactual-untested', '反事实未测试', 'UNKNOWN', ['只写建议未执行可区分实验'], counterfactual_tested=False),
    make('alternative-open', '替代解释未检查', 'UNKNOWN', ['相关性可能被误作因果'], alternative_explanation_checked=False),
    make('negative-evidence-open', '负证据边界未闭合', 'UNKNOWN', ['not found可能被写成不存在'], negative_evidence_bound=False),
    make('contradiction-search-missing', '矛盾检索未完成', 'UNKNOWN', ['只保留支持性来源'], contradiction_search_done=False),
    make('conflict-not-preserved', '冲突被静默覆盖', 'UNKNOWN', ['来源不一致但只保留一方'], conflict_preserved=False),
    make('status-grade-open', '证据等级未绑定', 'UNKNOWN', ['verified/inferred/unverified边界不明'], status_grade_bound=False),
    make('inference-boundary-open', '推断边界未记录', 'UNKNOWN', ['source内容被过度外推'], inference_boundary_bound=False),
    make('unknown-not-explicit', 'UNKNOWN未显式标注', 'UNKNOWN', ['缺证据被写成肯定/否定'], unknown_explicit=False),
    make('open-question-unbound', '开放问题未绑定', 'UNKNOWN', ['未解决问题没有状态'], open_question_bound=False),
    make('owner-missing', '开放问题owner缺失', 'UNKNOWN', ['没有后续责任人'], open_question_owner_bound=False),
    make('next-test-missing', '下一测试未定义', 'UNKNOWN', ['问题无法推进到可证伪实验'], next_test_defined=False),
    make('source-tier-open', 'source tier未绑定', 'UNKNOWN', ['primary/vendor/secondary层级不明'], source_tier_bound=False),
    make('evidence-class-open', 'evidence class未绑定', 'UNKNOWN', ['规范性指南与实证证据混淆'], evidence_class_bound=False),
    make('scope-limit-open', 'scope limit缺失', 'UNKNOWN', ['结论适用范围不明'], scope_limit_bound=False),
    make('migration-reason-missing', 'status迁移理由缺失', 'UNKNOWN', ['inferred到confirmed变化不可解释'], migration_reason_bound=False),
    make('resolution-readback-missing', 'resolution未读回', 'UNKNOWN', ['开放问题可能仍未解决'], resolution_readback=False),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['project/question/claim字段不完整'], same_identity=False),
    make('identity-conflict', '跨项目结论合并', 'REJECT', ['不同project/question的证据被错误合并'], same_identity=False, identity_conflict=True),
    make('research-conflict', '研究结论冲突', 'REJECT', ['同一question/scope出现不可调和结论且未能解释'], research_conflict=True),
]

assert len(cases) == 29
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S59-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['project', 'question_id', 'claim_id', 'source_id', 'experiment_id', 'owner'],
    'research_domain': ['question', 'claim', 'evidence_window', 'counterfactual', 'alternative_explanation', 'negative_evidence', 'contradiction', 'status_grade', 'inference_boundary', 'open_question', 'owner', 'next_test', 'source_tier', 'evidence_class', 'scope_limit', 'migration_reason', 'resolution'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')
