#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','decision_id_bound','reviewer_identity_bound',
    'reviewer_role_bound','separation_of_duties_closed','approval_scope_bound',
    'approval_evidence_bound','override_reason_bound','override_authorized',
    'dissent_recorded','appeal_path_bound','appeal_owner_bound','reopen_condition_bound',
    'decision_version_monotonic','prior_decision_digest_bound','effective_time_bound',
    'expiry_review_bound','audit_sequence_closed','notification_bound','stakeholder_ack_bound',
    'final_decision_readback','review_conflict','unknown_review_state'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'review_conflict': False, 'unknown_review_state': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('review-decision-closed', '人工决策身份/范围/审计闭合', 'RECOVERED', ['decision/reviewer/role/scope绑定','audit sequence和最终read-back闭合']),
    make('separation-approval-closed', '职责分离与批准闭合', 'RECOVERED', ['reviewer与approver职责分离','approval evidence可追溯']),
    make('authorized-override-closed', '授权override闭合', 'RECOVERED', ['override reason和授权完整','前一决策digest/version绑定']),
    make('dissent-appeal-closed', '异议与申诉闭合', 'RECOVERED', ['dissent/appeal path/owner完整','stakeholder notification和ack闭合']),
    make('reopen-review-closed', 'reopen/re-review闭合', 'RECOVERED', ['reopen condition和新版本决策绑定','旧决策不可静默覆盖']),
    make('expiry-version-audit-closed', '有效期/版本/审计闭合', 'RECOVERED', ['expiry review与effective time明确','decision version单调且可复验']),
    make('decision-id-missing', 'decision id缺失', 'UNKNOWN', ['无法稳定关联审核/申诉/审计'], decision_id_bound=False),
    make('reviewer-identity-missing', 'reviewer identity缺失', 'UNKNOWN', ['无法确认谁作出决定'], reviewer_identity_bound=False),
    make('reviewer-role-missing', 'reviewer role缺失', 'UNKNOWN', ['无法验证职责权限'], reviewer_role_bound=False),
    make('separation-open', '职责分离未闭合', 'UNKNOWN', ['同一人可能同时申请/批准/验收'], separation_of_duties_closed=False),
    make('approval-scope-missing', '批准范围缺失', 'UNKNOWN', ['批准不能映射到具体动作/资源'], approval_scope_bound=False),
    make('approval-evidence-missing', '批准证据缺失', 'UNKNOWN', ['批准状态只能由执行者自报'], approval_evidence_bound=False),
    make('override-reason-missing', 'override理由缺失', 'UNKNOWN', ['新决策无法解释为何偏离前决策'], override_reason_bound=False),
    make('override-unauthorized', 'override未授权', 'UNKNOWN', ['存在覆盖但没有合法授权'], override_authorized=False),
    make('dissent-missing', '异议记录缺失', 'UNKNOWN', ['不同意见可能被静默丢弃'], dissent_recorded=False),
    make('appeal-path-missing', '申诉路径缺失', 'UNKNOWN', ['争议无法进入复核流程'], appeal_path_bound=False),
    make('appeal-owner-missing', '申诉责任人缺失', 'UNKNOWN', ['申诉没有处理owner'], appeal_owner_bound=False),
    make('reopen-condition-missing', 'reopen条件缺失', 'UNKNOWN', ['何时重新打开决定不明'], reopen_condition_bound=False),
    make('version-regression', '决策版本回退', 'UNKNOWN', ['版本顺序无法证明'], decision_version_monotonic=False),
    make('prior-digest-missing', '前决策digest缺失', 'UNKNOWN', ['override/reopen无法绑定历史决定'], prior_decision_digest_bound=False),
    make('effective-time-missing', '生效时间缺失', 'UNKNOWN', ['决定适用时间窗口不明'], effective_time_bound=False),
    make('expiry-review-missing', '有效期复核缺失', 'UNKNOWN', ['旧决定可能继续生效'], expiry_review_bound=False),
    make('audit-sequence-gap', '审计序列缺口', 'UNKNOWN', ['动作/批准/通知顺序无法复核'], audit_sequence_closed=False),
    make('notification-missing', '通知未闭合', 'UNKNOWN', ['stakeholder可能未收到最终决定'], notification_bound=False),
    make('stakeholder-ack-missing', 'stakeholder ack缺失', 'UNKNOWN', ['收到/理解状态不明'], stakeholder_ack_bound=False),
    make('final-readback-missing', '最终决定未读回', 'UNKNOWN', ['审核流程完成不等于目标状态已提交'], final_decision_readback=False, unknown_review_state=True),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['project/decision/reviewer字段不完整'], same_identity=False),
    make('identity-conflict', '跨项目决定合并', 'REJECT', ['不同project/decision的review状态被错误合并'], same_identity=False, identity_conflict=True),
    make('review-conflict', '人工决策冲突', 'REJECT', ['同一decision出现不可调和的终态且无解释'], review_conflict=True),
]

assert len(cases) == 29
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S61-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['project', 'decision_id', 'reviewer', 'approver', 'role', 'appeal_id', 'version'],
    'review_domain': ['decision', 'scope', 'approval', 'override', 'dissent', 'appeal', 'reopen', 'effective_time', 'expiry', 'audit', 'notification', 'ack', 'readback'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')
