#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','evidence_window_closed','source_set_closed',
    'claim_scope_closed','precondition_closed','postcondition_readback','independent_verifier',
    'decision_policy_bound','recovered_rule_closed','unknown_rule_closed','reject_rule_closed',
    'quarantine_on_unknown','escalation_owner_bound','manual_review_gate_bound',
    'review_evidence_bound','remediation_action_bound','remediation_idempotency_bound',
    'retry_reconciliation_closed','final_state_revalidated','decision_immutability',
    'audit_record_closed','conflict_resolution_bound','decision_conflict'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'decision_conflict': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('final-evidence-gate-closed', '最终证据门闭合', 'RECOVERED', ['evidence window/source/claim范围完整','pre/postcondition与独立verifier闭合']),
    make('quarantine-escalation-closed', 'UNKNOWN隔离与升级闭合', 'RECOVERED', ['unknown自动隔离','escalation owner与manual review gate明确']),
    make('manual-review-remediation-closed', '人工审核与修复闭合', 'RECOVERED', ['review evidence和remediation action绑定','最终状态可复验']),
    make('idempotent-compensation-closed', '补偿与幂等闭合', 'RECOVERED', ['retry/reconciliation和remediation idempotency完整','无重复外部动作']),
    make('revalidation-decision-closed', '重新验证与决策不可变闭合', 'RECOVERED', ['最终read-back触发revalidation','decision immutable且audit完整']),
    make('conflict-resolution-audit-closed', '冲突处理与审计闭合', 'RECOVERED', ['conflict resolution policy明确','人工/自动决策全链路审计']),
    make('evidence-window-open', '证据窗口未闭合', 'UNKNOWN', ['无法证明结论覆盖完整时间/资源范围'], evidence_window_closed=False),
    make('source-set-open', '来源集合未闭合', 'UNKNOWN', ['来源增删影响不明'], source_set_closed=False),
    make('claim-scope-open', 'claim范围未闭合', 'UNKNOWN', ['结论适用对象和边界不明'], claim_scope_closed=False),
    make('precondition-open', '前置条件未闭合', 'UNKNOWN', ['无法证明动作具备执行前提'], precondition_closed=False),
    make('postcondition-missing', '后置条件未读回', 'UNKNOWN', ['平台完成不等于目标状态已提交'], postcondition_readback=False),
    make('verifier-missing', '独立验证者缺失', 'UNKNOWN', ['写入方自证不能升级状态'], independent_verifier=False),
    make('decision-policy-unknown', '决策规则未知', 'UNKNOWN', ['RECOVERED/UNKNOWN/REJECT门槛不明'], decision_policy_bound=False),
    make('recovered-rule-open', 'RECOVERED规则未闭合', 'UNKNOWN', ['证据不足可能被误升级'], recovered_rule_closed=False),
    make('unknown-rule-open', 'UNKNOWN规则未闭合', 'UNKNOWN', ['缺证据可能被误判为成功/失败'], unknown_rule_closed=False),
    make('reject-rule-open', 'REJECT规则未闭合', 'UNKNOWN', ['不可调和冲突处理不明'], reject_rule_closed=False),
    make('quarantine-missing', 'UNKNOWN隔离缺失', 'UNKNOWN', ['未知状态可能继续进入下游'], quarantine_on_unknown=False),
    make('escalation-owner-missing', '升级责任人缺失', 'UNKNOWN', ['未知状态没有处理责任'], escalation_owner_bound=False),
    make('manual-review-missing', '人工审核门缺失', 'UNKNOWN', ['高风险状态缺少人工决策门'], manual_review_gate_bound=False),
    make('review-evidence-missing', '审核证据缺失', 'UNKNOWN', ['人工结论没有可追溯依据'], review_evidence_bound=False),
    make('remediation-action-unknown', '修复动作未知', 'UNKNOWN', ['补偿/修复是否执行不明'], remediation_action_bound=False),
    make('remediation-idempotency-unknown', '修复幂等性未知', 'UNKNOWN', ['重试可能重复外部动作'], remediation_idempotency_bound=False),
    make('retry-reconciliation-open', '重试对账未闭合', 'UNKNOWN', ['重试后目标状态不可确认'], retry_reconciliation_closed=False),
    make('final-state-not-revalidated', '最终状态未重新验证', 'UNKNOWN', ['早期证据不能覆盖最新目标状态'], final_state_revalidated=False),
    make('decision-mutability-open', '决策可变性未闭合', 'UNKNOWN', ['既有结论可能被静默覆盖'], decision_immutability=False),
    make('conflict-resolution-open', '冲突解决规则未闭合', 'UNKNOWN', ['多源冲突无法安全收敛'], conflict_resolution_bound=False),
    make('identity-conflict', '跨任务身份合并', 'REJECT', ['不同project/task的证据被错误合并'], same_identity=False, identity_conflict=True),
    make('decision-conflict', '最终决策状态冲突', 'REJECT', ['同一目标同时出现不可调和的终态决策'], decision_conflict=True),
]

assert len(cases) == 28
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S60-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['project', 'task', 'operation', 'evidence_window', 'decision_id', 'review_id'],
    'decision_domain': ['precondition', 'postcondition', 'verifier', 'policy', 'recovered', 'unknown', 'reject', 'quarantine', 'escalation', 'manual_review', 'remediation', 'retry', 'revalidation', 'audit', 'conflict'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')
