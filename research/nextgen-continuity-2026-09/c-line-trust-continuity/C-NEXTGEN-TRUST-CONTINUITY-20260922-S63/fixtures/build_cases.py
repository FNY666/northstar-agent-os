#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','decision_version_bound',
    'supersession_chain_closed','reopen_reason_bound','revoke_state_bound',
    'effective_window_bound','recipient_state_bound','ack_transition_bound',
    'read_state_semantics_known','unack_state_closed','delivery_evidence_retained',
    'retention_policy_bound','export_manifest_bound','audit_digest_bound',
    'cross_channel_consistency','recipient_reconciliation_closed','late_ack_handled',
    'stale_decision_rejected','reissue_id_bound','dedup_reissue_bound',
    'final_state_readback','notification_conflict','unknown_propagation_state'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'notification_conflict': False, 'unknown_propagation_state': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('supersession-chain-closed', '决定supersession链闭合', 'RECOVERED', ['旧/新decision version与supersession原因绑定','recipient最终状态可读回']),
    make('revoke-withdraw-closed', '撤回/撤销闭合', 'RECOVERED', ['revoke state和effective window明确','跨渠道状态一致']),
    make('reopen-review-closed', 'reopen与复核闭合', 'RECOVERED', ['reopen reason/new version完整','旧决定不再错误生效']),
    make('retained-export-audit-closed', '通知证据保留/导出/审计闭合', 'RECOVERED', ['delivery evidence retention与export manifest完整','audit digest可重算']),
    make('recipient-convergence-closed', 'recipient状态收敛闭合', 'RECOVERED', ['ack/read/unack语义明确','recipient reconciliation和最终read-back闭合']),
    make('late-ack-reconciled', '迟到ack对账闭合', 'RECOVERED', ['late ack按decision version处理','reissue/dedup规则防止旧ack污染']),
    make('decision-version-missing', 'decision version缺失', 'UNKNOWN', ['旧新通知和recipient状态无法区分'], decision_version_bound=False),
    make('supersession-gap', 'supersession链缺口', 'UNKNOWN', ['新决定存在但无法证明替代旧决定'], supersession_chain_closed=False),
    make('reopen-reason-missing', 'reopen理由缺失', 'UNKNOWN', ['重新打开决定的依据不明'], reopen_reason_bound=False),
    make('revoke-state-unknown', '撤回状态未知', 'UNKNOWN', ['撤销请求与recipient最终状态不能关联'], revoke_state_bound=False),
    make('effective-window-open', '生效窗口未闭合', 'UNKNOWN', ['决定适用时间范围不明'], effective_window_bound=False),
    make('recipient-state-unknown', 'recipient状态未知', 'UNKNOWN', ['已送达/已读/已采用语义不明'], recipient_state_bound=False),
    make('ack-transition-gap', 'ack状态迁移缺口', 'UNKNOWN', ['ack重复/回退/跨版本迁移未定义'], ack_transition_bound=False),
    make('read-semantics-unknown', 'read语义未知', 'UNKNOWN', ['已接收不等于已读或已理解'], read_state_semantics_known=False),
    make('unack-state-open', '未ack状态未闭合', 'UNKNOWN', ['未确认recipient的处置不明'], unack_state_closed=False),
    make('delivery-retention-open', '投递证据保留未闭合', 'UNKNOWN', ['过期后无法重建receipt/ack链'], delivery_evidence_retained=False),
    make('retention-policy-missing', '通知保留策略缺失', 'UNKNOWN', ['审计窗口和删除边界不明'], retention_policy_bound=False),
    make('export-manifest-missing', '通知证据导出manifest缺失', 'UNKNOWN', ['导出包内容/版本/hash不明'], export_manifest_bound=False),
    make('audit-digest-missing', '通知审计digest缺失', 'UNKNOWN', ['审计内容变化无法检测'], audit_digest_bound=False),
    make('cross-channel-inconsistent', '跨渠道状态不一致', 'UNKNOWN', ['同一version在不同channel状态无法解释'], cross_channel_consistency=False),
    make('recipient-reconciliation-open', 'recipient reconciliation未闭合', 'UNKNOWN', ['应通知集合与实际recipient状态不能对账'], recipient_reconciliation_closed=False),
    make('late-ack-unhandled', '迟到ack未处理', 'UNKNOWN', ['旧版本ack可能污染当前决定'], late_ack_handled=False),
    make('stale-decision-protection-open', '旧决定保护未闭合', 'UNKNOWN', ['stale decision可能继续被采用'], stale_decision_rejected=False),
    make('reissue-id-missing', '重发id缺失', 'UNKNOWN', ['reissue无法与原通知和决定绑定'], reissue_id_bound=False),
    make('dedup-reissue-open', '重发去重未闭合', 'UNKNOWN', ['重发可能造成重复动作/计数'], dedup_reissue_bound=False),
    make('final-readback-missing', '最终状态未读回', 'UNKNOWN', ['传播流程完成不等于所有recipient状态已更新'], final_state_readback=False, unknown_propagation_state=True),
    make('identity-conflict', '跨项目决定传播合并', 'REJECT', ['不同project/decision的recipient状态被错误合并'], same_identity=False, identity_conflict=True),
    make('notification-conflict', '通知状态冲突', 'REJECT', ['同一recipient/version同时出现不可调和的active/revoked或delivered/failed'], notification_conflict=True),
]

assert len(cases) == 28
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S63-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['project', 'decision_id', 'notification_id', 'recipient_id', 'channel', 'version'],
    'propagation_domain': ['supersession', 'reopen', 'revoke', 'effective_window', 'recipient_state', 'ack_transition', 'read_state', 'unack', 'retention', 'export', 'audit', 'reconciliation', 'late_ack', 'stale_decision', 'reissue', 'dedup', 'readback'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')
