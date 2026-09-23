#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','notification_id_bound','decision_version_bound',
    'recipient_set_closed','channel_bound','payload_digest_bound','delivery_attempt_bound',
    'delivery_receipt_bound','retry_state_bound','dedup_key_bound','ack_semantics_known',
    'ack_bound','ack_timestamp_bound','deadline_bound','escalation_policy_bound',
    'escalation_owner_bound','channel_fallback_bound','coverage_reconciled',
    'notification_order_closed','final_decision_readback','audit_record_closed',
    'notification_conflict','unknown_delivery_state'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'notification_conflict': False, 'unknown_delivery_state': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('delivery-receipt-closed', '投递与receipt闭合', 'RECOVERED', ['notification/decision/recipient identity完整','attempt与receipt可对账']),
    make('multi-channel-fallback-closed', '多渠道fallback闭合', 'RECOVERED', ['主渠道失败后fallback顺序明确','最终channel receipt可读回']),
    make('ack-coverage-closed', 'recipient ack覆盖闭合', 'RECOVERED', ['recipient set完整','ack语义、时间和coverage均闭合']),
    make('retry-dedup-closed', '重试与去重闭合', 'RECOVERED', ['retry state和dedup key绑定','无重复通知计数']),
    make('deadline-escalation-closed', 'deadline升级闭合', 'RECOVERED', ['deadline/escalation policy/owner完整','升级动作有receipt']),
    make('final-decision-propagation-closed', '最终决定传播闭合', 'RECOVERED', ['notification order与final read-back完整','audit record可追溯']),
    make('notification-id-missing', 'notification id缺失', 'UNKNOWN', ['无法稳定关联投递/ack/审计'], notification_id_bound=False),
    make('decision-version-missing', 'decision version缺失', 'UNKNOWN', ['旧决定和新决定可能混淆'], decision_version_bound=False),
    make('recipient-set-open', 'recipient集合未闭合', 'UNKNOWN', ['无法证明所有应通知对象均覆盖'], recipient_set_closed=False),
    make('channel-unknown', '通知渠道未知', 'UNKNOWN', ['投递路径和审计边界不明'], channel_bound=False),
    make('payload-digest-missing', 'payload digest缺失', 'UNKNOWN', ['重试/ack无法绑定同一内容'], payload_digest_bound=False),
    make('attempt-missing', '投递attempt缺失', 'UNKNOWN', ['无法判断是否尝试发送'], delivery_attempt_bound=False),
    make('receipt-missing', 'delivery receipt缺失', 'UNKNOWN', ['发送请求不等于目标已接收'], delivery_receipt_bound=False, unknown_delivery_state=True),
    make('retry-unknown', 'retry状态未知', 'UNKNOWN', ['重试次数和最终投递状态不明'], retry_state_bound=False),
    make('dedup-key-missing', 'dedup key缺失', 'UNKNOWN', ['重复通知可能造成重复动作'], dedup_key_bound=False),
    make('ack-semantics-unknown', 'ack语义未知', 'UNKNOWN', ['已读/已接收/已理解语义混淆'], ack_semantics_known=False),
    make('ack-missing', 'ack缺失', 'UNKNOWN', ['recipient是否收到无法确认'], ack_bound=False),
    make('ack-timestamp-missing', 'ack时间缺失', 'UNKNOWN', ['deadline前后状态无法确定'], ack_timestamp_bound=False),
    make('deadline-missing', 'deadline缺失', 'UNKNOWN', ['升级时点不可判定'], deadline_bound=False),
    make('escalation-policy-missing', '升级策略缺失', 'UNKNOWN', ['未ack时下一步不明'], escalation_policy_bound=False),
    make('escalation-owner-missing', '升级责任人缺失', 'UNKNOWN', ['升级事件没有处理owner'], escalation_owner_bound=False),
    make('fallback-missing', '渠道fallback缺失', 'UNKNOWN', ['主渠道失败后可能静默丢失'], channel_fallback_bound=False),
    make('coverage-unreconciled', '通知coverage未对账', 'UNKNOWN', ['recipient set与实际结果不一致'], coverage_reconciled=False),
    make('order-gap', '通知顺序缺口', 'UNKNOWN', ['旧决定/新决定可能乱序到达'], notification_order_closed=False),
    make('final-readback-missing', '最终决定传播未读回', 'UNKNOWN', ['流程完成不等于所有目标状态已更新'], final_decision_readback=False, unknown_delivery_state=True),
    make('audit-gap', '通知审计缺口', 'UNKNOWN', ['动作、receipt和ack无法完整追溯'], audit_record_closed=False),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['project/decision/recipient字段不完整'], same_identity=False),
    make('identity-conflict', '跨项目通知合并', 'REJECT', ['不同project/decision的通知状态被错误合并'], same_identity=False, identity_conflict=True),
    make('notification-conflict', '通知终态冲突', 'REJECT', ['同一recipient/version同时出现不可调和的delivered/failed'], notification_conflict=True),
]

assert len(cases) == 29
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S62-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['project', 'decision_id', 'notification_id', 'recipient_id', 'channel', 'version'],
    'notification_domain': ['recipient_set', 'payload_digest', 'attempt', 'receipt', 'retry', 'dedup', 'ack', 'deadline', 'escalation', 'fallback', 'coverage', 'order', 'readback', 'audit'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')
