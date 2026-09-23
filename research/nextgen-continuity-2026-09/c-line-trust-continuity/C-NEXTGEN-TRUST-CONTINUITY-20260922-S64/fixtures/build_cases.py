#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','notification_class_declared',
    'recipient_authorization_bound','consent_state_bound','purpose_bound',
    'payload_minimization_bound','redaction_policy_bound','channel_data_policy_bound',
    'region_constraint_bound','retention_period_bound','deletion_attested',
    'export_scope_bound','export_destination_bound','access_role_bound',
    'access_audit_closed','template_version_bound','locale_variant_bound',
    'decision_version_bound','recipient_preference_bound','fallback_privacy_consistent',
    'replay_privacy_safe','privacy_conflict','unknown_privacy_state'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'privacy_conflict': False, 'unknown_privacy_state': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('privacy-notification-closed', '通知隐私/授权闭合', 'RECOVERED', ['recipient授权/consent/purpose完整','payload最小化与redaction已验证']),
    make('retention-deletion-closed', '保留/删除闭合', 'RECOVERED', ['retention period和deletion attestation完整','导出范围受控']),
    make('access-audit-closed', '访问角色与审计闭合', 'RECOVERED', ['access role和audit closed','destination/region可追溯']),
    make('template-locale-closed', '模板/locale版本闭合', 'RECOVERED', ['template/locale/decision version绑定','recipient preference一致']),
    make('fallback-privacy-closed', 'fallback隐私一致性闭合', 'RECOVERED', ['主/备渠道data policy一致','重放不会泄露更多payload']),
    make('export-access-closed', '导出与访问边界闭合', 'RECOVERED', ['export scope/destination和access audit完整','内容分类可追溯']),
    make('class-unknown', '通知分类未声明', 'UNKNOWN', ['无法选择数据处理策略'], notification_class_declared=False),
    make('recipient-auth-open', 'recipient授权未绑定', 'UNKNOWN', ['不能证明该recipient可接收内容'], recipient_authorization_bound=False),
    make('consent-unknown', 'consent状态未知', 'UNKNOWN', ['同意/拒绝/撤回状态不明'], consent_state_bound=False),
    make('purpose-open', '通知目的未绑定', 'UNKNOWN', ['无法判断是否超出原始目的'], purpose_bound=False),
    make('minimization-open', '数据最小化未证明', 'UNKNOWN', ['payload可能包含不必要敏感字段'], payload_minimization_bound=False),
    make('redaction-open', 'redaction策略未绑定', 'UNKNOWN', ['敏感字段处理方式未知'], redaction_policy_bound=False),
    make('channel-policy-open', '渠道数据策略未知', 'UNKNOWN', ['不同channel可能使用不同隐私规则'], channel_data_policy_bound=False),
    make('region-unknown', '数据区域约束未知', 'UNKNOWN', ['内容可能跨区域处理'], region_constraint_bound=False),
    make('retention-open', '保留周期未知', 'UNKNOWN', ['通知证据删除边界不明'], retention_period_bound=False),
    make('deletion-unattested', '删除未证明', 'UNKNOWN', ['过期数据可能仍可访问'], deletion_attested=False),
    make('export-scope-open', '导出范围未绑定', 'UNKNOWN', ['导出可能超出recipient/decision范围'], export_scope_bound=False),
    make('destination-open', '导出目的地未知', 'UNKNOWN', ['数据可能流向未审查系统'], export_destination_bound=False),
    make('access-role-open', '访问角色未绑定', 'UNKNOWN', ['读取权限可能越界'], access_role_bound=False),
    make('audit-open', '访问审计未闭合', 'UNKNOWN', ['读取动作不可追溯'], access_audit_closed=False),
    make('template-version-open', '模板版本未绑定', 'UNKNOWN', ['内容版本无法复核'], template_version_bound=False),
    make('locale-open', 'locale变体未绑定', 'UNKNOWN', ['不同语言内容可能语义不一致'], locale_variant_bound=False),
    make('decision-version-open', '决定版本未绑定', 'UNKNOWN', ['旧决定内容可能继续传播'], decision_version_bound=False),
    make('preference-open', 'recipient偏好未绑定', 'UNKNOWN', ['渠道/语言/频率偏好未知'], recipient_preference_bound=False),
    make('fallback-inconsistent', 'fallback隐私不一致', 'UNKNOWN', ['备用渠道可能放宽数据保护'], fallback_privacy_consistent=False),
    make('replay-privacy-open', '重放隐私边界未闭合', 'UNKNOWN', ['重复投递可能扩大敏感内容暴露'], replay_privacy_safe=False),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['project/decision/recipient字段不完整'], same_identity=False),
    make('identity-conflict', '跨项目隐私合并', 'REJECT', ['不同project/recipient的数据策略被错误合并'], same_identity=False, identity_conflict=True),
    make('privacy-conflict', '通知隐私状态冲突', 'REJECT', ['同一recipient/decision同时出现不可调和的allow/deny或retained/deleted'], privacy_conflict=True),
]

assert len(cases) == 29
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S64-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['project', 'decision_id', 'recipient_id', 'notification_id', 'channel', 'region', 'version'],
    'privacy_notification_domain': ['classification', 'authorization', 'consent', 'purpose', 'minimization', 'redaction', 'channel_policy', 'retention', 'deletion', 'export', 'destination', 'access_role', 'audit', 'template', 'locale', 'preference', 'replay'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')
