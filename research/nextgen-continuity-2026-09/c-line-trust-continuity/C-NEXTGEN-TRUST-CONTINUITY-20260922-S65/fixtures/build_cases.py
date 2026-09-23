#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','principal_bound','resource_bound',
    'action_bound','scope_bound','purpose_bound','least_privilege_attested',
    'grant_time_bound','expiry_bound','renewal_policy_bound','revocation_state_bound',
    'revocation_propagated','delegation_chain_bound','tool_permission_bound',
    'model_capability_bound','data_class_bound','region_bound','tenant_bound',
    'lease_fence_bound','stale_writer_rejected','access_readback','audit_closed',
    'permission_conflict','unknown_access_state'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'permission_conflict': False, 'unknown_access_state': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('least-privilege-closed', '最小权限principal/resource/action闭合', 'RECOVERED', ['principal/resource/action/scope/purpose完整','access readback/audit闭合']),
    make('lease-revocation-closed', '租约/过期/撤销闭合', 'RECOVERED', ['grant/expiry/renewal/revocation传播完整','stale writer被拒绝']),
    make('delegation-tool-model-closed', '委托/tool/model capability闭合', 'RECOVERED', ['delegation chain与tool/model capability绑定','data class/tenant/region一致']),
    make('fenced-access-closed', 'fence与访问闭合', 'RECOVERED', ['lease fence token绑定资源写入','撤销后访问read-back一致']),
    make('audit-access-closed', '访问审计闭合', 'RECOVERED', ['每次grant/use/revoke可追溯','权限scope可重算']),
    make('renewal-boundary-closed', 'renewal边界闭合', 'RECOVERED', ['renewal policy不扩大scope','过期后旧权限不可用']),
    make('principal-missing', 'principal未绑定', 'UNKNOWN', ['无法确认谁在访问资源'], principal_bound=False),
    make('resource-missing', 'resource未绑定', 'UNKNOWN', ['权限可能作用于错误资源'], resource_bound=False),
    make('action-scope-open', 'action/scope未闭合', 'UNKNOWN', ['read/write/admin范围不明'], action_bound=False, scope_bound=False),
    make('purpose-open', 'purpose未绑定', 'UNKNOWN', ['访问目的不能核验'], purpose_bound=False),
    make('least-privilege-unproven', '最小权限未证明', 'UNKNOWN', ['grant可能超过任务需要'], least_privilege_attested=False),
    make('grant-time-missing', 'grant time缺失', 'UNKNOWN', ['权限生效窗口不明'], grant_time_bound=False),
    make('expiry-missing', 'expiry缺失', 'UNKNOWN', ['权限可能永久有效'], expiry_bound=False),
    make('renewal-unknown', 'renewal策略未知', 'UNKNOWN', ['续期可能扩大scope或绕过审批'], renewal_policy_bound=False),
    make('revocation-unknown', '撤销状态未知', 'UNKNOWN', ['撤销请求与实际访问不一致'], revocation_state_bound=False),
    make('revocation-propagation-open', '撤销传播未闭合', 'UNKNOWN', ['缓存/代理/worker可能仍接受旧权限'], revocation_propagated=False),
    make('delegation-open', 'delegation chain未闭合', 'UNKNOWN', ['派生principal权限来源不明'], delegation_chain_bound=False),
    make('tool-permission-open', 'tool permission未绑定', 'UNKNOWN', ['工具可访问资源范围未知'], tool_permission_bound=False),
    make('model-capability-open', 'model capability未绑定', 'UNKNOWN', ['模型可调用的工具/数据能力不明'], model_capability_bound=False),
    make('data-class-open', 'data class未绑定', 'UNKNOWN', ['敏感数据访问边界不明'], data_class_bound=False),
    make('region-open', 'region约束未绑定', 'UNKNOWN', ['跨区域访问策略不明'], region_bound=False),
    make('tenant-open', 'tenant约束未绑定', 'UNKNOWN', ['跨tenant访问可能发生'], tenant_bound=False),
    make('lease-fence-open', 'lease fence未绑定', 'UNKNOWN', ['旧租约写者可能继续写入'], lease_fence_bound=False, unknown_access_state=True),
    make('stale-writer-open', 'stale writer拒绝未证明', 'UNKNOWN', ['过期principal可能仍成功写入'], stale_writer_rejected=False, unknown_access_state=True),
    make('access-readback-missing', '访问readback缺失', 'UNKNOWN', ['policy存在但运行时效果未知'], access_readback=False),
    make('audit-open', '权限审计缺失', 'UNKNOWN', ['访问动作无法追溯'], audit_closed=False),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['project/principal/resource字段不完整'], same_identity=False),
    make('identity-conflict', '跨tenant权限合并', 'REJECT', ['不同tenant/principal的权限状态被错误合并'], same_identity=False, identity_conflict=True),
    make('permission-conflict', '权限终态冲突', 'REJECT', ['同一grant同时出现不可调和allow/revoke'], permission_conflict=True),
]

assert len(cases) == 29
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S65-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['tenant', 'project', 'principal', 'resource', 'action', 'scope', 'purpose', 'grant_id', 'lease_id', 'fence_token'],
    'access_domain': ['least_privilege', 'grant', 'expiry', 'renewal', 'revocation', 'delegation', 'tool_permission', 'model_capability', 'data_class', 'region', 'lease', 'fence', 'stale_writer', 'audit'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')
