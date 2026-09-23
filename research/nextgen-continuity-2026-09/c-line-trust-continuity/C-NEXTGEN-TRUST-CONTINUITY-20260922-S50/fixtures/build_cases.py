#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','auth_method_declared','credential_source_bound',
    'token_scope_valid','token_fresh','quota_scope_known','quota_remaining_known',
    'billing_mode_known','billing_identity_bound','privacy_policy_bound','telemetry_policy_bound',
    'model_requested_bound','model_selected_readback','fallback_policy_known',
    'provider_identity_bound','routing_precedence_known','rate_limit_state_known',
    'retry_charge_semantics_known','region_constraint_known','usage_record_closed',
    'auth_route_conflict','unknown_provider_state'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'auth_route_conflict': False, 'unknown_provider_state': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('api-key-route-closed', 'API key认证/模型路由闭合', 'RECOVERED', ['credential source/scope/freshness可验证','requested model与selected model可读回']),
    make('oauth-route-closed', 'OAuth认证与fallback闭合', 'RECOVERED', ['OAuth identity和quota/billing绑定','fallback policy与最终provider可追溯']),
    make('vertex-billing-closed', 'Vertex配额计费隐私闭合', 'RECOVERED', ['region/provider/billing identity固定','usage record与telemetry policy闭合']),
    make('model-precedence-closed', '模型选择优先级闭合', 'RECOVERED', ['CLI/env/settings/router precedence已知','最终model read-back一致']),
    make('rate-limit-retry-closed', '限流重试费用语义闭合', 'RECOVERED', ['rate-limit state可观察','retry是否计费与usage record可对账']),
    make('privacy-telemetry-closed', '隐私与遥测策略闭合', 'RECOVERED', ['privacy policy和telemetry opt-out边界明确','数据来源可归因']),
    make('auth-method-unknown', '认证方式未声明', 'UNKNOWN', ['无法判断credential/quota/privacy路径'], auth_method_declared=False),
    make('credential-source-unbound', '凭据来源未绑定', 'UNKNOWN', ['token/key可能来自错误环境'], credential_source_bound=False),
    make('scope-invalid', 'token scope无效', 'UNKNOWN', ['认证成功不等于目标API被授权'], token_scope_valid=False),
    make('token-stale', 'token freshness未知', 'UNKNOWN', ['无法确认token在请求时有效'], token_fresh=False),
    make('quota-unknown', 'quota范围/余额未知', 'UNKNOWN', ['失败可能是配额、权限或网络'], quota_scope_known=False, quota_remaining_known=False),
    make('billing-unknown', '计费模式未知', 'UNKNOWN', ['无法判断请求归属于哪个账单身份'], billing_mode_known=False, billing_identity_bound=False),
    make('privacy-policy-missing', '隐私政策边界未知', 'UNKNOWN', ['认证方式对应的数据处理条款未绑定'], privacy_policy_bound=False),
    make('telemetry-policy-missing', 'telemetry策略未知', 'UNKNOWN', ['prompt/tool/session数据是否采集不明'], telemetry_policy_bound=False),
    make('model-request-unbound', 'requested model未绑定', 'UNKNOWN', ['CLI/env/settings输入不完整'], model_requested_bound=False),
    make('model-readback-missing', 'selected model未读回', 'UNKNOWN', ['router/fallback可能选择了不同模型'], model_selected_readback=False),
    make('fallback-unknown', 'fallback策略未知', 'UNKNOWN', ['失败后是否切换provider/model不明'], fallback_policy_known=False, unknown_provider_state=True),
    make('provider-unbound', 'provider identity未绑定', 'UNKNOWN', ['同名模型来自不同provider'], provider_identity_bound=False),
    make('precedence-unknown', 'routing precedence未知', 'UNKNOWN', ['--model/env/settings/router优先级不明'], routing_precedence_known=False),
    make('rate-limit-unknown', 'rate limit状态未知', 'UNKNOWN', ['错误可能被误判为认证失败'], rate_limit_state_known=False),
    make('retry-charge-unknown', '重试计费语义未知', 'UNKNOWN', ['重试是否产生额外费用无法对账'], retry_charge_semantics_known=False),
    make('region-unknown', 'region约束未知', 'UNKNOWN', ['provider/quota/隐私区域不能确定'], region_constraint_known=False),
    make('usage-record-gap', 'usage record缺口', 'UNKNOWN', ['请求结果与账单/usage无法对账'], usage_record_closed=False),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['account/project/provider字段不完整'], same_identity=False),
    make('identity-conflict', '跨账户/项目合并', 'REJECT', ['不同account/project被错误合并'], same_identity=False, identity_conflict=True),
    make('auth-route-conflict', '认证路由状态冲突', 'REJECT', ['同一请求同时声明不同credential/provider终态'], auth_route_conflict=True),
    make('billing-privacy-conflict', '计费与隐私状态冲突', 'REJECT', ['同一请求被归属不可调和的billing/privacy路径'], auth_route_conflict=True, billing_identity_bound=False),
]

assert len(cases) == 27
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S50-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['account', 'project', 'provider', 'model', 'region', 'request_id'],
    'auth_routing_domain': ['auth_method', 'credential', 'scope', 'freshness', 'quota', 'billing', 'privacy', 'telemetry', 'model', 'fallback', 'routing_precedence', 'rate_limit', 'retry', 'usage'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')
