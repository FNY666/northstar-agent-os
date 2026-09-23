#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','server_declared','server_trusted',
    'tool_allowlist_closed','resource_allowlist_closed','include_exclude_consistent',
    'transport_authenticated','request_context_bound','argument_schema_valid',
    'resource_uri_bound','resource_version_closed','result_captured',
    'error_state_captured','timeout_semantics_known','side_effect_class_known',
    'approval_boundary_known','source_attribution_closed','pagination_closed',
    'retry_state_reconciled','permission_conflict','unknown_remote_state'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'permission_conflict': False, 'unknown_remote_state': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('mcp-tool-closed', 'MCP tool授权与结果闭合', 'RECOVERED', ['server trust和tool allowlist明确','request/result/error均可追溯']),
    make('mcp-resource-closed', 'MCP resource读取闭合', 'RECOVERED', ['resource URI/version绑定','分页和source attribution闭合']),
    make('web-fetch-boundary-closed', 'web tool边界闭合', 'RECOVERED', ['请求上下文与资源边界明确','返回内容和错误状态已捕获']),
    make('include-exclude-closed', 'include/exclude策略一致', 'RECOVERED', ['allow/exclude没有交叉歧义','effective permission可读回']),
    make('retry-timeout-closed', '超时重试已对账', 'RECOVERED', ['retry state和最终返回闭合','未知远端状态已排除']),
    make('approval-side-effect-closed', '审批与副作用分类闭合', 'RECOVERED', ['approval boundary已定义','side-effect class明确']),
    make('server-undeclared', 'MCP server未声明', 'UNKNOWN', ['无法判断server属于哪个信任域'], server_declared=False),
    make('server-untrusted', 'MCP server未信任', 'UNKNOWN', ['server存在但未通过信任/allowlist'], server_trusted=False),
    make('tool-allowlist-open', 'tool allowlist未闭合', 'UNKNOWN', ['server暴露的tool范围不明'], tool_allowlist_closed=False),
    make('resource-allowlist-open', 'resource allowlist未闭合', 'UNKNOWN', ['resource URI可能越界'], resource_allowlist_closed=False),
    make('include-exclude-confused', 'include/exclude语义不明', 'UNKNOWN', ['两套过滤规则的优先级未知'], include_exclude_consistent=False),
    make('transport-unauthenticated', 'transport未认证', 'UNKNOWN', ['无法绑定响应来源或防止中间人替换'], transport_authenticated=False),
    make('context-unbound', '请求上下文未绑定', 'UNKNOWN', ['tool request可能被移植到不同session/tenant'], request_context_bound=False),
    make('argument-schema-invalid', '参数schema无效', 'UNKNOWN', ['参数解释可能与server不同'], argument_schema_valid=False),
    make('resource-uri-unbound', 'resource URI未绑定', 'UNKNOWN', ['同一URI可能指向不同资源版本'], resource_uri_bound=False),
    make('resource-version-open', 'resource version未闭合', 'UNKNOWN', ['读取时点与资源内容无法关联'], resource_version_closed=False),
    make('result-missing', 'tool结果未捕获', 'UNKNOWN', ['不能判断工具返回或部分结果'], result_captured=False),
    make('error-missing', '错误状态未捕获', 'UNKNOWN', ['失败可能被当作空结果'], error_state_captured=False),
    make('timeout-unknown', '超时语义未知', 'UNKNOWN', ['请求可能已在远端执行'], timeout_semantics_known=False, unknown_remote_state=True),
    make('side-effect-unknown', '副作用类别未知', 'UNKNOWN', ['不能判断read-only还是改变状态'], side_effect_class_known=False),
    make('approval-unknown', '审批边界未知', 'UNKNOWN', ['工具调用是否需要用户确认不明'], approval_boundary_known=False),
    make('source-attribution-open', '来源归因未闭合', 'UNKNOWN', ['web/resource返回内容无法追溯来源'], source_attribution_closed=False),
    make('pagination-open', 'resource分页未闭合', 'UNKNOWN', ['当前页不代表完整resource结果'], pagination_closed=False),
    make('retry-reconciliation-open', 'retry未对账', 'UNKNOWN', ['重试后可能重复或漏掉结果'], retry_state_reconciled=False),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['session/tenant/server字段不完整'], same_identity=False),
    make('identity-conflict', '跨身份域调用', 'REJECT', ['tenant/session明确不同'], same_identity=False, identity_conflict=True),
    make('permission-conflict', 'MCP授权冲突', 'REJECT', ['同一请求同时allow与deny且无优先级闭合'], permission_conflict=True),
    make('remote-result-conflict', '远端结果状态冲突', 'REJECT', ['同一request返回不可调和成功/错误状态'], permission_conflict=True, result_captured=False),
]

assert len(cases) == 28
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S44-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['session', 'tenant', 'server', 'tool', 'resource_uri', 'request_id'],
    'mcp_web_domain': ['server', 'tool_allowlist', 'resource_allowlist', 'include_exclude', 'transport', 'context', 'schema', 'URI', 'version', 'result', 'error', 'timeout', 'approval', 'attribution', 'pagination', 'retry'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')
