#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','agent_card_bound','auth_scheme_declared',
    'auth_credential_bound','proxy_scope_known','streaming_capability_known',
    'task_id_bound','context_id_bound','message_request_bound','task_status_bound',
    'artifact_update_bound','status_update_order_closed','session_state_persisted',
    'cross_invocation_state_bound','abort_signal_bound','cancel_state_observed',
    'error_classified','retry_policy_known','remote_effect_readback',
    'a2a_version_compatible','auth_conflict','unknown_remote_state'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'auth_conflict': False, 'unknown_remote_state': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('a2a-stream-task-closed', 'A2A streaming task闭合', 'RECOVERED', ['agent card/auth/task/context identity完整','status/artifact stream顺序可验证']),
    make('a2a-session-persisted', '跨invocation session state闭合', 'RECOVERED', ['contextId/taskId持久化并可复用','新invocation与历史绑定']),
    make('a2a-cancel-error-closed', '取消/错误分类闭合', 'RECOVERED', ['abort/cancel状态可观察','error class/retry语义与最终read-back一致']),
    make('a2a-auth-proxy-closed', 'A2A认证与proxy边界闭合', 'RECOVERED', ['auth scheme/credential和proxy scope绑定','agent card与endpoint一致']),
    make('a2a-artifact-status-closed', 'artifact/status更新闭合', 'RECOVERED', ['task status与artifact update顺序完整','无未知远端状态']),
    make('a2a-compatible-readback-closed', '协议兼容与远端读回闭合', 'RECOVERED', ['A2A version/streaming capability兼容','独立read-back确认远端状态']),
    make('agent-card-missing', 'agent card未绑定', 'UNKNOWN', ['无法确认远端能力/auth/endpoint'], agent_card_bound=False),
    make('auth-scheme-unknown', '认证scheme未知', 'UNKNOWN', ['Bearer/Basic/OAuth等语义无法确定'], auth_scheme_declared=False),
    make('credential-unbound', '认证凭据未绑定', 'UNKNOWN', ['credential可能来自错误环境/agent'], auth_credential_bound=False),
    make('proxy-scope-unknown', 'proxy scope未知', 'UNKNOWN', ['请求可能经过未审查proxy'], proxy_scope_known=False),
    make('streaming-capability-unknown', 'streaming能力未知', 'UNKNOWN', ['客户端期待stream但远端能力不明'], streaming_capability_known=False),
    make('task-unbound', 'taskId未绑定', 'UNKNOWN', ['更新事件不能归属于单一task'], task_id_bound=False),
    make('context-unbound', 'contextId未绑定', 'UNKNOWN', ['跨invocation上下文可能串线'], context_id_bound=False),
    make('message-unbound', 'message request未绑定', 'UNKNOWN', ['消息与task/session无法关联'], message_request_bound=False),
    make('task-status-unbound', 'task status未绑定', 'UNKNOWN', ['working/completed/failed/canceled状态不明'], task_status_bound=False),
    make('artifact-unbound', 'artifact update未绑定', 'UNKNOWN', ['远端输出不能归属于task'], artifact_update_bound=False),
    make('status-order-gap', 'status/update顺序缺口', 'UNKNOWN', ['stream事件可能丢失/乱序'], status_update_order_closed=False),
    make('session-persistence-unknown', 'session state未持久化', 'UNKNOWN', ['后续invocation无法确认是否续接原session'], session_state_persisted=False),
    make('cross-invocation-unbound', '跨invocation状态未绑定', 'UNKNOWN', ['同一context/task可能被错误重建'], cross_invocation_state_bound=False),
    make('abort-unbound', 'abort signal未绑定', 'UNKNOWN', ['取消可能作用于错误task'], abort_signal_bound=False),
    make('cancel-unknown', 'cancel状态未观察', 'UNKNOWN', ['abort request不等于远端已停止'], cancel_state_observed=False, unknown_remote_state=True),
    make('error-unclassified', 'A2A错误未分类', 'UNKNOWN', ['HTTP/RPC/task error不能映射到可重试状态'], error_classified=False),
    make('retry-unknown', 'retry策略未知', 'UNKNOWN', ['重试可能重复远端副作用'], retry_policy_known=False),
    make('remote-readback-missing', '远端效果未读回', 'UNKNOWN', ['task completed不等于外部效果已提交'], remote_effect_readback=False, unknown_remote_state=True),
    make('version-unknown', 'A2A版本兼容未知', 'UNKNOWN', ['agent card与client protocol可能不兼容'], a2a_version_compatible=False),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['client/project/agent/session字段不完整'], same_identity=False),
    make('identity-conflict', '跨agent身份合并', 'REJECT', ['不同agent/session的task被错误合并'], same_identity=False, identity_conflict=True),
    make('auth-conflict', '认证状态冲突', 'REJECT', ['同一agent request同时出现不可调和auth结果'], auth_conflict=True),
]

assert len(cases) == 28
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S53-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['client', 'project', 'agent', 'agent_card', 'context_id', 'task_id', 'message_id', 'request_id'],
    'a2a_domain': ['agent_card', 'auth', 'proxy', 'streaming', 'task', 'context', 'message', 'status_update', 'artifact_update', 'session_state', 'invocation', 'abort', 'error', 'retry', 'version'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')
