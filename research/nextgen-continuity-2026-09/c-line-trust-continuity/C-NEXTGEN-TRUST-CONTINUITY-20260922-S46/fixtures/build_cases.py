#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','protocol_declared','initialize_complete',
    'session_id_bound','new_session_attested','load_session_attested','prompt_bound',
    'cancel_request_attested','cancel_state_observed','notification_sequence_closed',
    'tool_call_permission_bound','context_update_bound','diff_open_close_bound',
    'accepted_rejected_bound','stdin_transport_closed','session_persistence_attested',
    'reconnect_state_reconciled','unknown_remote_effect_absent','duplicate_notification_deduped',
    'lifecycle_conflict','unknown_session_state'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'lifecycle_conflict': False, 'unknown_session_state': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('acp-new-session-closed', 'ACP initialize/newSession闭合', 'RECOVERED', ['协议握手和session id绑定','newSession结果可验证']),
    make('acp-prompt-cancel-observed', 'prompt/cancel状态闭合', 'RECOVERED', ['prompt与cancel request可关联','cancel后状态可独立观察']),
    make('acp-load-session-closed', 'loadSession持久化闭合', 'RECOVERED', ['session persistence已证明','加载后的identity与历史一致']),
    make('ide-context-diff-closed', 'IDE context/diff通知闭合', 'RECOVERED', ['contextUpdate与diff open/close顺序完整','accepted/rejected状态绑定']),
    make('notification-tool-permission-closed', '通知与tool permission闭合', 'RECOVERED', ['tool_call与request_permission顺序完整','权限结果可追溯']),
    make('stdio-transport-closed', 'stdio JSON-RPC传输闭合', 'RECOVERED', ['stdin transport边界明确','notification去重和session state均闭合']),
    make('protocol-unknown', '协议未声明', 'UNKNOWN', ['无法判断是ACP还是IDE companion语义'], protocol_declared=False),
    make('initialize-missing', 'initialize未完成', 'UNKNOWN', ['后续session操作缺少能力协商'], initialize_complete=False),
    make('session-id-unbound', 'session id未绑定', 'UNKNOWN', ['消息不能安全归属于单一session'], session_id_bound=False),
    make('new-session-unread', 'newSession结果未读回', 'UNKNOWN', ['创建请求发送但session状态未知'], new_session_attested=False),
    make('load-session-unread', 'loadSession未读回', 'UNKNOWN', ['加载结果与历史状态不可核对'], load_session_attested=False),
    make('prompt-unbound', 'prompt未绑定', 'UNKNOWN', ['prompt与session/turn关联不明'], prompt_bound=False),
    make('cancel-unread', 'cancel结果未观察', 'UNKNOWN', ['cancel request不等于远端已停止'], cancel_state_observed=False, unknown_session_state=True),
    make('notification-sequence-gap', '通知序列缺口', 'UNKNOWN', ['部分update/permission通知缺失'], notification_sequence_closed=False),
    make('tool-permission-unbound', 'tool permission未绑定', 'UNKNOWN', ['tool_call与审批结果不能关联'], tool_call_permission_bound=False),
    make('context-update-gap', 'contextUpdate缺口', 'UNKNOWN', ['IDE上下文可能未被远端接收'], context_update_bound=False),
    make('diff-close-missing', 'diff open/close缺口', 'UNKNOWN', ['编辑器差异状态无法闭合'], diff_open_close_bound=False),
    make('accepted-rejected-unknown', 'accepted/rejected状态未知', 'UNKNOWN', ['用户动作与编辑应用结果不明'], accepted_rejected_bound=False),
    make('stdin-transport-open', 'stdin transport未闭合', 'UNKNOWN', ['JSON-RPC消息边界/断流状态不明'], stdin_transport_closed=False),
    make('session-persistence-unknown', 'session持久化未知', 'UNKNOWN', ['重连或load后历史是否保留未知'], session_persistence_attested=False),
    make('reconnect-unreconciled', '重连状态未对账', 'UNKNOWN', ['断线后无法判断远端session/任务状态'], reconnect_state_reconciled=False, unknown_session_state=True),
    make('duplicate-notification-open', '重复通知未去重', 'UNKNOWN', ['重连可能重复计算tool/result'], duplicate_notification_deduped=False),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['client/session/project字段不完整'], same_identity=False),
    make('identity-conflict', '跨session身份合并', 'REJECT', ['不同session或project被错误合并'], same_identity=False, identity_conflict=True),
    make('lifecycle-conflict', '生命周期状态冲突', 'REJECT', ['同一session同时出现不可调和的active/cancelled/closed'], lifecycle_conflict=True),
    make('cancel-prompt-conflict', 'cancel与prompt终态冲突', 'REJECT', ['同一turn同时声明已取消和已完成且无顺序可解释'], lifecycle_conflict=True, cancel_state_observed=False),
]

assert len(cases) == 26
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S46-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['client', 'project', 'session_id', 'turn_id', 'request_id'],
    'lifecycle_domain': ['initialize', 'newSession', 'loadSession', 'prompt', 'cancel', 'notification', 'tool_call', 'request_permission', 'contextUpdate', 'diff', 'accepted', 'rejected', 'stdio', 'reconnect'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')
