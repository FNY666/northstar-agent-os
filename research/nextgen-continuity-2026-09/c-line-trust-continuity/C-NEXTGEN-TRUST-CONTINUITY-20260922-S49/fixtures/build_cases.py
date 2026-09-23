#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','mode_declared','event_schema_valid',
    'json_or_jsonl_framing_closed','message_event_bound','tool_use_event_bound',
    'tool_result_event_bound','error_event_bound','exit_code_semantics_known',
    'plan_mode_declared','plan_scope_closed','write_boundary_closed',
    'approval_request_bound','approval_obtained','cancel_signal_bound',
    'cancel_state_observed','headless_input_bound','stream_order_closed',
    'final_state_readback','external_effect_not_claimed','mode_conflict','unknown_final_state'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'mode_conflict': False, 'unknown_final_state': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('headless-jsonl-closed', 'headless JSON/JSONL事件闭合', 'RECOVERED', ['event framing和schema完整','message/tool/result/error顺序可追溯']),
    make('plan-mode-approval-closed', 'Plan Mode与批准边界闭合', 'RECOVERED', ['plan scope与写入边界明确','批准后实施状态可读回']),
    make('cancel-exit-state-closed', '取消与退出码语义闭合', 'RECOVERED', ['cancel signal和最终状态绑定','exit code语义与final read-back一致']),
    make('stream-order-closed', '流式事件顺序闭合', 'RECOVERED', ['stream framing和sequence完整','错误/工具/消息事件不混淆']),
    make('headless-input-bound', 'headless输入与结果绑定', 'RECOVERED', ['输入session/run identity固定','结果和退出状态可复核']),
    make('external-effect-separated', '外部效果边界分离', 'RECOVERED', ['输出成功不被写成外部提交','独立read-back作为另一个门']),
    make('mode-unknown', '运行模式未声明', 'UNKNOWN', ['无法判断interactive/headless/plan语义'], mode_declared=False),
    make('event-schema-invalid', '事件schema无效', 'UNKNOWN', ['JSON/JSONL事件无法可靠解析'], event_schema_valid=False),
    make('framing-open', 'JSONL framing未闭合', 'UNKNOWN', ['多行输出边界不明'], json_or_jsonl_framing_closed=False),
    make('message-unbound', 'message事件未绑定', 'UNKNOWN', ['消息不能归属于run/turn'], message_event_bound=False),
    make('tool-use-unbound', 'tool_use事件未绑定', 'UNKNOWN', ['工具调用事件不能关联请求'], tool_use_event_bound=False),
    make('tool-result-unbound', 'tool_result未绑定', 'UNKNOWN', ['工具结果不能关联调用'], tool_result_event_bound=False),
    make('error-unbound', 'error事件未绑定', 'UNKNOWN', ['错误可能被当作普通输出'], error_event_bound=False),
    make('exit-code-unknown', '退出码语义未知', 'UNKNOWN', ['非零/零不能映射到最终状态'], exit_code_semantics_known=False, unknown_final_state=True),
    make('plan-scope-open', 'Plan Mode范围未闭合', 'UNKNOWN', ['计划目录/只读边界不明'], plan_scope_closed=False),
    make('write-boundary-open', '写入边界未闭合', 'UNKNOWN', ['计划阶段可能发生未授权写入'], write_boundary_closed=False),
    make('approval-unbound', '批准请求未绑定', 'UNKNOWN', ['批准与具体计划/动作不能关联'], approval_request_bound=False),
    make('approval-missing', '批准缺失', 'UNKNOWN', ['需要批准但没有确认'], approval_obtained=False),
    make('cancel-unbound', '取消信号未绑定', 'UNKNOWN', ['取消可能作用于错误run'], cancel_signal_bound=False),
    make('cancel-state-unknown', '取消后状态未知', 'UNKNOWN', ['cancel request不等于已停止'], cancel_state_observed=False, unknown_final_state=True),
    make('headless-input-open', 'headless输入未绑定', 'UNKNOWN', ['stdin/参数与run identity不稳定'], headless_input_bound=False),
    make('stream-order-open', '流式顺序缺口', 'UNKNOWN', ['事件可能丢失/乱序'], stream_order_closed=False),
    make('final-readback-missing', '最终状态未读回', 'UNKNOWN', ['输出结束不等于目标已提交'], final_state_readback=False, unknown_final_state=True),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['session/run/project字段不完整'], same_identity=False),
    make('identity-conflict', '跨run身份合并', 'REJECT', ['不同run/project输出被错误合并'], same_identity=False, identity_conflict=True),
    make('mode-conflict', '模式语义冲突', 'REJECT', ['同一run同时声明互斥plan/headless写入状态'], mode_conflict=True),
    make('approval-cancel-conflict', '批准与取消终态冲突', 'REJECT', ['同一动作不可调和地同时approved/cancelled'], mode_conflict=True, cancel_state_observed=False),
]

assert len(cases) == 27
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S49-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['session', 'run_id', 'turn_id', 'project', 'input_id'],
    'output_domain': ['headless', 'JSON', 'JSONL', 'message', 'tool_use', 'tool_result', 'error', 'exit_code', 'Plan_Mode', 'approval', 'cancel', 'stream'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')
