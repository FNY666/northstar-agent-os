#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','tool_declared','tool_scope_allowed',
    'policy_decision_attested','approval_required_known','approval_obtained',
    'sandbox_boundary_closed','cwd_boundary_closed','path_allowlist_closed',
    'command_arguments_bound','input_canonical','output_captured',
    'side_effect_attested','postcondition_readback','timeout_semantics_known',
    'failure_state_known','retry_policy_known','user_visible_result_bound',
    'tool_chain_complete','permission_conflict','unknown_side_effect'
]
BASE = {k: True for k in FIELDS}
BASE.update({
    'identity_conflict': False, 'permission_conflict': False,
    'unknown_side_effect': False
})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('tool-call-closed', '工具声明/授权/后置条件闭合', 'RECOVERED', ['tool scope与policy decision明确','postcondition read-back闭合']),
    make('shell-sandbox-closed', 'shell sandbox边界闭合', 'RECOVERED', ['cwd/path/argument边界已绑定','副作用可由独立读回确认']),
    make('filesystem-write-closed', 'filesystem写入闭合', 'RECOVERED', ['allowlist与目标文件稳定','写入后内容和hash可复核']),
    make('ask-user-approval-closed', 'ask-user审批闭合', 'RECOVERED', ['审批要求明确且已获得','用户可见结果与实际动作绑定']),
    make('skill-activation-closed', 'skill激活边界闭合', 'RECOVERED', ['skill/tool chain完整','权限和失败语义可追溯']),
    make('timeout-postcondition-closed', '超时后置条件闭合', 'RECOVERED', ['timeout语义已定义','独立read-back确认是否发生副作用']),
    make('tool-undeclared', '工具未声明', 'UNKNOWN', ['无法知道动作属于哪一权限域'], tool_declared=False),
    make('scope-unknown', '工具scope未知', 'UNKNOWN', ['工具存在但允许资源范围不明'], tool_scope_allowed=False),
    make('policy-unread', 'policy decision未读回', 'UNKNOWN', ['不能证明动作被允许而非默认放行'], policy_decision_attested=False),
    make('approval-required-unknown', '审批要求未知', 'UNKNOWN', ['无法判断是否应先征得用户同意'], approval_required_known=False),
    make('approval-missing', '所需审批缺失', 'UNKNOWN', ['动作可能需要审批但没有确认记录'], approval_obtained=False),
    make('sandbox-open', 'sandbox边界未闭合', 'UNKNOWN', ['命令可能触及未授权资源'], sandbox_boundary_closed=False),
    make('cwd-open', 'cwd边界未闭合', 'UNKNOWN', ['相对路径解析位置不确定'], cwd_boundary_closed=False),
    make('path-allowlist-open', '路径allowlist未闭合', 'UNKNOWN', ['目标路径可能发生越界或替换'], path_allowlist_closed=False),
    make('arguments-unbound', '命令参数未绑定', 'UNKNOWN', ['shell参数/重定向/解释器语义无法复核'], command_arguments_bound=False),
    make('input-noncanonical', '输入未规范化', 'UNKNOWN', ['相同意图可能产生不同tool request'], input_canonical=False),
    make('output-missing', '工具输出未捕获', 'UNKNOWN', ['不能判断动作结果或错误状态'], output_captured=False),
    make('side-effect-unread', '副作用未读回', 'UNKNOWN', ['tool success不能证明目标状态已提交'], side_effect_attested=False, unknown_side_effect=True),
    make('postcondition-missing', 'postcondition缺失', 'UNKNOWN', ['没有独立验证动作是否达到目标'], postcondition_readback=False),
    make('timeout-unknown', '超时语义未知', 'UNKNOWN', ['timeout后可能已执行也可能未执行'], timeout_semantics_known=False, unknown_side_effect=True),
    make('failure-state-unknown', '失败状态未知', 'UNKNOWN', ['exit/error不等于目标未改变'], failure_state_known=False, unknown_side_effect=True),
    make('retry-unknown', '重试策略未知', 'UNKNOWN', ['重试可能重复副作用'], retry_policy_known=False),
    make('user-result-unbound', '用户可见结果未绑定', 'UNKNOWN', ['展示成功与真实目标状态可能不一致'], user_visible_result_bound=False),
    make('tool-chain-gap', '工具链缺口', 'UNKNOWN', ['中间skill/tool步骤不可追溯'], tool_chain_complete=False),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['session/project/target字段不完整'], same_identity=False),
    make('permission-conflict', '权限决策冲突', 'REJECT', ['同一tool request出现不可调和allow/deny'], permission_conflict=True),
    make('side-effect-conflict', '副作用状态冲突', 'REJECT', ['read-back与tool result对同一目标不可调和'], permission_conflict=True, side_effect_attested=False),
]

assert len(cases) == 27
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S43-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['session', 'project', 'target', 'tool_request', 'approval'],
    'tool_domain': ['shell', 'filesystem', 'ask_user', 'skill', 'sandbox', 'cwd', 'allowlist', 'postcondition', 'timeout', 'retry'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')
