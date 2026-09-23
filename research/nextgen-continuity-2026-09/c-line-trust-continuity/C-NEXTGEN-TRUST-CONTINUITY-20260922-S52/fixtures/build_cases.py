#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','hook_declared','event_scope_bound',
    'hook_order_closed','stdout_schema_valid','exit_semantics_known','timeout_bound',
    'continue_semantics_known','decision_semantics_known','fingerprint_trust_bound',
    'subagent_declared','subagent_tools_bound','mcp_scope_bound','max_turns_bound',
    'timeout_mins_bound','history_isolated','tool_isolation_bound','recursion_guard_bound',
    'policy_override_bound','model_override_bound','result_state_readback',
    'hook_conflict','unknown_loop_effect'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'hook_conflict': False, 'unknown_loop_effect': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('hook-lifecycle-closed', 'hook lifecycle闭合', 'RECOVERED', ['事件范围与顺序完整','hook结果可追溯']),
    make('stdout-exit-closed', 'hook stdout/exit语义闭合', 'RECOVERED', ['JSON stdout schema有效','exit 0/2/other语义可区分']),
    make('timeout-loop-closed', 'timeout/continue/decision闭合', 'RECOVERED', ['timeout bound已知','continue与decision结果可读回']),
    make('fingerprint-trust-closed', 'fingerprint与项目信任闭合', 'RECOVERED', ['hook fingerprint变化可检测','trust状态与动作绑定']),
    make('subagent-isolation-closed', 'subagent工具/历史隔离闭合', 'RECOVERED', ['tools/MCP/max turns/timeout已绑定','history与tool isolation可验证']),
    make('recursive-policy-model-closed', '递归/策略/model override闭合', 'RECOVERED', ['recursion guard有效','policy/model override和最终状态可读回']),
    make('hook-undeclared', 'hook未声明', 'UNKNOWN', ['无法知道何时何地执行hook'], hook_declared=False),
    make('event-scope-open', '事件范围未绑定', 'UNKNOWN', ['hook可能作用于错误事件'], event_scope_bound=False),
    make('hook-order-gap', 'hook顺序缺口', 'UNKNOWN', ['agent loop通知顺序不可复核'], hook_order_closed=False),
    make('stdout-schema-invalid', 'hook stdout schema无效', 'UNKNOWN', ['输出不能可靠解析为控制结果'], stdout_schema_valid=False),
    make('exit-semantics-unknown', 'exit语义未知', 'UNKNOWN', ['非零状态不能映射到允许/拒绝/失败'], exit_semantics_known=False),
    make('timeout-unknown', 'hook timeout未知', 'UNKNOWN', ['超时是否阻断loop不明'], timeout_bound=False, unknown_loop_effect=True),
    make('continue-unknown', 'continue语义未知', 'UNKNOWN', ['continue false的终止边界不明'], continue_semantics_known=False),
    make('decision-unknown', 'decision语义未知', 'UNKNOWN', ['deny/allow结果与工具动作不能关联'], decision_semantics_known=False),
    make('fingerprint-trust-open', 'fingerprint/trust未闭合', 'UNKNOWN', ['项目hook变化是否触发信任门未知'], fingerprint_trust_bound=False),
    make('subagent-undeclared', 'subagent未声明', 'UNKNOWN', ['无法判断是否发生递归/隔离执行'], subagent_declared=False),
    make('subagent-tools-open', 'subagent tools未绑定', 'UNKNOWN', ['subagent可用工具范围不明'], subagent_tools_bound=False),
    make('mcp-scope-open', 'subagent MCP scope未闭合', 'UNKNOWN', ['MCP server/resource范围不明'], mcp_scope_bound=False),
    make('max-turns-open', 'max_turns未绑定', 'UNKNOWN', ['subagent循环上限不明'], max_turns_bound=False),
    make('timeout-mins-open', 'subagent timeout未绑定', 'UNKNOWN', ['超时后远端状态可能未知'], timeout_mins_bound=False, unknown_loop_effect=True),
    make('history-not-isolated', 'subagent history未隔离', 'UNKNOWN', ['主/子agent上下文可能串线'], history_isolated=False),
    make('tool-isolation-open', '工具隔离未闭合', 'UNKNOWN', ['子agent可能越过工具边界'], tool_isolation_bound=False),
    make('recursion-guard-open', '递归保护未闭合', 'UNKNOWN', ['subagent递归深度不可证明'], recursion_guard_bound=False),
    make('policy-override-open', 'policy override未绑定', 'UNKNOWN', ['子agent policy覆盖范围不明'], policy_override_bound=False),
    make('model-override-open', 'model override未读回', 'UNKNOWN', ['最终subagent model可能不同'], model_override_bound=False),
    make('result-readback-open', '最终状态未读回', 'UNKNOWN', ['hook/subagent成功消息不能证明loop状态'], result_state_readback=False, unknown_loop_effect=True),
    make('identity-conflict', '跨session身份合并', 'REJECT', ['不同session/project的hook状态被错误合并'], same_identity=False, identity_conflict=True),
    make('hook-conflict', 'hook控制结果冲突', 'REJECT', ['同一tool/loop同时出现不可调和allow/deny或continue终态'], hook_conflict=True),
]

assert len(cases) == 28
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S52-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['session', 'project', 'agent', 'hook_id', 'tool_request', 'turn_id'],
    'hook_subagent_domain': ['SessionStart', 'BeforeAgent', 'AfterAgent', 'BeforeTool', 'AfterTool', 'PreCompress', 'stdout_json', 'exit_code', 'timeout', 'continue', 'decision', 'fingerprint', 'trust', 'subagent', 'tools', 'MCP', 'max_turns', 'history', 'isolation', 'recursion', 'policy_override', 'model_override'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')
