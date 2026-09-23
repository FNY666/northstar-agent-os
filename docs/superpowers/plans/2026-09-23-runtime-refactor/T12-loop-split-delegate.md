# T12：`loop.py` 拆分 `_delegate()`

> 总方案与全局规则：[README](README.md)。参考补丁：[`patches/T12.patch`](patches/T12.patch)。依赖 T11 已合入。每个 commit 都要跑 `verify_invariants.py`。

**目标：** 按子代理委托的生命周期，把 298 行的 `_delegate()` 拆成 4 步：准入 → 构造子运行时 → 运行 → 汇总结果。拆完后 `_delegate()` 只剩 26 行。第 2 步“子代理不能放宽父运行的权限”是安全关键代码，拆出来以后可以单独审查。行为不变。

**分支：** `refactor/T12-loop-delegate`

**要改的文件：** `components/northstar-agent-runtime/loop.py`

## 新类型

放在 T09 新增的 `_Delegate` 之后、`class AgentRuntime:` 之前：

```python
@dataclass(frozen=True)
class _Admission:
    """A delegation that passed every check in `_admit_delegation()`."""

    definition: AgentDefinition
    task_prompt: str
    gate: Any
    provider: Any
```

## 4 个新方法

放在 `_delegate` 之后、`_child_may_delegate` 之前。方法体都逐字复制原代码。

| 新方法 | 原代码起点（含） | 原代码终点（不含） | 返回 | 改动 |
| --- | --- | --- | --- | --- |
| `_admit_delegation(self, call, spec, payload, state, *, turn_index) -> _Refused \| _Admission` | `agent_name = str(payload.get("agent") …` | 注释 `# Permission policy inheritance.` | `_Admission(definition=definition, task_prompt=task_prompt, gate=gate, provider=child_provider)` | 7 处 `return (` 三元组改为 `return _Refused(`，括号里的三个元素和结尾的 `)` 不变 |
| `_child_runtime(self, definition, child_provider, state) -> tuple["AgentRuntime", RuntimeConfig, str]` | 注释 `# Permission policy inheritance.` | `with span.child(f"subagent:{definition.name}")` | `child, child_config, child_mode` | 那段长注释（inherit / allowed / disallowed / can_use_tool 四条规则）原样保留在方法开头 |
| `_run_child(self, child, child_config, child_mode, admission, *, span) -> tuple[SubagentReport, Verdict \| None]` | `with span.child(f"subagent:{definition.name}")` | `state.subagents.append(subagent_report)` | `subagent_report, verdict` | 开头从 `admission` 取出 `definition`、`provider`（原名 `child_provider`）、`task_prompt`、`gate` |
| `_subagent_result(self, call, spec, definition, subagent_report, verdict, state, *, turn_index, rewritten)` | `state.subagents.append(subagent_report)` | 方法结尾（含 `return block, report_row, None`） | `(block, report_row, None)` | — |

`_admit_delegation` 的 docstring：

```python
        """Every check a delegation must pass before a child run exists, in order.

        The agent must exist, the prompt must be text, depth must allow it, the run must
        offer every tool the agent declares, the delegation gate and the SubagentStart hook
        must agree, and the agent's provider (if it names one) must have been given.
        """
```

**检查顺序不能变**：provider 检查必须在 SubagentStart 钩子**之后**，和原代码一致。钩子被触发与否会影响审计记录和测试断言。

## `_delegate()` 的方法体

保留原签名和 docstring，方法体替换为：

```python
        admission = self._admit_delegation(call, spec, payload, state, turn_index=turn_index)
        if isinstance(admission, _Refused):
            return admission.block, admission.report, admission.fatal
        child, child_config, child_mode = self._child_runtime(admission.definition, admission.provider, state)
        subagent_report, verdict = self._run_child(child, child_config, child_mode, admission, span=span)
        return self._subagent_result(
            call, spec, admission.definition, subagent_report, verdict, state, turn_index=turn_index, rewritten=rewritten
        )
```

## 步骤

- [ ] 1. 记录基线（含 `verify_invariants.py`）。
- [ ] 2. 应用 `patches/T12.patch`，失败时按上文手工完成。
- [ ] 3. 核对：`_delegate` 26 行；`grep -c 'return _Refused(' components/northstar-agent-runtime/loop.py` 为 10（T10 的 3 处加本卡的 7 处）。
- [ ] 4. 验证：`make test` 全绿（重点：`test_agents`、`test_loop`、`test_budget`、`test_permissions`、`test_governance_bench`）；`cli_golden.py check` 一致；`verify_invariants.py` 输出 `all five guards verified`。
- [ ] 5. 提交：`refactor(loop): split _delegate into admit, build child, run child and report`。开 PR，更新状态表。

**建议的后续工作（不在本卡范围内）：** `_child_runtime()` 抽出来以后，可以为“子代理不能放宽父运行权限”补一组表格化测试：父运行分别是 plan / default / acceptEdits，agent 分别声明 plan / 默认，检查子运行的 mode、allowed 和 disallowed。这类测试应该单独开一个 PR。
