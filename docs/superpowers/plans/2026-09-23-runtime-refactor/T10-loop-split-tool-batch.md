# T10：`loop.py` 拆分 `_run_tool_batch()` 和 `_authorize_tool()`

> 总方案与全局规则：[README](README.md)。参考补丁：[`patches/T10.patch`](patches/T10.patch)。依赖 T09 已合入。每个 commit 都要跑 `verify_invariants.py`。

**目标：** 两个 170–180 行的方法按现有注释标出的阶段拆开。拆完后 `_run_tool_batch()` 只剩 20 行调度，`_authorize_tool()` 读起来就是“未知工具 → PreToolUse 钩子 → 委托 → 权限闸门 → 批准”这条链。行为不变。

**分支：** `refactor/T10-loop-tool-batch`

**要改的文件：** `components/northstar-agent-runtime/loop.py`

## 第一部分：`_run_tool_batch()`

原方法已经用注释分出了三段，按注释拆开即可。新方法都放在 `_run_tool_batch` 之后、`_authorize_tool` 之前：

| 新方法 | 内容来源 | 返回 |
| --- | --- | --- |
| `_halted_block(call, halted) -> ToolResultBlock` | 串行和并行两条路径里**完全相同**的“not executed: this run halted after the current turn …”结果块，合并成一处 | 该结果块 |
| `_run_serial_batch(calls, state, *, turn_index, span)` | 原 `if not can_parallel:` 分支的整个循环；`results`、`halted` 在方法内初始化 | `results, halted` |
| `_authorize_parallel_batch(calls, specs, state, *, turn_index, span)` | 注释 `# Parallel-safe path: authorize each call on the main thread first…` 下面的循环（T09 改过的版本） | `prepared, early, halted` |
| `_execute_parallel_batch(prepared, state, *, workers, turn_index)` | 注释 `# Execute approved handlers concurrently.` 下面的线程池部分，包括内嵌的 `_run_one` | `handler_results` |
| `_assemble_parallel_batch(calls, prepared, early, handler_results, halted, state, *, turn_index, span)` | 注释 `# Assemble in original order; post-hooks stay serial on the main thread.` 下面的循环（这条注释改为该方法的 docstring） | `results, halted` |

`_run_tool_batch()` 保留原来的签名和 docstring，方法体变为：

```python
        from tools.parallel import batch_is_parallel_safe

        workers = int(getattr(self.config, "parallel_tools", 1) or 1)
        specs = [self.tools.get(call.name) for call in calls]
        can_parallel = workers > 1 and batch_is_parallel_safe(specs)

        if not can_parallel:
            return self._run_serial_batch(calls, state, turn_index=turn_index, span=span)
        prepared, early, halted = self._authorize_parallel_batch(calls, specs, state, turn_index=turn_index, span=span)
        handler_results = self._execute_parallel_batch(prepared, state, workers=workers, turn_index=turn_index)
        return self._assemble_parallel_batch(
            calls, prepared, early, handler_results, halted, state, turn_index=turn_index, span=span
        )
```

`_halted_block` 是本卡唯一的“合并重复代码”。两处原文逐字相同（同样的 `tool_use_id`、同样的两段 f-string、`is_error=True`），合并后输出不变。

## 第二部分：`_authorize_tool()`

把三种“拒绝”分支搬进三个新方法，放在 `_authorize_tool` 之后、`_finish_tool_result` 之前。方法体都是原分支的内容，缩进减一级：

| 新方法 | 原分支 | 签名 |
| --- | --- | --- |
| `_refuse_unknown_tool` | `if spec is None:` 的内容 | `(self, call, state, *, turn_index) -> _Refused` |
| `_refuse_by_hook` | `if pre.denied:` 的内容 | `(self, call, spec, pre, state, *, turn_index, span) -> _Refused` |
| `_refuse_by_gate` | `if not decision.allowed:` 的内容 | `(self, call, spec, decision, state, *, turn_index, span) -> _Refused` |

`_authorize_tool` 里对应的分支各缩成一行：

```python
        if spec is None:
            return self._refuse_unknown_tool(call, state, turn_index=turn_index)
        ...
        if pre.denied:
            return self._refuse_by_hook(call, spec, pre, state, turn_index=turn_index, span=span)
        ...
        if not decision.allowed:
            return self._refuse_by_gate(call, spec, decision, state, turn_index=turn_index, span=span)
```

**注意 `_refuse_by_hook` 和 `_refuse_by_gate` 的执行顺序不能变**：钩子在前，闸门在后（spine §3：钩子可以先改写输入，但任何钩子顺序都绕不过闸门）。本卡只移动代码，不改变 `_authorize_tool` 里各步骤的先后。

## 步骤

- [ ] 1. 记录基线（含 `verify_invariants.py`）。
- [ ] 2. 应用 `patches/T10.patch`，失败时按上文手工完成。建议分两个 commit：先做第一部分，再做第二部分，每个 commit 后都完整验证一次。
- [ ] 3. 核对：`_run_tool_batch` 约 25 行（含 docstring），`_authorize_tool` 约 60 行。
- [ ] 4. 验证：`make test` 全绿（重点：`test_parallel_tools`、`test_permissions`、`test_hooks`、`test_governance_bench`）；`cli_golden.py check` 一致；`verify_invariants.py` 输出 `all five guards verified`。
- [ ] 5. 提交：`refactor(loop): split tool batch dispatch into serial, authorize, execute and assemble` 和 `refactor(loop): one method per refusal in _authorize_tool`。开 PR，更新状态表。
