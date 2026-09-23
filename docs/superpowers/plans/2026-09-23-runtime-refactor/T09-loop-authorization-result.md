# T09：`loop.py` 用三个小类型替代 `_authorize_tool()` 的元组返回值

> 总方案与全局规则：[README](README.md)。参考补丁：[`patches/T09.patch`](patches/T09.patch)。依赖 T08 已合入。
> 从本卡开始改 `loop.py`，**每个 commit 都要额外运行 `python3 tools/verify_invariants.py`**，最后一行必须是 `all five guards verified`。

**目标：** `AgentRuntime._authorize_tool()` 目前返回三种形状不同的元组，调用方靠“第一个元素是什么”来猜是哪一种：

| 含义 | 现在的返回值 |
| --- | --- |
| 批准，可以运行 handler | `(None, spec, payload, decision, rewritten)` |
| 在 handler 之前拒绝 | `(block, report, fatal, None)` |
| 这是委托调用，交给 `_delegate()` | `("delegate", call, spec, payload, rewritten)` |

docstring 只写了前两种。第三种在并行路径里如果出现，会被当成“拒绝”，把字符串 `"delegate"` 当作结果块。这种情况目前不会发生，因为 `batch_is_parallel_safe()` 会排除所有委托工具。但读代码的人无法从代码本身看出这一点。本卡改成三个冻结 dataclass，调用方用 `isinstance` 分支。行为不变。

**分支：** `refactor/T09-loop-authorization-result`

**要改的文件：** `components/northstar-agent-runtime/loop.py`

## 改动

1. 在 `class AgentRuntime:` 正上方新增三个类型：
   ```python
   @dataclass(frozen=True)
   class _Refused:
       """`_authorize_tool()` refused the call before any handler ran."""

       block: ToolResultBlock
       report: ToolCallReport
       fatal: str | None


   @dataclass(frozen=True)
   class _Authorized:
       """`_authorize_tool()` approved the call; the handler may run with ``payload``."""

       spec: Any
       payload: dict[str, Any]
       decision: Any
       rewritten: bool


   @dataclass(frozen=True)
   class _Delegate:
       """`_authorize_tool()` passed a delegation call on to `_delegate()` (never parallel-batched)."""

       call: ToolUseBlock
       spec: Any
       payload: dict[str, Any]
       rewritten: bool
   ```
2. `_authorize_tool()`：
   - 返回类型 `-> tuple:` 改为 `-> _Authorized | _Refused | _Delegate:`；
   - docstring 的第二段改为：“Returns ``_Authorized`` when the call is approved for handler execution, ``_Refused`` when it is refused before the handler, and ``_Delegate`` for a delegation call, which `_dispatch()` hands to `_delegate()`.”
   - `return (block, report, None, None)` → `return _Refused(block, report, None)`（1 处）；
   - `return (block, report, fatal, None)` → `return _Refused(block, report, fatal)`（2 处）；
   - `return ("delegate", call, spec, payload, rewritten)` → `return _Delegate(call, spec, payload, rewritten)`；
   - `return (None, spec, payload, decision, rewritten)` → `return _Authorized(spec, payload, decision, rewritten)`。
3. `_run_tool_batch()` 并行路径里调用 `_authorize_tool` 之后的那段（从注释 `# Authorized shape:` 开始，到 `if fatal is not None: halted = fatal` 结束）改为：
   ```python
               # A parallel batch never holds a delegation call (batch_is_parallel_safe
               # refuses is_delegation specs), so the outcome is authorized or refused.
               assert not isinstance(outcome, _Delegate), "a delegation call reached a parallel batch"
               if isinstance(outcome, _Authorized):
                   prepared.append((call, outcome.spec, outcome.payload, outcome.decision, outcome.rewritten))
                   early.append(None)
                   state.tool_calls += 1
               else:
                   early.append((outcome.block, outcome.report, outcome.fatal))
                   prepared.append(None)
                   state.tool_calls += 1
                   if outcome.fatal is not None:
                       halted = outcome.fatal
   ```
4. `_dispatch()` 里调用 `_authorize_tool` 之后的分支（从 `head = outcome[0]` 开始，到 `_, spec, payload, decision, rewritten = outcome` 结束）改为：
   ```python
           if isinstance(outcome, _Delegate):
               return self._delegate(
                   outcome.call,
                   outcome.spec,
                   outcome.payload,
                   state,
                   turn_index=turn_index,
                   span=span,
                   rewritten=outcome.rewritten,
               )
           if isinstance(outcome, _Refused):
               return outcome.block, outcome.report, outcome.fatal

           spec, payload, decision, rewritten = outcome.spec, outcome.payload, outcome.decision, outcome.rewritten
   ```

`assert` 那一行不改变可达路径的行为，它只是把原来隐含的前提写了出来。

## 步骤

- [ ] 1. 记录基线（含 `verify_invariants.py`）。
- [ ] 2. 应用 `patches/T09.patch`，失败时按上文手工完成。
- [ ] 3. 核对：`grep -n 'outcome\[' components/northstar-agent-runtime/loop.py` 应无输出；`grep -c 'return _Refused(' …/loop.py` 应为 3。
- [ ] 4. 验证：`make test` 全绿（`test_parallel_tools`、`test_permissions`、`test_hooks` 覆盖这三条路径）；`cli_golden.py check` 一致；`python3 tools/verify_invariants.py` 输出 `all five guards verified`。
- [ ] 5. 提交：`refactor(loop): typed outcomes for _authorize_tool instead of shape-sniffed tuples`。开 PR，更新状态表。
