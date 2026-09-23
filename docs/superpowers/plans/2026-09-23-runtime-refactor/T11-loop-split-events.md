# T11：`loop.py` 拆分 `_events()`

> 总方案与全局规则：[README](README.md)。参考补丁：[`patches/T11.patch`](patches/T11.patch)。依赖 T10 已合入。每个 commit 都要跑 `verify_invariants.py`。
> **本卡要同步修改 `tools/verify_invariants.py` 里一个守卫的锚点文本**，见下面的“守卫锚点”一节。

**目标：** `AgentRuntime._events()` 是运行的主循环，也是一个生成器，共 342 行。本卡把它拆成 5 个辅助方法，拆完后只剩 83 行：一次 init 记录，加上一个每轮“检查上限 → 压缩 → 生成 → 校验流式输出 → 无工具则收尾 / 有工具则执行批次”的循环。行为不变，事件顺序不变。

**分支：** `refactor/T11-loop-events`

**要改的文件：**
- `components/northstar-agent-runtime/loop.py`
- `components/northstar-agent-runtime/tools/verify_invariants.py`（只改一个锚点）

## 生成器拆分的规则（必读）

`_events()` 是生成器，拆出来的辅助方法也要按下面的规则写：

- 需要 `yield` 事件的辅助方法本身也是生成器，返回类型写 `Generator[Message, None, <返回值类型>]`，调用方用 `result = yield from self._helper(...)` 调用。**不能**写成 `for e in self._helper(...): yield e`，因为那样拿不到返回值。
- 原代码里 `yield self._finish(state, …)` 后面紧跟的 `return`，在辅助方法里改为 `return True`，意思是“运行已经结束”。调用方写成：
  ```python
  if (yield from self._helper(...)):
      return
  ```
  注意 `yield from` 外面**必须**有括号。
- 辅助方法的正常结束路径返回 `False`。

## 5 个新方法

都放在 `_events` 之后、`_claim_session` 之前：

| 新方法 | 原代码 | 类型 | 返回 |
| --- | --- | --- | --- |
| `_init_data(self, state) -> dict[str, Any]` | 从 `init_data = {` 到 `init_data["stream"] = True`（含 sandbox 探测、postconditions、resumed_from、checkpoint、session_lease、stream 各段） | 普通方法 | `init_data` |
| `_open_session(self, state, prompt)` | 从注释 `# SessionStart may seed context or refuse the run outright.` 到写入 `"user_prompt"` 那一行 | 生成器 | `True` 表示钩子拒绝、运行已结束 |
| `_generate(self, state, turn_index, turn_span)` | 从 `request = GenerationRequest(` 到 `generation_span.record_usage(...)` 所在的 `with turn_span.child("generation")` 块结束 | 生成器 | `(generation, breakdown, streamed, stream_withheld)` |
| `_stream_mismatch(self, state, turn_index, turn_span, assistant, streamed, stream_withheld)` | `if config.stream:` 里面的内容（从 `problem = None` 开始） | 生成器 | `True` 表示输出不一致、运行已结束 |
| `_finish_without_tools(self, state, turn_index, assistant)` | `if not calls:` 里面的内容 | 生成器 | `True` 表示运行已结束；`False` 表示 Stop 钩子要求继续（原来的 `continue`） |

需要用到 `config` 的方法，在开头写 `config = self.config`。

拆完后 `_events()` 的主要部分如下（完整版本见补丁）：

```python
        init_data = self._init_data(state)
        try:
            # Taken before the first yield so a hook or a tool cannot be the thing
            # that changes what "before" means.
            self.postconditions.snapshot()
        except PostConditionError as error:
            raise RuntimeConfigurationError(f"postconditions: {error}") from error
        init = SystemMessage(subtype="init", content=f"runtime ready: {self.provider_name}/{config.model}", data=init_data)
        self.sessions.record_system(init, agent=config.agent)
        yield init

        if (yield from self._open_session(state, prompt)):
            return

        # ...（逐轮循环的开头不变：heartbeat、上限检查、压缩、cost_at_turn_start、turn span）
            with run_span.child(f"turn[{turn_index}]") as turn_span:
                turn_span.set_attributes({...})
                generation, breakdown, streamed, stream_withheld = yield from self._generate(state, turn_index, turn_span)
                if generation is None or breakdown is None:
                    yield self._finish(state, "error_during_execution")
                    return
                assistant = AssistantMessage(...)
                if config.stream:
                    if (yield from self._stream_mismatch(state, turn_index, turn_span, assistant, streamed, stream_withheld)):
                        return
                state.transcript.append(assistant)
                ...
                calls = assistant.tool_uses
                if not calls:
                    if (yield from self._finish_without_tools(state, turn_index, assistant)):
                        return
                    continue
                # ...（工具批次部分不变）
```

**不要移动的东西：**
- `postconditions.snapshot()` 必须在第一个 `yield` 之前，它留在 `_events()` 里；
- `_ceiling_stop()` 的调用（预算守卫）留在循环开头，不动；
- `with run_span.child(f"turn[{turn_index}]")` 留在 `_events()` 里，`_generate` 在它里面打开 `generation` 子 span。

## 守卫锚点（必须同步修改）

`tools/verify_invariants.py` 的第 5 个守卫是 “usage and cost are recorded before the generation span ends”。它按**精确文本（含缩进）**在 `loop.py` 里定位 `generation_span.record_usage(`。这段代码搬进 `_generate()` 后，缩进从 24 个空格变为 16 个空格，所以锚点也要改成 16 个空格。在 `GUARDS` 里找到：

```python
        [("                        # goes missing from the trace with no error anywhere.\n                        generation_span.record_usage(",
          "                        # goes missing from the trace with no error anywhere.\n                        generation_span.end()  # MUTATION: write after end\n                        generation_span.record_usage(")],
```

改为（每一处 24 个空格都换成 16 个空格，其余一字不改）：

```python
        [("                # goes missing from the trace with no error anywhere.\n                generation_span.record_usage(",
          "                # goes missing from the trace with no error anywhere.\n                generation_span.end()  # MUTATION: write after end\n                generation_span.record_usage(")],
```

改完后自查：`grep -n "goes missing from the trace" components/northstar-agent-runtime/loop.py` 输出的那一行，前面恰好有 16 个空格。

**改错的后果：** 如果只改了 `loop.py` 没改锚点，`verify_invariants.py` 会报告这个守卫 `anchor not found`，CI 的 “Guard verification” 步骤会失败。反过来，如果锚点改对了，但 `record_usage` 被挪到了 `with` 块外面（也就是 span 结束之后），变异测试同样会发现。

## 步骤

- [ ] 1. 记录基线（含 `verify_invariants.py`）。
- [ ] 2. 应用 `patches/T11.patch`（它同时修改 `loop.py` 和 `tools/verify_invariants.py`），失败时按上文手工完成。
- [ ] 3. 核对：`_events` 约 83 行；上面的 5 个新方法都存在；`grep -c "yield from self\._" components/northstar-agent-runtime/loop.py` 比改动前多 4（`_open_session`、`_generate`、`_stream_mismatch`、`_finish_without_tools`）。
- [ ] 4. 验证：`make test` 全绿（重点：`test_loop`、`test_streaming`、`test_provider_retry`、`test_tracing`、`test_hooks`、`test_postconditions`、`test_checkpoints`）；`cli_golden.py check` 一致；`verify_invariants.py` 输出 `all five guards verified`，其中第 5 个守卫显示 `RED`（表示变异后测试确实失败了，这是正确结果）。
- [ ] 5. 提交：`refactor(loop): split _events into init, session opening, generation, stream check and finish`。开 PR，更新状态表。
