# T13（可选）：`sdk._build()` 复用 `checkpoint_usage`

> 总方案与全局规则：[README](README.md)。参考补丁：[`patches/T13.patch`](patches/T13.patch)。依赖 T08 已合入（需要 `run_setup.checkpoint_usage`）。

**目标：** 把检查点里记录的 token 用量转换成 `Usage` 对象，这段逻辑目前在 `cli.py`（T08 之后在 `run_setup.checkpoint_usage`）和 `sdk.py` 里各写了一遍，内容逐行相同。本卡让 SDK 复用 `run_setup` 里那一份，以后字段有变化只需要改一处。

**范围刻意很小。** SDK 和 CLI 的检查点恢复代码看起来相似，但**不能**整体合并：
- 两边的错误文字不同（SDK：`resume_from needs session_dir …`；CLI：`--resume-from needs --session-dir …`），合并会改变用户看到的消息；
- SDK 不读取策略文件，没有“收紧后的上限”这个概念；
- SDK 调用 `select_checkpoint(records)` 时不传 `record_index`。

所以本卡只共享那段完全相同的数据转换。

**唯一的细微差别：** `run_setup.checkpoint_usage()` 用 `getattr(checkpoint, "usage", None) or {}` 取用量，SDK 原来直接写 `checkpoint.usage`。二者只在 `checkpoint.usage` 为 `None` 时表现不同：原代码会抛 `AttributeError`，新代码按 0 计算。`checkpoints.select()` 返回的检查点总是带有 usage 字典，所以这条路径实际上走不到。把这一点写进 PR 描述。

**分支：** `refactor/T13-sdk-checkpoint-usage`

**要改的文件：** `components/northstar-agent-runtime/sdk.py`

## 改动

在 `sdk._build()` 的 `if options.resume_from:` 分支里：

1. `from providers.base import Usage` 改为 `from run_setup import checkpoint_usage`；
2. 把
   ```python
           data = checkpoint.usage
           budget = Budget(
               max_budget_usd=options.max_budget_usd,
               total_cost_usd=checkpoint.cost_usd,
               total_usage=Usage(
                   input_tokens=int(data.get("input_tokens", 0) or 0),
                   output_tokens=int(data.get("output_tokens", 0) or 0),
                   cache_read_input_tokens=int(data.get("cache_read_input_tokens", 0) or 0),
                   cache_creation_input_tokens=int(data.get("cache_creation_input_tokens", 0) or 0),
               ),
           )
   ```
   替换为
   ```python
           budget = Budget(
               max_budget_usd=options.max_budget_usd,
               total_cost_usd=checkpoint.cost_usd,
               # One conversion from a checkpoint's recorded usage, shared with the CLI.
               total_usage=checkpoint_usage(checkpoint),
           )
   ```

## 步骤

- [ ] 1. 记录基线。
- [ ] 2. 应用 `patches/T13.patch`，失败时按上文手工完成。
- [ ] 3. 验证：`make test` 全绿（`test_checkpoints.SdkParityTests` 和 `test_sdk` 覆盖 SDK 的恢复路径）；`cli_golden.py check` 一致（CLI 不受影响）。
- [ ] 4. 提交：`refactor(sdk): reuse run_setup.checkpoint_usage when resuming from a checkpoint`。开 PR，更新状态表。
