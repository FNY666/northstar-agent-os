# northstar-agent-runtime 重构总方案（2026-09-23）

> **给执行者（包括较小的模型）：** 一次只做**一张任务卡**（`T01`…`T15`），做完就停。
> 开始前先读完本页的“全局规则”和你那张卡的全文。卡里的每一步都用 `- [ ]` 标出，请逐项完成。
> 卡里没写的事情一律不做。遇到卡里没有覆盖的情况，按“停止条件”处理，不要自己发挥。

## 目标

`components/northstar-agent-runtime` 里有两个过大的函数体，使代码难审、难测、难改：

| 位置 | 规模（2026-09-23，`70d2a4e`） | 问题 |
| --- | --- | --- |
| `cli.py` → `_run()` | 616 行 | 一个函数包揽插件、策略、权限、钩子、MCP、提示词、会话校验、构建运行时和事件打印 |
| `loop.py` → `AgentRuntime._events()` | 342 行 | 主循环混杂 init 记录、钩子、生成、流式校验、收尾、工具批次 |
| `loop.py` → `AgentRuntime._delegate()` | 298 行 | 子代理委托的准入、继承收紧、运行、汇总都在一处 |
| `loop.py` → `_run_tool_batch()` / `_authorize_tool()` | 180 / 168 行 | 分支嵌套深，返回两种长度不同的元组 |

本方案把它们拆成命名清晰的小函数。**除 T02 外，每张卡都必须保持行为完全不变**：CLI 参数、退出码、stdout/stderr 文本、事件顺序、会话文件内容和公开 API 都不能变。

T02 修复了两个真实的治理缺陷，它是唯一有意改变行为的卡，见 [T02](T02-resume-ceilings.md)。

## 任务卡与顺序

每张卡对应一个分支、一个 PR。必须按顺序合入：**前一张卡的 PR 合入 `main` 之后，才能开始下一张。**

| 卡 | 内容 | 改变行为？ | 依赖 | 状态 |
| --- | --- | --- | --- | --- |
| [T01](T01-link-check.md) | 文档链接检查跳过 `research/`，让测试恢复全绿 | 仅测试工具 | — | 待办 |
| [T02](T02-resume-ceilings.md) | 修复：`--resume-from` 丢失策略文件的轮次和费用上限 | **是** | T01 | 待办 |
| [T03](T03-cli-configuration-error.md) | `cli._run()`：引入 `RunConfigurationError`，收拢 23 处“打印后返回 64” | 否 | T02 | 待办 |
| [T04](T04-cli-extract-loaders.md) | `cli._run()`：抽出提示词读取和 6 个“加载”步骤 | 否 | T03 | 待办 |
| [T05](T05-cli-extract-resolvers.md) | `cli._run()`：抽出权限、工具、agent、MCP、上限的“解析”步骤 | 否 | T04 | 待办 |
| [T06](T06-cli-extract-system-prompt.md) | `cli._run()`：抽出系统提示词拼接 | 否 | T05 | 待办 |
| [T07](T07-cli-extract-session-and-output.md) | `cli._run()`：抽出会话参数校验、会话解析、dry-run 说明和事件输出 | 否 | T06 | 待办 |
| [T08](T08-cli-move-to-run-setup.md) | 把 T04–T07 抽出的函数移到新模块 `run_setup.py` | 否 | T07 | 待办 |
| [T09](T09-loop-authorization-result.md) | `loop.py`：用 `_Authorized` / `_Refused` 替代两种长度的元组 | 否 | T08 | 待办 |
| [T10](T10-loop-split-tool-batch.md) | `loop.py`：拆分 `_authorize_tool()` 和 `_run_tool_batch()` | 否 | T09 | 待办 |
| [T11](T11-loop-split-events.md) | `loop.py`：拆分 `_events()` | 否 | T10 | 待办 |
| [T12](T12-loop-split-delegate.md) | `loop.py`：拆分 `_delegate()` | 否 | T11 | 待办 |
| [T13](T13-sdk-share-resume.md) | 可选：`sdk._build()` 复用 `run_setup` 的检查点恢复逻辑 | 否 | T08 | 待办 |
| [T14](T14-doctor-split-checks.md) | 可选：拆分 `doctor._checks()` | 否 | T01 | 待办 |
| [T15](T15-cli-group-run-arguments.md) | 可选：按主题拆分 `cli._add_run_arguments()` | 否 | T08 | 待办 |

T13–T15 互相独立，可以在各自依赖合入后任意时间进行。

## 参考补丁（T01–T13）

[`patches/`](patches/) 目录里的 `T01.patch` … `T13.patch` 是每张卡的**参考实现**。它们已经在 `main` 的 `70d2a4e` 提交上验证过：

- 在一份干净的克隆上，按 T01 → T12 的顺序依次 `git apply`，每一步都能干净地应用；
- 每一步之后都跑了 `make test`、`cli_golden.py check` 和（改了 `loop.py` 的卡）`verify_invariants.py`，全部通过；
- 12 步全部完成后：runtime 组件 1,297 个测试、TypeScript 端 57 个测试、仓库文档 71 个测试全部通过，其余 5 个组件的测试也全部通过；48 个 CLI 快照用例中，只有 T02 预期的 2 个发生变化；5 个安全守卫的变异测试全部正常变红。

补丁**不包含** `docs/api/` 下的生成文件（它们由 `python3 tests/docbuild.py build` 生成，应用补丁后要自己重新生成），也不包含本目录下的文件。

**推荐的执行方式：** 先 `git apply --check` 检查补丁能否应用。能应用就直接用补丁，然后**按任务卡逐条核对 diff**：核对的目的是让你和审查者都理解这次改了什么，不能跳过。如果 `main` 在此期间有其它改动，导致补丁无法应用，先试 `git apply -3`；还不行就按卡里的文字说明手工完成。卡里的文字说明和补丁描述的是同一个改动。

T14、T15 没有参考补丁，只能按卡里的说明手工完成。

## 完成后的效果

| 函数 | 现在 | 完成 T12 后 |
| --- | --- | --- |
| `cli._run()` | 616 行 | 153 行（其中约 40 行是配置字典） |
| `AgentRuntime._events()` | 342 行 | 83 行 |
| `AgentRuntime._delegate()` | 298 行 | 26 行 |
| `AgentRuntime._run_tool_batch()` | 180 行 | 27 行 |
| `AgentRuntime._authorize_tool()` | 168 行 | 62 行 |
| `cli.py` 文件 | 1,675 行 | 约 1,380 行，另有新模块 `run_setup.py` 约 530 行 |

拆出来的函数里最长的是 `compose_system_prompt`（96 行）和 `_admit_delegation`（123 行）。两者都是按固定顺序排列的检查和拼接，继续拆分收益不大。

**更新状态**：你的 PR 除了代码改动，还要在上表中把自己那张卡的“状态”改为 `已完成（#PR 号）`。这是本表唯一允许你修改的地方。

## 全局规则（每张卡都适用）

1. **从最新的 `main` 开始。** `git checkout main && git pull && git checkout -b refactor/<卡号>-<短名>`，例如 `refactor/T04-cli-loaders`。
2. **先记录基线，再改代码。** 在改任何代码之前运行下面三条命令，并把输出摘要贴进 PR 描述：
   ```sh
   make test                                                     # 全部测试
   python3 docs/superpowers/plans/2026-09-23-runtime-refactor/cli_golden.py record /tmp/cli-golden.json
   (cd components/northstar-agent-runtime && python3 tools/verify_invariants.py)   # 约 1–2 分钟
   ```
   基线必须全绿。如果 `make test` 在你改代码之前就失败，说明 `main` 有问题：停止，报告失败的测试名，不要继续。
   （T01 例外：它就是来修 `make test` 里那 1 个已知失败的。）
3. **只移动，不改写。** 把代码搬进新函数时，逐字复制原来的语句和注释。不改变量名以外的任何东西，不“顺手优化”，不改错误信息的一个字，也不调整语句顺序。如果某行看起来是 bug，把它记进 PR 描述的“发现的问题”一节，但不要修。
4. **注释跟着代码走。** 原来写在某段代码上方的注释，要和这段代码一起搬走。长段落的“为什么”注释可以改成新函数的 docstring，但内容不能删。
5. **不改测试。** 除非卡里明确要求，不要修改、删除或跳过任何现有测试。测试是证明“行为不变”的唯一证据。卡里要求新增的测试可以加。
6. **小步提交。** 每张卡按卡里的“提交”小节分成几个 commit。**每个 commit 之后**都要运行：
   ```sh
   make test
   python3 docs/superpowers/plans/2026-09-23-runtime-refactor/cli_golden.py check /tmp/cli-golden.json
   ```
   两条都必须通过（`cli_golden.py check` 要输出 `all N cases identical`），才能继续下一个 commit。
   改了 `loop.py` 的 commit 还要再跑一次 `python3 tools/verify_invariants.py`，最后一行必须是 `all five guards verified`。
7. **新模块要登记。** 在 `components/northstar-agent-runtime/` 下新建 `.py` 文件时，必须同时：
   - 把模块名加进 `components/northstar-agent-runtime/pyproject.toml` 的 `[tool.setuptools] py-modules` 列表（按字母顺序）；
   - 把模块名加进 `tests/docbuild.py` 的 `MANIFEST["northstar-agent-runtime"]` 元组；
   - 运行 `python3 tests/docbuild.py build` 重新生成 `docs/api/northstar-agent-runtime.md`，并提交生成的结果。
   漏掉任何一项，`make test` 都会失败并告诉你缺什么。
8. **API 文档要保持新鲜。** 只要改了任何公开函数、类或它们的 docstring，就运行 `python3 tests/docbuild.py build` 并提交 `docs/api/` 的变化。以下划线开头的名字不会进入 API 文档。
9. **PR 描述**使用下面的模板。CONTRIBUTING.md 要求写明“完整的测试命令和结果”：
   ```markdown
   ## 做了什么
   <卡号>：<一句话>

   ## 改动的文件
   - `path`：原因

   ## 验证（本次新运行的输出）
   - `make test`：<每个组件的 Ran N tests / OK 行>
   - `cli_golden.py check`：all N cases identical
   - `verify_invariants.py`（若改了 loop.py）：all five guards verified

   ## 发现的问题（没有修）
   - 无 / <描述>

   ## 回滚
   纯代码移动，无数据或格式变化；`git revert` 合并提交即可。
   ```

## 停止条件

出现以下任何一种情况，就停下来。在 PR 描述里说明（或者不开 PR，直接报告），不要自己找办法绕过去：

- 某个 commit 之后 `make test` 失败，而且回头检查后仍找不到自己复制错的地方；
- `cli_golden.py check` 报告有用例变化（T02 除外，那张卡规定了哪些变化是预期的）；
- `verify_invariants.py` 报告 `anchor not found`，而这张卡没有告诉你新的锚点文本应该是什么；
- 卡里给的锚点文本（“从哪一行开始、到哪一行结束”）在代码里找不到，或者能找到不止一处；
- 你需要修改卡里“不要改”列表中的文件；
- 你发现自己想要修改测试才能让测试通过。

## 两个验证工具

- **`cli_golden.py`**（本目录）会对 `northstar run` 跑 48 组固定调用，记录 stdout、stderr、退出码，以及 CLI 实际构造出来的运行时配置：完整的系统提示词、工具列表、所有上限，以及 `Budget` 对象里真正生效的费用上限。只看 dry-run 文字发现不了“提示词拼接顺序变了”或“预算对象丢了上限”，这个工具能发现。它只用标准库，不联网，不需要 API key，一次约 5 秒。
- **`tools/verify_invariants.py`**（组件自带）会在临时副本里逐个撤掉 5 个安全守卫，确认对应的测试会变红。它是**按精确文本定位守卫的**：其中两个守卫在 `loop.py` 里，如果你移动或改动了守卫代码的缩进，它会报告 `anchor not found`。T11 专门说明了怎样同步更新锚点。

## 背景：审查时发现的两个缺陷（T02 修复）

用 `--resume-from` 从检查点分叉恢复时，`cli._run()` 用**命令行参数**重建上限，而没有用**经过策略文件和插件收紧后**的值：

- 第 1460 行 `config_kwargs["max_turns"] = max(args.max_turns, checkpoint.turns)`：策略文件写 `max_turns = 1`，恢复后变成 25 轮；
- 第 1463 行 `_Budget(max_budget_usd=args.max_budget_usd, …)`：策略文件写 `max_budget_usd = 1.0`，恢复后的运行花掉了 6 美元也没有停下。更糟的是 `--dry-run` 仍然照策略显示费用上限（例如 `max_budget_usd=0.5`），而实际计费的 `Budget` 对象里上限是 `None`，会误导操作者。

这违反了项目“策略文件只能收紧”的核心承诺。修复和三个回归测试已在本地验证过（新测试在旧代码上失败、在修复后通过，全量 1,297 个测试通过），具体步骤见 [T02](T02-resume-ceilings.md)。

`sdk.py` 不读取策略文件，不受这个缺陷影响。
