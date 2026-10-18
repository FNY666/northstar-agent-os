# 按工程师的方式学习 Northstar 代码

这份指南记录一套可复用的陌生代码库学习流程，并把它应用到 Northstar 当前的产品路径。它不是“读完所有文件”的清单，而是从具体行为建立、验证并保存心智模型。

## 我参考的做法

- GitHub 工程师收集到的实践包括：从手边代码开始做小而明确的任务，追问设计背后的原因，逐步绘制架构和数据流图，再把理解写成别人能使用的文档。
- Peter Norvig 对编程熟练度的建议侧重刻意练习：选择略高于当前水平、目标明确的任务，观察结果、分析失误并修正；他也特别建议阅读他人程序、参与多人项目和维护别人写过的项目。他提出“十年”是长期练习的尺度，不是从业年限门槛。
- Thoughtworks Principal Engineer Rahul Garg 建议先把项目架构、版本、命名约定、好代码示例和反模式交给新的开发者或编码助手。否则即使生成的代码可运行，也可能违背仓库的边界和设计理由。
- Thoughtworks Distinguished Engineer Birgitta Böckeler 在遗留系统探索记录中展示了另一个约束：AI 能帮助找到相关文件，但可能给出不准确的定位，也无法凭空消除旧项目的构建和复现成本；结果要回到代码、文档和真实反馈核对。

来源：

- [How GitHub engineers learn new codebases](https://github.blog/developer-skills/application-development/how-github-engineers-learn-new-codebases/)
- [Peter Norvig: Teach Yourself Programming in Ten Years](https://www.norvig.com/21-days.html)
- [Knowledge Priming — Martin Fowler](https://www.martinfowler.com/articles/reduce-friction-ai/knowledge-priming.html)
- [Onboarding to a legacy codebase with the help of AI — Martin Fowler](https://www.martinfowler.com/articles/exploring-gen-ai/09-ai-help-onboarding-codebase.html)
- [Securely using `pull_request_target` — GitHub Docs](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
- [GHSL-2026-199: DataDog/trivy API Diff Check workflow](https://securitylab.github.com/advisories/GHSL-2026-199_DataDog_trivy_repository/)

## 学习循环

1. **从行为开始。** 写清楚用户看到的输入、输出、失败结果和安全边界。先看已有文档与相关提交，知道这项行为为什么存在。
2. **沿一条真实路径走到底。** 从 CLI 或 API 入口跟到状态变化、权限边界、外部适配器和结果写入。用符号搜索和调用点缩小范围，再读实现细节。
3. **把理解变成可证伪的假设。** 例如“resume 会从 checkpoint 继承预算”应能在 CLI setup、checkpoint 校验和 runtime 初始化三处找到依据。文档与代码不一致时，先查调用方和历史，不猜。
4. **做一个略难但有边界的改动。** 先列受影响的入口、调用方、不变量、危险路径和安全对照。修改后按任务授权运行最相关的验证；若没有运行，就明确区分静态检查与行为验证。
5. **纠正并教会下一位维护者。** 检查差异、调用者、失败路径和兼容约束；把稳定的架构信息写回指南，避免下一轮重新发现同一件事。

这套方法受上述工程师实践启发；“从某一条用户路径开始，而不是逐文件通读”是对这些方法在 Northstar 上的操作化，不是来源中的原句。

## Northstar 产品路径地图

```text
bin/northstar
  └─ 设置仓库内 runtime 的 Python 路径
      └─ cli.main
          ├─ agent / resume: 改写成统一的 run 参数
          └─ _run: 载入策略、hooks、plugins、工具、agent 和 session 设置
              └─ AgentRuntime
                  └─ run: provider 生成 → 每个工具调用过 PreToolUse 和权限门
                      └─ GovernedActionRunner → 工具 handler / ToolSandbox
                          └─ events、session transcript、checkpoint、最终 ResultMessage
```

沿路径查文件：

| 问题 | 从哪里开始 | 继续追踪 |
| --- | --- | --- |
| 产品命令如何保留统一语义？ | `bin/northstar`、`components/northstar-agent-runtime/cli.py` | `product_path.py`、`_run()` |
| 策略和工具如何进入一次运行？ | `cli.py` 的 `_run()` | `run_setup.py`、`tools/`、`hooks.py`、`permissions.py` |
| 每轮与工具调用由谁控制？ | `loop.py` 的 `AgentRuntime.run()` | `_dispatch()`、`_authorize_tool_call()`、`GovernedActionRunner` |
| 会话如何恢复而不重置预算？ | `run_setup.py` 的 `resolve_session()` | `sessions.py`、`checkpoints.py`、`loop.py` resume 分支 |
| 安全门如何影响成功结果？ | `cli.py` 的 `security_gate` 配置 | `security_gate.py`、`coding_acceptance.py`、`loop.py` 结束条件 |
| Codex 实际在哪里执行？ | `loop.py` 注册 `CodexReadOnly` 的条件 | `sidecar_client.py`、`components/northstar-codex-sidecar/` |

运行时的中心不变量是：模型提议不直接执行工具。调用先触发 `PreToolUse`，再由权限引擎判定；批准后才进入受治理执行器和工具处理器。run 收尾再形成唯一的 `ResultMessage`。做工具、hook、权限或恢复改动时，应沿这条链核对，不能只看 CLI 参数是否能解析。

## 本轮应用：Actions 不可信代码执行

这轮从现有风险行为出发，而非从文件名猜功能：GitHub Security Lab 的 GHSL-2026-199 案例显示，`pull_request_target` checkout PR merge ref 后调用 `uses: ./.github/actions/setup-go`，会执行 PR 可修改的 action 源码。GitHub 文档说明 `./path` 相对 `$GITHUB_WORKSPACE`，依赖 checkout；`$/.path` 则解析到运行提交的自仓库 action，不依赖该工作区。因此这里只扩展 checkout-relative `./...` 路径，不把两种语义混为一谈。检查路径是：

```text
workflow event
  → jobs / steps 索引
  → checkout 的 ref / repository 是否来自 PR
  → 后续是否有 run 块或 uses: ./... 本地 action
  → 高危 finding + 安全对照 fixture
```

同一执行点模型也用于 `workflow_run` checkout、artifact 下载和 shell `gh pr checkout`。规则保持静态启发式：它不会执行 workflow，也不能证明本地 action 或 artifact 内容真的含恶意代码。SecurityProbe 的 YAML 样例是临时文本夹具；容量上限必须覆盖所有夹具，否则新增样例可能从未进入扫描结果。

本次改动适合说明“刻意练习”的实际含义：发现原判断只枚举 `run`，提出缺失分支假设，追到 workflow 的 `uses` 语义，补上危险样例和可信 checkout 的安全样例，再检查探针的扫描上限。行为验证与静态编译是两种证据；本任务只做了 `py_compile` 和 `git diff --check`，没有运行测试或探针。

## 下一轮的读码顺序

遇到新问题时先从这张产品路径图选择一段，继续向一个边界展开，不要一次扫描所有模块：

1. CLI 参数与 `run_setup` 是否保持相同的产品/内核语义。
2. `AgentRuntime` 中 event、权限、budget 和 dispatch 的顺序是否可被旁路。
3. tool handler 与 Shell sandbox 是否共享同一真实 workspace 根目录。
4. session、checkpoint、resume 和 coding evidence 是否覆盖失败与恢复分支。
5. 只有在本地路径明确后，再对照官方协议/安全文档和维护者的设计说明。

每次完成后留下三样东西：行为变化、验证证据、仍未覆盖的边界。这样新一轮开发从已验证的系统模型开始，而不是从一批孤立模块名重新开始。
