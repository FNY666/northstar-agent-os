# Northstar 六角色团队试点

这是基于现有 Agent Runtime 的轻量角色包：一个协调者，加五个按需调用的专职子代理。它展示可用的委派方式，不新增调度器或运行时依赖，并用每个角色的预算上限演示逐层限额。

## 六个角色

| 名称 | 职责 | 静态工具 / 能力 | 单次角色运行预算上限 |
|---|---|---|---:|
| team_lead | 拆解任务、选择必要角色、汇总结论 | Read、Grep、LS、DescribeTools、Write、Edit、Shell；设 `allow_delegation: true` 后由运行时注册 Task | 宿主总预算 |
| team_researcher | 搜索仓库证据，标出文件与行号 | Read、Grep、LS、DescribeTools | $0.03 |
| team_architect | 对照现有实现，提出最小变更方案 | Read、Grep、LS、DescribeTools | $0.02 |
| team_implementer | 按明确范围修改代码 | Read、Grep、LS、Write、Edit | $0.08 |
| team_qa | 找对应测试并执行授权的验证 | Read、Grep、LS、Shell | $0.03 |
| team_safety_reviewer | 独立检查权限、预算、数据与回归风险 | Read、Grep、LS、DescribeTools | $0.02 |

六个角色是可选成员，不代表每个请求都要调用六次。Lead 应按任务需要选择一到三个角色；独立只读检查可以由一个子代理完成，避免重复上下文和 token 成本。

## 运行

先检查工作区与角色定义：

~~~sh
bin/northstar doctor --workspace examples/six-agent-team

bin/northstar agent \
  --workspace examples/six-agent-team \
  --agent team_lead \
  --provider anthropic \
  --model claude-sonnet-4-5 \
  --max-turns 10 \
  --max-tool-calls 18 \
  --max-budget-usd 0.25 \
  --dry-run \
  --prompt "检查当前仓库的一个具体问题，给出证据、最小修复建议和验证方式"
~~~

移除 `--dry-run` 并设置 `ANTHROPIC_API_KEY` 后，才会发起模型请求。示例的 `--max-budget-usd 0.25` 是整个父运行的硬上限，包含协调者和所有子代理。子代理文件里的 `max_budget_usd` 则限制每次委派；重复调用会各自受该上限约束，但总花费仍不能超过父运行上限。若直接用 `--agent team_researcher` 运行角色，角色上限同样生效，命令行和工作区策略只能进一步收紧它。Northstar 会把子代理的实际 usage 与费用汇总到父运行。若模型价格未知，结果会标记为估算价。

默认权限模式保持安全。只读调查无需额外授权。需要 implementer 改文件时，在同一条 `agent` 命令上逐项增加 `--allow-tool Write --allow-tool Edit`；需要 QA 执行命令时，再增加 `--allow-tool Shell` 并检查 sandbox 配置。不要在纯调查任务上授予这些工具。父运行的授权也适用于子代理，子代理只能进一步收窄工具集合，不能获得更高权限。Shell 不会因团队角色定义而自动获准。

## 运行语义与边界

- 每个子代理有独立上下文、声明的工具集合和 turn / tool-call 上限；费用汇总到父运行。
- `--max-budget-usd` 限制整次父运行，含其子代理费用；角色文件的 `max_budget_usd` 是每次委派的可选上限，运行时取角色、工作区策略、插件和宿主总预算中的最小值。
- `Task` 是运行时按 `allow_delegation: true` 动态注册的委派入口，不应写进角色文件的 `tools`。每个子代理声明的实际工具仍受父级权限门控。
- 当前 Task 委派按调用顺序执行；六个角色不会自动并行。Read-only 工具批次的并发与子代理调度是两回事。
- 当前样例采用 LLM 决定是否调用角色的方式，不是固定 DAG。Prompt 约束能引导流程，不能证明模型一定调用某角色。
- 子代理默认不能继续委派；样例使用一层委派，避免无限递归。
- Researcher 只读当前工作区。联网检索需要宿主另外配置并授权 MCP 工具，角色包不会偷偷联网。
- QA 只会在 Shell 被明确授权且 sandbox 可用时运行测试；否则应报告未验证，并给出建议命令。

## 设计依据

官方框架普遍提供经理委派、handoff、顺序 / 并行 workflow 等不同形态。Northstar 的首个角色包选择 manager + bounded subagent：父代理保留最终答复，子代理只做窄任务，并沿用父级权限与预算。

- [OpenAI Agents SDK: agent orchestration](https://openai.github.io/openai-agents-python/multi_agent/)
- [Microsoft Agent Framework: workflow orchestrations](https://learn.microsoft.com/en-us/agent-framework/workflows/orchestrations/)
- [LangGraph: thinking in workflows and checkpoints](https://docs.langchain.com/oss/javascript/langgraph/thinking-in-langgraph)
- [Agno: tool-call limits are configured separately for team leaders and members](https://docs.agno.com/tools/tool-call-limit)
- [AutoGen community discussion: production cost and observability](https://github.com/microsoft/autogen/discussions/7171)
- [Northstar product spine](../../docs/next-gen-agent-os.zh-CN.md)
- [Northstar runtime guide](../../components/northstar-agent-runtime/README.md)
