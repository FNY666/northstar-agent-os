# Northstar Agent OS：AI Agent 生态扫描（2026-10-15）

> 资料检查日期：2026-10-15。范围包括官方协议与文档、公开代码仓库、公开 issue 和论坛讨论。本文记录可核对的代表性趋势，不声称穷尽所有 AI 项目。私有 Slack、Discord、微信群等内容不可公开检索，本轮没有访问。

## 结论

主流 Agent 系统正在把「模型循环」扩展为完整的任务环境：隔离工作区、跨步骤状态、恢复点、可追溯权限和执行后证据。Northstar 已有治理门、预算、审计、checkpoint、MCP 与本地执行侧车；当前最直接的缺口是把每个 run 的执行状态也严格限于该 run 的生命周期。

本轮代码审查发现具名 Shell session 的 cwd 和环境变量保存在模块级字典中，键是可在多个嵌入式 run 间复用的 session ID。AgentRuntime.run() 虽为每次调用创建新的 RunState，模块字典却不会随 run 结束清理。若调用方在同一个进程里复用 session ID，后续 run 可能继承前一 run 的 Shell cwd 和环境变量。分支修复将这份状态移入每次 run 的上下文；单次 run 内的多步 Shell 工作仍可保留状态。

## 生态观察

| 方向 | 近期可核实的做法 | 对 Northstar 的启发 |
| --- | --- | --- |
| 可恢复执行 | OpenAI Agents SDK 的 sandbox session 将 workspace、进程、mount 与 provider 状态放在 session 边界内，支持 snapshot 与 resume；其 scripted model 和 scripted sandbox 测试可离线验证编排。LangGraph 按 thread/checkpoint 保存状态，并区分单线程状态与跨线程 store。Microsoft Agent Framework 也提供可选 durable workflow 扩展。 | 继续明确区分 run、会话 transcript、workspace 与长期记忆的生命周期；恢复只恢复已授权的状态，不从 ID 推断授权。 |
| 沙箱和工作区 | OpenHands 用 Agent Server 与 sandbox runtime 分开；托管部署加入每个 session 独立的 microVM。OpenHands 的自动化可由 issue、Slack、Jira 或定时任务触发，并以 PR 供人审阅。 | 远程 worker 是有价值的后续执行后端，但应继续由 contract、narrowed grant、预算和 receipt 包住；托管云不应成为本地版的隐式依赖。 |
| 协议互操作 | MCP 2026-07-28 已是稳定规范版本：现代请求逐请求携带版本与能力，不再依赖旧式 initialize/session 握手；规范同时定义 discovery、MRTR 和扩展协商。A2A v1.0.1 使用 Agent Card 声明能力与认证要求，并用 task/context 标识关联多轮工作。 | 保留 legacy MCP 兼容，并用规范 conformance fixtures 检查现代与旧代际的拒绝/回退行为。A2A 网络后端要等 host 认证、代理身份、scope 收窄、预算和审计对齐后再接。 |
| 技能和扩展 | Agent Skills 已有跨产品的开放 SKILL.md 格式；技能可带 references 与 scripts。Northstar 已有本地技能检查、digest lock 和受治理的脚本执行路径。 | 继续兼容格式，但保持来源审查、digest 固定和执行过门；不因生态广泛采用就自动下载或执行第三方 skill。 |
| 社区反馈 | OpenAI SDK issue 讨论 sandbox capability 间的 run-scoped cwd；OpenHands issue 讨论 TenantContext 如何贯穿 runtime、LLM、storage 和 events。公开讨论反复出现「工作区可持续使用」与「会话间隔离」必须同时成立的需求。 | 用明确的生命周期归属解决问题，而不是将隔离寄托在随机 session ID 或调用方约定上。 |

## 本轮代码审查与修复

最新主线提交加入了具名 Shell session，让多次工具调用可以沿用 cwd 和额外环境变量。原实现的全局状态表与文档中的「仅当前 run」承诺不一致：

1. 状态表在 tools/shell.py 模块加载时创建，整个 Python 进程都持有。
2. session key 只有 (ctx.session_id, 名称)；嵌入式调用方可能重复使用 transcript session ID。
3. run 结束不会清理 dict 中的 cwd/env，变量可能一直留在内存中。
4. 本分支把 dict 放进 RunState，并通过该 run 的 ToolContext 传给 Shell handler。新的 run（包括复用 transcript ID 的 run）会取得空 dict；同一 run 内具名 session 的 cwd/env 仍会续用。

确定性回归测试覆盖同一进程、同一 transcript session ID 下的两个独立 run；第二个 run 不得看到第一个 run 的 cwd/env。现有单 run 续用场景继续覆盖 cwd/env 跨工具调用保持、显式 per-call 覆盖，以及不同具名 session 隔离。

## 建议的实施顺序

1. **完成 Shell 生命周期验证**：补上上面的跨 run 回归测试，并运行 Shell session、runtime、全仓离线套件。检查子代理共享/隔离语义是否与文档一致。
2. **维护 MCP 代际矩阵**：分别验证 2026-07-28 modern discovery、逐请求元数据、MRTR/取消及旧代际初始化与拒绝回退；按规范与 SDK 更新记录行为，而不是只记录规范发布日期。
3. **将 A2A 保持在明确边界之后**：先写 transport/身份设计和恶意 Agent Card/超范围 capability fixtures，再决定是否接真实网络客户端。
4. **为远程 sandbox 预留后端，不扩张默认权限**：执行 backend 应报告隔离等级、运行身份、workspace digest 与可验证 receipt；本地 process fallback 仍必须如实标为非 OS 隔离。
5. **最后再做事件触发的长期 agent**：GitHub/Slack/cron 触发要绑定 host 身份、显式数据域、预算上限、幂等键与人工 review。自动创建 draft PR 可以纳入产品，自动合并或绕过 permission gate 不应纳入默认路径。

## 来源

### 官方规范与实现

- [MCP 2026-07-28 规范](https://modelcontextprotocol.io/specification/2026-07-28/) · [版本与兼容性](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)
- [A2A v1.0.1 规范](https://a2a-protocol.org/v1.0.1/specification/)
- [Agent Skills 规范](https://agentskills.io/specification)
- [OpenAI Agents SDK sandbox guide](https://openai.github.io/openai-agents-python/sandbox/guide/) · [确定性测试工具](https://openai.github.io/openai-agents-python/testing/)
- [OpenHands sandbox guide](https://docs.openhands.dev/openhands/usage/advanced/custom-sandbox-guide) · [Agent Server 与托管 microVM 公告](https://hub.openhands.dev/blog/run-digitalocean-managed-agents-with-openhands)
- [LangGraph persistence](https://docs.langchain.com/oss/python/langgraph/persistence)
- [Google Agent Development Kit overview](https://google.github.io/adk-docs/get-started/about/)
- [Microsoft Agent Framework concepts](https://learn.microsoft.com/en-us/agent-framework/concepts/) · [durable agents extension](https://learn.microsoft.com/en-us/azure/durable-task/sdks/durable-agents-microsoft-agent-framework)

### 公开社区信号（个案，不作为规范证据）

- [OpenAI Agents SDK：run-scoped cwd issue #4401](https://github.com/openai/openai-agents-python/issues/4401)
- [OpenHands：跨 runtime/LLM/storage/events 传播 tenant context issue #14545](https://github.com/OpenHands/OpenHands/issues/14545)
- [OpenHands：每个 conversation 独立 sandbox 讨论 issue #15630](https://github.com/OpenHands/OpenHands/issues/15630)
- [r/AI_Agents：自托管 workspace 与每 chat 独立 sandbox 的讨论](https://www.reddit.com/r/OpenSourceAI/comments/1wa2kgi/a_selfhosted_ai_agent_workspace_where_every_chat/)

这些社区条目说明真实使用者会遇到工作区持久化、运行隔离和身份跨层传递的问题；它们不是对任一产品安全性的独立审计结论。
