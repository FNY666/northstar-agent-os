# Agent Runtime 生态与安全做法（2026-10）

这份调研把公开文档、开源项目、安全社区讨论与 Northstar 源码放在一起看，目标是找能验证并实现的工程做法，不做“框架排行榜”。公开搜索覆盖官方文档、GitHub 项目/议题、Hacker News 与 Reddit 公开帖子；私有论坛、登录后内容和群聊不在本次可见范围内。

## 公开资料的共同结论

### 1. 把安全检查放在每次实际工具执行前

OpenAI Agents SDK 将工具 guardrail 作为函数工具执行管线的一部分，也明确说明 handoff、托管工具和若干内建工具不走同一 guardrail 管线；只配置 agent 输入/输出 guardrail，不等于覆盖每次工具调用。Northstar 应继续保持单一、完整的执行授权点，并把任何新工具类型接入 `AgentRuntime` 的 pre-tool gate，而不是只在模型输入或最终回答处过滤。[OpenAI Agents SDK Guardrails](https://openai.github.io/openai-agents-python/guardrails/)、[Handoffs](https://openai.github.io/openai-agents-python/handoffs/)

Anthropic 的可信 agent 资料强调，用户监督可以从逐个动作转到策略和目标层，但多步子 agent 工作流会让用户更难理解、引导。Northstar 对应的工程要求是：保留有界委派、可见的工具轨迹、可暂停/恢复点，以及不能被子 agent 扩大的权限 ceiling。[Trustworthy agents in practice](https://www.anthropic.com/research/trustworthy-agents)

### 2. MCP 工具定义和工具结果都属于不可信输入

MCP 官方本地服务器安全指南明确指出，工具描述可用来影响模型选工具，甚至指示模型调用其他服务器的工具；安装时审查不能覆盖服务器运行时返回的描述。官方安全最佳实践也要求考虑 token 受众、禁止 token passthrough，并按具体工具/能力细分授权。[MCP local server security](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/docs/2026-07-28/tutorials/security/local-server-security.mdx)、[MCP security best practices](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/docs/2026-07-28/tutorials/security/security_best_practices.mdx)、[MCP authorization security considerations](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/authorization/security-considerations.mdx)

公开的 MCP 议题和讨论反映出两种不同输入边界：`tools/list` 描述可以在调用前污染选择；tool result 可以在调用后注入下一轮上下文。不能把两者都当成“字符串扫描”就结束，最好同时做运行时定义完整性、模型可见内容降权，以及工具结果来源标记。[MCP-2026-015 issue](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/3213)、[Tool results and taint discussion](https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/3093)

Northstar 已经对 MCP schema/description 建 admission baseline、发现 drift 时 quarantine，并在接入时记录描述 coercion。基于运行时提示注入资料，本轮进一步做到：命中已知 coercion 特征时，向模型隐藏原始 tool description；schema 的 description/title/comment/examples 元数据命中时从模型 schema 中移除；若命中出现在 enum/default/pattern 等功能字符串中，则不把该 tool 暴露给模型，以免为了清洗提示词而悄悄改写工具契约。handler 仍由现有权限门保护。该规则依然是启发式；未知措辞、非文本元数据和恶意工具结果需要其它控制。

### 3. 暂停/恢复需要持久化状态，而且批准必须绑定正在执行的动作

LangGraph 的官方 interrupt 文档将人工介入建立在 checkpoint/persistence 上：运行可暂停，稍后按 thread id 从保存状态恢复；同一机制也提供故障恢复和时间旅行。这与 Northstar 的 checkpoint + fork resume 路径方向一致。Northstar 还需要继续把审批锚定到具体 call id、参数摘要、policy revision 和 run 身份，防止“恢复后旧批准变成通行证”。[LangGraph interrupts](https://langchain-ai.github.io/langgraph/concepts/breakpoints/)、[LangGraph durable execution](https://langchain-ai.github.io/langgraph/concepts/durable_execution/)

### 4. 社区反馈支持 OS 级隔离，但只能作定性线索

LocalLLaMA 与 Hacker News 的公开讨论反复提到 coding agent 的目录边界、进程级隔离、网络访问和“沙箱并不自动保护服务端状态”的差别。这些是使用者经验贴，不是系统性测量；可作为场景清单，不能当作安全证明。Northstar 已有 workspace containment、bwrap/seccomp/capability drop、可选 Landlock 和受限 egress，后续验证应把权限策略和 OS 强制边界分开记录。[LocalLLaMA: agent sandbox choices](https://www.reddit.com/r/LocalLLaMA/comments/1vrps78/what_sandbox_are_you_all_using_for_ai_agents/)、[HN: deep dive on agent sandboxes](https://news.ycombinator.com/item?id=46595393)、[HN: filesystem permissions for coding agents](https://news.ycombinator.com/item?id=47550282)

OWASP 将 Excessive Agency 作为 agent 风险，强调能力范围、权限与输入处理之间的关系。它为 Northstar 的限制方向提供了风险分类，不代表本地实现已经通过 OWASP 认证。[OWASP LLM06: Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)

## 本轮代码核对与改造

1. 对比外部 agent 工具 guardrail 覆盖范围与本地 `AgentRuntime`，核实 Northstar 在执行器侧集中执行权限判断，而非依赖模型拒绝。
2. 追踪 MCP server `tools/list` → `RemoteTool` → `mcp_tool_specs()` → provider tool schema。发现 Northstar 有 admission 审计和完整 schema digest，但命中 coercion 的 description 仍进入模型上下文。
3. `mcp_tool_specs()` 现在对命中描述做降权：模型收到 Northstar 生成的中性占位说明；命中注入的 schema 注释被移除，命中功能字符串的工具不会暴露给模型；原有 handler 仍在权限门后，筛查结果进入 audit。
4. 追踪 scope ceiling → permission layers → tool dispatch，修复 scope 提升提前返回导致的策略旁路，见前一提交与 `docs/architecture/intervention-points.md`。

静态编译和差异检查通过；没有运行测试、探针或真实 MCP server。因未做运行时试验，本轮不能声称新描述降权行为已通过端到端验证。

## 后续优先项

- 对 MCP tool result、资源、prompt 和 elicitation 返回值使用统一来源标签，并验证标签跨会话摘要/压缩仍然存在。
- 建立 Northstar adapter 对接公开 agent security regression corpus 的离线评测入口；需要先审查测试样例的 license 和执行隔离要求。
- 将工具名、server identity、schema digest、权限决定、callback 回执和执行收据关联成一个可查询的 run evidence 链。
- 将公开讨论中常见的“沙箱只隔离进程、未隔离凭据/服务端状态/网络”整理为显式威胁模型对照表。

## 搜索边界

搜索的“所有 AI”在逻辑上没有穷尽办法；此文是截至 2026-10 的一组可复核公开来源抽样。GitHub 搜索只代表可见索引，公开论坛只反映参与发言的人，私有 Slack/Discord/微信群等需要成员身份或连接器授权。本轮没有读取或联系这些私有渠道。
