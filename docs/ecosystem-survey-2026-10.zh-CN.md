# Northstar Agent OS 生态调研与吸收建议

> 调研日期：2026-10-15  
> 范围：公开的一手文档、协议规范、安全基线与少量社区索引。本文不是“所有 AI”的完整清单；生态每日变化，结论只对下列可复核来源负责。  
> 证据标记：**规范/官方文档**表示来源项目的正式资料；**草案/扩展**表示尚在演进；**社区信号**用于发现项目，不作为能力或安全结论。

## 结论摘要

Northstar 的差异化方向仍然成立：让每项执行能力经过权限、策略、预算和可审计路径。最近的主分支提交已经把四道治理门接入真实工具派发、默认启用封存审计，并加入运行内 Shell 会话；因此，旧版“尚未接线”的对标结论不能直接沿用。外部项目值得学习的是产品工作流和互操作边界，不能只按功能数量做并集。

建议下一轮按以下顺序推进：

1. **先做新鲜度与证据治理**：每项对标能力记录来源、版本/发布日期、核验日期、证据等级和本仓验证状态。旧报告中的测试数、协议代际、实现状态必须在发布前从当前主分支重核。
2. **把 Agent 身份与授权做成明确的主机接口**：区分“模型建议”“运行时授权”“主机身份”；委派不能扩大身份或权限，凭据不进入模型上下文、转录或子代理输入。NIST 的身份与授权工作仍处在概念/项目阶段，应作为设计输入，而非已定标准。
3. **把互操作拆成可审查的薄适配器**：MCP 负责工具/上下文边界，A2A 负责 agent 间任务交接；两者都不应成为绕过本地治理的执行捷径。先定义最小的能力映射、签名/来源、取消与回执，再接外部后端。
4. **让外部能力按威胁模型进入基准**：每个新适配器要有 scripted 离线用例、拒绝路径、参数变更/重放检查、超时和取消测试；外部 benchmark 可补充攻击样例，但不能替代 Northstar 的端到端治理测试。
5. **暂缓市场与自动导入**：先维持锁定摘要、人工评审和默认拒绝。公开目录和社区技能适合作为候选发现来源，不应直接成为信任根。

## 生态分层

| 领域 | 值得跟踪的项目/规范 | 从公开资料可确认的设计 | 对 Northstar 的含义 |
|---|---|---|---|
| Agent SDK / 工具流 | [OpenAI Agents SDK](https://openai.github.io/openai-agents-python/) | agent handoff、工具与输出 guardrails、sessions、tracing；SDK 文档也提供 scripted 模型与 sandbox 测试配方。工具 guardrail 与 handoff 的覆盖边界需要逐项核验。 | 对标委派、轨迹和可测性；任何 handoff 都应保留本地授权门、审计和累计预算。 |
| 编码代理 / 权限交互 | [Claude Code 文档](https://docs.anthropic.com/en/docs/claude-code/overview) | 提供命令行代理、工具权限配置、hooks 和子代理等产品交互。CLI 文档列出跳过权限提示的危险选项。 | 学习清楚的权限体感和人机交互；不得把“自动批准”当成治理能力。需要将不同版本的 hooks / settings 与本仓配置逐项对照。 |
| 持久编排 | [LangGraph 持久执行](https://docs.langchain.com/oss/python/langgraph/durable-execution) | checkpoint、interrupt 与从持久状态继续执行；持久边界和副作用处理是工作流语义的一部分。 | 对照 resume、checkpoint 和人工审批的恢复语义；Northstar 的 session/checkpoint 记录不能与外部工作流状态混为一谈。 |
| Google Agent SDK | [Google ADK 文档](https://google.github.io/adk-docs/) | 多 agent 构造、session、工具、评估和部署文档分层齐全；其社区资源页提供课程和交流入口。 | 适合做入门体验与评估流程对标。部署、云服务、身份体系是供应商能力，不应暗示为本地运行时能力。 |
| Microsoft agent frameworks | [Microsoft Agent Framework](https://github.com/microsoft/agent-framework)；[AutoGen 状态说明](https://github.com/microsoft/autogen) | Agent Framework 提供 Python/.NET 的编排、middleware、checkpoint 和 tracing；Microsoft AutoGen 仓库已注明进入 maintenance mode，并建议新项目转向 Agent Framework。 | 新适配器要跟踪上游生命周期与迁移路线，避免把 AutoGen 新功能当成持续维护承诺；框架 checkpoint 也不能替代 Northstar 的授权与审计账本。 |
| 开源多 agent 工作流 | [CrewAI](https://github.com/crewAIInc/crewAI)；[官方文档](https://docs.crewai.com/) | 项目自述支持 crews/flows、MCP、A2A、checkpoint 和沙箱工具集成，并维护公开社区论坛；这些产品能力未在 Northstar 中独立复测。 | 重点对照流程状态、并发、恢复与跨 agent 参数边界；不要把流程抽象或厂商的 sandbox 集成描述为 Northstar 已有的执行隔离。 |
| 本地优先的 agent 应用 | [Block Goose](https://github.com/block/goose)；[AAIF 项目介绍](https://www.linuxfoundation.org/press/linux-foundation-announces-the-formation-of-the-agentic-ai-foundation?_bhlid=794175d0dc8bbd1e4786c6d7debc273bb0e98d97) | Goose 是开源本地 agent 项目，早期即采用 MCP 扩展模型；它与 MCP、AGENTS.md 同属 Linux Foundation 的 AAIF 项目群。 | 对照本地运行、工具扩展发现和用户权限体验；“本地优先”不等于具备强隔离或默认可信。 |
| 工具/上下文互操作 | [MCP 2026-07-28 规范](https://modelcontextprotocol.io/specification/2026-07-28)；[正式发布说明](https://blog.modelcontextprotocol.io/posts/2026-07-28/)；[上一代 2025-11-25 规范](https://modelcontextprotocol.io/specification/2025-11-25) | 截至调研日，2026-07-28 已是正式发布版本，不是候选。该版引入无状态核心和扩展机制，强化 OAuth issuer 校验及凭据绑定、将 Tasks 移出核心并扩展化；DCR 被弃用，Roots、Sampling、Logging 与旧 HTTP+SSE 进入弃用周期。官方称四个 Tier 1 SDK 已支持该版。 | 维护版本化协议适配；新旧版本迁移要检查认证发现、凭据来源、长任务的创建/查询/取消，以及旧能力弃用。所有远端调用仍映射到 Northstar 本地授权与审计路径。 |
| Agent 间交接 | [A2A 1.0 文档](https://a2a-protocol.org/latest/)；[A2A 官方社区与集成目录](https://a2a-protocol.org/latest/community/)；[Linux Foundation 2026-04 项目更新](https://www.linuxfoundation.org/press/a2a-protocol-surpasses-150-organizations-lands-in-major-cloud-platforms-and-sees-enterprise-production-use-in-first-year) | A2A 1.0 提供跨框架 agent 发现、消息和任务交互；Linux Foundation 于 2026-04 称其已有 150 多家支持组织，并覆盖多个云平台。该数字是项目生态信号，不证明安全或互操作质量。 | 优先做窄桥接：远端 agent 只收到被批准的最小任务上下文；回执视为不可信输入，并走本地独立验证。 |
| Agent 治理框架 | [Microsoft Agent Governance Toolkit / Agent OS](https://github.com/microsoft/agent-governance-toolkit) | 仓库展示确定性策略评估、身份、审批、审计、框架适配器和 MCP server；其 README 也明确指出应用层策略会被直接 `subprocess`/`open` 调用绕过，并标出部分适配器或控制平面组件仍属实验状态。这些是项目自述，本文未独立复测。 | 对比策略作者体验、框架适配面和 MCP 运维入口；继续把 Northstar 的 sidecar/OS 隔离与应用策略作为不同防线验证，不因对方功能清单推断安全等价。 |
| Kubernetes 部署参考 | [Azure KARS](https://github.com/Azure/kars)；[架构说明](https://github.com/Azure/kars/blob/main/docs/architecture.md) | Kubernetes 参考栈使用每个 agent 一个 sandbox，并用 CRD 表达 agent 身份、A2A 入口、带 OAuth/工具 allowlist 的 MCP server、工具策略和模型预算；其范围是云原生部署与运维。 | 借鉴策略、身份、egress 和 peer 关系的声明式运维；KARS 面向 Kubernetes 平台，不等同于 Northstar 的便携式本地 runtime。 |
| 开放行业协作 | [Agentic AI Foundation (AAIF)](https://aaif.io/)；[Linux Foundation 项目更新](https://www.linuxfoundation.org/press/agentic-ai-foundation-welcomes-57-new-members-gaining-major-financial-services-players-and-apac-leaders?hs_amp=true) | Linux Foundation 将 MCP、goose、AGENTS.md、agentgateway 等列为 AAIF 项目；其公开活动与项目页提供跨公司的标准和开发者协作入口。成员数和新闻稿采用度是时效性生态信号，不是技术安全结论。 | 跟踪中立治理、标准议题、conformance 工具和维护者反馈；是否采用协议仍按规范版本、实现测试和 Northstar 威胁模型判断。 |
| 技能格式 | [Agent Skills](https://agentskills.io/) | 以可移植的技能目录/说明文件为中心的开放格式和文档生态。 | 格式兼容不等于代码可信。脚本仍应在沙箱内运行、由操作者显式授权并固定内容摘要。 |
| 安全基线与身份 | [OWASP Agentic Applications Top 10 (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)；[NIST 软件与 AI agent 身份授权项目](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization) | OWASP 按 agentic 威胁组织风险；NIST 正在研究如何把身份标准与实践用于软件 agent，包含公开意见和项目产出。 | 将风险映射为可复现的攻击/防护用例。NIST 项目是发展中的参考，不是已发布的强制合规标准。 |

## 公开社区与发现渠道

社区入口的作用是发现候选工具、用户摩擦和新攻击样例；帖子、星标数和自述不能证明实现安全或生产可用。

- [Google ADK community resources](https://google.github.io/adk-docs/community/)：官方列出的课程与社区入口。
- [A2A 官方 community hub](https://a2a-protocol.org/latest/community/)：列出官方 Discord 入口、框架集成、社区 SDK 与贡献要求；将其作为公开讨论和候选发现渠道，不推断私聊内容。
- [Agentic AI Foundation](https://aaif.io/) 与 [Linux Foundation 活动](https://events.linuxfoundation.org/2026/04/17/agentic-ai-foundation-announces-global-2026-events-program-anchored-by-agntcon-mcpcon-north-america-and-europe/)：跟踪 MCP Dev Summit、AGNTCon 和 MCPCon 的公开议程、演讲与标准讨论。
- [Microsoft Agent Framework Community & Feedback](https://github.com/microsoft/agent-framework)；[Azure AI Foundry Discord](https://aka.ms/foundry/discord)：官方列出与开发者和产品团队交流的入口。
- [AutoGen GitHub Discussions 与 Discord](https://github.com/microsoft/autogen)：上游明确标注 AutoGen 处于维护模式、社区支持响应可能有限；新项目应跟踪其 Agent Framework 迁移指南。
- [LangChain Forum](https://forum.langchain.com/) 与 [Community Slack](https://www.langchain.com/community)：可见 LangChain/LangGraph 的公开问题、版本摩擦和维护者回应。
- [CrewAI 官方社区论坛](https://community.crewai.com/)：用于发现用户实践和问题；产品能力仍回到文档、源码与可复现测试确认。
- [Reddit: agent framework comparison discussion](https://www.reddit.com/r/AgentsOfAI/comments/1sya972/top_agentic_frameworks_let_me_know_if_i_missed_any/)：可观察框架清单和用户提问；内容是个人讨论，需回到项目文档核实。
- [awesome-cli-coding-agents](https://github.com/bradAGI/awesome-cli-coding-agents)：社区维护的 CLI 编码代理目录；适合发现新工具，不适合作为完整性或质量排名。
- GitHub 项目 issue、release、specification discussion：研究时先看维护者发布和可复现 issue；社区聊天中未公开、不可检索的内容不纳入结论，也不尝试读取私人群聊。

## 当前仓库的状态基线

以本次可读取的主分支记录为准，近期提交包括：

- `2a2c421`（2026-10-09）：生产串行与并行工具派发接入 GovernedActionRunner；默认 SealedAuditSink；记录 allow/deny 并对授权与评估间参数变化做检查。
- `ec02ee7`（2026-10-09）：对生产路径做红队验证，包括并行审计序列与篡改检测。
- `efa374a`（2026-10-09）：加入运行内命名 Shell session，显式 cwd/env 仍按既有解析与沙箱规则处理。
- `1f96ae3`（2026-10-09）：增加灾难性 Shell 命令默认拒绝规则及红队回归用例。

这些是提交说明中的声明，本文未在本地重新运行测试，也没有独立审计代码。旧基准报告仍可作为历史记录，但引用其中的差距或测试总数前，应先对照当前代码、CI 结果和对应测试。

## 后续研究与实现门槛

每个吸收提案写清楚：

- **来源与版本**：官方文档/规范链接、发布日期或提交、本文复核日期；把草案、社区帖子标出来。
- **价值**：具体用户任务为何变得更可完成，使用脚本 provider 给出成功路径。
- **权限映射**：每个外部动作如何映射到本地工具、参数策略、人工批准和拒绝结果。
- **生命周期**：预算继承、超时、取消、恢复、重复请求、部分失败及子代理身份。
- **数据边界**：发送给 provider / 远端 agent 的字段、凭据排除规则、审计脱敏。
- **验证与回滚**：离线确定性攻击用例、受影响协议/记录版本、功能关闭方式。

如果一个能力无法以这些条件接入同一治理路径，就只记录为研究候选，不把它宣称为 Northstar 已支持的能力。

## 来源与时效说明

本调查于 2026-10-15 通过公开可访问的官方文档、协议站点、OWASP/NIST 站点、GitHub 提交说明及少量公开社区页面完成。官方文档可能滚动更新；实现与规范的兼容情况需要仓库 CI 或显式互操作测试验证。这里没有访问私人论坛、登录后社区或群聊，也没有检查付费/私有资料。
