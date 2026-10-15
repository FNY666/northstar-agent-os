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
| 工具/上下文互操作 | [MCP 规范](https://modelcontextprotocol.io/specification/2025-11-25)；[2026-07-28 发布候选说明](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/)；[Tasks 扩展](https://tasks.extensions.modelcontextprotocol.io/) | 2025-11-25 是已发布规范来源；2026-07-28 资料描述无状态核心、扩展、Tasks、Apps 与授权加固的发布候选。Tasks 现以扩展形式演进。草案和扩展不可写成当前稳定兼容承诺。 | 维护版本化协议适配；分别声明已发布协议与实验性扩展支持情况。远端任务的创建、查询、取消和 elicitation 都要映射到本地审批与审计事件。 |
| Agent 间交接 | [A2A 最新文档](https://a2a-protocol.org/latest/) | 开放协议定义跨 agent 发现、消息与任务交互；规范页是能力和数据结构的来源。 | 优先做窄桥接：远端 agent 只收到被批准的最小任务上下文；回执视为不可信输入，并走本地独立验证。 |
| 技能格式 | [Agent Skills](https://agentskills.io/) | 以可移植的技能目录/说明文件为中心的开放格式和文档生态。 | 格式兼容不等于代码可信。脚本仍应在沙箱内运行、由操作者显式授权并固定内容摘要。 |
| 安全基线与身份 | [OWASP Agentic Applications Top 10 (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)；[NIST 软件与 AI agent 身份授权项目](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization) | OWASP 按 agentic 威胁组织风险；NIST 正在研究如何把身份标准与实践用于软件 agent，包含公开意见和项目产出。 | 将风险映射为可复现的攻击/防护用例。NIST 项目是发展中的参考，不是已发布的强制合规标准。 |

## 公开社区与发现渠道

社区入口的作用是发现候选工具、用户摩擦和新攻击样例；帖子、星标数和自述不能证明实现安全或生产可用。

- [Google ADK community resources](https://google.github.io/adk-docs/community/)：官方列出的课程与社区入口。
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
