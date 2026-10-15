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

## MCP 代际行为核对（2026-10-15）

本轮按规范和官方 SDK 行为核对了 Northstar 的 stdio 客户端；“支持某个日期”只描述协议线格式，不代表实现了该版的所有可选能力。

| 行为 | MCP 2026-07-28 现代代际 | MCP 2024-10-07 至 2025-11-25 旧代际 | Northstar 结果 |
| --- | --- | --- | --- |
| 连接与发现 | 无 `initialize`；每个请求自带 `_meta.protocolVersion` 与 `_meta.clientCapabilities`。双代际 stdio 客户端先调用 `server/discover`；服务器身份放在结果 `_meta.serverInfo`，只供显示。 | `initialize` 协商版本与能力，再发 `notifications/initialized`；最终版本以服务器返回值为准。 | 自动模式探测现代版；现代错误不触发旧版降级，其他错误或超时进入旧握手。旧握手接受上述五个官方日期，并保存协商出的版本。 |
| 版本不匹配 | `-32022` 标明现代协议拒绝。只重试本客户端支持且服务器列出的现代版；若没有共同现代版，向操作者报错。 | 服务器可在 `initialize` 中返回自身支持的旧版；客户端必须确认版本可用。 | 覆盖现代错误或 discovery 只列旧版时失败且不发 `initialize`；旧握手接受服务器返回的 `2024-11-05`。 |
| 请求元数据 | 版本与客户端能力逐请求携带；`clientInfo` 是 SHOULD。现代普通结果带必需的 `resultType`；普通结果为 `complete`。 | 能力和客户端身份在握手交换；后续请求不附加现代 `_meta`。旧版未带 `resultType` 时按 `complete` 处理。 | 现代请求逐条断言元数据；工具调用拒绝缺少 `resultType` 的现代结果，也拒绝未支持的结果种类，例如 Tasks 扩展的 `task`。 |
| MRTR | `input_required` 结束当前 JSON-RPC 请求；客户端用新请求 ID 重发原始方法，附上 `inputResponses`，并原样回送可选 `requestState`。 | 没有 `resultType` / MRTR；旧版仍使用握手代际的功能和交互。 | 离线夹具逐字核对新 ID、状态、答案和不变的 `_meta`；拒绝所有请求时停止本地重试并返回错误。 |
| 取消 | 只有仍在途请求才可由 stdio `notifications/cancelled` 取消；已返回 `input_required` 的请求已经完成。Tasks 若启用则使用其 `tasks/cancel`。 | 仍使用旧代际取消通知。 | MRTR 拒绝路径不再对已完成请求发送取消通知。同步 stdio API 当前没有外部中止挂起请求的接口；Tasks 未实现。 |

SDK 行为与规范分开记录：官方 TypeScript SDK v2 将 2024-10-07 至 2025-11-25 归为一个旧代际，`versionNegotiation.mode: 'auto'` 会先探测再回退，而默认仍是旧握手；Python SDK v2 的高阶 `Client` 默认 `auto`，而底层 `ClientSession.initialize()` 仍是显式旧握手入口。两者均把 2026 版的 MRTR 字段、逐请求元数据及结果判别留在线路层处理。Northstar 仅实现 stdio 的工具调用路径，不据此声称支持现代 Streamable HTTP、subscriptions/listen 或 Tasks。

## A2A 身份与传输边界核对（2026-10-15）

A2A v1.0.1 的 Agent Card 以 `supportedInterfaces` 声明协议绑定、版本和 URL；skills 与 extensions 描述远端行为，不是 Northstar 的本机权限。Card 的 JWS 只有在签名密钥通过独立 host trust store 绑定身份时才提供身份依据。设计记录明确将 operator 配置的 principal、允许 origin、TLS 身份、凭据 audience 和当前 host grant 分开，并要求禁重定向、拦截私网/链路本地/metadata 地址、限制 DNS rebinding、响应大小和远端任务引用。

离线夹具覆盖了 link-local metadata endpoint、skills/extensions 冒称 `workspace:write` 与 `secrets:read`、card 内攻击者控制的签名 key，以及超出 parent grant 的 handoff。现有 handoff 测试验证 Agent Card 不能直接成为 registry profile，且 parent capability 与 target profile 任一上限都能拒绝扩权。夹具不是未来 HTTP client 的 URL/TLS/DNS 实现测试；真实网络客户端仍需另行审查并通过独立 adversarial canary。

## 本轮代码审查与修复

最新主线提交加入了具名 Shell session，让多次工具调用可以沿用 cwd 和额外环境变量。原实现的全局状态表与文档中的「仅当前 run」承诺不一致：

1. 状态表在 tools/shell.py 模块加载时创建，整个 Python 进程都持有。
2. session key 只有 (ctx.session_id, 名称)；嵌入式调用方可能重复使用 transcript session ID。
3. run 结束不会清理 dict 中的 cwd/env，变量可能一直留在内存中。
4. 本分支把 dict 放进 RunState，并通过该 run 的 ToolContext 传给 Shell handler。新的 run（包括复用 transcript ID 的 run）会取得空 dict；同一 run 内具名 session 的 cwd/env 仍会续用。

确定性回归测试覆盖同一进程、同一 transcript session ID 下的两个独立 run；第二个 run 不得看到第一个 run 的 cwd/env。现有单 run 续用场景继续覆盖 cwd/env 跨工具调用保持、显式 per-call 覆盖，以及不同具名 session 隔离。

## 建议的实施顺序

产品排序以 [Northstar 次世代 Agent OS 总纲](../docs/next-gen-agent-os.zh-CN.md) 第 5 节为准。基础设施协议工作持续维护，不得挤占首要产品路径。

1. **先打磨编程任务闭环**：用现有 `Read` / `Write` / `Edit` / `Shell` 和独立后置条件完成“理解仓库 → 修改 → 运行相关检查 → 审阅 diff → 汇报证据”；补齐体验与验收缺口，不把工具已注册等同于端到端编程体验已完成。
2. **把攻击测试与防护工具成对产品化**：目前攻防相关模块分散在专项验证与独立能力中，尚未组成统一的默认产品工具面。分别定义工具权限、目标范围、预算和审计；攻击测试只针对显式授权的本地项目、隔离靶场或 allowlist，防护工具负责检查、分级、修复建议和复测闭环。
3. **再扩展多模态输入**：先稳定图片理解，再按实际任务需求加入音频和视频；媒体输入沿用 workspace 范围、来源标注、预算和不可信内容处理规则。
4. **为远程 sandbox 预留后端，不扩张默认权限**：执行 backend 应报告隔离等级、运行身份、workspace digest 与可验证 receipt；本地 process fallback 仍必须如实标为非 OS 隔离。
5. **最后再做事件触发的长期 agent**：GitHub/Slack/cron 触发要绑定 host 身份、显式数据域、预算上限、幂等键与人工 review。自动创建 draft PR 可以纳入产品，自动合并或绕过 permission gate 不应纳入默认路径。

MCP 代际矩阵（现代发现、逐请求元数据、MRTR/取消及旧代际拒绝回退）与 A2A 身份 / handoff 边界已完成本轮核对；继续在协议或官方 SDK 改变协商语义时更新 fixtures。真实 A2A 网络客户端仍需 host trust/config、DNS 与 redirect guard、凭据 audience、bounded task/stream 与独立 adversarial canary 后再决定。

## 来源

### 官方规范与实现

- [MCP 2026-07-28 规范](https://modelcontextprotocol.io/specification/2026-07-28/) · [版本与兼容性](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)
- [现代发现](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) · [现代工具调用与 MRTR](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [官方 TypeScript SDK v2：protocol versions](https://ts.sdk.modelcontextprotocol.io/v2/protocol-versions) · [2026-07-28 support](https://ts.sdk.modelcontextprotocol.io/v2/migration/support-2026-07-28)
- [官方 Python SDK v2：protocol versions](https://py.sdk.modelcontextprotocol.io/protocol-versions/) · [v2 behavior changes](https://py.sdk.modelcontextprotocol.io/whats-new/)
- [A2A v1.0.1 规范](https://a2a-protocol.org/v1.0.1/specification/)
- [A2A Agent Card 字段与签名](https://a2a-protocol.org/v1.0.1/specification/#441-agentcard) · [Discovery 与协议绑定](https://a2a-protocol.org/v1.0.1/specification/#82-discovery-mechanisms)
- [A2A 授权范围与安全考虑](https://a2a-protocol.org/v1.0.1/specification/#131-data-access-and-authorization-scoping)
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
