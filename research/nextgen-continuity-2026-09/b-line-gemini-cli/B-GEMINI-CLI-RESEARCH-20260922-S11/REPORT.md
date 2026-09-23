# S11：工具执行前后的授权与身份边界

- **研究日期**：2026-09-22（Asia/Shanghai）
- **范围**：仅检视 `google-gemini/gemini-cli` 官方 GitHub 的公开文档、源码与测试；不运行 Gemini CLI，不连接 MCP，不访问真实服务或凭据。
- **版本口径**：URL 使用官方仓库 `main` 分支；`main` 是移动分支，因此下述结论是该公开版本的可复核切片，不等同于不可变发布版本。
- **证据等级**：E1=官方源码/类型实现；E2=官方文档；E3=官方测试。
- **判定词**：verified=资料直接支持；inferred=由实现结构作出的限定推断；unknown=本切片未找到官方证明（不是对不存在的断言）；conflict=官方资料彼此存在表述不一致。

## 结论矩阵

### A. 工具执行前：MCP trust 与 trusted folder

1. **结论：MCP `trust` 会在“可信目录”条件同时满足时绕过该 MCP 工具的确认；默认 `trust` 为 false。** **verified**（E1/E2）
   - 官方文档将 `mcpServers.<name>.trust` 定义为“true 时绕过该 server 的所有工具调用确认”，默认 false。
   - 源码的 `getConfirmationDetails()` 只有在 `isTrustedFolder() && this.trust` 时返回无确认；否则继续 allowlist/确认流程。
   - Caveat：这是 CLI 侧确认/策略边界，不是 MCP server、OAuth 服务器或业务系统的授权证明。

2. **结论：trusted folder 是加载项目能力的前置边界，并不是一个调用者身份凭证。** **verified**（E2）
   - 未信任目录不加载工作区 settings 与 `.env`，禁用工具自动接受，不连接 MCP servers；选择会写入 `~/.gemini/trustedFolders.json`，可按目录/父目录复用。
   - `--skip-trust` 或 `GEMINI_CLI_TRUST_WORKSPACE=true` 是“本次会话信任”旁路。
   - Caveat：文档没有把 folder-trust decision 绑定到用户、设备、进程或远端主体 ID。

3. **结论：未信任目录会强制工具执行前提示，但不应解释为“所有执行都绝对阻断”。** **inferred**（E2）
   - 文档明确写“always prompted before any tool is run”，但同一文档还允许 headless 使用 `--skip-trust`/环境变量旁路；因此它是当前 CLI 会话的门控，而不是不可绕过的远端授权。

### B. 策略与审批模式

4. **结论：策略支持 `allow`、`deny`、`ask_user`，并按匹配条件和优先级决定执行前结果；非交互模式下 `ask_user` 按 deny 处理。** **verified**（E2/E1）
   - 条件可包含工具名、稳定 JSON 参数正则、approval mode、interactive、MCP server name、工具 annotations；高优先级匹配规则先决定。
   - 源码还严格检查 `mcpName` 与运行时 serverName，并支持 MCP FQN/短名映射。
   - Caveat：本结论是 CLI 的策略判定，不等于远端 server 对请求的二次授权。

5. **结论：MCP 规则可以分别绑定 server、tool 与 args；工具参数参与策略匹配，但不是防篡改的签名。** **verified**（E1/E2）
   - `PolicyRule` 有 `mcpName`、`toolName`、`argsPattern`、`toolAnnotations`；源码将参数稳定序列化后做正则匹配。
   - MCP invocation 将原始 `serverName`、`serverToolName`、`params` 放入确认详情，并调用 server tool name 与 params。
   - Caveat：没有看到对 server/name/args 生成密码学承诺或由远端验证的声明。

6. **结论：Plan Mode 是内建只读策略集合，但官方允许用户通过策略自定义；YOLO 是显式宽松模式。** **verified**（E2）
   - Plan 只允许读文件、搜索、只读 MCP 等工具；可用 `--approval-mode=plan` 进入。
   - 文档定义 `yolo` 为所有工具自动批准，并警告谨慎使用；源码对危险命令在 YOLO 下保留原决策而不强制 ask。
   - Caveat：YOLO 的“自动批准”仍是 CLI 侧模式，不是效果成功、提交成功或 exactly-once 的承诺。

7. **结论：持久化“允许未来会话”是按 approval mode 层级传播的策略规则，而非所见的授权快照。** **verified + inferred**（E2/E3/E1）
   - 文档描述 `plan < default < autoEdit < yolo` 的传播：Plan 授权覆盖所有模式；default 覆盖 default/autoEdit/yolo；autoEdit 覆盖 autoEdit/yolo；YOLO 仅 YOLO。
   - 官方测试证明 `persist=true` 会写入/追加 `auto-saved.toml`，而未设置 persist 不写入；MCP 持久化选项可包含 `mcpName` 和 argsPattern。
   - `DiscoveredMCPToolInvocation` 的 server/tool allowlist 是进程内 `static Set`；源码注释说持久化策略由 scheduler 集中处理。
   - Inferred caveat：持久化的是规则/allowlist 语义，不是带时间、调用参数、策略版本和批准者的 per-call snapshot。

8. **结论：资料对 workspace policy 的有效性存在官方内部冲突。** **conflict**（E2）
   - policy 文档警告 workspace `.gemini/policies` 当前无效，同时其优先级表/说明仍描述 workspace tier 与“Workspace policies override Default”。
   - Caveat：本切片不替仓库解决该冲突；实际部署应以对应版本源码/测试和运行配置为准。

### C. 工具声明与事件关联

9. **结论：MCP 工具在 CLI 内部有明确的 server/tool 双重命名边界。** **verified**（E1/E2）
   - invocation 保存 `serverName`、原始 `serverToolName`、displayName、参数；策略可用 `mcpName` 精确绑定，注册名使用 server 与 tool 的组合。
   - 配置中的 server key、`includeTools`/`excludeTools` 也按 server/tool 名称控制发现范围。
   - Caveat：显示名/注册名与远端 MCP 原始 name 的关系不能当作远端身份认证。

10. **结论：工具调用上下文提供 callId、schedulerId、可选 parentCallId、subagent；MCP progress 事件提供 serverName + callId。** **verified**（E1）
    - 官方 `ToolCallContext` 类型明确列出四类字段；`McpProgressPayload` 列出 `serverName`、`callId`、progress token 等。
    - 这是可用于进程内追踪/父子调用关联的结构。
    - Caveat：在本切片看到的是类型/存储接口，不是“每个批准事件、执行请求、远端副作用都必然携带同一个关联键”的端到端证明。

11. **结论：Agent 事件有 streamId、递增 event id、timestamp，且 translator 维护 pending tool name map；这提供事件流内关联，不构成审计不可抵赖链。** **verified + inferred**（E1）
    - `makeEvent` 生成 `${streamId}-${eventCounter++}`，并附 timestamp/streamId；状态有 `pendingToolNames: Map<callId, toolName>`。
    - Inferred caveat：递增 ID/UUID 和内存 map 不是签名、哈希链或外部审计日志；未见策略 hash/version、approval record ID 或 actor principal 被统一写入这些 Agent events。

### D. 身份、授权快照与审计边界

12. **结论：本切片未找到官方证明存在“每次调用的授权快照”。** **unknown**（E1/E2/E3）
    - 找到的是当前内存 `PolicyEngine`（rules、approvalMode、defaultDecision）、MCP trust、进程内 allowlist 和可选持久化 TOML；未找到 per-call immutable decision object，包含调用前规则快照/模式快照/批准者/时间/策略版本。
    - Caveat：`unknown` 仅表示官方公开资料切片未证明，不声称整个仓库绝对不存在其他机制。

13. **结论：本切片未找到官方证明存在策略版本号或策略哈希与调用事件的关联。** **unknown**（E1/E2）
    - `PolicyRule.source` 能标注来源（例如设置/MCP trusted），但不是版本号；事件结构显示 stream/event IDs，未显示 policy version/hash。

14. **结论：本切片未找到工具执行统一、可验证的调用者身份（principal/actor identity）字段。** **unknown**（E1/E2）
    - 有 serverName、subagent、sessionId/streamId、callId 等技术关联字段，也有 MCP OAuth/token provider 说明；但资料没有证明这些字段代表经过远端验证的最终用户/服务账号身份，或在每次工具调用中端到端传递。
    - Caveat：认证 token 的存在不等于 CLI 审批身份、业务主体身份或审计 actor 身份。

15. **结论：官方资料未证明调用者可伪造/重放/跨进程转移身份的防护，也未证明不存在这些风险。** **unknown**（E1/E2）
    - 未找到调用签名、nonce、重放检测、跨进程认证 channel 或 server-side proof-of-possession 的统一规范。
    - Caveat：这是一项“未证明”结论，不能据此断言存在漏洞。

16. **结论：审批持久化有有限证明，但审批者/原始调用上下文的持久化审计关联未被证明。** **verified + unknown**（E3/E2）
    - verified：trustedFolders.json、auto-saved policy TOML 和“Allow for all future sessions”的规则传播均有官方资料支持。
    - unknown：未看到保存批准者、审批 UI 事件 ID、原始 args、当时策略版本、server auth principal，并在未来实际调用时强绑定校验。

### E. 效果、远端提交、回滚、exactly-once

17. **结论：工具“被允许/被调用”不等于业务效果、远端提交或回滚成功。** **verified + unknown**（E2/E1）
    - MCP 架构支持 stdio、SSE、Streamable HTTP，并调用 MCP server；文档描述的是 discovery/call/response 与确认逻辑。
    - 未找到官方端到端保证业务事务提交、远端写入成功、自动回滚或补偿语义。

18. **结论：本切片未找到 exactly-once 执行保证。** **unknown**（E1/E2/E3）
    - 可见的是 abort signal、超时/连接状态、错误返回、事件 callId 等控制/观察结构；这些不等于远端幂等键、提交序列号或 exactly-once 协议。
    - 因此不能把“单次工具调用完成”解释为“单次业务效果已且仅已发生”。

## 最小结论

官方实现清楚证明了**执行前**的 CLI 边界：folder trust 影响项目配置/MCP 连接，MCP `trust` 与 allowlist 影响确认，policy engine 按 server/tool/args/mode 计算 allow/deny/ask_user，Plan/YOLO 改变模式。实现也提供 `serverName`、tool name、args、callId、scheduler/parent/subagent、stream/event id 等**技术关联字段**。

但在本片规定的窄主题内，公开官方资料没有证明一个跨审批、策略、进程、MCP 传输和业务副作用的**不可变授权快照 + 策略版本 + 验证调用者身份 + 端到端审计关联**模型；同样没有证明伪造/重放防护、审批者持久化、业务提交/回滚或 exactly-once。应将这些项目标为 unknown，而不是从 CLI 的一次 allow/execute 或一个 callId 推导出来。
