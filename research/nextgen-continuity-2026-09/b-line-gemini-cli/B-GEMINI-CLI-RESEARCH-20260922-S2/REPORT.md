# Gemini CLI 官方一手资料研究切片 S2

- 研究时间：2026-09-22（Asia/Shanghai）；资料从 `main` 分支官方 raw/API 端点读取。
- 研究问题：Gemini CLI 的 policy engine、Plan Mode 规划工具权限边界、MCP allowlist/denylist/trust、环境变量/凭据泄露边界、工具超时/连接失败/恢复语义，以及 Model Steering 对任务生命周期和人工干预的影响是什么？
- 证据边界：只使用 `google-gemini/gemini-cli` 官方 GitHub 仓库文档/API；未访问私有数据、真实服务或受保护目录；未运行 Gemini CLI，也未对生产环境或 exactly-once 语义作验证。

## 结论（按证据等级）

1. **Verified（官方文档直接支持）**：Plan Mode 是只读研究/设计环境；其工具集合明确限于文件系统读、搜索、只读 MCP/资源、交互和规划写入（仅计划目录的 Markdown）。`enter_plan_mode` 切换并要求确认；`exit_plan_mode` 要求计划路径位于临时 plans 目录、经正式审核后才切换到实现模式。
2. **Verified**：policy engine 对工具调用按匹配规则决定 `allow`、`deny` 或 `ask_user`，高 priority 规则胜出；`deny` 对无 `argsPattern` 的全局规则会把工具从模型记忆中排除；非交互模式下 `ask_user` 按 deny 处理。MCP 策略推荐 `mcpName`，可按单工具、服务器或所有 MCP 服务器配置。
3. **Verified**：MCP 服务器侧有两层工具暴露边界：全局 `mcp.allowed`/`mcp.excluded` 控制可连接服务器；服务器级 `includeTools` 是 allowlist，`excludeTools` 是 denylist，后者优先。`trust: true` 绕过该服务器的工具调用确认；文档还描述单次、工具级永久、服务器级永久授权选项。trust 是确认绕过语义，不等于服务器安全或最小权限保证。
4. **Verified**：MCP 连接支持 stdio、SSE、Streamable HTTP；请求 timeout 默认 600,000 ms（10 分钟，服务器配置示例及 reference 明示）。发现阶段连接失败会记录并设为 `DISCONNECTED`；成功发现工具的服务器保持持久连接；没有可用工具的服务器连接会清理。官方公开文档描述了状态/诊断/手动重试 OAuth 连接，但没有承诺通用自动重连、指数退避、幂等或 exactly-once。
5. **Verified**：环境变量加载 `.env` 有明确搜索顺序；执行工具时对继承环境和 `.env` 变量做“best effort”秘密脱敏，按名称/值模式识别 token、secret、password、key、auth、credential、private/cert 等；MCP `env` 显式配置是用户对特定服务器的明示共享，自动脱敏不再保护这些显式变量。未定义变量在 MCP env 展开为空字符串。该边界降低意外泄露风险，但不构成秘密不出站的保证。
6. **Verified**：Model Steering 是实验性、默认关闭（文档当前描述），开启后，agent 工作 spinner 可输入文字并 Enter；CLI 先用小模型生成一句确认，再把提示注入主模型下一轮上下文，要求重新评估当前计划并对受影响任务做最小差异调整。它改变正在执行任务的下一轮决策，且不是回滚、事务或取消当前已发出的工具调用机制。
7. **Inferred（基于文档机制的受限推断）**：严格 Plan Mode + 默认 `ask_user` + MCP include/exclude + policy deny 可以组成“研究阶段最小暴露面”；但只要用户在 Plan Mode 主动授予长期信任，该信任按官方文档会覆盖当前及更宽松模式，因而需要把计划模式授权视作高影响安全决策。
8. **Unknown**：官方文档没有给出通用工具调用的重试次数、重试条件、连接断开后的自动恢复算法、重复调用去重、提交语义、故障中断后的状态恢复或 exactly-once 保证；也没有以独立测量证明“脱敏”覆盖所有秘密形态。不能将上述机制描述为 production verified。

## 证据台账

### C1 — Plan Mode 的规划权限边界
- **状态：verified / high（primary，规范/产品文档）**
- `docs/cli/plan-mode.md` 明确称 Plan Mode 为 read-only environment；只允许 FileSystem read、Search、Research Subagents、Interaction、只读 MCP/资源、Planning write。规划写操作限于临时 plans/custom plans 目录的 `.md` 文件（文档同时说明自定义 plans 目录）。
- 直接边界：写入普通项目文件、一般 shell、非只读工具不在列出的允许集合中；默认只读策略由 policy engine 的内置 `plan.toml` 执行。
- caveat：这是官方说明的设计/配置语义；本切片没有运行 CLI 逐工具实测。

### C2 — `enter_plan_mode` / `exit_plan_mode` 与人工审批
- **状态：verified / high**
- `docs/tools/planning.md`：enter 工具切换到 PLAN 并提示用户确认；exit 工具要求 `plan_path` 在项目临时 plans 目录且文件存在有内容，展示最终计划并要求正式审批。批准后才切换到 DEFAULT/AUTO_EDIT（按用户选择）并标记可实施；拒绝则留在 Plan Mode，反馈返回模型。
- `plan-mode.md` 补充：自然语言可触发 `enter_plan_mode`；YOLO 不提供该工具；正式计划前应先在人机对话中达成非正式一致。
- caveat：文档没有给出计划审核的持久化、崩溃恢复或审批事件的 exactly-once 语义。

### C3 — Policy engine 决策、优先级与模式
- **状态：verified / high**
- `docs/reference/policy-engine.md`：匹配条件包括 toolName/参数正则/interactive 等；决策为 allow、deny、ask_user；高 priority 匹配规则决定结果。`ask_user` 在非交互模式按 deny 处理；无 argsPattern 的全局 deny 会从模型记忆中排除被拒工具。
- 模式为 default、autoEdit、plan、yolo；无 modes 的规则一直生效。官方说明持久授权沿 `plan < default < autoEdit < yolo` 传播：Plan 中授予的授权包含所有模式；其它模式只向更宽松模式传播。
- **官方文本内部冲突（conflicting / high）**：同一 policy 文档的 tier 表写 Default=1、Extension=2、Workspace=3、User=4、Admin=5，并称 Workspace disabled；但其随后示例把 Workspace 计算为 2.010、User 3.100、Admin 4.020，且文字称 Admin Base 4。此处不能推断实际实现优先级；应以当前代码/测试或修订后的文档核验。

### C4 — MCP 服务器/工具 allowlist、denylist 与 trust
- **状态：verified / high**
- `docs/tools/mcp-server.md` 与 `docs/reference/configuration.md`：`mcp.allowed` 设置后仅连接列表中的服务器；`mcp.excluded` 排除服务器。服务器定义支持 `includeTools`（仅列出的工具可用）与 `excludeTools`（始终不可用，优先于 includeTools）。
- `trust` 为 boolean，true 时绕过该服务器所有工具调用确认，默认 false。非 trusted 服务器在调用时可“proceed once / always allow this tool / always allow this server / cancel”。扩展和本地配置合并时，exclude union、include intersection、exclude 优先，官方称“最严格策略胜出”。
- policy engine 还支持 `mcpName`：按单工具、整服务器或 `mcpName="*"` 全 MCP 服务器设置 allow/deny/ask_user；推荐用 `mcpName` 而非手写 FQN wildcard。服务器别名不得含下划线，否则策略解析可能静默失效。

### C5 — 环境变量与凭据泄露边界
- **状态：verified / high（但保护强度受限）**
- `docs/tools/mcp-server.md`：MCP env 支持 `$VAR`、`${VAR}`（跨平台）及 Windows `%VAR%`；未定义变量为空字符串。显式 env 变量被视为用户明示信任，不受自动 redaction；文档建议不要硬编码 secret，而用运行时展开。
- 同文档：继承主机环境默认脱敏核心项目 key 及名称匹配 `TOKEN/SECRET/PASSWORD/KEY/AUTH/CREDENTIAL` 和证书/私钥模式；明确传给 MCP 的变量是例外。
- `docs/reference/configuration.md`：`.env` 查找为 cwd → 父目录至项目 root/home → `~/.env`；执行工具时按名称和已知 secret 值模式做 best-effort redaction，常见系统变量和 `GEMINI_CLI_` 前缀为允许示例；可配置 allowed/blocked 环境变量。`security.environmentVariableRedaction.enabled` 在该 reference 的设置表中默认 false，与正文“automatically redacts”措辞存在需要版本/实现核对的表述张力，不能据此宣称默认保护在所有安装中开启。
- 结论边界：显式 MCP env、命令行参数、工具输出、服务器自身日志、未识别的新秘密格式不被文档承诺完全阻断；不是秘密零泄露保证。

### C6 — MCP 超时、连接失败、状态与恢复
- **状态：verified / high（恢复部分 limited）**
- `mcp-server.md`：每服务器 timeout 默认 600,000ms；发现流程连接时使用配置 timeout，失败记录并标记 DISCONNECTED；成功注册工具则保持持久连接，无可用工具则清理。状态为 CONNECTING/CONNECTED/DISCONNECTED，发现状态为 NOT_STARTED/IN_PROGRESS/COMPLETED（即便有错误）。
- 诊断：启动后台服务器的连接错误默认静默，出现问题时提示 `/mcp list`；交互命令、模型尝试调用或 MCP prompt 会重新启用详细诊断；`gemini mcp list` 可查看连接错误。文档给出手动检查配置、日志、权限、依赖和提高 timeout 的建议。
- OAuth 是特例：初始 401 → 发现 OAuth → 浏览器认证 → 交换 token → 安全存储 → connection retry；这只证明 OAuth 流程中的一次重试路径，不是所有 MCP 断线的自动重连协议。
- unknown：未找到通用重试/退避/断线恢复、工具执行失败后的自动重试、调用去重、事务回滚、exactly-once 或 at-least-once 语义。

### C7 — Model Steering 与任务生命周期/人工干预
- **状态：verified / high（experimental）**
- `docs/cli/model-steering.md`：功能 experimental、默认关闭，可能需要 `/settings` 或 `experimental.modelSteering=true`。agent 工作时输入的文字作为 steering hint，Enter 提交；小模型立即生成一句确认，主模型下一轮收到注入的内部指令，重新评估活动计划、分类更新并对受影响任务最小差异调整。
- 影响：人工能在运行中纠偏、补上下文、跳过步骤、重定向工作或消除歧义，不必停止并重启；但是文档只说“next turn”，不说当前正在执行的工具会被取消，也不说已发生副作用会撤销。因此“实时”应理解为下一轮决策边界，而非强制抢占/事务中断。
- unknown：确认小模型、主模型各自失败时如何恢复；hint 排队、并发工具、重复 hint、取消与审计日志语义，官方页面未说明。

## 对任务安全边界的综合判断

- 可直接采用的官方事实：Plan Mode 只读工具集合；policy 高优先级匹配；MCP server/tool 双层 allow/deny；trust 绕过确认；环境变量显式注入会突破自动脱敏；超时/状态/诊断；steering 在下一轮注入。
- 可作为配置推论（inferred）而非已证实效果：对不可信 MCP 使用 `mcp.allowed` + `includeTools` + policy 的 `mcpName` deny/ask_user，保持 `trust=false`，并对凭据只使用显式、最小范围 env；在 Plan Mode 避免授予持久授权。
- 禁止外推：这些文档未测量安全效果，未验证真实生产部署、故障恢复、幂等或 exactly-once；不能把“持久连接”“OAuth connection retry”改写成普遍自动重连，也不能把 redaction 改写成零泄露。

## 未解决缺口

1. Policy tier 文档内部的基数/示例冲突；需要官方源码/测试或修订文档核验。
2. `security.environmentVariableRedaction.enabled` 的 reference 默认值与正文自动脱敏叙述需按具体版本源码核验。
3. 未发现通用 MCP 工具调用重试、退避、断线自动重连、重复调用去重、取消/回滚和 exactly-once 规范。
4. 未发现 Plan Mode / Model Steering 的崩溃恢复、审批审计、并发工具抢占及人工 hint 排队语义。
5. 未运行 CLI；本包是文档证据切片，不是部署/生产验证。
