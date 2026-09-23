# B线独立公开研究：Gemini CLI 任务生命周期、权限边界、审计与失败恢复

- 研究目录：`/tmp/B-GEMINI-CLI-RESEARCH-20260922/`
- 研究对象：Google Gemini CLI（官方仓库 main 分支文档）
- 访问日期：2026-09-22
- 证据范围：仅官方一手资料；未访问 Northstar、shared/P0、事故目录、D10/L12/D14、canonical、140、tri-line、systemd、凭据或真实服务。

## 结论摘要

### 1. 任务生命周期分层清楚，但“计划完成”不等于“副作用完成”

官方 Plan Mode 是只读的规划环境。文档明确列出其允许工具主要是文件读取、搜索、只读 MCP、研究子代理和用户交互；写入仅允许计划目录中的 Markdown。计划流程包括：读取/研究、讨论策略、生成 Markdown 计划、用户正式批准、进入实现。Plan Mode 会在实现前等待确认，而不是把模型提出的计划视为授权。

迁移原则：Northstar 可以把任务拆成 `RESEARCH → PLAN_DRAFT → HUMAN_APPROVAL → EXECUTE → VERIFY`，并把“计划文件存在”“用户批准”“工具调用返回”分别建模，不能合并为一个 completed 状态。

### 2. Gemini 的 checkpoint 是本地文件恢复边界

官方 checkpointing 文档说明：在 AI 工具获准修改文件系统前，CLI 可以创建 checkpoint。checkpoint 包含：

- shadow Git repository 中的项目快照；
- 到该工具调用前的会话历史；
- 即将执行的具体 tool call。

`/restore` 会恢复项目文件与会话历史，并重新提出原始工具调用。该功能默认关闭，需在 settings 中启用；官方明确说明数据保存在本机。

关键边界：这是**本地工作区和会话状态恢复**，不是外部 API、数据库、远程主机或其他工具副作用的回滚证明。恢复后重新提出原始 tool call 也不是 exactly-once 证明，反而要求外部操作具备幂等键、目标侧 read-back 或补偿机制。

### 3. 信任目录、沙箱、批准模式、工具信任是不同闸门

官方资料把以下机制分开：

- trusted folder：工作目录是否被用户信任；
- sandbox：命令/工具在哪种隔离环境中运行；
- approval mode：Default、Auto-Edit、Plan、YOLO 等批准行为；
- MCP server `trust`：是否绕过该 MCP server 的工具调用确认；
- `includeTools`/`excludeTools`：MCP 工具允许列表和排除列表；
- Plan Mode policy：规划阶段默认只读工具限制；
- checkpointing：修改前的本地恢复快照。

这些机制不能相互替代。例如 sandbox 只能限制执行环境，不证明业务目标状态；MCP `trust=true` 只表示跳过调用确认，不表示工具结果可信；trusted folder 不等同于所有文件操作都安全。

### 4. MCP 是能力扩展面，也是权限和供应链边界

官方 MCP 文档说明 Gemini CLI 会发现 server 的 tools/resources，并通过 stdio、SSE 或 Streamable HTTP 连接。server 配置支持：

- `allowed`/`excluded` server 名称；
- `includeTools`/`excludeTools` 工具列表，且 exclude 优先；
- `trust` 绕过该 server 的全部工具确认；
- request timeout；
- cwd、headers、env；
- OAuth 远程 server；
- 目标 audience 和 service account impersonation 配置。

官方还说明，启动 MCP server 时会默认清理继承环境中的敏感变量，例如 `*TOKEN*`、`*SECRET*`、`*PASSWORD*`、`*KEY*`、`*AUTH*`、`*CREDENTIAL*` 等；只有用户显式在 server `env` 中配置的变量才会被传递。即使如此，文档建议仍使用 `$VAR` 引用，不要把秘密硬编码进配置。

迁移原则：Northstar 的外部工具注册表应保存 `server_id`、transport、allowed/excluded 工具、trust 状态、timeout、audience、explicit_env_names 和 policy revision；不得把“工具发现成功”当作工具被授权或其结果可信。

### 5. 遥测是可观察性，不是业务审计

官方 telemetry 文档说明 Gemini CLI 支持 OpenTelemetry 的 logs、metrics、traces，可导出到本地文件、OTLP collector 或 Google Cloud。配置包括 enabled、traces、target、endpoint、outfile、是否记录 prompt 等。遥测默认关闭，且 prompt logging 是敏感信息边界。

可迁移的审计字段包括：session、task、tool、model、latency、error、trace/span 关联。结论仍必须保持：遥测能帮助定位执行过程，但不能单独证明资源副作用、授权有效性、目标最终状态或回滚完成。需要独立 receipt、资源 read-back、postcondition 和对账。

### 6. 模型 steering 是实时控制输入，不是授权变更

官方 model steering 文档说明：该实验功能允许 agent 正在执行时接收用户文字提示，并在下一轮上下文中重新评估计划。它会先产生确认，再注入上下文；功能默认关闭，需 settings 启用。

迁移原则：steering 应被建模为新的控制事件（`STEER_RECEIVED`/`PLAN_REEVALUATED`），而不是静默改写原始授权。已经执行的副作用不能因为后续 steering 被模型重新解释而自动回滚。

## 对 Northstar 的可迁移控制面模型

```text
TASK_ACCEPTED
  -> PLAN_READ_ONLY
  -> PLAN_APPROVAL_REQUIRED
  -> TOOL_AUTHORIZED
  -> TOOL_DISPATCHED
  -> TOOL_RETURNED
  -> POSTCONDITION_READBACK
  -> RECONCILED
```

附加约束：

1. `PLAN_APPROVED` 不能直接推出 `TOOL_EFFECT_VERIFIED`；
2. checkpoint/restore 只恢复本地工作区，外部副作用必须走幂等/对账；
3. trust、sandbox、scope、audience、approval、postcondition 是独立字段；
4. MCP server 的显式环境变量必须记录为授权事实，并尽量只传变量名/引用，不落盘秘密值；
5. steering、cancel、retry、restore 都必须留下事件，而不是覆盖原状态；
6. telemetry 与业务 receipt 分离；
7. 没有独立 read-back 时，最终状态保持 `UNKNOWN_NEEDS_RECONCILE`。

## 证据等级

### verified（官方文档直接支持）

- Plan Mode 是只读规划环境并限制工具；
- Plan Mode 在正式批准前等待用户确认；
- checkpoint 保存本地 shadow Git 快照、会话历史和 tool call；
- restore 会恢复本地文件/会话并重新提出原始调用；
- MCP 支持多种 transport、server allow/exclude、tool include/exclude、trust 和 timeout；
- MCP 默认清理继承环境中的敏感变量，显式 env 才传递；
- Gemini CLI 支持 OpenTelemetry telemetry；
- model steering 是实验性、实时的上下文控制输入。

### inferred（由官方边界推导）

- checkpoint 不能证明外部副作用回滚；
- telemetry 不能独立证明业务 postcondition；
- trust/sandbox/approval 不等价于结果真实性；
- steering/cancel/restore/retry 应作为不可覆盖的控制事件；
- MCP server 应以 capability grant 方式审计，而不是只记录发现结果。

### unknown / not proven

- Gemini CLI 外部副作用 exactly-once；
- checkpoint 与远程 API、数据库、远程主机状态的一致回滚；
- telemetry 是否覆盖所有工具副作用；
- MCP server 是否诚实返回结果；
- Northstar 是否已实现上述分层。

## 一手来源

- https://github.com/google-gemini/gemini-cli
- https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/plan-mode.md
- https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/checkpointing.md
- https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/session-management.md
- https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/sandbox.md
- https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/trusted-folders.md
- https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/telemetry.md
- https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/headless.md
- https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/settings.md
- https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/tools/mcp-server.md
- https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/model-steering.md

production_verified=false
synthetic_only=false
