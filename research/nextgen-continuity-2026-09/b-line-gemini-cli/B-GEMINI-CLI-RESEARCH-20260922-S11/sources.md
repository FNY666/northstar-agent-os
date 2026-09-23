# S11 官方来源清单

所有来源均为公开官方 GitHub（`google-gemini/gemini-cli`）文档、源码或测试；访问日期：2026-09-22。行号对应当日抓取内容/源码结构，URL 为 exact URL（未使用搜索引擎或第三方镜像）。

| ID | Exact URL | 类型/证据等级 | 用途与关键证据 | Caveat |
|---|---|---|---|---|
| S11-01 | https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/policy-engine.md | 官方文档 E2 | policy 条件、allow/deny/ask_user、优先级、approval modes、持久批准传播、workspace 警告 | `main` 可变；文档内部有 workspace policy 表述冲突 |
| S11-02 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/trusted-folders.md | 官方文档 E2 | trusted folder、`trustedFolders.json`、不可信目录限制、MCP 不连接、headless bypass | 是 CLI 配置/会话门控，不是远端 principal 证明 |
| S11-03 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/plan-mode.md | 官方文档 E2 | Plan 只读工具集合、Plan/YOLO 进入方式、策略自定义与 mode-specific approval | 文档描述不等于端到端业务效果保证 |
| S11-04 | https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md | 官方文档 E2 | MCP discovery/execution、server `trust`、server/tool allow-exclude、传输与 OAuth 概述 | OAuth 认证存在不等于调用审计 actor/execution proof |
| S11-05 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/cli-reference.md | 官方文档 E2 | `--approval-mode`、`--skip-trust`、`--allowed-mcp-server-names` | CLI 参数语义，不是远端授权协议 |
| S11-06 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/tools/mcp-tool.ts | 官方源码 E1 | `serverName`/`serverToolName`/params、MCP policy update options、trusted-folder + trust confirmation gate、server/tool in-process allowlist、callTool args | 源码位于 `main`；未见 per-call auth snapshot |
| S11-07 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/policy/types.ts | 官方源码 E1 | `PolicyDecision`、`ApprovalMode`、`PolicyRule` 的 mcpName/toolName/argsPattern/annotations/source | 类型定义不单独证明所有运行时路径 |
| S11-08 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/policy/policy-engine.ts | 官方源码 E1 | mode/subagent/mcpName/toolName/annotations/args/interactive 匹配与信任目录/YOLO shell heuristics | policy 判定是 CLI 内部结果 |
| S11-09 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/policy/persistence.test.ts | 官方测试 E3 | `persist=true` 写入/追加 auto-saved TOML；无 persist 不写；argsPattern/mcpName 持久化覆盖 | 测试证明 persistence 行为，不证明审批者/版本审计 |
| S11-10 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/utils/toolCallContext.ts | 官方源码 E1 | `callId`、`schedulerId`、`parentCallId`、`subagent` 与 AsyncLocalStorage | 上下文结构不证明跨进程或远端传递 |
| S11-11 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/utils/events.ts | 官方源码 E1 | MCP progress 的 `serverName` + `callId`、approval/session event 类型 | 事件接口不等于不可抵赖审计日志 |
| S11-12 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/agent/event-translator.ts | 官方源码 E1 | streamId、递增事件 ID、timestamp、pending callId→toolName map | 内存关联不是签名/哈希链 |
| S11-13 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/telemetry/tool-call-decision.ts | 官方源码 E1 | confirmation outcome → ACCEPT/REJECT/MODIFY/AUTO_ACCEPT 映射 | 仅决策分类，不含统一 actor/principal 或 policy version |
| S11-14 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/policy/persistence.test.ts | 官方测试 E3 | 再次用于持久审批字段测试；列出以便复核测试断言 | 同一 exact source 的不同断言 |

## 关键源码/文档摘录索引（便于快速复核）

- S11-01：`Decision`、`Tool Name`/`argsPattern`、`Approval modes`、持久审批 mode hierarchy。
- S11-02：信任选择写入 `~/.gemini/trustedFolders.json`；不可信目录不连 MCP；`--skip-trust`/环境变量旁路。
- S11-04：`trust: true` 绕过该 server 工具确认；`includeTools`/`excludeTools`；OAuth 2.0 章节。
- S11-06：`getConfirmationDetails()` 的 `isTrustedFolder() && this.trust`；confirmation details 的 server/tool/args；`callTool([{name,args}])`。
- S11-08：`ruleMatches()` 严格 mcpName、工具名/FQN、稳定 JSON args、mode、interactive。
- S11-09：`persist` 为 true 写 `auto-saved.toml`，false/undefined 不写。
- S11-10/11/12：调用与事件的技术关联字段，但未出现授权快照/策略版本/审计 actor。
