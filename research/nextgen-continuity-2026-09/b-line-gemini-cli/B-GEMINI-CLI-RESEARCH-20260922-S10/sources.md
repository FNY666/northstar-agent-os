# S10 来源清单

固定官方来源版本：`google-gemini/gemini-cli` commit `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`（GitHub API commit date 2026-09-21T20:36:40Z）。以下仅列官方 GitHub 文档、源码、测试；访问时间 2026-09-22。

## 主要来源

1. **Policy engine reference** — <https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/reference/policy-engine.md>  
   等级：`verified`（官方文档，primary）。直接支持 allow/deny/ask_user、最高优先级规则、tier 与 priority、non-interactive ask_user→deny、approval modes；同页明确 Workspace tier 当前 non-functional。
2. **PolicyEngine implementation** — <https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policy-engine.ts>  
   等级：`verified`（官方源码，primary）。直接支持降序 priority、first matching rule、默认 decision、YOLO no-match、shell heuristics、复合命令聚合、路径/build-file/safety-checker 后处理。
3. **Policy types** — <https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/types.ts>  
   等级：`verified`（官方源码，primary）。支持 approval mode 枚举及 permissiveness 顺序、policy decision 类型和配置字段。
4. **YOLO built-in policy** — <https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policies/yolo.toml>  
   等级：`verified`（官方内置策略，primary）。priority 999 ask_user/deny 特例与 priority 998 yolo allow-all。
5. **Plan built-in policy** — <https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policies/plan.toml>  
   等级：`verified`（官方内置策略，primary）。Plan mode 的 catch-all deny、只读 allow/ask 及 enter/exit 规则。
6. **Non-interactive built-in policy** — <https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policies/non-interactive.toml>  
   等级：`verified`（官方内置策略，primary）。non-interactive 对 ask_user 工具的 deny 规则。
7. **Plan Mode documentation** — <https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/cli/plan-mode.md>  
   等级：`verified`（官方文档，primary）。Plan Mode 的只读定位、进入/退出、批准与 Esc 取消流程。
8. **Trusted Folders documentation** — <https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/cli/trusted-folders.md>  
   等级：`verified`（官方文档，primary）。不信任 safe mode：禁用自动接受、MCP 连接等；信任文件及 headless 行为。
9. **Trust implementation** — <https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/utils/trust.ts>  
   等级：`verified`（官方源码，primary）。TrustLevel、env/IDE/file 来源、最长路径匹配及文件持久配置结构。
10. **MCP server documentation** — <https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/tools/mcp-server.md>  
    等级：`verified`（官方文档，primary）。MCP `trust` 配置、server/tool allow-list、Proceed/Cancel、timeout 描述及执行流程。
11. **MCP tool implementation** — <https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/tools/mcp-tool.ts>  
    等级：`verified`（官方源码，primary）。`isTrustedFolder() && trust` confirmation bypass、会话 allowlist、持久 policy update 交由 scheduler、AbortSignal race。
12. **Policy updater tests** — <https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policy-updater.test.ts>  
    等级：`verified`（官方测试，primary）。直接覆盖 UPDATE_POLICY、persist true 写 TOML、MCP mcpName/toolName 持久化，以及 invocation 不直接 publish 的行为。
13. **Policy persistence tests** — <https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/persistence.test.ts>  
    等级：`verified`（官方测试，primary）。覆盖策略文件持久化成功/失败与原子 rename 等边界。
14. **Activity logger implementation** — <https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/cli/src/utils/activityLogger.ts>  
    等级：`verified`（官方源码，primary）。文件日志 entry 的类型为 console/network，并带 sessionId/timestamp；未在核验段落中发现策略/审批生命周期事件字段。
15. **Pinned commit** — <https://github.com/google-gemini/gemini-cli/commit/d5b3e3accb26000d273abf16e0f1dd83aa5428a9>  
    等级：`verified`（官方 GitHub commit metadata，primary）。来源 pin；不表示运行时行为本身。

## 证据状态边界

- 审批请求/拒绝/超时/取消的统一持久审计记录：`unverified/unknown`；已证实的取消仅是 AbortSignal 控制流。
- policy mutation 与单次 tool call 的稳定 correlation ID：`unverified/unknown`；sessionId 不能替代 call ID。
- 审批或策略日志是否代表业务副作用成功、远端提交、回滚、exactly-once：`unverified`；官方来源未作此保证。
- Workspace tier：文档抽象表称可覆盖，但同页明确当前 non-functional；运行事实按该警告处理，标 `conflict`。
