# S4 官方一手来源

固定仓库基线：`https://github.com/google-gemini/gemini-cli/tree/d5b3e3accb26000d273abf16e0f1dd83aa5428a9`

| ID | Exact URL | 类型/等级 | 用途 |
|---|---|---|---|
| S1 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/cli/plan-mode.md | 官方 docs / B | Plan Mode 只读限制、计划批准/迭代/取消、YOLO 不可用、policy 自定义 caveat |
| S2 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/reference/policy-engine.md | 官方 docs / B | allow/deny/ask_user、优先级 tier、Workspace 非功能、approval modes |
| S3 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/cli/trusted-folders.md | 官方 docs / B | untrusted folder 能力边界、MCP 不连接、headless fatal/skip-trust |
| S4 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/cli/checkpointing.md | 官方 docs / B | shadow Git checkpoint、会话历史、restore、默认关闭及回滚 caveat |
| S5 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/cli/telemetry.md | 官方 docs / B | OTel logs/metrics/traces、默认关闭、local/GCP 输出、prompt logging |
| S6 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/scheduler/types.ts | 官方源码 / A | 完整 CoreToolCallStatus、终态类型、response/duration/approval 字段 |
| S7 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/scheduler/scheduler.ts | 官方源码 / A | validating/approval、scheduled、execute、terminalize、AbortSignal、并行/等待 |
| S8 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/scheduler/state-manager.ts | 官方源码 / A | active/queue/completed、cancelAllQueued、terminal statuses、MessageBus snapshot、partial output |
| S9 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policies/plan.toml | 官方 policy / A | Plan Mode catch-all deny、read-only allow、plan markdown 例外写入 |
| S10 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policies/yolo.toml | 官方 policy / A | YOLO allow-all、ask_user 保留、Plan 转换 deny |
| S11 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policies/read-only.toml | 官方 policy / A | 只读工具和 complete_task allow |
| S12 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/tools/mcp-tool.ts | 官方源码 / A | MCP trust + folder trust、session allowlist、AbortError race |
| S13 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/tools/mcp-client-manager.ts | 官方源码 / A | admin MCP allow/block、用户 session/file enablement |
| S14 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/tools/mcp-client.ts | 官方源码 / A | MCP 默认 10 分钟 timeout、配置覆盖与 discovery |
| S15 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/tools/shell.ts | 官方源码 / A | shell inactivity timeout、AbortSignal、超时用户可见消息 |
| S16 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/services/shellExecutionService.ts | 官方源码 / A | abort 终止进程组、kill 生命周期 |
| S17 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/utils/retry.ts | 官方源码 / A | retry 分类、最大尝试、429/5xx/network、abort、backoff/fallback |
| S18 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/utils/checkpointUtils.ts | 官方源码 / A | snapshot、history、tool call、commit hash、失败降级记录 |
| S19 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/scheduler/scheduler.test.ts | 官方测试 / A | abort 后 cancelled、队列取消、审批中 abort |
| S20 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/scheduler/tool-executor.test.ts | 官方测试 / A | cancelled response、partial output |
| S21 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/services/shellExecutionService.test.ts | 官方测试 / A | abort 时 SIGTERM 后 SIGKILL |
| S22 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/tools/mcp-client.test.ts | 官方测试 / A | MCP discovery timeout abort/error |
| S23 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/utils/retry.test.ts | 官方测试 / A | retry 行为与 abort 的测试覆盖 |
| S24 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/integration-tests/checkpointing.test.ts | 官方集成测试 / A | checkpoint snapshot/restore |
| S25 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/integration-tests/resume_repro.test.ts | 官方集成测试 / A | session resume regression |
| S26 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/integration-tests/context-fidelity.test.ts | 官方集成测试 / A | resume 上下文再现 |

## 证据取证说明

所有源码/测试均由官方仓库在上述 commit 的 shallow clone 中读取；URL 中固定 commit，便于复核。未采用搜索摘要、博客、第三方文章、Issue 讨论作为证据。对“不可证明”结论，报告明确标为 unknown，而没有把文件存在或测试名称当作行为保证。
