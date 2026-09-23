# S15 官方来源索引

所有来源均为 `google-gemini/gemini-cli` 官方 GitHub 公开仓库，访问时间 2026-09-22；URL 为 exact raw 或 GitHub 文件 URL。

| ID | Exact URL | 类型/证据等级 | 支持内容 |
|---|---|---|---|
| S1 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/checkpointing.md | 官方文档 / A | checkpoint 内容、restore 语义、文件快照与 tool call re-propose |
| S2 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/session-management.md | 官方文档 / A | session 自动保存、tool executions 记录、resume、保留策略 |
| S3 | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/utils/retry.ts | 官方源码 / A | retry 判定、默认次数、backoff/jitter、AbortSignal、无可见幂等键/远端 read-back |
| S4 | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/utils/retry.test.ts | 官方测试 / A | 重试次数、成功/失败、400/429、maxDelay/jitter |
| S5 | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/core/geminiChat_network_retry.test.ts | 官方测试 / A | 流已有片段后 503 retry；fetch error 配置；400 不重试 |
| S6 | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/integration-tests/checkpointing.test.ts | 官方集成测试 / A | snapshot/restore 文件状态验证 |
| S7 | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/integration-tests/resume-gc.test.ts | 官方集成测试 / A | resume 后上下文 GC 与继续对话响应 |
| S8 | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/services/shellExecutionService.ts | 官方源码 / A | abort handler 调用 killProcessGroup；kill() 清理/终止 |
| S9 | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/services/shellExecutionService.test.ts | 官方测试 / A | mock 下 SIGTERM→SIGKILL、aborted、PTY destroy、监听器清理 |
| S10 | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/tools/shellBackgroundTools.test.ts | 官方测试 / A | 后台进程历史/日志/kill 行为（mock 及状态记录） |
| S11 | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/scheduler/tool-executor.ts | 官方源码 / A | tool cancellation 分支与 aborted 响应；不证明外部副作用终止 |
| S12 | https://api.github.com/repos/google-gemini/gemini-cli/git/trees/main?recursive=1 | 官方 API / B | 首轮窄范围路径定位；未下载仓库 |

## 关键定位

- `retry.ts`：`DEFAULT_MAX_ATTEMPTS = 10`；`isRetryableError`；`retryWithBackoff`；`throwIfAborted`；指数退避与 signal-aware `delay`。
- `geminiChat_network_retry.test.ts`：`First part` → 503 → `RETRY` → `Retry success`。
- `shellExecutionService.ts`：child/PTY abort handler 的 `killProcessGroup({ ..., escalate: true })`；`kill(pid)` 调用 `ExecutionLifecycleService.kill`。
- `shellExecutionService.test.ts`：Aborting Commands 段落（约 679 行起）及 PTY kill/abort 段落（约 1215 行起）。
- checkpointing 文档：checkpoint 在文件修改前保存 shadow Git、conversation history、tool call；restore re-propose 原 tool call。

## Caveat

URL 指向 `main`，随官方仓库更新可能发生内容漂移；报告结论是基于取证时看到的公开内容。未对 GitHub 之外的服务端实现、真实子进程或真实外部资源进行验证。
