# Sources — Gemini CLI S6

固定官方 commit：`d5b3e3accb26000d273abf16e0f1dd83aa5428a9`，访问日期 2026-09-22。

1. https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/tools/shell.ts — shell AbortSignal、进程终止、超时。
2. https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/tools/shell.test.ts — SIGTERM/SIGKILL 与取消测试。
3. https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/tools/mcp-client.ts — MCP 调用取消/超时路径。
4. https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/core/geminiChat.ts — 工具响应历史、dangling response 修复与流处理。
5. https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/core/geminiChat.test.ts — resume、取消和历史行为测试。
6. https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/utils/checkpointUtils.ts — checkpoint 数据与失败处理。
7. https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/utils/checkpointUtils.test.ts — checkpoint 测试边界。
8. https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/cli/checkpointing.md — restore 恢复对象和重新提出工具调用。

官方源码/测试证据不覆盖真实远端服务状态、崩溃后副作用查询、跨重启幂等、远端回滚或 exactly-once；这些保持 unknown。
