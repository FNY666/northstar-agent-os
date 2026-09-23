# S19 官方来源清单

研究仅使用 Google Gemini CLI 官方文档与官方 GitHub 仓库源码/测试。访问日期：2026-09-22。源码引用固定至 commit `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`。

## 官方文档

1. **Checkpointing** — Google Gemini CLI 官方文档
   - URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/cli/checkpointing.md
   - 支持：checkpoint 的触发条件、shadow Git、会话历史/工具调用保存、`/restore` 的恢复与 re-propose、默认关闭。
   - 读取行：1–35、37–63、73–95。

2. **Manage sessions and history** — Google Gemini CLI 官方文档
   - URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/cli/tutorials/session-management.md
   - 支持：`--resume`/`-r`、`/resume`、会话浏览/删除、`/exit --delete`、rewind/fork 语义。
   - 读取行：12–42、46–75、77–110。

3. **Settings reference** — Google Gemini CLI 官方文档
   - URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/cli/settings.md
   - 支持：`general.sessionRetention.enabled` 默认 true、`maxAge` 默认 `30d`；retry fetch errors 与 max attempts 为一般网络重试设置，不等同工具调用恢复。
   - 读取行：约 33–44。

## 官方 GitHub 源码

4. **ChatRecordingService** — Google Gemini CLI
   - URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/services/chatRecordingService.ts
   - 支持：JSONL 初始化/恢复、逐条 append、不可读文件 fallback 与 temp+rename、tool call 记录合并、删除 session artifacts、rewind。
   - 关键实现：`appendRecord`、`rewriteConversationFile`、`recordToolCalls`、`recordCompletedToolCalls`、`rewindTo`。

5. **Chat recording types** — Google Gemini CLI
   - URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/services/chatRecordingTypes.ts
   - 支持：`ToolCallRecord` 字段（`result?`、`status`、timestamp 等）、conversation record 与 JSONL/session 常量。

6. **Checkpoint utilities** — Google Gemini CLI
   - URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/utils/checkpointUtils.ts
   - 支持：checkpoint 数据 schema、Git snapshot、client/history、tool call、message ID；缺少 `file_path` 时不创建可恢复工具调用。

7. **Session cleanup** — Google Gemini CLI
   - URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/cli/src/utils/sessionCleanup.ts
   - 支持：启动清理入口、配置校验、扫描、损坏文件删除、年龄/数量 retention、当前会话排除、关联 artifacts 清理。

8. **Scheduler types** — Google Gemini CLI
   - URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/scheduler/types.ts
   - 支持：`validating`、`scheduled`、`executing`、`awaiting_approval`、`success`、`error`、`cancelled` 状态及工具调用请求字段。

## 官方测试

9. **Checkpoint utilities tests**
   - URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/utils/checkpointUtils.test.ts
   - 支持：checkpoint schema、Git snapshot fallback、缺少 file_path 跳过、messageId 解析。

10. **Chat recording service tests**
    - URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/services/chatRecordingService.test.ts
    - 支持：工具调用状态/字段写入、同一 message 中合并、agentId 记录、session 删除 artifacts。

11. **Session cleanup unit tests**
    - URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/cli/src/utils/sessionCleanup.test.ts
    - 支持：maxAge/maxCount 校验与删除、当前会话保留、损坏文件删除、最小 retention 限制等。

12. **Session cleanup integration tests**
    - URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/cli/src/utils/sessionCleanup.integration.test.ts
    - 支持：不存在目录不阻断启动、disabled 不扫描、无效配置 graceful handling、旧/新/当前会话删除结果、子代理清理。

## 明确未作为证据的内容

- 未使用第三方文章、issue 评论、搜索摘要或非 Google 来源。
- 未访问真实服务、账户、凭据或运行态数据。
- 未将一般 HTTP/model retry 设置解释为工具副作用恢复或 exactly-once。
- 未发现并因此未声称官方已证明 power-loss durability、自动 dangling-call replay、远端回滚、去重或生产验证。
