# S13 官方来源清单

研究范围限定为 `google-gemini/gemini-cli` 官方 GitHub 公开文档、源码与测试/API；以下均为 exact URL，访问时间 2026-09-22。

## S01 — Session management 文档
- URL: https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/session-management.md
- Raw: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/session-management.md
- 发布/更新：repository `main`（页面未声明独立发布日期）
- 证据等级：L1 / primary official documentation
- 用途：自动保存内容、tool execution 输入/输出、token usage、存储路径、保留与删除边界。
- Caveat：文档描述产品行为，不在此处证明崩溃尾部、逐行 JSONL schema 或后端交付。

## S02 — Checkpointing 文档
- URL: https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/checkpointing.md
- Raw: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/checkpointing.md
- 发布/更新：repository `main`
- 证据等级：L1 / primary official documentation
- 用途：shadow Git 路径、snapshot、conversation/tool-call checkpoint、restore 行为与启用设置。
- Caveat：文档范围是本地项目/CLI 恢复，不是远端副作用事务。

## S03 — Telemetry 文档
- URL: https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/telemetry.md
- Raw: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/telemetry.md
- 发布/更新：repository `main`
- 证据等级：L1 / primary official documentation
- 用途：trace 默认关闭的详细属性、GenAI span attributes、conversation ID、tool call ID 与 telemetry 设置。
- Caveat：列出字段/配置不等于证明 exporter 后端已收到或永久保存。

## S04 — Policy engine 文档
- URL: https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/policy-engine.md
- Raw: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/reference/policy-engine.md
- 发布/更新：repository `main`
- 证据等级：L1 / primary official documentation
- 用途：规则、优先级、approval modes、持久批准的模式语义。
- Caveat：规则语义不能反推出某次运行的完整规则文件版本或授权主体快照。

## S05 — Checkpoint utility 源码
- URL: https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/utils/checkpointUtils.ts
- Raw: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/utils/checkpointUtils.ts
- 发布/更新：repository `main`
- 证据等级：L2 / primary official source
- 用途：`ToolCallData`、`commitHash`、`messageId`、checkpoint 文件、tool call→checkpoint 映射、snapshot 失败 fallback 与缺少 file_path 行为。
- Caveat：源码结构证明实现边界，不证明每次运行 snapshot 成功。

## S06 — Scheduler types 源码
- URL: https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/scheduler/types.ts
- Raw: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/scheduler/types.ts
- 发布/更新：repository `main`
- 证据等级：L2 / primary official source
- 用途：`ToolCallRequestInfo.callId`、tool name/args、状态类型。
- Caveat：类型定义不是持久化日志或 exactly-once 协议。

## S07 — Scheduler 源码
- URL: https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/scheduler/scheduler.ts
- Raw: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/scheduler/scheduler.ts
- 发布/更新：repository `main`
- 证据等级：L2 / primary official source
- 用途：按 callId 查找/更新调度状态，sessionId 进入 schedule span，调度批次输出。
- Caveat：内存调度路径不能单独证明 MessageBus 事件持久化。

## S08 — Tool executor 源码
- URL: https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/scheduler/tool-executor.ts
- Raw: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/scheduler/tool-executor.ts
- 发布/更新：repository `main`
- 证据等级：L2 / primary official source
- 用途：工具执行使用 sessionId 与 `gen_ai.tool.call_id`，span input/output/error。
- Caveat：span 关联 ID 不承诺去重或远端执行次数。

## S09 — Core events 源码
- URL: https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/utils/events.ts
- Raw: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/utils/events.ts
- 发布/更新：repository `main`
- 证据等级：L2 / primary official source
- 用途：approval-mode-changed、consent-request、MCP progress 等 CoreEvent payload，以及有限内存 backlog。
- Caveat：EventEmitter/backlog 是进程内机制，不是审计存储。

## S10 — Telemetry SDK 源码
- URL: https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/telemetry/sdk.ts
- Raw: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/telemetry/sdk.ts
- 发布/更新：repository `main`
- 证据等级：L2 / primary official source
- 用途：session resource attribute、exporter 类型、buffer、batch/periodic exporter 配置。
- Caveat：配置与 exporter 调用不等于 collector/backend delivery。

## S11 — OTel file exporters 源码
- URL: https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/telemetry/file-exporters.ts
- Raw: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/telemetry/file-exporters.ts
- 发布/更新：repository `main`
- 证据等级：L2 / primary official source
- 用途：append stream、写入回调 flush、shutdown，以及 span/log/metric export。
- Caveat：只有实际文件、成功回调与 shutdown 证据才支持本地写出；不支持远端送达推断。

## S12 — Telemetry trace 源码
- URL: https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/telemetry/trace.ts
- Raw: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/telemetry/trace.ts
- 发布/更新：repository `main`
- 证据等级：L2 / primary official source
- 用途：sessionId→`gen_ai.conversation.id`、span metadata、tool/LLM input/output、error 与 span end。
- Caveat：详细 input/output 受 traces 开关影响，span end 也不等于后端持久化。

## S13 — Session conversion 源码
- URL: https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/utils/sessionUtils.ts
- Raw: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/utils/sessionUtils.ts
- 发布/更新：repository `main`
- 证据等级：L2 / primary official source
- 用途：现代 content 作为来源、旧 toolCalls 转 function call/response、工具结果与 stable IDs 的转换。
- Caveat：转换能力不证明输入文件无截断、无丢失或固定 JSONL schema。

## S14 — Agent history provider 源码
- URL: https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/context/agentHistoryProvider.ts
- Raw: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/context/agentHistoryProvider.ts
- 发布/更新：repository `main`
- 证据等级：L2 / primary official source
- 用途：历史 token 限制、截断、summary bridge 与 function call/response 配对边界。
- Caveat：上下文历史的截断意味着当前模型上下文不必然等同于完整审计历史。

## S15 — Telemetry loggers 源码
- URL: https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/telemetry/loggers.ts
- Raw: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/telemetry/loggers.ts
- 发布/更新：repository `main`
- 证据等级：L2 / primary official source
- 用途：tool/user/API 等 telemetry event 经 UI/Clearcut 与 `bufferTelemetryEvent` 写出路径。
- Caveat：buffer、采样、禁用和异常都会使 event 视图不完整。

## S16 — 官方 OTel GenAI semantic conventions 引用
- URL: https://github.com/open-telemetry/semantic-conventions/blob/8b4f210f43136e57c1f6f47292eb6d38e3bf30bb/docs/gen-ai/gen-ai-events.md
- 发布/更新：固定官方 OpenTelemetry commit
- 证据等级：L1 / authoritative independent (official OTel reference)
- 用途：Gemini CLI telemetry 文档引用的 event 语义参照。
- Caveat：该规范定义语义，不证明 Gemini CLI 实例的事件一定发出或被接收。
