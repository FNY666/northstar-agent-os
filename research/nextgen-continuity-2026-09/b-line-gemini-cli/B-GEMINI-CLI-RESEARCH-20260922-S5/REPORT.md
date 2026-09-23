# Gemini CLI S5：恢复/重复调用/重试窄范围核验

## 范围与基线

仅读取 `google-gemini/gemini-cli` 官方公开源码与测试，固定在 main 提交 `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`（2026-09-21）；未访问真实服务、凭据、私有数据或 S4 目录。S5 只核验 S4 保留的恢复/重复调用未知项。

## 结论

1. **[verified | A] 工具响应被写入线性可恢复历史，但这不是执行去重。** `GeminiChat` 在收到工具响应时调用 recording service 产生 durable ID，并把 tool response 作为 user message/history 记录；完成工具调用另保存 id、name、args、result、status、timestamp。源码注释明确目的为保证 resume 的 durable ID 和 linear history。证据证明“响应历史持久化”，不证明远端工具副作用已持久化或重放安全。
   - URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/core/geminiChat.ts

2. **[verified | A] 恢复遇到未回答的工具响应时，下一条真正的新用户消息到来前会关闭 dangling tool-response turn。** 官方测试模拟 resumed session 以 unanswered tool response 结尾，验证 guard 在新消息到来时修复；这避免新文本与旧 functionResponse 被错误合并。它是历史结构修复，不是自动重新执行原工具。
   - URLs: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/core/geminiChat.ts
   - https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/core/geminiChat.test.ts

3. **[verified | A] 模型流重试会重新请求模型流，但不等于工具调用重试。** `streamWithRetries` 在空响应/无效流等情况下发出 RETRY 并再次调用 content generator；测试验证 generator 调用两次、历史只记录成功文本一次。该测试边界是模型响应流与 history 去重，不是已执行 shell/MCP 工具的 exactly-once。
   - URLs: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/core/geminiChat.ts
   - https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/core/geminiChat.test.ts

4. **[verified | A] MCP `idempotentHint` 在本批证据中只被保留/暴露为 tool annotation。** discovery 测试构造 `idempotentHint: true` 并验证注册工具保留完整 annotations；未发现该 hint 被用于 scheduler 去重、自动重试、事务提交或 exactly-once。不要将 MCP 元数据 hint 解读为 CLI 保证。
   - URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/tools/mcp-client.test.ts

5. **[verified | B] checkpoint 的恢复对象仍是项目 shadow Git、会话和待执行 tool call。** checkpoint 工具数据保存 commitHash、history、clientHistory、toolCall、messageId；`/restore` 的官方说明是恢复文件和对话、重新提出原工具。没有字段或逻辑证明远端副作用事务日志、执行去重 token 或回滚协议。
   - URLs: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/utils/checkpointUtils.ts
   - https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/cli/checkpointing.md

6. **[verified | A] 取消/流失败的历史处理是“保留或关闭结构”，不是“断点继续执行”。** 源码注释与测试覆盖 stream error 后保留 tool response、取消工具后不把下一用户消息融合到 cancelled response；resumed session 的 dangling response 会被关闭。未见自动判断“远端调用是否完成”后安全重试。
   - URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/core/geminiChat.test.ts

7. **[unknown | D] 崩溃/断线后最后一次工具的实际副作用状态未知。** 本批没有官方 end-to-end 测试证明进程在 shell/MCP 已产生副作用后崩溃，再 resume 时会查询、跳过或补偿该调用。

8. **[unknown | D] exactly-once、幂等执行键、远端回滚、断线重连去重均未知/未承诺。** `callId`、`prompt_id`、durable history ID 是关联与历史结构字段；源码证据不足以将其升级为跨重启幂等键。工具 registry/诊断的 dedup 也不等于副作用执行 dedup。

## 对 S4 的修正/补充

S4 的“未发现 exactly-once/崩溃后副作用恢复”结论得到窄范围核验支持；新增限定：官方实现确实为工具响应和调用记录提供 durable history，并对 resumed dangling response 做结构修复，但这些能力不应被描述为“没有任何恢复机制”。准确表述是：**有会话/历史恢复与人工 checkpoint restore，有模型流 retry；没有本批可验证的外部副作用 exactly-once 或 crash-uncertainty resolution 保证。**

## Evidence caveat

- “unknown”是本批固定 commit 的官方源码/测试检索结果，不是数学意义上的不存在。
- 模型流 retry 的历史无重复测试不能外推到工具执行；MCP `idempotentHint` 的保留不能外推到执行语义。
- 本片不访问 S4 文件，所有产物写入新的 S5 目录。
