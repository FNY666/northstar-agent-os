# S14 官方来源清单

所有来源均为 `google-gemini/gemini-cli` 官方 GitHub 公开仓库；访问时间/研究截点：2026-09-22。E1=可执行官方测试断言；E2=官方当前实现源码/注释；E3=官方文档。

| ID | 证据等级 | exact URL | 用途与直接支持 | caveat |
|---|---|---|---|---|
| S1 | E3 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/checkpointing.md | checkpoint 的 Git snapshot、conversation history、待执行 tool call；`/restore` 恢复本地文件/会话并重新提出 tool | 产品文档；不证明远端服务状态 |
| S2 | E3 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/session-management.md | session 自动保存、保存 prompts/responses/tool executions/outputs、resume 语义与路径 | 不证明崩溃中断写入的原子性 |
| S3 | E1 | https://github.com/google-gemini/gemini-cli/blob/main/integration-tests/checkpointing.test.ts | 临时项目中 snapshot、修改/删除文件、restore 后本地文件精确恢复 | 只覆盖本地 Git shadow snapshot |
| S4 | E1 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/core/geminiChat_network_retry.test.ts | 503 在 stream iteration 中、已有 chunk 后重试；generic fetch error 开关；400 不重试 | mock stream；无真实远端副作用探针 |
| S5 | E2 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/utils/retry.ts | signal 检查；AbortError；Undici timeout 分类；fetch/incomplete JSON 重试分类 | 实现路径，不是服务端提交证明 |
| S6 | E1 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/utils/retry.test.ts | abort 期间停止 retry 且仅一次调用；abort 时不触发 onRetry；`UND_ERR_HEADERS_TIMEOUT` 重试成功 | 没有 `AbortSignal.timeout()` 直接测试 |
| S7 | E2 | https://github.com/google-gemini/gemini-cli/blob/main/packages/cli/src/ui/hooks/useGeminiStream.ts | UI abort 顺序、pending tool 取消、取消后抑制额外 content；shell tool Cancelled | 客户端 UI 状态，不是远端撤销 |
| S8 | E2 | https://github.com/google-gemini/gemini-cli/blob/main/packages/cli/src/ui/hooks/useAgentStream.ts | agent `tool_response.isError`→Error、非 error→Success、agent error 事件显示 | 事件层状态，不证明外部副作用 |
| S9 | E2 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/utils/checkpointUtils.ts | restorable tool checkpoint 数据结构；snapshot 失败 fallback current commit；无 hash 时跳过并报错 | fallback 不构成原子性或远端回滚 |
| S10 | E1 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/utils/checkpointUtils.test.ts | checkpoint 内容含 history/clientHistory/toolCall/messageId；snapshot failure fallback；缺 path/无 hash 行为 | 单元 mock；不覆盖进程崩溃 |
| S11 | E2 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/core/agentChatHistory.ts | durable turn wrapper、set/get、rollback(length)；注释将 rollback 与 stream failure 关联 | 内存抽象；不证明持久化恢复 |
| S12 | E1 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/core/agentChatHistory.test.ts | history 初始化/push/set/clear/rollback 边界和 getContents | 没有模拟半写文件/崩溃 |
| S13 | E2 | https://github.com/google-gemini/gemini-cli/blob/main/packages/cli/src/ui/hooks/useAgentStream.ts | tool event 的 scheduled/executing/error/success 状态映射 | 与 S8 同一文件不同关注点；不能推出远端执行语义 |
| S14 | E2 | https://github.com/google-gemini/gemini-cli/blob/main/packages/cli/src/ui/hooks/useGeminiStream.ts | tool 终态分组、取消时 history item 处理与 response cancel 分支 | UI history 与持久化 session 不同层 |

## 覆盖与缺口

直接覆盖：AbortSignal 取消边界（S5/S6/S7）；网络/Undici timeout 分类（S5/S6）；stream failure/retry 与错误分类（S4-S6）；tool execution event failure/cancel（S7/S8/S13/S14）；checkpoint 创建、失败 fallback 与本地恢复（S1/S3/S9/S10）；session/history resume 与内存 rollback（S2/S11/S12）。

未证明且在报告中保持 UNKNOWN：`AbortSignal.timeout()` 专门测试、远端副作用发生/未发生、远端去重/幂等、远端回滚/补偿、崩溃后最后一条或部分 message 的原子重建、exactly-once。stream retry 或本地 checkpoint 不能替代这些证明。
