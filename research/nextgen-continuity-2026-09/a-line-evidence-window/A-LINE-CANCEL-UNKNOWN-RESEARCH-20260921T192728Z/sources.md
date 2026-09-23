# Sources

访问日期统一：2026-09-22。以下均为公开官方一手资料；`verified` 仅表示页面直接支持相邻陈述，不表示供应商保证本文提出的跨系统 UNKNOWN 协议。

## S1 — Temporal Go SDK：取消 Workflow
- URL: https://docs.temporal.io/develop/go/workflows/cancellation
- Publisher: Temporal Technologies, official documentation
- Accessed: 2026-09-22
- Status: verified
- 能证明：Workflow 可处理 cancellation；可用 `workflow.NewDisconnectedContext` 执行清理；Activity 用 heartbeat 接收取消；`CancelWorkflow` 按 Workflow ID 发送且可提供 Run ID；取消后 heartbeat 可能报 context canceled 但仍已发送；reset 会创建新执行并应监控。
- 不能证明：取消请求已发出但无响应时外部业务动作一定未发生/已发生；通用取消 ACK、跨服务 read-back、幂等键或 Saga 补偿保证；生产效果。

## S2 — Temporal 文档：Workflow ID（补充检索页）
- URL: https://docs.temporal.io/workflows#workflow-id
- Publisher: Temporal Technologies, official documentation
- Accessed: 2026-09-22
- Status: unknown
- 能证明：本次抓取未得到可核验正文（请求未在本片可靠完成）。
- 不能证明：不将其作为证据；报告中关于 Workflow ID/Run ID 仅使用 S1 中直接可见的内容。

## S3 — LangGraph：Persistence
- URL: https://docs.langchain.com/oss/python/langgraph/persistence
- Publisher: LangChain, official documentation
- Accessed: 2026-09-22
- Status: verified
- 能证明：checkpointer 持久化 thread 的 graph state snapshots；用于恢复、故障容错和 human-in-the-loop；store 用于应用定义的跨线程数据；内存 checkpointer 重启丢失；生产建议持久化 checkpointer。
- 不能证明：checkpoint 已确认任意外部 side effect；请求超时后的远程结果；跨服务 idempotency key；Saga/补偿完成。

## S4 — LangGraph：Interrupts
- URL: https://docs.langchain.com/oss/python/langgraph/interrupts
- Publisher: LangChain, official documentation
- Accessed: 2026-09-22
- Status: verified
- 能证明：interrupt 保存 graph state 并等待恢复；使用相同 thread/checkpoint 恢复；恢复从包含 interrupt 的 node 开头重跑；interrupt 前副作用应幂等，upsert 为正例，创建记录/append 为反例；可用人工审批并在后续 resume。
- 不能证明：任何具体外部系统的幂等实现或生产成功率；timeout/断连时 side effect 的真实完成状态；统一 Saga 协议。

## S5 — OpenAI Agents SDK：Running agents
- URL: https://openai.github.io/openai-agents-python/running_agents/
- Publisher: OpenAI, official Agents SDK documentation
- Accessed: 2026-09-22
- Status: verified
- 能证明：Runner 可用 RunState 恢复 paused run；streaming 后有完整结果；Responses WebSocket 重连有 previous_response_id 缓存限制和重建上下文说明；模型调用可抛 ModelTimeoutError；工具超时有配置行为；RunState/持久化 durable integrations 可用于暂停恢复（页面列举 Temporal/Dapr 等）。
- 不能证明：ModelTimeoutError 表示远端 tool/业务 side effect 未执行；OpenAI SDK 自动 read-back/reconcile 或跨请求 idempotency；断连后的 UNKNOWN 会自动收敛；生产效果。

## S6 — OpenAI Agents SDK：Human-in-the-loop
- URL: https://openai.github.io/openai-agents-python/human_in_the_loop/
- Publisher: OpenAI, official Agents SDK documentation
- Accessed: 2026-09-22
- Status: verified
- 能证明：工具审批可产生 interruption；可将结果转为 RunState，approve/reject 后用原始 top-level agent resume；审批决策可序列化，恢复后继续；审批是暂停/决策编排模式。
- 不能证明：审批前后外部请求的执行事实；取消或 timeout 的 read-back；幂等键或补偿动作安全；人工猜测 UNKNOWN 是安全的。

## S7 — RFC 9110 HTTP Semantics §9.2.2 Idempotent Methods
- URL: https://www.rfc-editor.org/rfc/rfc9110.html#name-idempotent-methods
- Publisher: IETF / RFC Editor, official standard
- Accessed: 2026-09-22
- Status: verified
- 能证明：幂等方法的多次请求预期效果等同单次；幂等性允许客户端在通信失败后重试；幂等性针对客户端意图的效果，不是服务器内部实现细节。
- 不能证明：POST/任意工具调用自动幂等；一次请求在断连时是否已执行；统一 `Idempotency-Key` 机制；业务 read-back、Saga、补偿或人工边界。

## S8 — RFC 9110 HTTP Semantics §15.5.9 / §15.6.5
- URL: https://www.rfc-editor.org/rfc/rfc9110.html#name-408-request-timeout
- URL: https://www.rfc-editor.org/rfc/rfc9110.html#name-504-gateway-timeout
- Publisher: IETF / RFC Editor, official standard
- Accessed: 2026-09-22
- Status: verified
- 能证明：规范定义 408 Request Timeout 与 504 Gateway Timeout 的 HTTP 语义及响应类别。
- 不能证明：这些响应意味着应用动作未被接受、未执行或已回滚；不能替代业务 read-back/reconcile；不提供幂等键或补偿语义。

## 证据边界与检索记录

- 通过官方 HTML/Markdown 页面直接读取了 S1、S3、S4、S5、S6；S7/S8 使用 RFC Editor HTML。
- 一次补充 Temporal Workflow ID URL 抓取未可靠完成，故标为 `unknown`，不把它计入证明。
- 公开官方页面没有找到足以证明“取消/超时/断连后的外部副作用必然未执行”的材料；因此该命题保持 `unknown`，报告采用保守 UNKNOWN 状态。
- 没有访问私有账户、cookies、凭据、真实服务、production、共享目录或父会话保护目录。
