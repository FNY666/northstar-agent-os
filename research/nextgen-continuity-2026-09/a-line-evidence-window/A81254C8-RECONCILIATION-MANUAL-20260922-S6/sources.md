# S6 Sources

仅列公开官方一手来源。访问/抓取日期：2026-09-22。页面未明确发布日期处标记“未声明”。摘录为研究笔记，结论见 report.md。

## S1 — Stripe
- URL: https://docs.stripe.com/api/idempotent_requests
- Publisher: Stripe
- Title: Idempotent requests | Stripe API Reference
- Published/updated: 未声明（页面当前版本；访问 2026-09-22）
- Tier: primary
- Direct support: Stripe 说明同一幂等键保存首次请求的 status code/body（成功或失败，包括 500）；后续同 key 返回相同结果；参数与首次不同则报错；key 至少 24 小时后可自动删除，删除后复用会生成新请求；校验失败或并发冲突且 endpoint 尚未执行时不保存结果；POST 接受 key，GET/DELETE 无需。
- Used for: 生命周期、结果重放、参数冲突、并发前执行边界。

## S2 — Amazon EC2
- URL: https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html
- Publisher: Amazon Web Services
- Title: Ensuring idempotency in Amazon EC2 API requests
- Published/updated: 未声明（页面当前版本；访问 2026-09-22）
- Tier: primary
- Direct support: client token 为区分大小写、最多 64 ASCII 字符的唯一字符串；成功后同 token/同参数重试不再执行动作；参数不同会有 `IdempotentParameterMismatch`；Regional/Zonal 幂等范围不同；官方 retry 表对 200 不重试、5xx 建议退避重试。
- Used for: 参数绑定、作用域、重复请求和重试策略。

## S3 — AWS Step Functions
- URL: https://docs.aws.amazon.com/step-functions/latest/dg/connect-to-resource.html
- Publisher: Amazon Web Services
- Title: Discover service integration patterns in Step Functions
- Published/updated: 未声明（页面当前版本；访问 2026-09-22）
- Tier: primary
- Direct support: callback task 传递 task token 并等待外部系统、人审或遗留系统回调；用 `SendTaskSuccess`/`SendTaskFailure` 完成；task token 超时会生成新随机 token；`HeartbeatSeconds` 控制等待窗口，示例中未及时回 token 会变为 `States.Timeout`。
- Used for: 外部处理、回调、超时和人工升级边界。

## S4 — Temporal
- URL: https://docs.temporal.io/activities
- Publisher: Temporal Technologies
- Title: What is a Temporal Activity?
- Published/updated: 未声明（页面 current 文档；访问 2026-09-22）
- Tier: primary
- Direct support: Activity 是单一明确动作；官方建议幂等以便重试不产生重复副作用；失败按 Retry Policy 自动重试；每次 attempt 默认从初始状态开始，Heartbeat detail 可作为 checkpoint 提供给下一次 attempt；文档列出发送邮件、提交支付等外部动作场景。
- Used for: Activity retry、checkpoint、外部副作用和幂等建议。

## S5 — IETF HTTP Semantics
- URL: https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2
- Publisher: Internet Engineering Task Force (IETF)
- Title: RFC 9110 HTTP Semantics §9.2.2 Idempotent Methods
- Published/updated: 2022-06（RFC 9110；访问 2026-09-22）
- Tier: primary
- Direct support: 幂等方法是多个相同请求的预期服务器效果与一次相同；PUT、DELETE 和 safe methods 属于幂等；连接在客户端读响应前关闭时可重试；服务器仍可为每次请求记录日志等副作用；非幂等请求一般不应自动重试，除非能证明语义幂等或原请求未应用。
- Used for: HTTP 术语边界、超时重试与“幂等不等于无任何副作用”。

## S6 — Apache Kafka
- URL: https://kafka.apache.org/42/design/design/#message_delivery_semantics
- Publisher: Apache Software Foundation / Apache Kafka
- Title: Message Delivery Semantics
- Published/updated: 未声明（Kafka 4.2 文档页；访问 2026-09-22）
- Tier: primary
- Direct support: at-most-once/at-least-once/exactly-once 定义；网络错误时 producer 不知提交前后；旧式重发为 at-least-once；idempotent producer 可防 log duplicate；Kafka Streams/transactional producer + offsets + read_committed 可在 Kafka topic 拓扑提供 exactly-once；写外部系统需要外部系统合作，否则默认 at-least-once。
- Used for: exactly-once 限定、外部效果账本与 read-back/合作边界。

## Evidence handling notes
- 未使用搜索摘要、转载、社交内容或私有资料作为证据。
- 未把官方厂商文档推广为所有平台的共同保证；跨平台统一字段/状态机明确标为 inferred。
- 没有发现官方统一的“效果账本”跨平台标准，因此相关 schema、阈值、人工 SLA 标为 unknown/inferred。
