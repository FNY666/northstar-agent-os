# S8 来源清单

仅列公开官方一手资料；访问日 2026-09-22。文档标题/版本若页面未给日期则标 `unknown`，不臆填发布日期。

- S1 — Stripe, “Idempotent requests”, https://docs.stripe.com/api/idempotent_requests — updated: unknown. 直接支持：POST 幂等键、保存首次状态码/响应体（包括 500）、最长 255、至少 24h 后可清理、参数不一致错误、GET/DELETE 不需键。
- S2 — Stripe, “Receive Stripe events in your webhook endpoint”, https://docs.stripe.com/webhooks — updated: unknown. 直接支持：签名/原始正文、快速 2xx、异步队列、投递状态与 HTTP 状态、生产约三天/测试约数小时重试、事件重复/乱序、event ID 去重、object ID+type 识别、retrieve 缺失对象、API version 固化。
- S3 — AWS EC2 Developer Guide, “Ensuring idempotency in Amazon EC2 API requests”, https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html — updated: unknown. 直接支持：client token <=64 ASCII、参数匹配、IdempotentParameterMismatch、默认/可选幂等、Regional/Zonal、异步完成与 retry recommendations。
- S4 — AWS Step Functions Developer Guide, “Handling errors in Step Functions workflows”, https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html — updated: unknown. 直接支持：错误名、HeartbeatTimeout/Timeout/Runtime、Retry/Catch、退避与 jitter。
- S5 — AWS Step Functions Developer Guide, “Discover service integration patterns”, https://docs.aws.amazon.com/step-functions/latest/dg/connect-to-resource.html — updated: unknown. 直接支持：Request Response、.sync、.waitForTaskToken、best-effort cancel、polling、task token 回传、同账户约束。
- S6 — AWS Step Functions API Reference, “SendTaskSuccess”, https://docs.aws.amazon.com/step-functions/latest/apireference/API_SendTaskSuccess.html — updated: unknown. 直接支持范围：SendTaskSuccess API；本切片未将未能完整抓取的细节扩展为声明。
- S6b — AWS Step Functions API Reference, “SendTaskFailure”, https://docs.aws.amazon.com/step-functions/latest/apireference/API_SendTaskFailure.html — updated: unknown.
- S6c — AWS Step Functions API Reference, “SendTaskHeartbeat”, https://docs.aws.amazon.com/step-functions/latest/apireference/API_SendTaskHeartbeat.html — updated: unknown.
- S7 — Temporal, “What is a Temporal Retry Policy?”, https://docs.temporal.io/encyclopedia/retry-policies — updated: unknown. 直接支持：Activity 默认 retry、Workflow 默认不 retry、initial 1s、backoff 2、max 100×、attempts 无限、non-retryable error type。
- S8 — IETF RFC 9110, “HTTP Semantics”, https://www.rfc-editor.org/rfc/rfc9110 — 2022-06. 直接支持：HTTP 语义、条件请求/表示/响应状态定义（具体章节以锚点为准）。
- S9 — IETF RFC 9111, “HTTP Caching”, https://www.rfc-editor.org/rfc/rfc9111 — 2022-06. 直接支持：HTTP caching 与 Cache-Control 规范（本切片未把具体 directive 展开为供应商字段）。
- S10 — IETF RFC 6585, “Additional HTTP Status Codes”, https://www.rfc-editor.org/rfc/rfc6585 — 2012-04. 直接支持：428 Precondition Required；RFC 9110 覆盖 409/412 等核心语义。
- S11 — Apache Kafka, “Documentation”, https://kafka.apache.org/documentation/ — version page accessed: unknown. 直接支持范围：producer/consumer、idempotence、transactions、read_committed、offset 概念。Kafka 官方文档页面内容按版本变化，具体版本必须在实现中锁定。
- S12 — Apache Kafka, “Design”, https://kafka.apache.org/documentation/#design — version/date unknown. 直接支持范围：log/partition/offset/consumer group 设计。
- S13 — Apache Kafka, “Producer configs / Consumer configs”, https://kafka.apache.org/documentation/#producerconfigs and https://kafka.apache.org/documentation/#consumerconfigs — version/date unknown. 直接支持范围：enable.idempotence、transactional.id、isolation.level=read_committed、offset 相关配置。

## 证据使用说明

- [verified] S1-S13 均是官方域名/原始标准；不是博客、搜索摘要或转载。
- [unknown] 本清单不把官方页面存在等同于每个字段均已核验；report.md 对页面抓取不完整、版本未锁定和未发现的字段明确降级。
- [inferred] 闸门、预算拆分、四阶段删除/取消流程均为系统设计推断，不是来源的供应商承诺。
