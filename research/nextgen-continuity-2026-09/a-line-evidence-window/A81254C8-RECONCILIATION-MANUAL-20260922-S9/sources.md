# S9 官方来源清单

仅列 Stripe 官方公开资料；访问时间约为 2026-09-22（Asia/Shanghai）。页面内容可能随 Stripe 文档版本更新，报告保留 verified/inferred/unknown/conflict 标记。

1. **The PaymentIntent object** — https://docs.stripe.com/api/payment_intents/object
   - verified：对象字段与 `status` 枚举：`requires_payment_method`, `requires_confirmation`, `requires_action`, `processing`, `requires_capture`, `canceled`, `succeeded`；`amount_received`, `amount_capturable`, `last_payment_error`, `latest_charge` 等字段。
2. **Retrieve a PaymentIntent** — https://docs.stripe.com/api/payment_intents/retrieve
   - verified：`GET /v1/payment_intents/:id`；publishable-key/client-secret retrieve 仅返回子集。
3. **Update a PaymentIntent** — https://docs.stripe.com/api/payment_intents/update
   - verified：`POST /v1/payment_intents/:id` 更新但不确认；部分更新需要再次确认。
4. **Cancel a PaymentIntent** — https://docs.stripe.com/api/payment_intents/cancel
   - verified：取消条件、`processing` 少数例外、`requires_capture` 剩余可捕获金额自动退款、取消后不能再产生额外 charge。
5. **How Payment Intents and Setup Intents work** — https://docs.stripe.com/payments/paymentintents/lifecycle
   - verified：PaymentIntent 生命周期/客户端流程背景；未将页面示意当作 SLA。
6. **Receive Stripe events with an event destination** — https://docs.stripe.com/webhooks
   - verified：快速 2xx、签名/原始 body、5 分钟默认签名容忍度、每次重试新签名/时间戳、live 最多三天指数退避、sandbox 三次/数小时、Dashboard 15 天和 CLI 30 天 resend、事件无顺序保证、事件 API version 规则。
7. **Idempotent requests** — https://docs.stripe.com/api/idempotent_requests
   - verified：POST 幂等、保存首次 status/body、参数一致性比较、key 最长 255、GET/DELETE 无效果。
8. **Versioning** — https://docs.stripe.com/api/versioning
   - verified：请求/账户 API version 的版本化背景；报告对 webhook event version 以 webhook 官方文档的直接说明为准。
9. **Error handling** — https://docs.stripe.com/error-handling
   - verified：错误字段 `code`, `doc_url`, `message`、request ID、连接错误 retrieve/read-back、幂等错误、限流退避与错误分类。
10. **Types of events** — https://docs.stripe.com/api/events/types
   - verified：官方事件类型参考入口；本报告不将未在当前抓取文本中逐项展开的类型当成运行时已启用。

## 证据使用规则

- **verified**：以上官方页面的明确文字/参数/状态枚举。
- **inferred**：四段内部状态机、窗口分离、去重/outbox/read-back 策略；不是 Stripe 字段或 Stripe 保证。
- **unknown**：无账户/endpoint/真实 API 调用时无法确认的运行时事实及固定窗口。
- **conflict**：参考页面默认版本、账户/endpoint/event 历史版本之间不能相互推断；cancel 对 `processing` 的少数例外与一般 processing 语义是上下文边界，不是 exactly-once 证据。
