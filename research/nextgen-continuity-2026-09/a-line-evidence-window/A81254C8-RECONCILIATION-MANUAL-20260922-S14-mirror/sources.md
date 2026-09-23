# S14 Sources

访问日期：2026-09-22。以下均为官方一手公开页面；摘要仅描述本切片使用的直接证据。

1. https://docs.stripe.com/payments/payment-intents/verifying-status.md — Stripe PaymentIntent 状态与 webhook：异步支付 `processing` 可持续 up to several days、期间不能保证；`succeeded`/`payment_failed` 事件；processing/succeeded/failed 处理语义。
2. https://docs.stripe.com/webhooks.md — Stripe webhook 投递：生产自动重试 up to three days；Dashboard 重发 up to 15 days；CLI 重发 up to 30 days；重复事件、并发/顺序处理注意事项。
3. https://docs.stripe.com/refunds.md — Stripe refunds：可用余额不足时卡退款 pending、其他支付方式失败；退款通常 5–10 business days 到客户；失败金额回 Stripe balance，最多 30 days；failed refund 可安排 alternative way；原支付方式/过期卡路径。
4. https://docs.stripe.com/payments/place-a-hold-on-a-payment-method.md — Stripe authorization/capture：在线卡通常 hold 7 days（Terminal 通常 2 days）；过期释放资金并变 canceled；automatic delayed capture 可在过期前约 6 小时 capture。
5. https://docs.stripe.com/disputes.md — Stripe disputes 产品入口；本切片未从该入口得到 debit/dispute 统一最终性或不可逆措辞，故相关结论为 unknown。
6. https://developer.paypal.com/api/rest/webhooks/event-names — PayPal Webhook Event Names：authorization 达到 30 day validity period 时 `PAYMENT.AUTHORIZATION.VOIDED`；capture pending/completed/declined；refund pending/failed；`CUSTOMER.DISPUTE.CREATED`/`RESOLVED`。退款 pending 示例为 eCheck 需 couple of days，failed 示例为银行结算未发出退款。
7. https://developer.paypal.com/api/nvp-soap/ipn — PayPal IPN（官方标注 legacy）：通知支付、authorization、eCheck pending/completed/denied、refund/dispute 等；通常 almost instantly，但非实时，可丢失/延迟；listener 未确认时自动重发 up to 4 days；checkout 不应等待 IPN。
8. https://developer.paypal.com/api/orders/v2 — PayPal Orders API 参考入口；本切片仅用于确认官方 API 文档范围，未调用 API，未以其空白表格推定 SLA。
9. https://developer.paypal.com/api/payments/v2 — PayPal Payments API 参考入口；本切片未调用 API，未以未展示的状态/字段推定客户退款窗口。

## URL 总数

9（其中 7 个为本切片直接证据页/入口，全部官方域名）。
