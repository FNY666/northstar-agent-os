# 官方来源

1. https://docs.stripe.com/payments/payment-methods/payment-method-support — Country/currency/product/API support、manual capture、setup future usage、redirect、Connect eligibility。
2. https://docs.stripe.com/payments/payment-intents/verifying-status — processing、requires_capture、succeeded、canceled、next_action。
3. https://docs.stripe.com/payments/place-a-hold-on-a-payment-method — capture 能力、授权过期、网络/BNPL/PayPal 窗口。
4. https://docs.stripe.com/api/payment_intents/capture — requires_capture、默认七日取消。
5. https://docs.stripe.com/api/payment_intents/cancel — 可取消状态、剩余 amount_capturable 自动 refund。
6. https://docs.stripe.com/api/events/types — PaymentIntent 状态事件。
7. https://docs.stripe.com/payments/checkout/fulfill-orders — ACH/银行转账延迟、async_payment_succeeded/failed、processing。
8. https://docs.stripe.com/webhooks — 乱序、重复、重试、对象补查。
9. https://docs.stripe.com/webhooks/process-undelivered-events — 三日自动重发、30日列表、手工补偿。
10. https://docs.stripe.com/refunds — 通用退款与余额不足规则。

只使用 Stripe 官方公开文档，未调用 API、凭据或真实账户。