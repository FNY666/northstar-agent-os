# A 线 S12 详细报告

完整证据化研究报告已在当前交付包中形成，核心覆盖：支付方式国家/币种/账户/API flow 条件；delayed notification、manual capture、refund、off-session、customer action/redirect；PaymentIntent `processing`、`succeeded`、`requires_capture`、`canceled`、授权过期；状态事件；Webhook 乱序/重复/重试与缺失事件补偿边界。

核心结论：`processing` 是异步处理中，不等于成功；`succeeded` 是可履约支付完成；`requires_capture` 是 separate capture 待捕获授权。官方列出的 manual capture 方式包括 cards、Affirm、Afterpay/Clearpay、Cash App Pay、Klarna、PayPal，ACH/iDEAL 明确不支持；其余空白矩阵单元保持 unknown。Stripe 明确不保证 webhook 顺序；live 自动重试最长三天，未交付查询仅近 30 天。未找到统一逐方式最终性或永久缺失事件补偿保证。

来源 URL：
- https://docs.stripe.com/payments/payment-methods/payment-method-support
- https://docs.stripe.com/payments/payment-intents/verifying-status
- https://docs.stripe.com/payments/place-a-hold-on-a-payment-method
- https://docs.stripe.com/api/payment_intents/capture
- https://docs.stripe.com/api/payment_intents/cancel
- https://docs.stripe.com/api/events/types
- https://docs.stripe.com/payments/checkout/fulfill-orders
- https://docs.stripe.com/webhooks
- https://docs.stripe.com/webhooks/process-undelivered-events
- https://docs.stripe.com/refunds

说明：仅使用 Stripe 官方公开文档；未调用 Stripe API、未使用凭据、未访问真实服务。