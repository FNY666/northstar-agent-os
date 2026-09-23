# S14 摘要

- **Stripe**：异步 PaymentIntent `processing` 官方仅给 up to several days，期间支付不能保证；成功/失败 webhook 为 `payment_intent.succeeded` / `payment_intent.payment_failed`。生产 webhook 自动重试最多 3 天，Dashboard/CLI 手动重发分别最多 15/30 天；不把投递窗口当资金最终性。
- **PayPal**：IPN 通常 almost instantly，但非实时，可丢失/延迟，未确认时自动重发最多 4 天；capture webhook 明确 pending/completed/declined，authorization 到 30 天 validity period 可 void。
- **Stripe refund**：卡退款约 5–10 个工作日客户看到；余额不足时卡退款 pending、其他支付方式失败；银行/发卡行失败时金额回 Stripe balance，最多 30 天，并可安排替代退款方式。
- **PayPal refund**：官方 webhook 只确认 refund pending（eCheck 示例需 couple of days）及 refund failed（银行结算未发出退款）；统一 submitted→pending→succeeded/failed 和客户到账最早/最晚窗口为 **unknown**。
- **争议最终性**：Stripe/PayPal 均 **unknown**；PayPal 仅有 dispute created/resolved 事件，不能推导终局或不可逆。
- **严格边界**：所有 unknown 均表示“官方本切片未陈述”，不是“没有该机制”；没有调用 API、使用 key 或建立测试对象。

下一步：见 `next-slice-dispatch.md`。
