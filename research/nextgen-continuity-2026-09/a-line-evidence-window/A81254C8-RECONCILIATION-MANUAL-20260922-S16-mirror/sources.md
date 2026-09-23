# S16 sources

访问日期均为 **2026-09-22**；只列 Stripe 官方或 PayPal 官方 URL。页面若为动态文档，摘要按当日公开页面正文/结构化 Markdoc/API reference 读取；未调用 API。

|#|官方 URL|摘要|
|---:|---|---|
|1|https://docs.stripe.com/disputes/responding|Stripe：争议通知后 response 窗口通常 7–21 天，取决于卡网络；逾期自动输掉且不能取回争议资金；并列出 dispute 事件通知方式。页面还说明 Visa/Mastercard compliance 机制，但不提供本文所需逐国固定 representment/appeal deadline。|
|2|https://docs.stripe.com/disputes/how-disputes-work|Stripe：卡网络通常允许持卡人 120 天内发起争议（某些情况更久）；chargeback 后商户通常 7–21 天响应；提交证据后 issuer 通常 60–75 天评估；全生命周期通常 2–3 个月。说明 Amex/Discover 常用 inquiry、Visa/Mastercard 不再用 inquiry、墨西哥国内跨品牌争议的 inquiry。|
|3|https://docs.stripe.com/disputes/reason-codes-defense-requirements|Stripe：所列常见争议理由码/证据覆盖 Visa、Mastercard、American Express；issuer 而非 Stripe 决定结果。无按国/网络给本文所需四类期限。|
|4|https://docs.stripe.com/disputes/withdrawing|Stripe：客户撤回争议不必然加速 issuer 时间线；争议中的 charge 在 issuer 判商户胜诉前不能退款；仍应提交证据。|
|5|https://docs.stripe.com/disputes/api|Stripe API reference：dispute/争议对象及相关程序化处理入口；用于确认官方对象域，不将 API 状态升级为客户银行入账。|
|6|https://docs.stripe.com/api/events/types|Stripe Event types：`charge.dispute.created`、`charge.dispute.closed`、`charge.dispute.funds_reinstated` 以及 `payment_intent.canceled` 等事件语义。|
|7|https://docs.stripe.com/api/balance_transactions/object|Stripe Balance Transaction：`amount`、`fee`、`net`、`source`、`status`（available/pending）、`available_on`；类型枚举含 charge、refund、refund_failure、payment_refund、payment_failure_refund 及 dispute 相关类型。|
|8|https://docs.stripe.com/api/payment_intents/cancel|Stripe：PaymentIntent 可取消状态；取消后不再额外扣款；`requires_capture` 时剩余 `amount_capturable` 自动退款；返回对象含 `status=canceled`、`canceled_at`、`cancellation_reason`。|
|9|https://docs.stripe.com/api/payment_intents/object|Stripe PaymentIntent object：对象字段含 status/canceled_at/cancellation_reason，以及手动 capture 场景的 `capture_before` 字段语义（过 future timestamp 后 charge 自动退款）。|
|10|https://developer.paypal.com/api/payments/v2|PayPal Payments v2 API reference：授权、capture、refund 对象/接口入口；用于对象域定位，不将对象状态当作客户银行入账。|
|11|https://developer.paypal.com/api/rest/webhooks/event-names/|PayPal 官方 webhook event names：`PAYMENT.AUTHORIZATION.VOIDED` 可因授权达到 30 天有效期或手动 void；关联 status=voided；`PAYMENT.REFUND.PENDING` 可因 eCheck 处理需数日；`PAYMENT.REFUND.FAILED` 可因银行结算无法发退款；另列 capture completed/declined/pending/refunded/reversed。|
|12|https://www.paypal.com/us/cshelp/article/where-is-my-refund-help130|PayPal 客户帮助：退款回原支付方式；不能入原方式或选择余额时可进入 PayPal balance；Refund Tracker 的 Initiated/Processing/Sent/Pending/Completed 语义；Refund Sent 尚未完成，银行/卡仍可能处理；信用卡 1–2 billing cycles，借记卡通常最多 5 工作日但可到 30 天，银行账户通常最多 5 工作日且某些情况到 30 天，余额同日。|

## 访问失败/转向记录

- `https://docs.stripe.com/payments/refunds` 当日返回 404；未把该失败页当证据，转用可访问的 Stripe API PaymentIntent cancel/object 与 PayPal 客户退款页；不使用搜索摘要。
- `https://developer.paypal.com/docs/api/webhooks/v1/event-names/` 当日返回 404；转向同域官方 canonical `https://developer.paypal.com/api/rest/webhooks/event-names/`，页面可访问并含事件表。
- `https://developer.paypal.com/api/payments/v2/#refunds_get` 与 `#captures_refund` 页面可访问但动态 API reference 锚点复用 overview；以同域 `https://developer.paypal.com/api/payments/v2` 作为 API 对象入口，以 webhook canonical 与 PayPal 客服页承载具体退款/void语义。
