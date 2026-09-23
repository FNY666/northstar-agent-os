# 下一独立切片建议：S12

## 建议主题
**Stripe PaymentMethod 支付方式能力矩阵与 PaymentIntent `processing`/`requires_capture` 可用性证据图**。

## 为什么独立且不重复 S11
S11 只核验了官方总览中的示例和状态/事件边界；S12 应逐支付方式读取 Stripe 官方 payment-method-support 与各方式集成页，建立可复核矩阵，而不重新研究事件顺序或履约总则。

## 研究问题
1. 对每个当前官方列出的 PaymentMethod，是否支持 delayed notification、manual capture、refund、off-session、customer action/redirect？
2. 哪些官方文本直接把某方式与 `processing`、`succeeded`、`requires_capture` 或取消/过期连接？
3. 兼容性受国家、币种、金额、账户能力、API/UI flow 哪些条件约束？
4. 官方是否承诺方式级事件顺序、最终性或缺失事件补偿？若未找到，仍标 unknown。

## 交付要求
使用新目录（不要读取任何既有 A 线目录）：逐方式 claims ledger、官方 URL/访问日期/直接支持范围、verified/inferred/unknown/conflicting/inaccessible 标记；运行通用 evidence-first validator 与 SHA256 校验。不得调用 Stripe API 或使用凭据。

## 首选官方入口
- https://docs.stripe.com/payments/payment-methods/payment-method-support
- https://docs.stripe.com/payments/payment-methods
- 各方式的 `accept-a-payment` 官方页面
- https://docs.stripe.com/payments/payment-intents/verifying-status
