# S16 摘要

## 已确认（confirmed）

- Stripe 官方对卡争议给出跨网络范围：商户 response 通常 7–21 天，取决于 card network；提交证据后 issuer 通常 60–75 天评估；不是逐网络固定值。
- Stripe 所查官方证据页面覆盖 Visa、Mastercard、American Express 的理由码/证据分类；issuer 决定结果。逐网络、逐国家 response/appeal/representment/second-presentment 截止日没有直接公开文字，均保留 unknown。
- Stripe 官方说明争议客户撤回不必然加速 issuer 时间线，争议中的 charge 在 issuer 判商户胜诉前不能退款。
- Stripe Balance Transaction 直接描述 `amount`/`fee`/`net`/`status`/`available_on`/`source`；`status` 为 available 或 pending；类型枚举包含 refund、refund_failure、payment_refund、payment_failure_refund 和 dispute 相关项。
- Stripe PaymentIntent cancel：取消后不再有额外扣款；`requires_capture` 剩余 capturable amount 自动退款；对象字段/事件为 canceled、canceled_at、cancellation_reason、`payment_intent.canceled`。
- PayPal 客户官方页：退款回原支付方式；无法入原方式或选余额时可入 PayPal balance。Refund Sent 尚未完成；信用卡约 1–2 billing cycles，借记卡通常最多 5 工作日但可到 30 天，银行账户通常最多 5 工作日且某些情况到 30 天，PayPal balance 同日。
- PayPal webhook 官方表：`PAYMENT.REFUND.PENDING`、`PAYMENT.REFUND.FAILED` 的 pending/失败语义；`PAYMENT.AUTHORIZATION.VOIDED` 因手动 void 或达到 30-day validity period，授权对象 status=voided。

## 必须保持 unknown

- Visa/Mastercard/Amex 及国家的固定 response deadline。
- appeal、representment、second presentment 的逐网络/逐国家 deadline。
- PayPal API refund `COMPLETED` 到客户银行卡/钱包最终可用的统一保证。
- Stripe/PayPal merchant balance 对正常退款、失败回流、争议 debit 的独立统一时间窗（除 Stripe 对象提供的 `available_on` 字段）。
- PayPal authorization void 是否自动 refund；release/void 不等于 refund。

## 交付检查

- `validate_research.py research-manifest.json`：待运行，须 PASS。
- `sha256sum -c SHA256SUMS`：待运行，须全 OK。
- 所有声明保留对象/事件、客户可见、商户账务三层，不把平台对象终态升级为客户银行入账。
