# S12 摘要

- Stripe 官方矩阵说明资格受国家、币种、产品、API flow 与 connected-account capability 限制；空白不等于 No。
- `processing` 是异步支付处理中；`succeeded` 是支付完成/资金在账户中/可履约；`requires_capture` 是 separate capture 下待捕获授权。
- 官方直接列出 manual capture 支持 cards、Affirm、Afterpay/Clearpay、Cash App Pay、Klarna、PayPal；ACH/iDEAL 明确不支持；其它方式 unknown。
- 通用 refund 能力有官方证明，但逐方式 refund、delayed notification、off-session、最终性及缺失事件永久补偿均未被统一证明。
- `payment_intent.processing/succeeded/canceled` 有事件连接；webhook 不保证顺序，可能重复；live 重试最多 3 天，未交付查询窗口 30 天。

详见 report.md 完整矩阵、状态图与证据边界。