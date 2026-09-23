# S15 Sources

访问日期统一：**2026-09-22**。全部为官方一手公开文档。

## Stripe

- **S1** — https://docs.stripe.com/refunds.md — Refund/cancel 总览；Refund 状态与 available balance 规则；成功退款约 5–10 business days；失败返 Stripe balance 最多 30 days；card reversal 与账单表现。
- **S2** — https://docs.stripe.com/api/refunds/object.md — Stripe Refund 对象字段/状态参考（包括 `status` 语义）。
- **S3** — https://docs.stripe.com/refunds.md — 退款使用 available Stripe balance；卡余额不足可 pending、其他 payment method 失败；失败返余额；requires_capture 不能直接 refund、需 cancel。
- **S4** — https://docs.stripe.com/payments/ach-direct-debit.md — ACH refund 最多 3 business days；独立 bank credit、非 reversal；`succeeded`/`failed`、webhook；180-day refund window；60-day dispute window；不可取消。
- **S5** — https://docs.stripe.com/payments/sepa-debit.md — SEPA refund 3–4 business days processing、within 5 business days 到客户账户；180-day window；8-week no-questions-asked、13-month unauthorized dispute；final/no appeal。
- **S6** — https://docs.stripe.com/payments/bacs-debit.md — Bacs refund 通常 3–4 business days；180-day submission；indefinite dispute period；final/can’t appeal；pending refund 与 charge 成功依赖。
- **S7** — https://docs.stripe.com/payments/paypal.md — Stripe PayPal payment method：180-day refund window；按 settlement preference 从 Stripe balance 或 PayPal balance/资金退款；dispute 链接。
- **S8** — https://docs.stripe.com/disputes/responding.md — 一般卡响应通常 7–21 days；提交响应 final、不能修改；lost 时 refund permanent。
- **S9** — https://docs.stripe.com/payments/paypal/disputed-payments.md — PayPal dispute 180 calendar days；2–19 calendar days evidence；30-day decision target；某些 lost dispute 可由 PayPal appeal，Stripe 不支持。
- **S10** — https://docs.stripe.com/payments/sepa-debit.md — SEPA timing/dispute/refund direct sections; same canonical source as S5 (listed once in URL set; retained here for the dispute/refund cross-reference).
- **S11** — https://docs.stripe.com/payments/capture-later.md — authorization validity；未及时 capture，funds released、payment status canceled；支持/不支持 capture 的支付方法。

## PayPal

- **P1** — https://developer.paypal.com/api/payments/v2 — Payments v2 官方 API reference；authorization void、capture refund、refund details endpoint 的资源分离。
- **P2** — https://developer.paypal.com/api/payments/v2/schema.json — Payments v2 官方 OpenAPI schema；`refund_status` 枚举 `CANCELLED/FAILED/PENDING/COMPLETED`；capture status `COMPLETED/DECLINED/PARTIALLY_REFUNDED/PENDING/REFUNDED/FAILED`；无 refund `SUCCEEDED`。
- **P3** — https://developer.paypal.com/api/rest/webhooks/event-names/ — 官方 webhook event names；Payments v2 的 `PAYMENT.CAPTURE.COMPLETED`, `PAYMENT.CAPTURE.REFUNDED`, `PAYMENT.REFUND.PENDING`, `PAYMENT.REFUND.FAILED`, `PAYMENT.CAPTURE.REVERSED`, `PAYMENT.AUTHORIZATION.VOIDED` 及描述；未列 `PAYMENT.REFUND.COMPLETED`/`SUCCEEDED`。
- **P4** — https://www.paypal.com/us/cshelp/article/how-long-do-i-have-to-file-a-dispute-help160 — PayPal 官方帮助；未升级 dispute 20 days 自动关闭；closed disputes 不能 reopen/escalate。

## 使用边界

未使用 Stripe/PayPal API 调用、密钥、测试对象或账户数据；schema/webhook 页面仅作公开文档读取。对官方未直接陈述的到账、余额回流、自动退款、跨国家/支付方式 appeal，报告明确标为 unknown，未用惯例补全。
