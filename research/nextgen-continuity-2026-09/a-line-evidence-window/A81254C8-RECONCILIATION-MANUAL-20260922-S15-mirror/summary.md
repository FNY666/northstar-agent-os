# S15 摘要

## 可直接落账的核心证据（访问 2026-09-22）

- Stripe 卡：Refund 对象状态与客户账单不是同一层；Stripe 说客户约 5–10 个工作日看到退款（依银行），成功账单显示亦依卡网络/发卡行；短期退款可能是 reversal，原扣款消失而非另行 credit。失败时银行金额返 Stripe，Stripe 加回 balance，最多 30 天。
- Stripe ACH：退款异步最多 3 个工作日；单独银行 credit、不是 reversal，账单不明确写 refund；成功/失败分别是 Refund `succeeded`/`failed`，失败金额返 Stripe balance；客户可见独立窗口 unknown。
- Stripe SEPA：退款通常处理 3–4 个工作日，资金在客户账户 5 个工作日内到达；以原 statement descriptor 作为 reference；8 周无条件争议，8 周至 13 个月仅 unauthorized；争议 final、无 appeal。
- Stripe Bacs：refund 通常 3–4 个工作日处理；180 天提交窗口；客户争议无固定/无限期；争议 final、不可 appeal。客户账单可见独立窗口 unknown。
- Stripe PayPal：退款可至原支付 180 天；资金由 Stripe balance 或 PayPal balance（按 settlement preference）提供；客户可见退款窗口与成功余额回流窗口 unknown；PayPal dispute 180 天，证据 2–19 天，PayPal 某些案件可 appeal 但 Stripe 不支持。
- PayPal Payments v2：REST refund `refund_status` 是 `CANCELLED/FAILED/PENDING/COMPLETED`，没有 `SUCCEEDED`；capture 状态另有 `PARTIALLY_REFUNDED/REFUNDED`。webhook 是 capture/refund pending/refund failed 事件组合，没有官方列出的 `PAYMENT.REFUND.COMPLETED` 或 `PAYMENT.REFUND.SUCCEEDED`；不能把 `PAYMENT.CAPTURE.REFUNDED` 改写成退款对象完成事件。
- Capture 过期：Stripe 未 capture 的授权过期→资金 released、payment canceled；PayPal authorization 到 30-day validity→`PAYMENT.AUTHORIZATION.VOIDED`。两者都是释放/void/cancel 层，不等同退款；官方未直接说自动退款，保持 unknown。

## 对账落地规则

1. 记录 Refund/status 或 PayPal refund status；另列 customer-visible；再列 merchant balance。三列不得合并。
2. “处理最多 3 日/通常 3–4 日”若官方只称 processing，不升级为银行 statement/账户可见。
3. “余额不足 pending/失败”与“失败后回余额最多 30 日”不得用于推算正常成功退款的固定回流日。
4. Capture expired 的 release/void/cancel 与 refund 事件严格拆开。

## 明确 unknown

Stripe ACH/Bacs/PayPal 客户可见独立到账窗口、正常成功退款 Stripe/PayPal balance 最终回流时点、PayPal refund COMPLETED 后客户钱包可见时点、跨国家/卡网络统一申诉可逆规则均 unknown（语义=unknown）。

完整逐事实、URL 与分层说明见 `report.md`；来源摘要见 `sources.md`。
