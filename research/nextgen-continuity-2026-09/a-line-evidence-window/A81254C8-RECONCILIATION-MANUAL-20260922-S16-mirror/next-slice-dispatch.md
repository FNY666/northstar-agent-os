# 下一切片派发建议（S17）

1. **Stripe 网络/国家 deadline 定点补洞（优先）**：仅继续查 `docs.stripe.com` 同域官方 canonical、Markdown/Markdoc/API schema 页面，逐一确认 Visa、Mastercard、American Express、Discover/JCB 及可识别国家/地区是否有 issuer response、appeal、representment/second-presentment 固定窗口。若官方仍只给 7–21 天范围，继续登记 unknown，不得外推。
2. **PayPal 原生退款失败回流闭环**：仅查 `developer.paypal.com` 与 `www.paypal.com`，把 `PAYMENT.REFUND.PENDING` / `PAYMENT.REFUND.FAILED` 与退款对象字段、客户 Refund Tracker、merchant balance/资金来源逐层对齐；重点搜官方说明失败后资金回流对象和时间，找不到就保持 unknown。
3. **余额交易可用时间**：对 Stripe 只核对官方 Balance Transaction 的 `available_on`、`status` 与 refund/refund_failure/payment_failure_refund/dispute 类型；对 PayPal 仅在官方直接描述 merchant balance ledger 或 dispute debit 时增加事实。禁止把客户余额“同日”写成商户 payout/结算时间。
4. **Capture 过期终态**：Stripe 继续核查 `capture_before`、`payment_intent.canceled` 与 balance transaction 的直接关系；PayPal 继续核查 authorization object/status、`PAYMENT.AUTHORIZATION.VOIDED` 与 capture/void 文档。自动 refund 必须有直接句子，否则标 unknown。
5. **质量门槛**：保持三层列（对象/事件、客户可见、商户账务），每个事实附访问日期和精确 URL；运行 validator 与 `sha256sum -c SHA256SUMS`；不得读取或触碰其他切片、shared/P0、事故目录、凭据或 staging/canonical 目录。

**不停线规则：** 先交付已确认事实与 unknown 表；新一轮只添加可追溯的一手直接陈述，不用搜索摘要、社区、SDK 示例或支付行业惯例补空白。
