# Next-slice dispatch — S14 → S15

## 建议切片
在不读取 S11–S14 产物之外的前提下，继续做 **A 线 S15：平台级退款/争议“客户可见入账”与商户账务终态的分层证据**，仍只使用 Stripe 与 PayPal 官方一手公开文档。重点补齐：

1. Stripe 各支付方法退款（卡、ACH/SEPA/Bacs/PayPal 等）官方客户到账窗口是否存在差异；严格区分 `Refund` 对象终态、发卡行/银行可见账单时间、Stripe balance 回流时间。
2. PayPal 当前 REST Refund API/Payments v2 的官方状态字段与 webhook 对照，确认是否存在 `COMPLETED/SUCCEEDED` 退款事件或仅由 capture/refund 事件表达；不要用空白表格推定。
3. 只在官方明确文本出现时，补充 dispute/debit 申诉期限、resolution/appeal 后是否可逆；按国家/支付方式分开，不产生统一跨平台结论。
4. Stripe 与 PayPal capture 过期后的“释放/void/cancel”与“自动退款”必须继续分开取证；任何未直接陈述的自动退款均保留 unknown。

## 执行护栏

- 访问日期写为 2026-09-22；不调用任何 API、不使用 key、不建测试对象。
- 不读取 S11–S14 产物来补证；本 dispatch 只是下一步建议，不是事实证据。
- 仅允许 `docs.stripe.com`、`developer.paypal.com`、`www.paypal.com` 官方页面；记录精确 URL、原文语义、状态、confidence、caveat。
- 对每个“窗口”分别记录 earliest、latest、条件、单位（business/calendar days）；官方没给就写 `unverified`，并在 caveat 写“unverified 语义=unknown”。
- 完成后复用本目录 manifest validator 和 `sha256sum -c SHA256SUMS`。

## 不停线交接

先验证本 S14 产物完整性，再开展 S15；发现 validator、SHA 或来源数量异常时先修复证据包，不要推进未知结论。
