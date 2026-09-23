# Next-slice dispatch — S16

建议下一切片继续 **A 线退款/争议终态证据的分国家/网络补洞**，不读取 S11–S15 产物以外的旧证据；本切片仅作为派发说明。

1. **Stripe 卡网络/地区**：只查 docs.stripe.com 中各 network/region 明确 dispute response、appeal、representment/second presentment deadline；按 Visa/Mastercard/Amex 与国家分表，若页面无明确文字保持 unknown。
2. **PayPal 原生退款客户可见层**：只查 developer.paypal.com/www.paypal.com 当前公开文档中 wallet/bank funding source 的 refund timing、pending/completed/failed 说明；严禁将“refund object COMPLETED”升级为客户银行入账。
3. **Balance 层**：只补官方直接描述的 Stripe balance transaction/PayPal balance 资金来源与时间，区分正常成功、失败回流、争议 debit；没有独立窗口继续 unknown。
4. **Capture 过期**：分别补 Stripe PaymentIntent canceled、PayPal authorization void/30-day validity 的官方 webhook/object 字段；自动 refund 仍需直接证据，不得由 release/void 推定。
5. 每个新事实保留三层列（对象/事件、客户可见、商户账务），附精确 URL 与访问日期；完成后运行 manifest validator 与 `sha256sum -c SHA256SUMS`，并在新目录单独生成校验输出。

**不停线规则：**若某页访问失败，仅记录为 inaccessible/unverified 并转向同域官方 canonical/markdown/schema 页面；不得使用搜索摘要、社区、SDK 示例或惯例补全。
