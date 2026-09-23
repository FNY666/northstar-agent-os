# Next-slice dispatch

## 建议下一切片

**跨平台最终性 SLA 对比 + 退款到达时间窗口**：在保持同一证据门槛（仅各支付平台官方公开文档、逐方式、访问日固定）的前提下，扩展 Stripe 代表方式与另一家平台的对应方式，建立：

1. payment success/failure notification 的最早/最晚官方窗口；
2. refund submitted → pending → succeeded/failed 的状态转换和 webhook/通知；
3. debit dispute/refund 的可逆性、申诉窗口和“最终”措辞分层；
4. capture expiry、未 capture 自动取消或自动退款的逐方法规则；
5. 对“未陈述”严格填 unknown，不用行业惯例补齐。

## 交接约束

- 继续仅使用目标平台官方公开文档，记录精确 URL 与访问日期。
- 不调用 API、不使用 key、不创建测试对象。
- 先复核本切片的 unknown 清单，避免把 dispute finality 误写为 payment finality。
- 输出同样的 manifest、校验和与 validator 真实输出。
