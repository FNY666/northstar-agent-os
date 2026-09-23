# Next-slice dispatch

## 建议下一独立切片：S11 — PaymentIntent 事件族与状态转移证据图

**问题**：仅用 Stripe 官方公开资料，逐事件建立 `payment_intent.*`、`charge.*` 与 PaymentIntent 状态的可验证映射，区分事件发生语义、对象状态语义、异步支付方式和履约信号；不调用 API、不读取其他切片产物。

**范围**：只查 `docs.stripe.com` 的 PaymentIntent/事件类型/生命周期/API reference；记录每个事件的触发描述、`data.object` 类型、可能状态、是否能作为订单动作输入、缺失时是否可由 retrieve 补偿。

**必须验证的断言**：
1. 哪些事件是 PaymentIntent 状态变化的官方信号，哪些只是 Charge/Checkout 相关信号。
2. `processing`、`succeeded`、`requires_capture`、`canceled` 在不同支付方式下的官方限制与履约措辞。
3. 是否有事件顺序/最终性/补偿读取的官方承诺；把没有找到标为 unknown，不推导统一 SLA。
4. 对每个事件给出 verified/inferred/unknown/conflicting/inaccessible 标签，并保留 URL、访问日期和直接支持文字。

**交付物**：沿用 S10 六件套（report.md、sources.md、summary.md、research-manifest.json、SHA256SUMS、next-slice-dispatch.md），运行研究清单验证器与 SHA-256 校验。严禁 Stripe API 调用、凭据、真实服务及既有研究目录。
