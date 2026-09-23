# A 线下一切片 S14：跨平台最终性 SLA 与退款到达窗口对比

- 取证日期：2026-09-22
- 证据边界：仅 Stripe（`docs.stripe.com`）与 PayPal（`developer.paypal.com` / `www.paypal.com`）官方公开文档；未调用 API、未使用 key、未创建测试对象；未读取 S11–S13 产物。
- 语义规则：官方直接陈述标为 **confirmed**；由官方状态/事件组合得出的有限归纳标为 **inferred**；官方未陈述标为 **unverified（本报告中语义为 unknown）**，不以行业惯例补全“最早/最晚”。

## 结论先行

1. **Stripe 支付最终性不是固定的单一 SLA。** 同步流程可进入 `succeeded`/`payment_failed`，但异步支付可能处于 `processing`，官方说确认成功与否“up to several days”；因此在 `processing` 未到终态前不能保证支付。Stripe webhook 事件本身没有顺序保证；实时推送之外，生产端点自动重试最多 3 天，Dashboard/CLI 可分别手动重发至事件创建后 15/30 天。
2. **PayPal IPN 是“几乎即时”但不是实时同步服务。** 官方明确消息可能丢失或延迟，失败未确认时最多重发 4 天；因此“最晚到达”可确认到 4 天（仅 IPN 语义），但未给出 capture/authorize webhook 的统一最短/最长业务状态窗口。PayPal webhook 事件表明确 capture `pending`、`completed`、`declined`，以及 authorize 创建/void 等语义。
3. **退款到达窗口：Stripe 卡退款约 5–10 个工作日到客户，且失败可在请求退款后最多 30 天回到 Stripe 余额；** Stripe 还明确余额不足时卡退款保持 `pending`、其他支付方式失败。PayPal 的官方 webhook 表只给出 `PAYMENT.REFUND.PENDING` 的 eCheck 示例“几天”、以及 `PAYMENT.REFUND.FAILED` 的银行结算失败语义，未给统一最早/最晚客户入账窗口。
4. **capture 期限：Stripe 在线卡支付通常 hold 7 天（按卡网络/交易类型而异），过期释放资金并转 `canceled`；PayPal 官方 webhook 表述授权达到 30 天有效期会被 void。** 这两个数字是各自文档上下文中的官方陈述，不能跨平台等同为客户退款到达 SLA。
5. **争议最终性/申诉不可逆：本切片所检索的官方页面没有足够的 debit/dispute 最终性或“不可逆”统一措辞，Stripe 与 PayPal 均记为 unknown。** PayPal 只确认有 `CUSTOMER.DISPUTE.CREATED`/`RESOLVED` 事件；这不等于法律或资金最终性。

## 1. Stripe

### 1.1 支付成功/失败通知窗口与最终性

- **confirmed — processing 窗口：** PaymentIntent `processing` 适用于异步支付；官方说此类支付确认是否成功可能“up to several days”，在此期间支付“can't be guaranteed”，并且可能“up to a few days to process”。因此：最早 = 官方未给出；最晚 = “up to several days”（未换算成具体日数）。
- **confirmed — 终态/通知语义：** `succeeded` 表示支付流程完成、资金已在账户中；`payment_intent.succeeded` 与 `payment_intent.payment_failed` webhook 分别通知成功与失败。`payment_failed` 描述为卡网络拒绝或支付方式过期；官方未给出从提交到该事件的统一最早/最晚时间。
- **confirmed — webhook 交付窗口：** Stripe 生产环境向 webhook destination 自动重试最多 3 天（指数退避）；Dashboard 可在事件创建后最多 15 天重发，Stripe CLI 可最多 30 天重发。该窗口是事件投递/补投窗口，不是支付状态完成 SLA。
- **confirmed — webhook 顺序/重复：** Stripe 官方 webhook 文档要求处理并发事件，并说明 endpoint 可能收到重复事件；事件顺序需由接收方按对象/事件设计处理。页面未提供一个保证的全局顺序，因此本报告不把 webhook 到达顺序当作最终性依据。

### 1.2 Refund 状态机与到达窗口

- **confirmed — 余额不足状态：** 退款使用可用 Stripe balance（不含 pending）；可用余额不足时，卡退款保持 `pending`，直到余额足够；其他支付方式的退款失败。官方还说可通过收款或 top up 解决负余额，适用地区 Stripe 可能自动扣银行账户。
- **confirmed — 客户到达窗口：** Stripe 在发起退款后向客户银行/发卡行提交请求；退款在客户银行账单上显示的时间取决于卡网络和发卡行。Stripe 退款页明确卡退款通常约 **5–10 个工作日**后客户看到退款。
- **confirmed — failed 与余额回流：** 银行/发卡行处理失败时，银行将退款金额返还 Stripe，Stripe 加回 Stripe account balance；官方说该过程从请求退款起最多 **30 天**。退款对象状态转为 `failed`，并带有 `failure_balance_transaction` 与 `failure_reason`。
- **confirmed — 替代路径：** 对失败退款，Stripe 官方要求/建议安排向客户提供替代退款方式（页面原文为“arrange an alternative way to provide your customer with a refund”）。对过期/取消卡，发卡行通常将退款记到 replacement card；没有 replacement card 时通常用其他方式（如支票或银行入账），但 Stripe 也明确极少数情况下卡退款会失败。
- **confirmed — 状态链边界：** 官方退款页直接陈述 `pending` 与 `failed` 的成因/行为；Stripe 退款事件表在同页内容中给出卡/银行退款的 `succeeded`、`pending`、`failed` 等语义。该页面没有承诺所有支付方式都严格经历 `submitted → pending → succeeded/failed` 每一状态，因此“所有方式统一状态机”是 unknown，不推定。

### 1.3 Refund webhook 缺失/失败后的处理

- **confirmed — 交付失败重试：** Stripe 对生产 webhook destination 自动重试最多 3 天，另有 Dashboard 15 天、CLI 30 天手动重发窗口；官方没有说 webhook 未到达会自动触发退款本身或改变退款对象状态。
- **confirmed — 业务替代依赖退款结果：** Stripe 对“退款失败”明确说资金回到 Stripe balance，并可安排替代退款方式；这属于退款业务失败路径，而非 webhook 丢失路径。
- **unverified（unknown）— webhook 丢失后的余额记账：** 官方页面未陈述“只因 refund webhook 缺失/失败，Stripe 如何处理退款余额、是否自动再退款或如何补偿”。不能把上述 3/15/30 天投递窗口推导成余额处理 SLA。

### 1.4 Dispute 最终性/申诉/不可逆

- **unverified（unknown）：** 本切片官方页面未给出适用于本范围的 debit/dispute 统一最终性时钟、申诉后不可逆或不可撤销的直接措辞。`disputes` 页面仅作为产品入口，不足以证明统一终局规则。

### 1.5 Capture 过期/自动取消或退款

- **confirmed — hold 期限：** Stripe 官方 separate authorization/capture 文档说，在线卡支付的金额通常 hold **7 天**（线下 Terminal 通常 2 天，依交易类型/卡网络而异）；可申请部分 extended authorization。
- **confirmed — 过期后状态：** 必须在授权过期前 capture；若授权先过期，资金释放，PaymentIntent 状态变为 `canceled`。官方没有把该路径表述为“自动退款”；因此本报告记为释放/取消，而非自动退款。
- **confirmed — 自动 capture 选项：** Stripe private-preview 的 automatic delayed capture 可在授权过期前约 6 小时自动 capture，作为防止漏 capture 的备份；这不是“过期后自动退款”。

## 2. PayPal

### 2.1 支付成功/失败通知窗口与最终性

- **confirmed — IPN 到达窗口：** PayPal IPN 官方页称 IPN 通常“almost instantly”通知交易事件，但不是实时服务；网络不可靠时消息可能丢失或延迟。IPN 服务在 listener 确认前自动重发，最多 **4 天**。因此可报告的最早是“几乎即时”（非硬 SLA），最晚是“最多 4 天重发”（IPN 交付语义），不是所有 webhook/支付状态的统一业务 SLA。
- **confirmed — IPN 事件语义：** IPN 覆盖支付收到、信用卡 authorization、eCheck 的 pending/completed/denied，以及 chargebacks、disputes、reversals、refunds。官方还明确 checkout 不应等待 IPN 才完成，因为系统负载等可能造成延迟。
- **confirmed — capture/authorize webhook 状态：** PayPal Webhook Event Names 官方表列出 `PAYMENT.AUTHORIZATION.CREATED`；`PAYMENT.CAPTURE.PENDING`（capture 状态变 pending）；`PAYMENT.CAPTURE.COMPLETED`（capture 完成）；`PAYMENT.CAPTURE.DECLINED`（capture 被拒）。这些是状态/事件语义，不构成官方统一的“从支付提交至终态 X 小时/天”窗口。
- **inferred — 不应把 IPN 4 天视作 capture 终态 SLA：** 因 IPN 页面将 4 天定义为 listener 未确认时的消息重发窗口，而 Webhook Event Names 页面仅定义状态事件，本报告将其限定为通知传输窗口，不外推成资金最终性。

### 2.2 Refund 状态机与到达窗口

- **confirmed — refund webhook 状态：** PayPal 官方 Webhook Event Names 列出 `PAYMENT.REFUND.PENDING`（退款变为 pending；例：eCheck-based refund 从商户银行处理需“a couple of days”）与 `PAYMENT.REFUND.FAILED`（退款失败；例：银行结算流程未发出退款）。同页还列出 `PAYMENT.CAPTURE.REFUNDED`（商户退款 capture）与 `PAYMENT.CAPTURE.REVERSED`（PayPal reverse capture）。
- **unverified（unknown）— submitted/succeeded 与客户到账窗口：** 上述 PayPal 官方事件页没有为 REST refund 给出统一 `submitted → pending → succeeded/failed` 完整状态机，也没有统一客户最早/最晚到账窗口。不能把“eCheck 几天”扩展到所有退款方式。
- **confirmed — IPN refund 通知覆盖：** PayPal IPN 官方页明确覆盖 refunds 及相关交易事件，但未给 refund IPN 的单独到账/重发窗口之外的资金到达承诺。

### 2.3 Refund webhook 缺失/失败后的余额处理与替代路径

- **confirmed — IPN 缺失/延迟替代机制：** 对 IPN listener 未确认，PayPal 自动重发至多 4 天；官方警告消息可能丢失/延迟并要求 checkout 处理延迟。
- **confirmed — refund failed 的官方语义：** PayPal 将 `PAYMENT.REFUND.FAILED` 定义为退款失败，例如银行结算过程未发出退款。
- **unverified（unknown）— 余额及替代退款路径：** PayPal 官方公开页面未陈述 refund webhook 缺失/失败后商户余额如何处理、是否自动回补、是否自动重试退款、或客户可采用的替代退款路径；不以 Stripe 的余额规则类推。

### 2.4 Dispute 最终性/申诉/不可逆

- **confirmed — 事件存在：** PayPal webhook 表列出 `CUSTOMER.DISPUTE.CREATED` 与 `CUSTOMER.DISPUTE.RESOLVED`。
- **unverified（unknown）— 最终性/申诉/不可逆：** 本切片官方材料没有给出 debit/dispute 的统一最终性窗口，也未给出可据以声称“申诉不可逆/终局不可撤销”的直接措辞；`RESOLVED` 仅是事件名/状态语义，不推定为法律或资金最终性。

### 2.5 Capture 过期/自动取消或自动退款

- **confirmed — authorization 期限/void：** PayPal Webhook Event Names 官方表明确：`PAYMENT.AUTHORIZATION.VOIDED` 可因 authorization 达到 **30 天有效期**而发生，也可因手动 Void Authorized Payment API 发生。
- **unverified（unknown）— 过期后的自动退款：** 该官方表述确认 void/cancel 语义，但没有说授权到期后会自动 refund 客户；因此自动退款为 unknown，不得由 void 推定。
- **unverified（unknown）— capture/authorize 其他期限：** 对不同资金来源、商户配置或 reauthorization 的更细分期限，本切片没有统一官方表格可据此外推；保留为 unknown。

## 对比表（只列已证实窗口）

| 维度 | Stripe | PayPal |
|---|---|---|
| 支付处理中 | 异步 PaymentIntent `processing` 最多“several days”；期间不能保证 | IPN 通常“almost instantly”，但可丢失/延迟；listener 未确认最多重发 4 天 |
| 支付成功/失败事件 | `payment_intent.succeeded` / `payment_intent.payment_failed` | capture `pending` / `completed` / `declined`；IPN 覆盖 completed/denied 等 |
| webhook/IPN 顺序或延迟 | 需处理重复/并发；生产自动重试最多 3 天，手动 15/30 天 | IPN 非实时、不同步，可丢失/延迟，自动重发最多 4 天 |
| 退款客户窗口 | 卡退款约 5–10 个工作日；失败回 Stripe balance 最多 30 天 | 统一客户到账窗口 unknown；eCheck pending 示例为“几天” |
| 退款余额路径 | 余额不足：卡 refund pending；失败额回 Stripe balance；可安排替代退款 | refund webhook 失败后的余额/替代路径 unknown |
| 授权/capture 期限 | 在线卡通常 hold 7 天；过期释放资金并 `canceled` | authorization 达 30 天有效期可 void |
| dispute 最终性 | unknown | unknown（仅有 created/resolved 事件） |

## 证据限制

- 访问日期统一为 **2026-09-22**；未记录页面内部的未来变更承诺。
- PayPal 页面中，IPN 属于官方明确标注的 legacy NVP/SOAP 通知机制；Webhook Event Names 是当前开发者文档中的事件表。两者语义不混用。
- “几乎即时”“several days”“a couple of days”均按官方原文保留，不擅自转换成小时/自然日/工作日。
- 未使用搜索结果摘要作为证据；sources.md 只列官方 URL。
