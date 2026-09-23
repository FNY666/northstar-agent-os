# A 线下一切片 S15：平台退款/争议“客户可见入账”与商户账务终态分层证据

**研究截止/访问日期：2026-09-22**  
**证据范围：**仅 Stripe 官方文档（docs.stripe.com）与 PayPal 官方开发者/帮助文档（developer.paypal.com、www.paypal.com）。未调用 API、未使用 key、未创建测试对象；未读取 S11–S14。

## 0. 结论口径

“退款成功”不能直接当作客户已经看到入账，也不能直接当作商户 Stripe/PayPal 余额已经最终回流。本文将每一事实拆为：

1. **平台退款对象/事件终态**：Refund 对象或 PayPal refund/capture 状态及 webhook；
2. **客户可见账单/银行到账**：发卡行、银行或 PayPal 钱包侧可见时间；
3. **商户账务**：Stripe balance 或 PayPal 资金来源/余额的扣回、回流、失败返还。

未见官方直接窗口或直接断言，记为 **unknown（语义=unknown）**，不以行业惯例补全。

## 1. Stripe：退款三层证据

### 1.1 通用卡退款

| 层 | 官方直接陈述 | 结论 |
|---|---|---|
| Refund 对象终态 | Stripe Refund 对象有 `pending`、`succeeded`、`failed` 等状态；卡退款在可用余额不足时可保持 pending，其他支付方式余额不足时失败。 | 以 Refund 对象状态为平台层终态；`succeeded` 不等同于客户账单已显示。 |
| 客户可见账单 | Stripe：成功退款在客户银行账单上的出现是实时的，取决于卡网络和发卡行；另一个追踪退款段落明确称客户约 **5–10 个工作日**后看到退款，取决于银行。短期退款可能作为 reversal，原始扣款从账单消失而非单独 credit。 | **约 5–10 个工作日**是 Stripe 对一般卡退款的官方 customer-visible 窗口；实时陈述体现网络/发卡行差异，不能精确到单一固定时间。reversal 不是另一次入账。 |
| Stripe balance | 若银行/发卡行无法处理而退款失败，银行把金额退回 Stripe，Stripe 加回 Stripe account balance；该过程可从请求退款起 **最多 30 天**。 | 这是失败退款金额回到 Stripe balance 的窗口，不是正常成功退款的结算窗口；正常成功退款何时从 balance 扣出/最终入账，页面未给统一窗口，**unknown**。 |

来源：S1、S2、S3。

### 1.2 ACH Direct Debit（美国银行账户）

| 层 | 官方直接陈述 | 结论 |
|---|---|---|
| Refund 对象终态 | ACH 退款异步，完成最多 **3 个工作日**；成功时 Refund 状态转 `succeeded`，失败时转 `failed`，金额返还 Stripe balance。`refund.updated` 或 `refund.failed` 通知最终状态。 | `succeeded`/`failed` 是平台层；ACH refund 不能取消。 |
| 客户可见账单 | ACH 退款总是作为客户银行账户的单独 credit，不是 reversal；账单不会明确标为 refund，而是引用原支付 statement descriptor。页面未给该 credit 出现的独立银行可见窗口。 | **unknown（语义=unknown）**；“最多 3 个工作日”是退款处理时间，不擅自等同于银行账面可见。 |
| Stripe balance | 失败时 Stripe 将金额返还 Stripe balance；正常成功退款扣款/回流时点未给独立窗口。 | 正常成功的 balance 终态时点 **unknown**；失败返还属于上述失败路径。 |

来源：S4。

### 1.3 SEPA Direct Debit（欧元区/SEPA）

| 层 | 官方直接陈述 | 结论 |
|---|---|---|
| Refund 对象终态 | Stripe 页面说明可退款；通用 Stripe Refund 对象状态仍以 `pending`/`succeeded`/`failed` 等为平台状态。SEPA 页面没有另列一个不同的 Refund 枚举。 | 不把银行到账当作 Refund `succeeded`；事件/对象字段需单独核验。 |
| 客户可见账单 | SEPA 退款通常 **3–4 个工作日处理**，资金在客户账户内 **5 个工作日内到达**；以原付款 statement descriptor 为 reference，不一定标为 refund。 | 官方给出的客户银行到账窗口：**within 5 business days**；处理窗口另为 3–4 个工作日。 |
| Stripe balance | SEPA 页面未给正常退款从/回 Stripe balance 的独立窗口；退款失败时适用 Stripe 通用失败返还规则。 | 正常成功 balance 结算窗口 **unknown**。 |

来源：S5、S3。

### 1.4 Bacs Direct Debit（英国）

| 层 | 官方直接陈述 | 结论 |
|---|---|---|
| Refund 对象终态 | Bacs refund 通常 **3–4 个工作日处理**；可在 Dashboard 或 Refund object 的 `status` 观察。原始支付仍 processing 时，refund 仅在 Charge 成功后开始；Charge 失败则 Stripe 取消 pending refund。 | 处理中的 pending 与最终 status 分开；页面未为 Bacs 单列完整状态枚举。 |
| 客户可见账单 | 页面只陈述“通常 3–4 个工作日处理”，并要求告知客户该预计处理时间；没有另给银行账单可见时间。 | **unknown（语义=unknown）**；不把处理时间直接升级成可见入账时间。 |
| Stripe balance | 正常成功退款的 Stripe balance 扣回/回流时间未给；Bacs 争议发生时 Stripe 从 balance 扣争议金额及费用。 | 正常成功退款 balance 窗口 **unknown**。 |

来源：S6、S3。

### 1.5 Stripe PayPal payment method

| 层 | 官方直接陈述 | 结论 |
|---|---|---|
| Refund 对象终态 | Stripe PayPal 页面未列 Stripe Refund 的 PayPal 专属状态或客户侧完成事件；通用 Refund 对象状态页面适用。 | PayPal 退款不能由该页面推定为某个“客户已入账”状态。 |
| 客户可见账单/钱包 | Stripe PayPal 页面仅说明 PayPal payment 可在原支付后 **180 天内**退款；未给退款客户可见到账窗口。 | **unknown（语义=unknown）**。 |
| 商户账务 | Stripe 根据 settlement preference 使用 Stripe balance 或 PayPal balance/PayPal 账户可用资金退款。 | 资金来源有官方陈述；正常从哪一余额何时最终扣回/回流的时间窗口未给，**unknown**。 |

来源：S7。

### 1.6 Stripe refund 与商户余额的边界

- Stripe refund 使用 available Stripe balance，不含 pending amount；余额不够时，**卡交易退款可 pending**，其他支付方式退款失败。这是平台账务可启动/挂起规则，不是客户银行入账时间（S3）。
- `failed` 路径：银行将金额返给 Stripe，Stripe 加回 Stripe account balance，最多 30 天（S3）。该事实不能反向证明每个成功退款都会在某一固定天数回流。

## 2. PayPal Payments v2 REST Refund 与 webhook 对照

### 2.1 REST 资源/字段

PayPal Payments v2 官方 API reference 将退款建模为“Refund captured payment”，并提供 `GET /v2/payments/refunds/{refund_id}` 查看退款；权威 schema 的 `refund_status` 枚举为：

`CANCELLED`, `FAILED`, `PENDING`, `COMPLETED`。

PayPal Payments v2 schema 的 capture 状态枚举为：`COMPLETED`, `DECLINED`, `PARTIALLY_REFUNDED`, `PENDING`, `REFUNDED`, `FAILED`。这里的 `PARTIALLY_REFUNDED`/`REFUNDED` 是 capture 状态，不是另造一个 `SUCCEEDED` 退款状态。schema 未列退款状态 `SUCCEEDED`。

### 2.2 webhook 对照（Payments v2）

| webhook | 官方描述/对应 | 是否是退款对象 COMPLETED 事件 |
|---|---|---|
| `PAYMENT.CAPTURE.COMPLETED` | payment capture completes | 否，capture 事件 |
| `PAYMENT.CAPTURE.REFUNDED` | merchant refunds a payment capture | 否，capture refund 关系事件；不应改写成 refund `COMPLETED` |
| `PAYMENT.REFUND.PENDING` | refund status changes to pending | 否，是 refund pending 事件 |
| `PAYMENT.REFUND.FAILED` | refund failed（示例：银行结算失败） | 否，是 refund failed 事件 |
| `PAYMENT.CAPTURE.REVERSED` | PayPal reverses a payment capture | 否，capture reversal 事件 |

**缺口/严格结论：**官方 webhook event-names 页面在 Payments v2 列出 `PAYMENT.REFUND.PENDING`、`PAYMENT.REFUND.FAILED`，并列出 `PAYMENT.CAPTURE.REFUNDED`；未在该官方列表中列出 `PAYMENT.REFUND.COMPLETED` 或 `PAYMENT.REFUND.SUCCEEDED`。因此“存在 `COMPLETED`/`SUCCEEDED` 级退款 webhook 事件”不能确认；REST refund 资源的 `status=COMPLETED` 是对象字段终态，不等价于一个同名 webhook。不要把 capture/refund 事件混写为客户已入账。

来源：P1、P2、P3。

## 3. dispute/debit 申诉期限、resolution/appeal 可逆性

### 3.1 Stripe 各支付方式（不跨方式合并）

| 支付方式/场景 | 官方期限 | resolution/appeal 可逆性 |
|---|---|---|
| 一般卡 dispute | 商户收到争议后响应窗口通常 **7–21 天**，取决于卡网络；逾期自动输掉且不能取回争议资金。Stripe 的提交证据动作在页面称 response final，提交后不能修改/补充；输争议时退款永久。 | 官方直接文本支持“提交后不能改”和“lost 时 refund permanent”；不据此推导所有网络的统一 appeal 规则，其他网络/国家为 **unknown**。 |
| ACH Direct Debit | 客户自购买日起最多 **60 个日历日**提出争议；每笔仅能争议一次。 | 页面未给 resolution 后商户 appeal/逆转机制，**unknown**。 |
| SEPA Direct Debit | 扣款后 **8 周内**“no questions asked”且自动受理；8 周后至 **13 个月**仅可因 unauthorized 向银行争议。 | SEPA dispute final，**no process for appeal**；成功争议后若要客户返还，必须客户重新付款。 |
| Bacs Direct Debit | 无固定时限；客户可在无限期内通过银行争议，每笔仅一次。 | Bacs dispute final，**can’t be appealed**；不可提交证据或 counter。 |
| Stripe PayPal payment method | 客户可在购买日起 **180 个日历日**内在 PayPal 提争议；也可能通过完成 PayPal 购买所用的银行/支付方法争议。向 Stripe 提证据期限为 **2–19 个日历日**，取决于争议类别；PayPal 目标在证据提交后 30 日内作决定。 | 某些情况下 PayPal 允许输争议 appeal；Stripe 当前不支持 appeal，应转 PayPal；在 PayPal 最终 resolution 前，争议在 Stripe 保持 open。不可把其写成必然可逆。 |

来源：S4、S5、S6、S8、S9、S10。

### 3.2 PayPal 官方消费者帮助（独立于 Stripe PayPal payment method 的边界）

PayPal 官方帮助页说明：争议若未升级，**20 天后自动关闭**；closed dispute 不能重新打开或升级为 claim。该文本是 PayPal Resolution Center 的消费者流程证据，不外推为所有 PayPal Payments v2 merchant refund/capture 状态，也不覆盖 Stripe 代收 PayPal 的全部争议路径。

来源：P4。

## 4. Capture 过期：release/void/cancel 与自动退款严格分开

### 4.1 Stripe

Stripe place-a-hold 页面明确：授权过期前未 capture，资金被释放，payment status 变为 `canceled`。这是**释放授权/取消未捕获支付**，不是对已 capture 交易发起 refund。

Stripe Refund 文档另明确：`requires_capture` 的 PaymentIntent 所挂 Charge 尚未 capture，不能直接 refund，必须 cancel PaymentIntent。该 cancel 路径属于取消/释放，不是自动退款。

Stripe 页面并未在上述直接文本中说“授权过期会自动创建退款对象”或“自动退款给客户”。因此：

- 释放/取消：**confirmed**（未捕获、授权过期路径）；
- 自动退款：**unknown（语义=unknown）**，不补全为 yes。

来源：S11、S3。

### 4.2 PayPal

PayPal Payments v2 官方 reference 明确存在：

- `POST /v2/payments/authorizations/{authorization_id}/void`：voids/cancels an authorized payment；
- capture refund 是另一个操作：`POST /v2/payments/captures/{capture_id}/refund`；
- webhook `PAYMENT.AUTHORIZATION.VOIDED` 的描述明确包括 authorization 到达 **30 day validity period** 或被手动 void；
- `PAYMENT.CAPTURE.REFUNDED` 是已 capture 后退款事件，不能与 authorization void 混淆。

因此 PayPal “授权到期/void”是释放或取消授权层事件；已 capture 后退款是另一条资源/事件链。官方材料未直接陈述 authorization 过期会自动创建 refund 或自动把款退回客户，因此：

- void/到期释放：**confirmed**；
- 自动退款：**unknown（语义=unknown）**。

来源：P1、P2。

## 5. 终态分层操作规则

1. 只有 Refund 对象/PayPal refund `status` 和其官方 webhook，才写“平台退款对象终态”。
2. 只有银行/发卡行/PayPal 官方明确到账或账单描述，才写“客户可见入账”；Stripe 卡的 5–10 个工作日、SEPA 的 within 5 business days 是各自页面窗口，不能迁移给 ACH/Bacs/PayPal。
3. 只有 Stripe balance 或 PayPal 资金来源的直接陈述，才写“商户账务”；失败返 Stripe balance 的最多 30 天不等于成功退款的固定回流窗口。
4. `capture expired → released/voided/canceled` 不等于 `refund created`；未有自动退款直接陈述时保持 unknown。
5. PayPal `refund.status=COMPLETED` 是 REST 对象字段；官方 webhook 列表并没有据此推出 `PAYMENT.REFUND.COMPLETED`/`SUCCEEDED` 事件，故必须与 `PAYMENT.CAPTURE.REFUNDED`、`PAYMENT.REFUND.PENDING`、`PAYMENT.REFUND.FAILED` 分开记录。

## 6. 未确认项（明确留白）

- Stripe ACH/Bacs/PayPal 的客户银行/钱包可见入账独立窗口：unknown（各官方页面没有对应窗口）。
- Stripe 正常成功退款何时最终体现在 Stripe balance 的统一时间窗口：unknown。
- PayPal REST refund `COMPLETED` 后客户何时可见钱包/原资金来源入账：unknown。
- 一般卡不同 issuer/network 的更细分差异表（仅官方总述为实时依网络/发卡行、约 5–10 工作日）：unknown。
- 各国/各卡网络 dispute resolution 后的统一 appeal/可逆规则：unknown；仅记录官方明确到的支付方式/路径。
