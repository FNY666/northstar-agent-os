# A 线下一切片 S16：退款/争议终态证据分国家/网络补洞

- 访问日期：2026-09-22（Asia/Shanghai）
- 证据边界：仅使用 Stripe 官方 `docs.stripe.com` 与 PayPal 官方 `developer.paypal.com` / `www.paypal.com` 公开页面；未调用 API、未使用 key、未创建测试对象；未读取其他切片产物。
- 术语：**对象/事件**=平台或网络记录的状态；**客户可见**=客户钱包/银行/卡账单能观察到的状态；**商户账务**=平台余额/余额交易层。三层不得互相升级。
- 重要结论：Stripe 当前公开文档给出卡争议响应窗口的跨网络概括（通常 7–21 天）及 issuer 评估概括（通常 60–75 天），但没有在所查官方页面按 Visa/Mastercard/Amex 或国家给出可直接引用的逐网络/逐国 response、appeal、representment/second-presentment 数值；因此分表保留 `unknown`。

## 1. Stripe 卡网络/地区：响应、appeal、representment/second presentment

Stripe 的争议总览明确：收到 chargeback 后，商户通常有 **7–21 天，取决于卡网络** 的响应窗口；不在截止前响应会自动输掉且不能取回争议资金。Stripe 同页/生命周期页还说，提交证据后 issuer 通常有 **60–75 天，取决于卡网络** 来评估并决定结果。这里是 Stripe 的跨网络范围，不是各网络的固定期限。

|网络/覆盖（Stripe 官方实际覆盖）|地区/国家|dispute response deadline|appeal deadline|representment / second presentment deadline|三层证据结论|
|---|---|---|---|---|---|
|Visa|未按国家列出；官方理由码/证据页面覆盖 Visa|通常 7–21 天（Stripe 仅给跨网络范围，未给 Visa 固定日数）|unknown|unknown|对象/事件：`charge.dispute.created`/争议响应路径可见；客户可见：issuer 处理中的争议，具体网络终态由 issuer 决定；商户账务：未答复会失去争议资金。|
|Mastercard|未按国家列出；官方理由码/证据页面覆盖 Mastercard|通常 7–21 天（未给 Mastercard 固定日数）|unknown|unknown|对象/事件同上；客户可见与商户账务同上。|
|American Express|未按国家列出；官方理由码/证据页面覆盖 American Express|通常 7–21 天（未给 Amex 固定日数）|unknown|unknown|对象/事件同上；客户可见与商户账务同上。|
|Discover / JCB / 其他卡网络|所查 Stripe 争议证据页面未形成可逐网络 deadline 表；`how disputes work`提到 Visa、Mastercard、JCB 的早期欺诈预警，且提到 Amex/Discover inquiry，但没有本文所需逐网络 response/appeal/representment 数值|unknown（不能把 7–21 天范围升级为该网络定值）|unknown|unknown|对象/事件：仅确认所查页面存在相应网络/阶段描述；客户可见：unknown；商户账务：unknown，除一般争议 debit/资金恢复事件外不推定窗口。|
|国家/地区维度（美国、英国、欧盟、中国大陆、其他）|Stripe 所查官方争议页面未按国家给上述四类期限；页面的 country selector/价格或本地支付法域信息不构成卡网络 deadline|unknown|unknown|unknown|所有国家行均保留 unknown；不能用 Stripe Dashboard 账户地区、卡发行国或惯例推算。|

**网络阶段的防误读：** Stripe 说 American Express 和 Discover 最常使用 inquiry 初步阶段，Mastercard 和 Visa 已不再使用该阶段；墨西哥国内跨品牌争议会在正式争议前使用 inquiry。这是流程描述，不是 response/appeal/representment/second-presentment 截止日，故不填入期限列。

**终态/撤回：** Stripe 说明即使客户声称已撤回争议，商户仍需提交证据；撤回不必然加速 issuer 时间线，且争议中的 charge 在 issuer 判商户胜诉前不能退款。不得把客户撤回、`won`、`lost` 或 `closed` 推导成银行卡入账或固定网络 appeal 窗口。

## 2. PayPal 原生退款：客户可见层

PayPal 客服官方页描述的是 checkout 退款追踪器及支付方式时间，不是 API 对象状态的银行结算保证。其明确说退款回原支付方式；若无法入原方式或选择余额，可能进入 PayPal balance。

|资金来源|对象/事件（平台/追踪器）|客户可见|商户账务|
|---|---|---|---|
|信用卡|Refund Initiated → Refund Processing → Refund Sent → Refund Pending → Refund Completed（PayPal 客服页的三步追踪器文字）|Refund Sent 仅表示 PayPal 已处理并发给发卡行/银行，官方明确说此时退款**尚未完成**；信用卡入账最多 1–2 个 billing cycles（约每周期 28–31 天，具体由发卡行）；不能把 API refund `COMPLETED` 直接升级为客户已入账|本页没有独立商户余额入账窗口；unknown|
|借记卡|同一追踪器；无法入借记卡时 PayPal 会加到 PayPal balance|一般最多 5 个工作日；依卡公司可能最多 30 天；仍应以卡/银行可见为准|没有独立商户余额窗口；unknown|
|银行账户|同一追踪器|通常退款发出后最多 5 个工作日；某些支付状态可能最多 30 天|没有独立商户余额窗口；unknown|
|PayPal balance|无银行清算等待的客户层陈述|使用余额支付时，退款同日回 PayPal Balance；余额+信用卡时余额部分同日、卡部分 1–2 billing cycles|客户余额变化不等于商户结算/商户 balance transaction；商户侧独立窗口 unknown|
|退款失败|PayPal 开发者官方 webhook 表直接定义 `PAYMENT.REFUND.FAILED`：退款失败，例如银行结算过程未能发出退款；`PAYMENT.REFUND.PENDING`可因 eCheck 从商户银行账户处理需几天|失败不能表示客户收到钱；pending 不能表示客户已入账；客户页的 `Refund Completed`也应以原方式实际可见为准|商户必须将失败作为失败回流候选并核对余额/对象；官方所查页面未给独立余额回流日数，unknown|

**严格区分：** PayPal developer 的 refund/capture API 文档只定义对象/接口语义，不能替代客户银行入账证据；即便对象状态为 `COMPLETED`，在本切片中也不生成“银行已入账”结论。

## 3. Balance 层

### Stripe

Stripe `Balance Transaction` 对象直接定义：`amount` 是交易金额，`fee` 是费用，`net` 是对 Stripe balance 的净影响；`status` 只有 `available` 或 `pending`；`available_on` 是可用时间戳；`source` 关联 Stripe 对象；类型枚举包含 `charge`、`refund`、`refund_failure`、`payment_refund`、`payment_failure_refund`、`dispute`/相关 dispute 类型等（页面的完整枚举很长）。因此：

- 正常成功收款：balance transaction 的正/负 `net` 与 `status`/`available_on`是商户账务证据；客户卡/银行入账仍 unknown。
- 正常退款：`refund` / `payment_refund` 等 balance transaction 可证明 Stripe balance 发生扣减；不证明客户原支付方式已收到。
- 失败回流：`refund_failure` / `payment_failure_refund` 等类型可证明 Stripe 余额层的失败回流分类；官方所查对象页没有一个对所有失败方式适用的独立客户可见/余额恢复时间窗口，故时间 unknown。
- 争议 debit / 资金恢复：争议创建及 dispute 相关 balance transaction 可产生商户余额扣减；Stripe 事件类型页直接列 `charge.dispute.created`、`charge.dispute.closed`（状态变化为 lost/warning_closed/won）及 `charge.dispute.funds_reinstated`（争议关闭后资金恢复）。这些是商户账务/对象事件，不是客户银行入账。具体可用时间仍以 balance transaction 的 `available_on`/`status`为准；没有统一窗口则 unknown。

### PayPal

本次仅在 PayPal 官方客户页确认：退款通常回原支付方式，不能入原方式或选择余额时可进 PayPal balance；以及开发者 webhook 对退款 pending/failed、capture completed/refunded/reversed 的事件语义。所查公开官方页面没有一个可直接引用、与某个具体 merchant balance ledger transaction 一一对应的独立资金可用窗口，也没有给出失败回流或争议 debit 的统一日数。因此 PayPal balance 层：

- 正常成功：只确认客户余额支付退款同日回 PayPal Balance；**不升级**为商户余额入账或 payout 可用。
- 失败回流：`PAYMENT.REFUND.FAILED`确认失败事件，具体商户 balance 回流时间 unknown。
- 争议 debit：本次所查 PayPal 一手公开页未提供可直接引用的 merchant balance dispute debit 及独立窗口，unknown。

## 4. Capture 过期与取消/void

### Stripe PaymentIntent

Stripe 官方 Cancel a PaymentIntent 页直接写：可取消状态包括 `requires_payment_method`、`requires_capture`、`requires_confirmation`、`requires_action`，罕见时 `processing`；取消后不会再由该 PaymentIntent 产生额外扣款，后续操作失败；对 `requires_capture` 的 PaymentIntent，剩余 `amount_capturable` 会**自动退款**。对象字段包括 `status=canceled`、`canceled_at`、`cancellation_reason`（可选值 duplicate、fraudulent、requested_by_customer、abandoned）；官方事件类型页定义 `payment_intent.canceled` 为 PaymentIntent 被取消。

三层：对象/事件=PaymentIntent canceled + `canceled_at`/`cancellation_reason`/`payment_intent.canceled`；客户可见=取消或对未捕获金额退款的后续支付方式可见状态，官方没有一刀切到账时间；商户账务=requires_capture 的 remaining capturable 自动退款这一点是官方直接陈述，具体 balance transaction 可用时点仍需对象/余额交易，未给统一窗口。这里的“自动退款”仅适用于上述 `requires_capture` PaymentIntent；不能从任意 capture 到期推断。

另：PaymentIntent 对象的 `capture_before` 字段说明手动 capture 时，过该 future timestamp 后 charge 会自动退款（该字段语义是直接证据）；不要把它扩大为所有付款方式或国家的同一日数。

### PayPal authorization

PayPal 官方 webhook 事件页直接写：`PAYMENT.AUTHORIZATION.VOIDED` 表示授权因达到 **30-day validity period** 而 void，或因手动调用 Void Authorized Payment API 而 void；关联授权对象响应 `status=voided`。这证明授权终态/事件及两种触发原因。

三层：对象/事件=`PAYMENT.AUTHORIZATION.VOIDED`、authorization `status=voided`；客户可见=授权被取消/释放，但本页没有保证客户银行何时显示释放，也没有自动 refund 陈述；商户账务=授权未 capture 的 void 不是退款交易，所查页面没有独立 balance 回流窗口，unknown。

**禁止推定：** Stripe PaymentIntent canceled、Stripe capture_before 到期、PayPal authorization void/30-day expiry 都不能仅凭 release/void 推导“自动退款”；Stripe 只有 `requires_capture` cancel 的明确自动 refund 句子，PayPal authorization void 页面没有这种自动退款句子。

## 5. 未覆盖/保留 unknown 的清单

1. Visa、Mastercard、Amex 按国家的固定 response deadline：unknown；官方只给跨网络通常 7–21 天。
2. 各网络 appeal deadline：unknown。
3. 各网络 representment/second-presentment deadline：unknown。
4. PayPal API refund 对象 `COMPLETED` 到银行卡/钱包最终可用的统一保证：unknown；客户层按 funding source 的官方时间只能作为可见层指引。
5. Stripe/PayPal merchant balance 对失败回流、争议 debit 的统一独立时间窗口：unknown。
6. PayPal authorization void 后自动 refund：unknown/不作推定。
7. 任何页面没有直接陈述的国家、发行行、清算行、周末/节假日、币种特例：unknown。
