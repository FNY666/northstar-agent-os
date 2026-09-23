# A 线下一切片 S13：Stripe 逐支付方式证据矩阵

- **访问日期**：2026-09-22
- **证据边界**：仅使用 `docs.stripe.com` 官方公开文档；未调用 Stripe API、未使用 key、未创建测试对象。
- **方法代表**：bank debit = ACH Direct Debit、SEPA Direct Debit、Bacs Direct Debit；bank redirect = iDEAL | Wero；voucher = Konbini；BNPL = Klarna。
- **判定规则**：官方页面直接陈述为 confirmed；由官方表格/文字作出的有限解释标为 inferred；官方页面未给出该字段的明确语义标为 unknown。`unknown` 不表示相反结论。

## 矩阵

| 支付方式 | Refund 到账/处理时间 | Refund 失败/取消语义与通知 | Delayed failure / 失败通知机制 | Mandate / 扣款授权 | Finality / 不可逆性 | Capture / 自动取消 |
|---|---|---|---|---|---|---|
| **ACH Direct Debit** | 最迟自原支付 180 天内提交；异步，最多 3 个工作日完成。退款是客户银行账户的**单独 credit**，不是 reversal；账单不明确标为 refund（引用原 payment descriptor）。**confirmed** | Refund 不能取消。Stripe 通过 `refund.updated` 或 `refund.failed` webhook 通知最终状态；成功为 `succeeded`；失败为 `failed`，金额退回 Stripe balance，商户须另行退款。Stripe 等原支付成功后才提交 refund。**confirmed** | 是 delayed notification payment method，最多 4 个工作日收到成功/失败确认；expected debit date 是估计值而非保证，并可在 `charge.updated`/`charge.succeeded`/`charge.failed` 中出现。**confirmed** | 扣款前必须取得客户授权/mandate；Stripe-hosted 前端可代收并记录，custom form 需展示所需 mandate 文案。客户可随时向商户或银行取消，取消使未来扣款请求无效，继续收款需新 mandate。**confirmed** | ACH dispute 在官方所述适用窗口内是 final、不可通过 ACH network challenge；官方也称所有 ACH Direct Debit disputes final、无 appeal。这里是**争议最终性**，不是所有成功支付均不可逆。**confirmed + caveat** | 官方能力段列出 Payment captures/Manual capture 等标签但未给出本页可核验的逐项值；本页未明确“未 capture 自动取消”规则。**unknown** |
| **SEPA Direct Debit** | 退款通常 3–4 个工作日处理，客户账户内 5 个工作日内到账；须在原支付 180 天内提交；以原 descriptor 引用的 credit 入账而非明确标为 refund。**confirmed** | 官方页未明确列出 SEPA refund failed webhook、失败后余额处理或 refund 自动取消语义。若原支付仍 processing，官方仅明确应等原支付 fully settled 后退款；其余 **unknown**。 | reusable、delayed notification；大多数失败发生在发起后 6 个工作日内；提交后有 5 个工作日 refusal window；少数可在此后以 dispute 形式失败。失败时 Stripe 从 balance 立即移除资金；以 Charge failure code/message 提供原因。**confirmed** | 必须收集 mandate，授权 Stripe 代表商户扣款；可生成并呈现 mandate。客户可随时通过商户或银行取消，未来请求无效；Stripe 仅在一次支付失败后得知取消并将 mandate inactive、发 `mandate.updated`。**confirmed** | SEPA Direct Debit disputes 为 final、无 appeal；8 周内“no questions asked”，8 周至 13 个月仅未授权情形。这里是争议最终性，不等于普通支付不可逆。**confirmed + caveat** | Manual capture support = No（官方 payment-method properties 表）；未找到“capture 未发生时自动取消”这一明确表述。**confirmed（不支持 manual capture）/ unknown（自动取消）** |
| **Bacs Direct Debit** | 须在原支付 180 天内提交；通常 3–4 个工作日处理；退款在 Bacs scheme 之外由 Stripe 提供；因 indefinite indemnity period，退款后仍可发生 dispute，可能同时损失 disputed 与 refunded 金额。**confirmed** | 原支付仍 processing 时发起 refund：仅在 Charge succeeds 后开始；若 Charge fails，Stripe 取消 pending refund，因为银行账户从未被扣款。官方页未给出独立 refund failure webhook/到账失败语义。**confirmed（pending refund cancel）+ unknown（其他 failure）** | 已有 mandate 时成功/失败确认需 4 个工作日；新 mandate 最多 7 个工作日。支付被 Stripe 标记 successful 后银行仍可能报告 failure，此时作为带原因码的 dispute。失败可启用自动 retry：最多 2 次且不超过原尝试后 30 天。**confirmed** | 必须收集 Bacs Direct Debit Instruction (DDI/mandate)，授权一次性及 recurring 扣款；Stripe 记录业务名、接受信息、mandate reference。客户可随时向商户或银行取消，未来扣款无效，继续收款需新 mandate。**confirmed** | Bacs disputes 可无限期提出，且 final、不可 appeal；不能提交 evidence/counter。此为 dispute finality，不代表支付一般不可逆。**confirmed + caveat** | 官方能力段列出 Payment captures/Manual capture 等标签但未给出逐项值；本页未明确“未 capture 自动取消”规则。**unknown** |
| **iDEAL | Wero** | 最多可在原支付 180 天内 refund；refund 可 pending 最长 7 天；7 天后未收到 failure signal，则视为成功。**confirmed** | 官方明确的失败判断是：7 天内收到 failure signal 则不满足“视为成功”；未进一步规定失败后的余额退回、webhook 或替代退款路径。**confirmed（failure signal 条件）+ unknown（后续语义）** | 不适用：本页将其描述为 authenticated bank transfer；未发现本支付方式 mandate/扣款授权要求。**confirmed（不属于 debit mandate 流程）** | iDEAL/Wero payment 是客户跳转银行并用第二因素认证；官方 payment properties 的 Dispute support = No。但官方未将其表述为支付绝对不可逆，故 finality = **unknown**。 | Manual capture support = No；未发现额外“自动取消”规则。**confirmed（不支持 manual capture）/ unknown（自动取消）** |
| **Konbini** | 官方表格标明 Refunds / Partial refunds = Yes / Yes，但退款完成需客户提供收款账户信息；Stripe 联系 PaymentIntent 确认时的 email，向客户索取信息后自动处理。到账时间未给出。**confirmed（流程）/ unknown（时间）** | 官方页未明确 refund failure、失败通知、失败后金额处理或自动取消语义。**unknown** | 客户在便利店现金付款后，官方流程写明“Receives notification that payment is complete”；未找到 delayed failure、失败时间窗或 failure webhook 的明确表述。**confirmed（完成通知）/ unknown（失败）** | 不适用：现金型 payment method；未发现 mandate/扣款授权要求。**confirmed（非 debit mandate）** | Payment properties 的 Dispute support = No；未找到“payment final/不可逆”的直接表述，故 **unknown**。 | Manual capture support = No；未发现未 capture 自动取消规则。**confirmed（不支持 manual capture）/ unknown（自动取消）** |
| **Klarna** | 可在支付完成后 180 天内退款；Klarna 取消 refunded charge 的剩余分期并退回已支付金额；通常 5–7 个工作日，可能因金融机构/购买类型更久。支持全额、部分、多次部分退款。**confirmed** | 若支付已升级为 dispute，Klarna 不支持退款。官方页未明确一般 refund failed webhook、失败到账后续或自动取消。**confirmed（dispute 限制）+ unknown（一般失败）** | 未找到该方法页对 delayed payment failure、失败时间窗或 failure notification 的直接表述。**unknown** | 不适用：BNPL；未发现本方法要求商户采集 debit mandate。**confirmed（非 debit mandate）** | Payment properties 的 Dispute support = Yes；官方未给出 Klarna 支付一般“最终性/不可逆性”声明，故 **unknown**。 | Manual capture support = Yes。另一个官方“Place a hold…”页列出 Klarna：授权阶段若有首付款则在未 capture 时退款，须在 30 天内 capture balance；该通用页未说明所有 Klarna 配置均适用，故按**条件性 confirmed**记录，不扩展为普遍自动取消。 |

## 关键限定

1. “最终性”严格拆成两种：官方明确的 **direct-debit dispute final / no appeal**，以及支付本身的绝对不可逆性。前者不能推出后者。
2. “退款处理/到账时间”只记录 Stripe 页面明确给出的时间；页面未给出时保留 unknown。
3. iDEAL 的“7 天后无 failure signal 即视为成功”是退款状态语义，不应改写成原支付不可逆。
4. Bacs/SEPA/ACH 均可能在支付被标记成功后出现银行侧争议/失败语义；不要把 Stripe 账户中的成功展示当作银行端无条件最终结算。

## 来源

完整 URL、摘要、日期见 `sources.md`；manifest 中每一条 claim 均带对应官方 URL、支持说明与 caveat。
