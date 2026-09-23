# S10 — PaymentIntent webhook delivery/read-back reconciliation

## 结论（截至 2026-09-22；仅 Stripe 官方公开资料）
本切片支持一个保守的收敛模型：**Webhook 是异步通知输入，不是外部效果完成证明；2xx 只证明 Stripe 已成功向端点发送该次 HTTP 请求。** 业务侧应以受签名验证的 event、`event.id` 去重、对象 ID + `event.type` 的重复/独立事件判别，以及在需要时用 API 读取同一 PaymentIntent 的最新状态共同构成审计记录。单次 event、单次 retrieve、或 webhook 2xx 都不能单独证明履约、银行入账、最终不可逆结算等外部效果。

证据状态使用：**verified**=官方文本直接支持；**inferred**=由官方文本合乎逻辑推导但未被原文直接承诺；**unknown**=官方材料未给出；**conflicting**=官方材料存在表述/适用范围差异；**inaccessible**=本切片未能访问或验证。

## 1. 事件重放与去重
- **verified**：Stripe 可能多次向 webhook 端点发送同一事件；官方建议记录已处理的 `event.id`，已记录则不再处理。事件不保证按生成顺序发送；不要以 `created` 判断顺序或是否已处理。
- **verified**：手动重新发送：Dashboard 适用于事件创建后 15 天内；Stripe CLI `stripe events resend` 适用于 30 天内。手动重发失败事件不会解除自动重试，即便返回 2xx。
- **verified**：在某些情形会生成两个独立 Event；官方给出的识别线索是 `data.object` 的对象 ID + `event.type`。这不是把两个不同 event.id 折叠成一个事件的充分业务规则，需保留二者并比较对象/版本/请求上下文。
- **inferred**：幂等消费键至少应有 `event.id`；对“不同 event.id、同 PaymentIntent、同 type”使用审查/业务幂等层，而非静默丢弃。事件处理应入队，先快速返回 2xx，再异步处理；这降低超时但不等于业务已完成。

## 2. API version 与 event version
- **verified**：Event 的 `api_version` 是创建事件时用于渲染数据的 Stripe API 版本；`data` 内容不变，该值不随当前 API 版本改变。
- **verified**：Event 创建时按事件发生时账户设置的 API 版本生成；请求中临时改变 API version 不改变已生成事件的结构。现有 Event 不会因账户版本后续升级而追溯改变；以较新版本 API 读取旧 Event 也不改其结构。
- **verified**：专门 webhook endpoint 可设置默认/最新 API 版本；发送到该 endpoint 的 Event 按 endpoint 指定版本构建（因此 endpoint/version 是事件消费契约的一部分）。
- **inferred**：reconciliation 必须持久化 `event.id`、`event.api_version`、接收端配置/期望版本、`event.created`、`data.object.id`、`event.type`，并按版本解析；不得把 webhook 事件 JSON 与当前版本 retrieve JSON 做无版本的全字段相等比较。
- **unknown**：本公开材料未给出“同一事件在不同 endpoint/API version 间所有字段如何逐字段映射”的保证，也未给出版本迁移期间具体字段差异清单。

## 3. event object 与 PaymentIntent retrieve 的一致性边界
- **verified**：Event 的 `data.object` 是相关 API 对象在事件中的定义；官方 API reference 说其信息与直接 retrieve 同一对象相同；对象属性发生改变时，`data` 还可能带变更字典。
- **verified**：但 Webhook 文档同时建议：事件中的对象定义可用于事件发生时逻辑，也可再从 API retrieve 以访问“最近最新”的对象定义。因此事件快照/事件版本与 retrieve 时点的当前资源不是同一时间点证明。
- **verified**：Event API 只能 retrieve 最近 30 天的事件；Event list 的数据按事件创建时 API version 渲染，而不是当前 API version 或请求 `Stripe-Version`。
- **inferred**：`event.data.object.id == retrieve.id` 是关联一致性必要条件之一；字段差异若来自合法后续更新、异步状态推进、expand/include、API version 或事件与读取之间的时间差，不应直接判为 Stripe 矛盾。应保存原始 event、read-back 响应、版本、读取时间并做字段级 diff。
- **unknown**：官方公开材料未定义 PaymentIntent webhook 与 immediate retrieve 的强一致性/线性化 SLA，也未定义一个通用“retrieve 看到的状态必须等于 event.data.object.status”的时间界限。

## 4. 投递窗口与业务状态收敛窗口
- **verified**：live mode 对端点尽量连续 3 天重试，频率递减；sandbox 中新建事件的投递会在几小时内重试三次。Workbench 可显示 Delivered/Pending/Failed、尝试 HTTP 状态码及下次待处理时间。
- **verified**：2xx 表示事件已成功发送到端点；不是“会计更新、履约、银行/网络效果已完成”的证明。官方示例明确要求在可能超时的复杂逻辑（如会计系统更新为已支付）前快速返回 200。
- **verified**：PaymentIntent `processing` 可能持续处理；异步支付方式可能需数日。`succeeded` 表示支付流程完成，官方生命周期指南称此时资金已存入账户、可放心履约；但 webhook 的运输与业务处理仍是另一条链。
- **inferred**：应分离两个窗口：`delivery_window`（Stripe 重试/重放仍可能到达）与 `business_convergence_window`（PaymentIntent 状态、异步支付处理、内部队列/履约完成及人工结论收敛）。官方只给出前者的 live/sandbox 重试上界式描述，未给后者统一 SLA。
- **unknown**：各支付方式、区域、账户配置下从 `processing` 到最终状态的统一最大时延；官方公开资料没有可泛化的单一数值。故不得据此设定跨场景硬超时。

## 5. update/cancel 错误与人工复核门
- **verified**：Update 不确认 PaymentIntent；某些属性更新可能要求再次 confirm，更新 payment_method 总是要求再次确认。Update 成功返回 PaymentIntent 对象，但这只是该请求的 API 结果。
- **verified**：Cancel 只允许在 `requires_payment_method`、`requires_capture`、`requires_confirmation`、`requires_action`，及少数 `processing` 情形；已取消后不会再产生额外扣款，任何操作会以错误失败；`requires_capture` 的剩余可捕获金额自动退款。已取消或不可取消状态，cancel 返回错误。生命周期指南补充：processing/succeeded 前通常可取消；特定异步方式在 processing 也可取消，但窗口有限且可能失败。
- **verified**：Stripe API 用 2xx 表示请求成功、4xx 表示因请求信息失败、5xx 表示 Stripe 服务器错误（罕见）；官方建议优雅处理所有 API 异常。API 幂等键可安全重试 POST；Stripe 保存首次结果（包括失败/500），同 key 后续返回相同结果，参数不一致会报错；key 可在至少 24 小时后自动清除。
- **inferred**：人工复核门应在以下任一情况触发：cancel/update 发生 4xx/5xx 或网络不确定；事件与 read-back 的对象 ID/版本/关键状态不一致；同一 PI 出现不同 event.id 的冲突状态；超过业务方设定的、且按支付方式定义的收敛窗口；或 cancel/update 后未观察到可解释的后续状态事件。复核门的通过条件应是证据包（原始 event、签名验证结果、event.id 去重记录、API 版本、retrieve 结果/时间、API 错误码与 request id、履约/退款账务记录），不是单个 2xx 或单个 retrieve。
- **unknown**：Stripe 没有在这些公开页面规定商户“人工复核”的统一阈值、自动化放行规则或最终外部结算证明字段。

## 推荐状态机（研究推论，非 Stripe 承诺）
1. 接收原始 body，验证签名；写入不可变 inbox（含 event.id/version/type/object id/created）。
2. 以 event.id 去重；不同 event.id 但同 PI/type 进入比较队列，不直接丢弃。
3. 快速 2xx 仅确认运输接收；异步 worker 解析与业务幂等。
4. 对需要“当前状态”的决策，再 retrieve 同一 PI；记录读取时间、请求 API version、expand/include；做字段级 diff，保留事件快照。
5. 仅当业务状态和外部效果证据满足本组织规则才放行；否则进入 pending/人工复核。`succeeded` 可作为 Stripe 文档层面的支付流程完成信号，但不能替代内部履约和账务对账。
6. 所有 POST update/cancel 使用稳定且语义正确的幂等键；对不可重试/状态非法错误不盲目重放，进入复核。

## 研究边界
仅检索/引用 `docs.stripe.com` 官方公开文档/API reference；未登录、未使用凭据、未执行 Stripe API 调用，也未读取或修改既有 A 线目录、其他研究产物、shared/P0、事故目录、D10/L12/D14/canonical/staging/140/tri-line/systemd/真实服务。没有把官方示例中的测试密钥当作凭据使用。
