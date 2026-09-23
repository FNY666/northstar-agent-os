# S9 研究报告：Stripe PaymentIntent 单一目标资源状态机与 webhook/read-back 窗口校准

- 研究切片：A 线 S9（独立公开研究）
- 资源：`PaymentIntent`（单一目标资源）
- 资料范围：仅 Stripe 官方公开文档（`docs.stripe.com`）；未调用 Stripe API、未使用凭据、未读取任何既有 A 线目录或本地研究产物。
- 研究日期：2026-09-22（Asia/Shanghai）
- 证据标签：**verified** = 官方原文直接支持；**inferred** = 由 verified 规则组合出的工程模型/建议；**unknown** = 官方公开资料未给出；**conflict** = 同一主题存在需以具体版本/上下文解决的差异。

## 1. 结论先行

1. **verified**：PaymentIntent 的 Stripe 对象 `status` 枚举为 `requires_payment_method`、`requires_confirmation`、`requires_action`、`processing`、`requires_capture`、`canceled`、`succeeded`。`processing` 只表示正在处理，不是成功；`requires_action` 需要客户额外动作；`requires_capture` 已确认但待 capture。
2. **verified**：创建/确认/更新等 API HTTP 请求的返回，只能证明该请求的 API 处理结果；Stripe 明确建议遇到连接错误时 retrieve 对象并检查 status。Webhook 端点快速返回 2xx 是投递确认，不等于本地业务副作用完成。
3. **inferred**：本切片将四个内部里程碑分开：`accepted`（写入请求得到明确 API 响应或安全重试被接纳）、`observed`（对同一 PaymentIntent 的 read-back 看到状态/版本）、`settled`（Stripe 资源进入终态）、`external_effect_committed`（本地/外部业务账本在去重后提交副作用）。四者不是 Stripe 的字段或承诺。
4. **verified**：live webhook 自动投递失败时，Stripe 最多重试三天并指数退避；sandbox 在数小时内重试三次。事件顺序不保证。Dashboard 可在事件创建后最多 15 天 Resend，Stripe CLI 可在最多 30 天 `stripe events resend`；手工 resend 不会取消原自动重试。
5. **unknown**：Stripe 公开资料没有为“业务 read-back 窗口”规定统一秒数、轮询次数、或“某个 2xx/单 webhook 即完成”的规则。窗口必须是调用方的显式策略，并受业务风险、支付方法和 webhook 投递窗口约束。
6. **verified**：所有 POST 接受 Idempotency-Key；Stripe 保存同一 key 第一次请求的 status code 和 body，并比较后续请求参数；参数不一致会产生幂等错误。GET/DELETE 发送该 key 没有效果。由此不能声称 exactly-once，也不能声称无重复副作用。

## 2. 资源操作面与字段

### 2.1 Retrieve

- **verified**：`GET /v1/payment_intents/:id` 返回 PaymentIntent；可使用 publishable key + client secret 做受限的 client-side retrieve，返回属性子集。服务端 read-back 应使用合适的服务端认证上下文（本报告不执行请求）。
- **inferred**：read-back 的键必须是同一个 PaymentIntent ID；不要以 webhook 到达顺序或客户端 UI 结果替代对象读取。记录读取时的 `id`, `status`, `amount_received`, `amount_capturable`, `latest_charge`, `last_payment_error`, `canceled_at`, `livemode` 和 API 请求 ID（若响应/SDK提供）。

### 2.2 Update

- **verified**：`POST /v1/payment_intents/:id` 更新属性但不确认；更新某些属性可能要求重新 confirm，更新 payment method 总是要求再次确认。POST 应带本次逻辑操作唯一的 Idempotency-Key。
- **inferred**：更新响应的 2xx 只代表该更新请求被 Stripe 接受/返回对象；若更新触发后续异步处理，仍须以 read-back 和适配事件观察最终状态。

### 2.3 Delete / Cancel

- **verified**：PaymentIntent 没有常规 DELETE 资源操作；官方提供 `POST /v1/payment_intents/:id/cancel`。可取消状态包括 `requires_payment_method`、`requires_capture`、`requires_confirmation`、`requires_action`，以及少数情况下的 `processing`；已取消后不会再由该 PaymentIntent 产生额外 charges，后续操作失败。`requires_capture` 取消时剩余 `amount_capturable` 自动退款。已取消或不可取消状态会报错。
- **inferred**：在状态机中将“删除”建模为不可逆的 `canceled` 终态转换，而不是把记录物理删除。取消请求同样使用唯一幂等键并以 read-back 确认；不要将取消 endpoint 的 2xx 直接解释为本地订单已完成/已关闭。

### 2.4 关键对象字段

- **verified**：官方对象示例和属性表包含 `status`, `amount_received`, `amount_capturable`, `last_payment_error`, `latest_charge`, `next_action`, `processing`, `canceled_at`, `cancellation_reason`, `livemode` 等字段。
- **inferred**：`status` 是主要 Stripe 状态信号；金额、charge、错误和取消时间是一致性校验/审计字段。`status=succeeded` 是 Stripe PaymentIntent 成功状态，但不能单独证明调用方的外部 fulfilment 已提交。

## 3. Stripe 状态与内部状态机

下表是工程校准模型，不是 Stripe 对外承诺的额外状态字段。

| 内部状态 | 进入条件（证据） | 允许动作/下一步 | 退出/完成条件 | 证据标签 |
|---|---|---|---|---|
| `accepted` | POST create/update/confirm/cancel 得到明确响应；网络超时则只有同 key 重试得到明确结果才可把请求层标记 accepted | 持久化 PaymentIntent ID、操作幂等键、请求 ID；开始 read-back 与 webhook 关联 | 读到对象为 `observed`；不要把请求 2xx 当 settled | **inferred**，其中 Idempotency 规则 **verified** |
| `observed` | 对同一个 ID 的 retrieve 返回并校验对象；保存 `status` 与读时刻/API version | 非终态继续轮询/等待 webhook；终态进入 settled 判定 | `status` 为 `succeeded` 或 `canceled`；其它状态继续处理 | **inferred**（状态枚举 **verified**） |
| `settled` | `succeeded`（支付成功）或 `canceled`（取消终态）被 read-back 或可信 webhook 事件交叉确认 | 先进行去重、金额/货币/订单绑定校验，再安排业务副作用 | 本地副作用事务成功提交 | **inferred** |
| `external_effect_committed` | 本地 outbox/ledger/fulfilment 事务以 `payment_intent_id` + effect key 去重提交，并保留 Stripe 对象状态、事件 ID、投递尝试记录 | 后续 webhook/read-back 只能成为重复/补偿输入，不重复发放 | 可审计、可重放、可补偿；不依赖 exactly-once | **inferred** |

**不可完成的中间态（verified + inferred 使用）：**

- `requires_payment_method`：需要附加 payment method；不可视为 accepted payment。
- `requires_confirmation`：需要确认；不可视为成功。
- `requires_action`：需要客户额外动作；不可视为成功。
- `processing`：正在处理；特别不能以 webhook 到达或一次 retrieve 即宣告 settled。
- `requires_capture`：已确认、待 capture；若业务采用手动 capture，尚未 settled 为已收款。
- `succeeded` / `canceled`：Stripe 资源终态；`canceled` 不是支付成功。

**冲突/边界：** 官方 cancel 文档允许少数 `processing` PaymentIntent 取消，而状态属性说明 `processing` 是当前处理中。两者并不矛盾：前者是操作前置条件的例外，后者是状态语义；具体请求仍以当时 API 响应为准。标记为 **conflict（上下文冲突，非文档矛盾）**。

## 4. Webhook 事件与 read-back

### 4.1 相关事件

- **verified**：Stripe webhook 示例处理 `payment_intent.succeeded` 与 `payment_intent.payment_failed`；PaymentIntent 事件类型页/事件体系还覆盖创建、处理中、需要动作、取消、可捕获金额更新等相关事件。
- **inferred**：至少将以下事件路由到同一 `payment_intent_id` 聚合器，并让处理器幂等：`payment_intent.created`, `payment_intent.processing`, `payment_intent.requires_action`, `payment_intent.payment_failed`, `payment_intent.amount_capturable_updated`, `payment_intent.succeeded`, `payment_intent.canceled`。事件白名单应以当前账户启用的 endpoint 版本和官方事件类型页为准。
- **verified**：Stripe 不保证事件按生成顺序投递；官方建议在缺少对象时可用 API retrieve，例如收到 `invoice.paid` 时再取相关对象。对单一 PaymentIntent，应按对象状态/版本合并，而不是按到达序列推进不可逆副作用。

### 4.2 投递窗口（delivery window）

- **verified**：live：失败投递最多自动重试三天，指数退避；sandbox：数小时内重试三次。Dashboard Resend 最多到事件创建后 15 天；CLI resend 最多 30 天。手工重发不取消原自动重试。
- **verified**：每次重试会生成新的 Stripe-Signature 时间戳/签名；签名校验需要原始 request body。官方库默认时间戳容忍度 5 分钟；这是防 replay 的签名新鲜度，不是事件业务完成窗口。
- **inferred**：delivery window 只界定“Stripe 还可能投递/重投该事件”的公开时间边界；它不等于业务 read-back window，也不等于本地副作用提交截止时间。

### 4.3 业务 read-back 窗口（明确分离）

- **verified**：Stripe error-handling 文档在不确定是否成功时给出的动作是 retrieve 相关对象并检查 status；文档没有给出所有 PaymentIntent 状态的统一等待秒数/轮询上限。
- **unknown**：官方公开资料未规定 read-back 的固定最大时长、退避参数、或 webhook 与 retrieve 的先后优先级。
- **inferred（建议策略，不是 Stripe SLA）**：`accepted` 后立即一次 retrieve 作为基线；若为 `processing`/`requires_action`/`requires_confirmation`/`requires_payment_method`/`requires_capture`，在业务定义的 read-back deadline 内按指数退避重复 retrieve，同时消费 webhook；deadline 到达时进入 `pending_reconciliation`/人工或补偿队列，而不是猜测成功。对高风险 fulfilment，要在副作用前再做一次 retrieve 或以事件对象和 retrieve 交叉校验。

### 4.4 三个“不足以证明完成”的命题

1. **verified + inferred**：webhook endpoint 返回单次 2xx，只证明 Stripe 得到成功的 HTTP 投递响应；官方要求快速返回 2xx，并把复杂逻辑放在之后。它不证明本地事务提交，更不证明重复事件不会再次触发副作用。
2. **inferred**：单次 query/retrieve 只是在一个时刻观察对象；若观察到 `processing` 等非终态，不能宣告 settled；即便看到 `succeeded`，仍不能证明外部效果已 committed。
3. **verified + inferred**：单个 webhook 事件不保证顺序，事件可能重试/手工重发；因此单事件到达不证明此前事件不存在、也不证明本地外部副作用 exactly-once。

## 5. API version 校准

- **verified**：Stripe 文档显示当前 API Reference 页面版本标签为 `2026-08-26`（页面显示的文档/API 参考上下文）；这不是本账户实际 pinned version 的证明。
- **verified**：Webhook 文档说明，事件生成时账户设置中的 API version 决定发送到 destination 的 Event 结构；事件创建后不能改变。请求级 version override 不会改写已生成事件采用的版本。
- **verified**：可为新 webhook endpoint 选择事件对象 API version；endpoint 的消费契约应随版本固定测试。
- **conflict**：同一 PaymentIntent 的 API retrieve/update 响应版本、Webhook Event envelope/object snapshot 版本、SDK 默认版本可能不同；不能仅凭 docs 页面默认版本推断某账户/endpoint/历史事件版本。解决办法是记录请求使用的 `Stripe-Version`（若显式设置）、endpoint event API version、SDK 版本和事件 `api_version`（若 payload 提供），并按版本回归。
- **unknown**：没有本账户上下文与真实请求，本切片无法验证任何具体账户的 pinned API version 或 endpoint version。

## 6. Idempotency-Key 与副作用边界

- **verified**：Stripe API 支持幂等以安全重试；所有 POST 接受 Idempotency-Key，key 最长 255 字符；Stripe 保存第一次请求的 status code/body；相同 key 的参数不一致会报错；GET/DELETE key 无效果。
- **inferred**：每个逻辑 mutation（create、confirm、update、cancel、capture）生成并持久化独立 key；网络超时只能用同 key、完全相同参数重试。不同操作不可复用同一 key。以 `payment_intent_id + operation + effect_version` 作为本地效果去重键，不能把 Stripe 的请求幂等层当作本地 webhook/fulfilment 去重层。
- **unknown**：公开资料不保证任意下游系统或本地事务 exactly-once；本报告不声称 production、exactly-once 或无重复副作用。

## 7. 错误码/异常与处理分层

- **verified**：Stripe error object 至少包含 `code`、`doc_url`、`message`；请求错误有 request ID。官方错误处理涵盖卡片错误、无效请求、连接/网络问题、幂等错误、限流等类别。
- **verified**：错误处理文档说明可通过 retrieve 相关对象和检查 status 判断不确定请求是否成功；对连接错误可用幂等 key 重试；限流应延迟并逐步增加延迟。
- **verified**：复用幂等 key 但参数不同属于 `IdempotencyError`/幂等错误，不应改参数继续复用同 key。
- **inferred**：建议持久化 `http_status`, Stripe `error.type`, `error.code`, `decline_code`（如有）、`doc_url`, request ID、幂等 key、PaymentIntent ID，并按错误类型分为：可安全同 key 重试、需 read-back 决定、需修正参数、需人工处理。示例 `payment_intent_unexpected_state`、`resource_missing`、`parameter_invalid_*`、`card_declined` 应以当次响应字段和对应 doc_url 为准，不把示例当成全量或固定映射。
- **unknown**：未执行真实请求，因此本切片不验证某个具体 ID 在某个 API version 下会返回哪一个 HTTP/code 组合。

## 8. 可执行但不宣称保证的校准流程

1. 创建/更新/确认/取消前生成操作级 key，落库 `intent_id`（如已知）、参数摘要、API version、开始时间。
2. 收到明确 API 响应：记录 request ID 和对象；标记 `accepted`，但不标记 settled。
3. 遇网络/超时：以同 key、同参数重试；并行/随后 retrieve 同一 ID（若 ID 已知），禁止新 key 猜测式重复 mutation。
4. webhook：先验签（原始 body、endpoint secret、时间戳容忍度），保存 event ID + delivery attempt + payload/object version；快速 2xx；异步按 `payment_intent_id` 合并。
5. 对非终态在本地 read-back deadline 内退避 query；收到事件不跳过状态/金额/订单绑定校验。
6. 只有 `succeeded` 或 `canceled` 通过 read-back/事件校验才标记 `settled`；`requires_capture` 不当作已 capture。
7. 业务副作用使用本地唯一 effect key/outbox 事务提交后标记 `external_effect_committed`；重复 webhook、乱序 webhook、手工重放只产生 no-op 或补偿任务。
8. delivery window 到期或 read-back deadline 到期仍不一致：保留待对账状态，使用 retrieve、事件查询/重放和人工队列补偿；不猜测、不声称成功。

## 9. 明确未验证项

- **unknown**：任何真实 Stripe 账户、真实 PaymentIntent、真实 webhook endpoint、生产配置、实际 retry 时间点。
- **unknown**：具体支付方法/地区/风险引擎导致的 processing 持续时间。
- **unknown**：本地业务数据库、库存、发货、退款等 external effect 是否提交。
- **unknown**：某一账户的 API version、endpoint secret、签名、事件过滤器。
- **conflict**：文档页面当前参考版本与账户/endpoint/历史 event version 可能不同；以运行时记录为准。

## 10. 研究边界与安全声明

本次仅访问 Stripe 官方公开文档 URL，未读取或修改任何既有 A 线目录、shared/P0、事故目录、D10、L12、D14、canonical、staging、140、tri-line、systemd、真实服务或凭据；未执行 Stripe API 调用。所有工程建议均标记为 inferred，不能被解释为 Stripe SLA、生产验证、exactly-once 或无重复副作用承诺。
