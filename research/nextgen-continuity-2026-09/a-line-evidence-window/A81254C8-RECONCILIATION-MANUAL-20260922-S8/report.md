# A线 S8：供应商特定 read-back 合同与预算校准

- 切片：S8（独立公开研究）
- 截止：2026-09-22（Asia/Shanghai）
- 目的：将通用 reconciliation 闸门参数化为供应商适配器字段，而不是把 HTTP 成功、一次查询、一次 webhook 或一次 offset 当作完成证据。
- 证据边界：[verified] 仅使用下列供应商/标准的公开官方一手文档；未读取任何既有 A 线目录或本地研究产物，未访问或修改 shared/P0、事故目录、D10、L12、D14、canonical、staging、140、tri-line、systemd、真实服务或凭据。
- 术语：[verified] “verified”表示官方原文直接支持；“inferred”表示由官方机制推导的闸门设计；“unknown”表示官方资料未给出、或本切片未找到；“conflict”表示官方资料间版本/语义冲突，不能静默合并。

## 1. 结论与预算校准

1. [verified] Stripe 的 POST 可带幂等键；服务保存同一键首次执行的状态码和响应体（包括 500），键可在至少 24 小时后自动清理；相同键参数不一致会报错；GET/DELETE 无需键且键无效。来源 S1。
2. [verified] Stripe webhook 事件可能重复且不保证顺序；应记录 event ID 去重，事件可用 data.object ID + event.type 识别某些独立重复；事件投递失败会重试，生产模式最长连续三天、测试模式约数小时；事件对象按生成时账户/端点 API 版本构建且创建后不变。来源 S2。
3. [verified] AWS EC2 的 client token 最长 64 个 ASCII 字符、大小写敏感；同 token 同参数成功重试不再执行动作，参数变化会产生 IdempotentParameterMismatch；RunInstances 的幂等域可按 Region 或 Availability Zone 变化。来源 S3。
4. [verified] EC2 文档把 200 标为“不重试”、400 系列标为“不重试”，但该表在可见抓取文本中被截断，5xx/超时完整行未作为本报告事实引用；应以具体 API 错误和请求 ID核验。来源 S3，限制见 U1。
5. [verified] Step Functions Task 可用 SendTaskSuccess/Failure 回传 task token；HeartbeatSeconds 超时会产生 States.HeartbeatTimeout/States.Timeout；Retry 支持 ErrorEquals、IntervalSeconds、MaxAttempts、BackoffRate、MaxDelaySeconds、JitterStrategy，Catch 处理指定错误。来源 S4-S6。
6. [verified] Temporal 默认自动重试 Activity、Workflow 默认不重试；默认 Activity 指数退避 initial 1s、系数 2、最大间隔 100×initial、最大 attempts 无限；非重试错误按错误类型匹配。来源 S7。
7. [verified] RFC 9110 定义 If-Match/If-None-Match、412、409、Retry-After；428 实际由 RFC 6585 定义而非 RFC 9110。RFC 9111 定义缓存控制。来源 S8-S9、S10。
8. [verified] Kafka 的 producer 幂等、事务、consumer isolation.level=read_committed、offset 管理是不同层次；事务可原子提交 Kafka records 与 consumer offsets，但外部系统的副作用仍需外部协作。来源 S11-S13。

### 预算口径（禁止冒充供应商承诺）

- [inferred] 预算单位至少拆成：`read_attempt`（一次 retrieve/Describe/查询）、`mutation_attempt`（一次可能改变状态的调用）、`event_delivery_attempt`、`reconcile_window`、`external_effect_attempt`、`manual_review`。这只是系统推断，不是任何供应商报价或 SLA。
- [inferred] 低成本的“2xx=完成”闸门应改为：`accepted`（供应商接受请求）→`read_back_verified`（在供应商规定/实测窗口内，读取到目标对象且字段/版本匹配）→`event_correlated`（事件 ID/对象键/版本已关联）→`external_effect_committed`（外部副作用有自身可审计证据）。
- [verified] Stripe 文档要求 webhook 处理程序先快速返回 2xx、复杂逻辑异步化；因此 2xx 只证明接收端响应，不证明会计/下游副作用已完成。来源 S2。
- [inferred] 重试预算不能只按次数：应按 `供应商重试策略 + 客户重试策略 + read-back 查询次数 + webhook 重新投递次数 + 状态收敛窗口` 计数，并把 429/Retry-After 或服务特定退避作为时间预算输入。
- [unknown] 本切片未找到 Stripe、EC2、Step Functions、Temporal 或 Kafka 对“业务对象最终一致性查询窗口”的统一数值 SLA；窗口必须由具体资源 API、实测或合同补充，不能填写伪精确秒数。

## 2. 逐供应商 read-back 合同矩阵

| 适配器 | 资源状态字段 | 版本/ETag | 幂等键 | Retry-After | 错误码/请求关联 | 事件→对象映射 | 查询窗口 | 删除/取消语义 |
|---|---|---|---|---|---|---|---|---|
| Stripe REST + webhook | [verified] 对象至少有 `id`、`object`，资源文档按对象定义状态；Webhook `event.type` 与 `event.data.object` 提供对象。具体资源状态字段必须按 endpoint schema 配置。[unknown] 本切片未把任一具体资源的完整状态枚举当作全 Stripe 通用字段。 | [unknown] 未发现 Stripe API 对目标资源以 HTTP ETag/If-Match 作为通用并发版本合同；Webhook Event 对象生成后不变且按 API version 构建。[verified] API version 是事件结构版本，不是资源 ETag。 | [verified] POST `Idempotency-Key`；最长 255 字符；推荐高熵 UUID；相同 key+参数返回首次结果；参数不一致报错；至少 24h 后可清理；GET/DELETE 不发送。[unknown] 文档未给出“超过 24h 的精确保留上限”。 | [unknown] 本切片未找到 Stripe 通用 Retry-After header 合同；不得把其 webhook “下次重试时间”当成客户端 HTTP Retry-After。 | [verified] 常规 HTTP 状态码；错误对象含 `type`、`code`（可空）、`message`、`param` 等；Webhook 发送记录显示 HTTP 状态。请求 ID/可用于日志的字段未在本切片目标页形成通用 read-back 合同。[unknown] | [verified] `event.id` 去重；`event.type` + `event.data.object.id` 关联对象；事件可乱序、重复；可从 API retrieve 缺失/最新对象。[inferred] 事件只作线索/触发 read-back，不作对象最终状态证明。 | [verified] 生产 webhook 失败尽量连续三天重试，测试约数小时；这是投递重试窗口，不是 REST 资源最终一致性 SLA。[unknown] 资源 query 窗口。 | [verified] GET retrieve 读取目标；POST update 需幂等键；DELETE 按 HTTP 定义幂等且不需键。[unknown] 各资源删除是立即删除、软删或可恢复，必须按具体资源文档。 |
| AWS EC2 | [verified] 资源/操作状态由具体 API 返回；异步 mutating request 可能在后台流程完成前先返回，RunInstances 重试可能返回更新后的创建状态。Describe 是 read-back 入口，但字段/状态枚举按具体 API。[unknown] 全 EC2 统一状态字段不存在。 | [unknown] 本切片未找到通用 HTTP ETag/If-Match；`requestId` 是请求关联标识，不是资源版本。[verified] `RunInstances` 的 Region/AZ 是幂等域维度。 | [verified] `ClientToken`，最长 64 ASCII、大小写敏感；默认幂等动作另列；参数不一致为 `IdempotentParameterMismatch`。 | [unknown] 本切片未确认 EC2 API 通用 `Retry-After` header；不得假设有。 | [verified] EC2 错误由错误码/HTTP 状态表达，AWS API response 含 request ID（S3 错误总览及各 API 结构需保留）；`IdempotentParameterMismatch` 是关键错误。[unknown] 具体错误重试分类应按 API/action 文档，不用一张截断表泛化。 | [unknown] EC2 本身不是 webhook 事件合同；CloudTrail/EventBridge 映射未纳入本切片。[inferred] 以 response request ID + Describe 目标 ID 做相关，而非把 request ID 当对象 ID。 | [verified] API 请求可能先于异步工作流完成；文档未给统一 Describe 收敛窗口。[unknown] 必须按 action/Region/AZ 实测和预算。 | [verified] 具体 action（如 TerminateInstances）默认幂等；其“请求成功”仍不能替代终止状态 read-back。[unknown] Modify/Terminate 的最终可见语义按 action 文档。 |
| AWS Step Functions | [verified] `Task` 的错误名包括 `States.Timeout`、`States.HeartbeatTimeout`、`States.TaskFailed` 等；Task token callback 任务等待 token 返回。[verified] SendTaskSuccess/Failure 用 token 完成任务，SendTaskHeartbeat 维持心跳。 | [unknown] 未找到 Step Functions execution/task 的通用 ETag；execution history/event ID 不是 HTTP ETag。[inferred] 用 execution ARN + event/history + task token 生命周期作版本/证据。 | [verified] Task token 是 callback 相关的关联键；其不是“业务 mutation 幂等键”。[unknown] SendTaskSuccess/Failure 的重复 token 处理不能由本切片材料推断，应按 API 错误实测。 | [unknown] 本切片未发现 Step Functions 通用 Retry-After header；Retry 字段是状态机内退避，不是 HTTP header。 | [verified] 错误名大小写敏感；Retry/Catch 按 `ErrorEquals`；`States.Runtime` 不可由 States.ALL 捕获。[verified] API 文档/调用响应带任务/请求关联字段，具体 request ID schema 需按 action。 | [verified] `.waitForTaskToken` 将 token 交给外部系统，外部以 SendTaskSuccess/Failure 回传；token 必须来自同一 AWS account；回调完成后工作流继续。[inferred] 外部事件必须保存 token→业务对象映射，单独“收到事件”不算完成。 | [verified] 任务可等待至 quota；HeartbeatSeconds/TimeoutSeconds 定义失败边界，Retry Interval/MaxAttempts/Backoff/Jitter定义重试窗口。[unknown] 默认业务对象 read-back 窗口。 | [verified] 停止/分支失败时 `.sync` 会尽力取消；可能因权限/服务暂时故障无法取消并产生额外费用。Callback task timeout 会生成新 token。[inferred] cancel 必须 read-back execution 状态，不能只看 Stop/Cancel API 返回。 |
| Temporal Activity/Workflow | [verified] Activity failure/error type 驱动 Retry Policy；Workflow replay/determinism 与 Activity 分工决定重试位置。[unknown] 资源对象状态不由 Temporal 统一定义。 | [unknown] 未发现 Temporal Activity 通用 ETag；Workflow event history/attempt 是执行证据，不是业务对象版本。 | [verified] Retry Policy 是失败类型、attempt、时间控制，不是一个跨外部资源的 idempotency key。[inferred] 外部 Activity 必须自带业务幂等键/去重表。 | [unknown] 本切片未找到 Temporal 对外 API 通用 Retry-After；服务端 retry policy 是另一层机制。 | [verified] non-retryable errors 按 Application Failure `type` 匹配；Activity 默认重试、Workflow 默认不重试。[unknown] 外部 provider 错误码到 Activity type 的映射需由适配器定义。 | [unknown] Temporal 不自动把第三方 webhook 映射为业务对象；应在 Activity 中验证 event/object ID。[inferred] 事件/读回/外部副作用的证据需写入 workflow state 或外部审计表。 | [verified] 默认 Activity initial 1s、backoff 2、最大间隔 100×initial、最大 attempts 无限；应用应配置 Workflow/Schedule-To-Close timeout 限制总预算。 | [unknown] Temporal 本身没有供应商资源删除/取消语义；Activity cancellation 与 provider cancel 必须分两阶段 read-back。[inferred] 取消后仍需查询 provider。 |
| Apache Kafka | [verified] Kafka record 的 key/value、partition/offset、consumer group position/committed offset 是消息状态/消费进度字段。[unknown] Kafka 不定义业务资源状态字段。 | [verified] offset 是日志位置，不是 ETag；transactional marker 与 `read_committed` 控制可见性。[unknown] 不可把 offset 当外部对象版本。 | [verified] producer idempotence 与 transactions 可抑制 Kafka 日志重复/原子提交；`transactional.id` 是事务身份。[verified] consumer offsets 可随事务提交。[unknown] 事务之外的外部副作用不自动幂等。 | [unknown] Kafka producer/consumer 协议不是 HTTP Retry-After 合同；需读取错误、timeout、throttle 和客户端 backoff 配置。 | [verified] Kafka 使用异常/错误码、producer epoch/offset 等协议状态；具体客户端错误映射取决于 API。[unknown] 不以 offset 作为唯一完成证据。 | [verified] `read_committed` 只读已提交事务；consume-transform-produce 可在 Kafka 内原子化；外部系统需要合作。[inferred] event key/headers→业务对象 mapping 必须由应用定义并可重放。 | [verified] consumer group 的 poll/session/max.poll 等是活性/处理窗口配置；本切片未找到统一业务 read-back 窗口。[unknown] offset 提交后外部副作用可仍未完成。 | [verified] Kafka 没有业务资源 delete/cancel 语义；墓碑/compaction、事务 abort、offset reset 是日志/消费语义，不等于外部删除。[inferred] 取消必须由应用事件和外部 provider 合同定义。 |

## 3. 通用 reconciliation 闸门（参数化草案）

每个供应商适配器输出同一结构（字段缺失显式为 `unknown`）：

```yaml
supplier: stripe|aws_ec2|step_functions|temporal|kafka
operation: retrieve|update|create|delete|cancel|consume|callback
correlation:
  request_id: <provider request id or unknown>
  operation_key: <client token/idempotency key/task token/transactional id or unknown>
  object_key: <provider object id or unknown>
  event_key: <event id + type + object id, or unknown>
version:
  etag_or_native_version: <value or unknown>
  source: <header/response/event/history/offset>
status:
  observed: <provider state>
  terminal: <true|false|unknown>
retry:
  retryable: <true|false|unknown>
  provider_backoff: <seconds/header/policy or unknown>
  attempts_budget: <count or unknown>
window:
  read_back_deadline: <configured value; not vendor SLA unless sourced>
evidence:
  retrieve: <request+response log reference>
  event: <validated event reference or unknown>
  external_effect: <independent commit reference or unknown>
```

- [inferred] 闸门顺序：验证请求参数哈希/幂等域 → 发送 mutation → 保存 response/request ID → 在窗口内 retrieve/Describe → 比较对象 ID、期望字段和 native version → 关联并验证 event（如有）→ 验证外部副作用 → 关闭或人工复核。
- [inferred] `accepted`、`observed`、`settled`、`external_effect_committed` 必须是不同状态；任何供应商的单一 2xx 只能推进到 `accepted`，除非该 API 的官方语义明确给出同步最终结果。
- [inferred] 任何单次 query 只能提供一个观测点；单 webhook 只能提供一个投递/事件事实；单 offset 只能提供 Kafka 日志位置/消费进度。它们都不能单独证明独立完成。
- [verified] RFC 9110 的条件请求可作为通用 HTTP 适配层：If-Match 防止对已变化表示执行更新；If-None-Match 可用于避免覆盖/条件创建；412 表示前置条件失败；409 表示与当前状态冲突；428 要求条件请求（RFC6585）。但 vendor 未实现时字段必须 unknown，不能强加。
- [inferred] 删除/取消闸门默认采用 `requested → provider_acknowledged → read_back_terminal → external_effect_verified`；Step Functions `.sync` 的取消可能 best-effort，Temporal Activity cancellation 和 Kafka abort 同理，不能因 cancel API 返回就关闭。

## 4. 明确禁止的推断

- [verified] 不把任何 2xx 当作独立完成证据；Stripe 官方特别要求 webhook 先快速返回 2xx，再异步处理。
- [inferred] 不把单次 query/retrieve/Describe 当作收敛证明；它只是时点观测，除非合同明定同步终态且字段已验证。
- [verified] 不把单 webhook 当作对象状态证明：Stripe 明示事件重复、乱序且可 retrieve 对象。
- [verified] 不把单 offset 当作外部副作用证明：Kafka 的事务/offset 语义覆盖 Kafka 内记录与消费进度；外部系统需合作。
- [inferred] 不声称 production、exactly-once 或无重复副作用。本报告仅给公开文档约束下的设计参数；即便 Kafka producer 幂等/事务或 Stripe/AWS 幂等键存在，端到端外部效果仍须独立验证。

## 5. 冲突、缺口与下一步

- [conflict] Stripe webhook 文档同时描述“HTTP 2xx 表示成功发送到端点”和“端点应在复杂逻辑前快速返回 2xx”；二者并不冲突，但若把 delivery success 解释为业务完成则是系统层面的语义冲突，应拆成 delivery 与 business gates。
- [conflict] AWS EC2 幂等文档的通用重试表在抓取文本中显示 200/400 系列行，但后续行不可见；不能据此补齐 5xx/timeout 规则，具体 action 文档优先。
- [unknown] 未覆盖：Stripe 每类目标资源的完整状态/删除语义和 list pagination；EC2 每个 Run/Modify/Terminate action 的状态图；Step Functions SendTask* 的所有 token 错误；Temporal SDK 各语言 cancellation；Kafka 各版本完整错误/重试矩阵。
- [inferred] 下一独立切片应只选一个供应商与一类资源，建立可执行的状态机、错误→retry 分类、read-back 采样窗口和预算公式，并对“事件到对象”做可重放测试；建议见 next-slice-dispatch.md。

## 6. 研究限制

[verified] 资料访问日期为 2026-09-22；官方页面可能随产品版本更新。未登录、未调用真实 API、未使用凭据、未进行生产验证。所有“预算”内容若非 `[verified]` 官方参数，均显式标为 `[inferred]` 或 `[unknown]`，不是供应商 SLA、报价或承诺。
