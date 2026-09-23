# S7 来源清单（仅公开官方一手资料）

检索日期：2026-09-22。以下 URL 均为官方文档/标准原文；“页面更新时间”在本切片未统一取得，故按 `unknown (retrieved 2026-09-22)` 记录，不将检索日伪装成发布日期。

| ID | 官方来源 | 用于核实 |
|---|---|---|
| S1 | Stripe, *Receive Stripe events in your webhook endpoint* — https://docs.stripe.com/webhooks | webhook 2xx、验签原始 body、live/sandbox 自动重试、事件乱序、event ID 去重、API 补取缺失对象 |
| S2 | Stripe, *The Event object / Retrieve an event* — https://docs.stripe.com/api/events | event ID 查询、最近 30 天、事件创建时 API 版本、data 内容不随当前 API 版本变化 |
| S3 | Amazon EC2 Developer Guide, *Eventual consistency in the Amazon EC2 API* — https://docs.aws.amazon.com/ec2/latest/devguide/eventual-consistency.html | EC2 最终一致性、创建后 ID 尚未传播、Describe 指数退避、数秒至数分钟、后续命令继续等待 |
| S4 | AWS Step Functions Developer Guide, *Callback with Task Token* — https://docs.aws.amazon.com/step-functions/latest/dg/connect-to-resource.html | waitForTaskToken、SendTaskSuccess/Failure/Heartbeat、HeartbeatSeconds、States.Timeout |
| S5 | Temporal Docs, *Detecting Activity failures* — https://docs.temporal.io/encyclopedia/detecting-activity-failures | Activity 四类 timeout、heartbeat、Start-To-Close、retry 触发与建议 |
| S6 | IETF RFC 9110, *HTTP Semantics* — https://www.rfc-editor.org/rfc/rfc9110.html | ETag/validator、If-Match/If-None-Match、304、GET 表示层语义 |
| S7 | IETF RFC 9111, *HTTP Caching* — https://www.rfc-editor.org/rfc/rfc9111.html | freshness、Age、validation、stale、must-revalidate |
| S8 | Apache Kafka, *Design / Message Delivery Semantics* — https://kafka.apache.org/documentation/#semantics | at-most/at-least/exactly-once 语义边界、事务与 offset、外部系统合作边界 |
| S9 | Apache Kafka, *Design / Using Transactions* — https://kafka.apache.org/documentation/#usingtransactions | Kafka 事务性读写/offset 范围；不得外推到外部 API 原子性 |

## 逐源证据摘录与判断

### S1 — Stripe webhook
- **VERIFIED**：Stripe live webhook 自动投递重试最长三天并指数退避；sandbox 数小时内重试三次。
- **VERIFIED**：事件可能乱序；不要用 `created` 判定顺序或已处理；跟踪 event ID 识别重复投递。
- **VERIFIED**：可用 API 检索缺失对象；endpoint 应尽快返回 2xx，再处理复杂逻辑。
- **INFERRED**：2xx 是 HTTP 接收确认，不是外部业务效果证明；事件 ID 去重仍要与资源版本/状态绑定。
- **UNKNOWN**：官方页面没有给出所有事件类型的统一 read-back 新鲜度上界。

### S2 — Stripe Event API
- **VERIFIED**：通过 event 唯一 ID retrieve 最近 30 天事件；`data` 内容固定，事件创建时 API 版本被记录。
- **INFERRED**：event ID + API version 可作为事件证据绑定字段。
- **UNKNOWN**：retrieve event 成功不自动证明下游外部副作用已完成。

### S3 — AWS EC2
- **VERIFIED**：API 是 eventual consistency；刚创建资源的 ID 可能还未传播，Describe/modify 可能返回不存在。
- **VERIFIED**：建议 Describe 指数退避，等待数秒逐渐增加到数分钟；即使已得到准确响应，后续命令仍加入等待。
- **INFERRED**：传播窗口内负结果属于待确认，不应立即判定失败。
- **UNKNOWN**：没有跨资源/区域的固定延迟 SLA。

### S4 — AWS Step Functions
- **VERIFIED**：callback 任务收到 token 后，外部系统用原 token SendTaskSuccess/Failure 才继续；可 SendTaskHeartbeat。
- **VERIFIED**：HeartbeatSeconds 到期无有效 token 会 States.Timeout。
- **INFERRED**：callback/heartbeat 是流程控制和活性，不是业务效果 read-back。

### S5 — Temporal
- **VERIFIED**：Activity failure detection 包含 Schedule-To-Start、Start-To-Close、Schedule-To-Close、Activity Heartbeats；建议 Start-To-Close，长任务使用 heartbeat/timeout。
- **VERIFIED**：Start-To-Close 超时作用于每个 Activity Task Execution，retry policy 可再次执行 task。
- **INFERRED**：retry/heartbeat 不等于外部效果；必须假设超时前外部调用可能已生效。

### S6/S7 — HTTP
- **VERIFIED**：RFC 9110 定义 validators/ETag 与条件请求，GET 可返回 304；RFC 9111 定义 freshness、Age、validation、stale、must-revalidate。
- **INFERRED**：ETag 应与资源 ID/目标后置条件/观察时间绑定；304 只是表示重验证，不是业务完成。负结果缓存不能被当成最终事实。
- **UNKNOWN**：标准不定义 provider 业务版本，也不保证业务语义自动随 ETag 传递。

### S8/S9 — Kafka
- **VERIFIED**：Kafka 的 exactly-once/事务语义涵盖 Kafka 记录与 offset 的特定链路；外部系统需要额外合作，不自动加入 Kafka 原子边界。
- **INFERRED**：单个 consumer offset 只证明消费进度，不证明外部 API 效果。
- **UNKNOWN**：具体外部系统是否有幂等键、事务、outbox 或可查询版本，须逐 provider 核实。

## 证据新鲜度设计边界

“新鲜”在本研究中不是 HTTP 响应到达快，而是：同一 `resource_id`、可识别的同一意图、可比较的版本/ETag/代次、满足业务后置条件，并且查询响应没有被未经验证的缓存掩盖。缺失其中任一项都降级为 UNKNOWN 或冲突待查。