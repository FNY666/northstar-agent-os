# S7｜效果 read-back 的证据新鲜度与补偿闸门

- **研究切片**：A 线 / S7（独立公开研究）
- **研究日期**：2026-09-22（Asia/Shanghai）
- **问题**：当外部写入已提交或 webhook 已到达时，什么证据才足以证明外部效果；在跨平台最终一致性、事件延迟、查询重试、负结果缓存、版本/ETag/资源 ID 绑定以及 webhook/read-back 不一致下，何时继续自动补偿，何时人工升级？
- **资料边界**：只使用公开官方一手资料；本切片未读取任何既有 A 线目录或其他本地研究产物，也未访问或修改 shared/P0、事故目录、D10、L12、D14、canonical、staging、140、tri-line、systemd、真实服务或凭据。

## 结论（先给闸门）

**read-back 是证据，不是效果本身；单次 2xx、单次 query、单个 webhook 或单个 consumer offset 都不能单独证明外部效果。** 可靠判定应是“同一资源、同一意图、同一版本/代次”的多信号闭环：

1. 写入意图拥有稳定的业务关联键（资源 ID / provider event ID / request 或 idempotency 关联信息），并记录首次提交时间、尝试次数、请求结果与证据时间。
2. webhook 只作为异步线索/状态证据：先验签、持久化 event ID，再去重；不能用 created 时间排序。Stripe 官方明确建议用 event ID 识别重复投递，并可用 API 补取缺失对象；live webhook 会自动重试最多三天且带指数退避。
3. read-back 必须查询**同一个资源 ID**，拿到可比较的对象字段以及版本标记（若服务提供 ETag/版本号/更新时间/状态代次）。比较目标是业务后置条件，而不是“HTTP 成功”。没有版本标记时，至少要保存响应时间、请求关联 ID、对象 ID 和完整目标字段；其证明强度下降为“弱确认”。
4. 对创建后暂时查不到、旧状态、或 webhook 先到而查询尚未跟上的情况，采用有截止时间的指数退避查询；AWS EC2 官方明确要求 Describe 重试，从数秒逐渐增加到数分钟，并即使返回准确响应也在后续命令之间加等待。
5. **负结果不得立即缓存为永久否定**：在传播窗口内，404/不存在/旧状态先标为 `PENDING_PROPAGATION`（短 TTL 或不缓存）；重复查询仍不匹配时才进入补偿调查。HTTP 缓存语义中的 `Age`、freshness、validation、`must-revalidate` 说明“可复用的缓存响应”与“最新事实”不是一回事；业务层应绕开会掩盖新状态的缓存，或显式 revalidate。
6. 自动补偿必须受预算闸门约束：同一意图/资源 ID 的单飞（single-flight）、最大总时长、最大 query 次数、最大副作用重试次数；每次重试都假定前次可能已生效，因此补偿动作必须是 provider 支持的幂等操作或先 read-back 再执行。不要声称 exactly-once 或无重复副作用。
7. 进入人工升级：截止时间到仍无绑定 read-back；webhook 与 read-back 在同一版本/代次上冲突；资源 ID 不一致或疑似错租户；连续出现 5xx/429/权限错误；查询命中缓存且无法 revalidate；补偿预算耗尽；或未知状态可能涉及资金、权限、删除等高风险效果。人工单必须携带原始意图、资源 ID、provider event ID、版本/ETag、每次 query 的时间/响应、重试/补偿历史与验签结论。

## 证据分级

- **VERIFIED（已核实）**：官方一手资料直接写出，或其 API 语义直接支持的事实。
- **INFERRED（推断）**：由多个 VERIFIED 事实组合出的控制设计；不是供应商承诺。
- **UNKNOWN（未知）**：官方资料没有给出、或本切片没有足够证据的事实，尤其是具体传播延迟分位数、跨系统全局顺序、缓存实际 TTL。
- **CONFLICT（冲突）**：两类信号对同一资源/代次给出不可同时成立的结果；不是简单“webhook 晚到”。

## 官方证据与含义

### Stripe：event/webhook/query

**VERIFIED**（Stripe Webhooks）：live 模式对 webhook destination 的事件投递会自动重试最多三天并指数退避；sandbox 会在数小时内重试三次。Stripe 还说明事件可能乱序，不能用 `created` 决定事件顺序或判断是否已处理；应跟踪 event ID 识别重复投递。Stripe 建议在先收到某事件时，可用 API 检索缺失的 invoice、charge、subscription 等对象。

**VERIFIED**（Stripe Events API）：Retrieve Event 通过 event 唯一 ID 获取最近 30 天创建的事件；事件 `data` 的内容不随当前 API 版本变化，事件创建时的 API 版本被记录。该事实支持“event ID + 事件版本”绑定，但不等于业务资源已完成，也不等于下游系统已观察到该效果。

**VERIFIED**（Stripe Webhooks）：endpoint 应快速返回 2xx，再做复杂逻辑；因此 2xx 证明的是接收端及时接受 HTTP 交互（以及代码选择返回成功），不是业务副作用已完成。Stripe 同页还要求验签使用原始请求体。

**INFERRED**：Stripe webhook 消费器应先验签并可靠落库 event ID/资源 ID，再异步处理；重复 event ID 不再重复副作用，但不同 event ID 可能指向同一资源演进，故还需按资源版本/状态代次比较。官方资料没有授权把单个 webhook 当作最终效果证明。

### AWS EC2：最终一致性与 Describe 重试

**VERIFIED**（EC2 Eventual Consistency）：EC2 API 遵循最终一致性；影响资源的命令结果可能不会立即对后续命令可见。刚创建资源后立即修改或 Describe，资源 ID 可能尚未传播，可能返回资源不存在。AWS 建议先确认状态，用适当 Describe 做指数退避，等待从数秒逐步增加到数分钟；即使 Describe 已返回准确响应，后续命令之间也应继续加入等待。

**INFERRED**：查询到 404/NotFound 在传播预算内是 `UNKNOWN/PENDING_PROPAGATION`，不能直接推断写入失败；预算耗尽后仍未出现绑定资源，才达到升级条件。AWS 页面没有给出适用于所有资源、区域或时段的统一 p99 延迟，因此不要把“几分钟”写成 SLA。

### AWS Step Functions：callback 与 heartbeat

**VERIFIED**（Callback with Task Token）：`.waitForTaskToken` 任务把 token 给外部系统；只有外部系统用原 token 调 `SendTaskSuccess` 或 `SendTaskFailure` 后工作流才继续。可用 `SendTaskHeartbeat` 保持等待任务活跃。

**VERIFIED**：等待 token 的任务可设置 `HeartbeatSeconds`；示例 600 秒，若该时间内未收到有效 token，任务以 `States.Timeout` 失败。该 heartbeat 是“外部流程仍在推进/联系”的活性信号，不是外部业务效果的 read-back。

**INFERRED**：callback token、provider 资源 ID、业务关联键必须同绑；callback 成功后仍应 read-back。单个 callback 成功或 workflow 继续不能证明外部副作用已经达到目标字段。

### Temporal：Activity timeout/heartbeat/retry

**VERIFIED**（Temporal Detecting Activity failures）：Temporal 以 Schedule-To-Start、Start-To-Close、Schedule-To-Close 和 Activity Heartbeats 等超时检测 Activity 执行失败；官方强烈建议设置 Start-To-Close。对长执行 Activity，建议使用 Activity Heartbeat 和 Heartbeat Timeout。Start-To-Close 超时可触发 Activity task retry；它作用于每个 Activity Task Execution。

**INFERRED**：Activity heartbeat 只证明 worker 在报告进度，timeout/retry 只提供故障检测与再次尝试机制；它们不证明外部资源效果。Activity 的 retry 必须把外部调用视为“可能已执行但响应丢失”，否则会制造重复副作用。

### HTTP RFC 9110 / RFC 9111：条件请求、ETag、缓存

**VERIFIED**（RFC 9110）：HTTP 定义 ETag 等 validator fields；条件请求包括 `If-Match`、`If-None-Match`、`If-Modified-Since` 等；GET 可产生 200 或 304（Not Modified）响应。304 是相对于 validator 的缓存重验证结果，不是业务“效果完成”状态。

**VERIFIED**（RFC 9111）：缓存有 freshness、Age、validation、serving stale 等语义；`must-revalidate` 要求在不能验证时不得随意复用，标准举例指出财务交易等错误操作场景应使用该指令。标准没有替业务系统定义资源业务版本，也没有保证所有代理都不缓存错误配置的负结果。

**INFERRED**：若 provider 暴露 ETag/版本号，应将其与资源 ID、目标状态和查询时刻一起记账；优先条件 GET/revalidation，避免把旧表示当新事实。`304`、`200`、缓存命中都只能说明 HTTP 表示层状态；仍需检查业务后置条件。负结果缓存应有极短、明确且小于传播预算的 TTL，或直接 `no-store/no-cache`/强制 revalidation（具体采用何者取决于 provider 合同）。

### Apache Kafka：transactions、offset 与外部系统

**VERIFIED（Apache Kafka 官方设计/语义文档）**：Kafka 的事务语义可把 Kafka 记录的生产与消费位移提交纳入事务；exactly-once 的强语义依赖事务性 producer、读隔离配置及处理链路。Kafka 文档对“读—处理—写”链路与外部系统另行对待：外部系统的副作用不因 Kafka offset/transaction 自动纳入同一原子边界。

**INFERRED**：consumer offset 只证明某 consumer group 对某 partition 的进度提交；它不证明外部 API 的写入成功，更不证明外部 API 的业务效果。外部副作用需 outbox/inbox、provider 幂等键、业务 read-back 或人工对账等合作机制；不要据 Kafka 语义声称跨 Kafka 与外部服务 exactly-once。

## 建议的补偿闸门（状态机）

### 1. 绑定记录（Effect Evidence Record）

最低字段：`intent_id`、`tenant/account`、`provider`、`resource_type`、`resource_id`（未知时记录候选 ID）、`request_id`/`idempotency_key`、`event_id`、`event_type`、event API/schema version、目标后置条件、observed version/ETag、首次提交时间、每次 query 的时间/缓存标志/HTTP 状态/响应摘要、webhook 验签结果、consumer topic-partition-offset、重试计数与人工处理编号。

### 2. 查询决策矩阵

| 观察 | 分类 | 自动动作 |
|---|---|---|
| 资源 ID 相同；版本/ETag 与目标后置条件匹配；webhook（若有）不冲突 | VERIFIED / confirmed | 结束补偿，写入证据包 |
| 同 ID 但暂时 404、旧状态或 webhook 先到 | UNKNOWN / pending propagation | 按指数退避 re-query；不执行危险重复写 |
| 200/2xx 但字段未达到目标，且无版本绑定 | UNKNOWN / weak evidence | 重新验证；不得以状态码结案 |
| webhook event ID 重复 | VERIFIED duplicate delivery | 去重，不重复副作用；必要时 query |
| webhook 与同资源同版本 read-back 字段不一致 | CONFLICT | 冻结自动补偿，人工升级 |
| event/resource ID 不同、租户不明、签名失败 | UNKNOWN 或安全冲突 | 拒绝应用效果，人工/安全队列 |
| query 5xx/429/网络超时 | UNKNOWN | 尊重 Retry-After（若有），有限重试；预算耗尽升级 |
| query 404 超过传播预算且无任何绑定证据 | UNKNOWN → escalation | 不把 404 写成已取消/未发生；人工对账 |
| 仅收到 2xx、单 webhook、单 query 或单 offset | UNKNOWN | 继续闭环，不得宣称效果完成 |

### 3. 时间与次数预算

预算应按 provider 的公开行为、风险等级和业务 SLO 配置，而不是从单次观测臆测。建议 `T_propagation`、`N_query`、`T_overall`、`N_side_effect` 分开；查询退避使用抖动，遇到 429/Retry-After 服从服务端指示。高风险写入的 `N_side_effect` 默认 0，直到资源 read-back 证明未生效且 provider 幂等合同明确允许重试。预算、TTL 和阈值属于本系统设计（INFERRED），不是 Stripe/AWS/Temporal/HTTP/Kafka 的统一保证。

## 人工升级规则（必须可操作）

1. **时间闸门**：达到 `T_overall`，或达到服务公开重试窗口末端，仍没有同资源、同版本的后置条件证据。
2. **冲突闸门**：webhook payload 与 read-back 的状态、金额、目标字段或版本在同一资源/同一代次上冲突；不得以“最后收到的”简单覆盖。
3. **身份闸门**：resource ID、account/tenant、event ID、request/idempotency key 无法绑定，或出现跨租户/错对象风险。
4. **缓存闸门**：响应被缓存、Age/ETag 不可判断新鲜度，且无法用 revalidation 获得可信表示；不得把缓存的 404/旧 200 作为最终结论。
5. **预算闸门**：query、callback heartbeat、Activity retry 或补偿次数耗尽；冻结同一意图的并行处理，防止风暴。
6. **安全/业务闸门**：签名失败、权限异常、资金/删除/权限提升等高影响操作进入未知状态，立即人工或安全队列。

## 明确未证明事项

- **UNKNOWN**：Stripe、EC2、Step Functions、Temporal、HTTP、Kafka 官方资料未共同定义一个跨平台最终一致性上界；本切片没有测得任何真实服务传播延迟，也没有声称 production 行为。
- **UNKNOWN**：没有证据表明 webhook 到达顺序等于资源状态提交顺序；Stripe 明确提醒事件可能乱序。
- **UNKNOWN**：没有证据表明某个 ETag 是业务全局版本，或某个 304 表示副作用成功。
- **UNKNOWN**：没有证据表明 Kafka offset 与外部 API 状态原子提交；不声称跨系统 exactly-once。
- **CONFLICT 的处理**：webhook/read-back 不一致不是“自动重试即可”问题；先冻结并收集证据。若后续同一版本证据无法解释，再人工对账。

## 非目标与禁止结论

本切片不声称 production 可靠性、exactly-once、无重复副作用、全局顺序、零丢失、固定 p99 延迟或任何供应商未公开的 SLA。HTTP 2xx、单次 query、单个 webhook、单个 callback heartbeat、单个 consumer offset 均不是独立的外部效果证明。

## 来源索引

详见 `sources.md`；结构化证据映射与状态详见 `research-manifest.json`。
