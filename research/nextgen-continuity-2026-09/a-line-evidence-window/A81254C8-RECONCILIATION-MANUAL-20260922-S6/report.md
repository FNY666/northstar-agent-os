# S6：幂等键与效果账本的跨平台可验证契约

- **切片**：A 线下一独立公开研究切片 S6
- **研究日期**：2026-09-22（Asia/Shanghai）
- **范围**：仅公开官方一手资料；Stripe API、Amazon EC2/Step Functions、Temporal、Apache Kafka、IETF HTTP Semantics。未访问任何私有服务、凭据或既有研究产物。
- **问题**：如何把业务幂等键生命周期、参数绑定/冲突、效果账本、read-back、重复请求、超时后查询、补偿与人工升级组织成跨平台可验证的状态机？

## 结论（校准）

跨平台可迁移的最小契约不是“有一个 key”，而是一个**带作用域、参数指纹、结果/外部效果证据、查询策略和升级策略的账本状态机**。Stripe 明确展示了服务端可按 key 保存首次 HTTP status/body、对后续相同 key 返回相同结果，并在参数不一致时拒绝；AWS EC2 明确展示了 client token + 参数一致性检查和 `IdempotentParameterMismatch`。但这两者都不能单独证明外部系统的效果已经发生、没有发生，或达成 exactly-once。HTTP RFC 9110 也把幂等限定为“请求对服务器的预期效果”，允许每次请求仍有日志等副作用。

建议把 `UNKNOWN` 当成**不可安全重放**的事实状态：先用同一业务身份做 read-back/供应商查询或核对效果账本，再依据可验证证据转为 `SUCCEEDED`、`NOT_APPLIED`（可安全重试）或 `CONFLICT/COMPENSATION_REQUIRED`；证据不足则 `MANUAL_REVIEW`。补偿是新业务动作，必须有自己的幂等键、账本记录与 read-back，不能把“重试原请求”误称为补偿。

> **边界结论（verified）**：幂等键、效果账本、平台成功回执各自都不能单独证明 exactly-once 或外部效果。跨系统 exactly-once 需要共同事务/原子提交、可核对的外部效果，或目标系统的合作；Kafka 官方明确指出写外部系统时需要目标系统合作，否则默认是 at-least-once。

## 证据与逐条判定

状态标签仅使用：**verified（官方原文直接支持）/ inferred（由证据合成的设计推论）/ unknown（官方资料未覆盖，不能据此断言）/ conflict（来源或语境不一致）**。

### 1. 幂等键生命周期

- **verified**：Stripe 接受所有 POST 的 `Idempotency-Key`；GET/DELETE 不需要，因为其方法定义为幂等。Stripe 保存同一 key 的首次 status code 和 body（成功或失败，包含 500），后续同 key 返回相同结果。
- **verified**：Stripe 允许至少 24 小时后自动移除 key；移除后复用同一 key 会生成新请求。因此 key 的生命周期有明确的服务端保留窗口，不能把“曾经使用过”假定为永久事实。
- **verified**：AWS EC2 client token 是最多 64 个 ASCII 字符、区分大小写的唯一字符串；官方说不应把同一 token 用于其他 API 请求。AWS 文档还区分 Regional 与 Zonal 作用域，同一 token 在不同区域/可用区可能代表不同幂等域。
- **inferred**：业务账本应显式持有 `key_scope`（租户/操作/区域/资源）和 `expires_at`，并在平台保留期、业务核对期和人工处置期之间取更保守的安全边界；过期复用前必须新建业务意图/键，而不是静默沿用旧键。
- **unknown**：所查资料没有给出 Stripe 所有 endpoint 的统一保留期、AWS 所有 client token 的统一保留期，亦未证明跨供应商 key 的全局唯一性、持久化方式或灾备语义。

### 2. 参数绑定、冲突和并发

- **verified**：Stripe 比较后来请求与原请求参数；参数不相同会报错，防止 key 误用。若参数校验失败，或请求与同时执行的请求冲突，Stripe 不保存幂等结果，因为 endpoint 尚未开始执行，这类请求可重试。
- **verified**：AWS EC2 在成功后以同 token + 同参数重试，不再执行动作；同 token + 参数变更（Region/AZ 例外按其 Regional/Zonal 规则）失败并返回 `IdempotentParameterMismatch`。
- **verified**：RFC 9110 的幂等定义是相同请求多次的“预期服务器效果”与一次相同；服务器仍可逐次记录日志、保留历史等非幂等副作用。
- **inferred**：业务层应对规范化参数做不可变 `request_fingerprint`，把 key 绑定到操作名、资源/租户作用域、版本和副作用参数；命中同 key 但指纹不同应进入 `CONFLICT`，禁止覆盖原意图。
- **unknown**：资料没有统一规定指纹算法、是否包含隐式默认值、浮点/排序/序列化规范，也没有提供所有平台并发竞争下的跨区域线性化证明。

### 3. 效果账本与 read-back

- **verified**：Stripe 的官方语义是保存并重放 HTTP 结果；这证明平台回执可作为“平台观察到的结果”记录，不等于第三方资源或下游效果证明。
- **verified**：Kafka 官方指出生产者遇到网络错误时无法确定错误发生在消息提交前还是提交后；旧式重发导致 at-least-once。Kafka 还明确说写外部系统时，offset 与实际输出需要协调，exactly-once 通常需要外部系统合作。
- **inferred**：效果账本必须与请求尝试账本分开建模或至少分字段：`intent_id/key/scope/fingerprint`、尝试时间、平台响应、供应商资源 ID、外部查询证据、证据时间/来源、当前 effect state、补偿关系。成功 HTTP 回执只能推进 `PLATFORM_ACKED`，只有 read-back 或目标系统可验证提交证据才能推进 `EFFECT_CONFIRMED`。
- **inferred**：read-back 必须按业务唯一身份查询（资源 ID、供应商幂等键或可验证事件），而不是盲目重新 POST；查询结果应做时间窗、参数/金额/目标绑定和版本校验，避免读到另一笔同形资源。
- **unknown**：所查官方资料没有给出跨平台统一的效果账本 schema、read-back 的一致性等待界限、负缓存规则、外部查询是否线性一致或事件最终一致的通用保证。

### 4. 重复请求与超时后查询

- **verified**：Stripe 的设计目标是连接错误后用同 key 重复请求，避免第二次创建/更新；同 key 的保存结果可包含失败（包括 500），因此不能简单把 HTTP 500 解释成“未执行”。
- **verified**：RFC 9110 允许在客户端还没读到响应、连接失败时重试幂等方法，但对非幂等方法，客户端不应自动重试，除非知道其语义幂等或能检测原请求未应用。
- **verified**：Temporal Activity 失败会按 Retry Policy 自动重试；每次尝试默认从初始状态开始，Heartbeat detail 可作为 checkpoint 并在下一次尝试提供。
- **verified**：Step Functions callback task 会等待 task token；任务超时会生成新的随机 token。可用 `HeartbeatSeconds` 避免长期卡住；未在窗口内收到有效 token 时失败为 `States.Timeout`。官方示例让外部系统处理后回传原 token。
- **inferred**：状态机应将网络超时、客户端无响应、平台 5xx、Activity attempt failure统一先进入 `UNKNOWN`（除非已有明确 `NOT_APPLIED`），并按固定 key 查询；不能因为“重试请求成功”就断言第一次没有效果。
- **unknown**：官方资料未定义一个跨平台的“超时后查询等待多久”或 read-back 成功次数阈值；这必须由业务风险、目标系统 SLA 和证据新鲜度制定。

### 5. 补偿与人工升级

- **verified**：Step Functions callback 模式支持等待外部、人审或遗留系统完成，并以 `SendTaskSuccess`/`SendTaskFailure` 继续或失败工作流；heartbeat 超时会结束等待。
- **verified**：Temporal 建议 Activity 幂等，使重试不产生重复副作用；其文档把发送邮件、支付等外部动作列为 Activity 类工作，并强调短 Activity 有助于故障恢复、超时和幂等。
- **inferred**：`UNKNOWN` 不能直接进入补偿；先 read-back。若确认效果存在但业务流程未完成，创建“后续修复/撤销”补偿意图；若确认未应用，才可用新尝试重做原意图；若证据互相冲突或补偿本身风险高，进入 `MANUAL_REVIEW`，要求人工锁定同一 key/scope 并留下决策证据。
- **inferred**：每个补偿动作都必须独立拥有 `compensation_id`、新幂等 key、参数指纹、前置效果引用、审批/权限与 read-back；补偿成功回执仍只能是平台层证据，不能跳过效果确认。
- **unknown**：所查平台文档没有定义跨平台人工升级的责任人、SLA、审批双人控制、证据保留年限或财务对账规则；这些是业务治理要求，不应伪装成平台保证。

## 推荐状态机（设计推论，不是任何供应商的已验证生产实现）

```text
NEW
 | validate(scope, key, normalized_args, fingerprint)
 +--> REJECTED_INVALID / CONFLICT (same key, different fingerprint)
 |
 +--> RECORDED_PENDING --submit once-->
       | definitive platform failure before execution -> NOT_APPLIED
       | accepted/response success -> PLATFORM_ACKED
       | transport timeout, 5xx, worker crash, lost callback -> UNKNOWN

UNKNOWN --read-back/query using same intent identity-->
   | matching external effect + trusted evidence -> EFFECT_CONFIRMED
   | no effect after bounded evidence window + policy -> NOT_APPLIED
   | contradictory/stale/insufficient evidence -> MANUAL_REVIEW

NOT_APPLIED --retry same intent/key if platform contract permits--> RECORDED_PENDING
EFFECT_CONFIRMED --business completion check--> COMPLETED
EFFECT_CONFIRMED + required repair --> COMPENSATION_RECORDED
COMPENSATION_RECORDED --new compensation key--> COMPENSATION_PENDING
COMPENSATION_PENDING --read-back--> COMPENSATED | MANUAL_REVIEW
MANUAL_REVIEW --human decision with evidence--> RETRY_ALLOWED | COMPENSATION_REQUIRED | CLOSED
```

### 状态转换的可验证条件

1. **入账前**：规范化参数和作用域校验通过；生成不可猜测 key；持久化 intent + fingerprint，再发外部请求（inferred，业务实现责任）。
2. **重复请求**：同 key + 同 fingerprint 只重放/查询，不创建新意图；同 key + 不同 fingerprint 永不覆盖，进入 conflict（Stripe/AWS verified，跨平台统一化 inferred）。
3. **UNKNOWN**：没有“未收到回执”即“未执行”的转换；先 query/read-back；查询请求本身也要记录其证据时间、版本和响应。
4. **效果确认**：至少绑定目标资源、关键参数和目标系统身份；仅“HTTP 2xx”“平台保存 body”“Kafka commit”不足以单独证明外部效果（verified + inferred boundary）。
5. **安全补偿**：补偿不是匿名重试；引用原效果账本，拥有新 key 和指纹，并可独立 read-back。高风险冲突升级人工。
6. **关闭**：只有达到 `EFFECT_CONFIRMED`/`COMPENSATED` 或经人工带证据关闭；保留原始尝试，不删除以掩盖不确定性。

## 反例与冲突记录

- **conflict（语境冲突，非同一保证）**：Kafka 文档在 Kafka Streams/事务 producer + offsets + `read_committed` 的受限拓扑中支持 exactly-once；同一文档对外部 destination 明确需要目标系统合作，默认语义是 at-least-once。不能把前者推广为任意 HTTP/支付/外部副作用 exactly-once。
- **conflict（术语边界）**：HTTP 的“幂等方法”关注预期服务器效果，Stripe/AWS 的 application-level key 关注重复请求识别与结果重放；两者不能互换，也不能由任一术语推出外部系统 exactly-once。
- **unknown**：未找到官方统一规范把“效果账本”命名为跨平台标准对象；本报告中的账本字段和状态机是证据约束下的设计推论，不是官方 API 合同。

## 非目标与限制

- 不声称 production、上线、事故修复或任何真实服务验证。
- 未执行真实 API 请求、未使用凭据、未读取私有数据；只读取公开官方页面。
- “verified”仅指对应官方资料直接支持该条边界；不等于在所有版本、区域、endpoint、故障模型中成立。
- 资料访问/页面版本以 2026-09-22 抓取为准；官方页面未明确发布日期处记为“未声明”，不能臆造日期。

## 可执行验收清单（设计建议）

- [ ] 同 key + 同 fingerprint 重放不会生成第二个业务 intent。
- [ ] 同 key + 不同 fingerprint 被拒绝并记录冲突。
- [ ] key scope、租户、操作、区域、资源和过期时间均可审计。
- [ ] 发送前 intent 已落账；发送后每次尝试都有 response/transport 状态。
- [ ] timeout/5xx/进程崩溃进入 UNKNOWN，不自动假设未生效。
- [ ] read-back 绑定同一业务身份并记录证据新鲜度。
- [ ] 平台回执、效果确认、补偿完成三个字段不能互相冒充。
- [ ] 补偿新建 key/指纹并引用原效果；冲突进入人工队列。
- [ ] 端到端测试覆盖重复、并发、超时后已生效、超时后未生效、参数冲突、过期复用、read-back 延迟和人工升级。
