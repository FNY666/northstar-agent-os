# Agent runtime transactional outbox/inbox 与 UNKNOWN 收敛

- 研究批次：A81254C8-OUTBOX-20260922
- 访问日期：2026-09-22（Asia/Shanghai）
- 范围：仅公开一手官方资料；未访问私有账号、凭据、真实服务、共享目标或上一切片目录。
- 证据标记：`verified` 表示来源直接陈述；`inferred` 表示由多个官方语义组合出的工程推论；`unknown` 表示来源未承诺。

## 1. 结论摘要

### 1.1 本地业务状态与事件必须在同一事务中落库

AWS Prescriptive Guidance 将 transactional outbox 定义为解决数据库写入与消息/事件通知之间 dual-write 不一致的模式。业务表变更与 outbox 行应在同一个本地数据库事务中提交：两者同时成功，或事务回滚时同时不可见。这样可以避免“业务已提交但通知未记录”，也避免“事务回滚但通知已经发出”。这是对**本地数据库原子性**的证明，而不是对下游投递或外部副作用的证明。[verified]

建议 outbox 最少记录：`event_id`、`operation_id`、`aggregate_id`、规范化 payload 摘要、schema/version、created_at、attempt、publish_state、last_error、next_attempt_at 与 retention deadline。业务事务提交后，relay 才有资格读取 committed outbox 行。

### 1.2 Relay 必须按至少一次建模，crash 窗口不可消除

一个 relay 可能在“已向 broker/HTTP 发送，但尚未把 sent 状态持久化”时崩溃；恢复后无法仅凭本地状态判断发送是否已经被目标接受，因此应重试同一稳定 `event_id/operation_id`，而不是生成新业务操作。反向顺序——先把 outbox 标记 sent、再发送——会产生丢投递窗口。[inferred]

Debezium Outbox Event Router 官方文档证明：connector 捕获 outbox 表变化并路由为事件；事件 ID 可用于移除重复消息。它证明的是 CDC/路由链路和重复关联键，不证明外部业务副作用 exactly-once、relay 与目标服务之间原子提交，也不证明任意 connector 故障窗口已经消除。[verified + inferred]

安全默认值：

```text
outbox committed
→ relay publishes / calls target
→ target receipt or durable query evidence
→ relay records delivery observation
```

其中 publish/call 与 relay 状态更新通常不在同一分布式事务内，因此仍必须接受重复或 UNKNOWN。

### 1.3 Consumer inbox 与唯一约束把重复变成可判定状态

AWS 明确指出事件处理服务可能发送重复消息，消费方应通过跟踪已处理消息使处理幂等。Debezium 官方说明事件 ID 可用于移除重复消息。工程上可在消费者本地 durable store 建立 inbox/processed-events 表，以 `event_id` 或稳定业务 operation key 建唯一约束，并将“首次接收、处理中、已提交、失败待重试”与业务变更放入同一数据库事务：

```text
BEGIN
  INSERT inbox(event_id, payload_hash, state)
    ON CONFLICT(event_id) ...
  IF first_delivery:
      apply business mutation
      write execution receipt / next outbox event
  COMMIT
ACK broker only after COMMIT
```

若已有相同 `event_id` 但 payload hash 不同，应拒绝为 `CONFLICT`，不能静默当重复；若状态为已提交，可安全重放已持久化结果或确认 receipt；若状态为处理中，恢复扫描器需要依据租约/版本重新取得处理资格。以上是工程设计推论；官方资料证明的是重复可能性、事件 ID 和幂等必要性，不证明某个自定义 inbox 实现的原子性。[inferred]

### 1.4 第三方 HTTP/支付调用无分布式事务时，UNKNOWN 是合法终态前置状态

Stripe 官方支付状态资料要求集成方监测并验证 PaymentIntent 状态，并可独立 retrieve PaymentIntent 检查当前状态；PaymentIntent 状态可能表示需要进一步处理、客户动作、成功或失败。由此可设计：HTTP/支付请求超时、连接断开或客户端未收到响应时，不得直接判定 `ABSENT`，也不得无保护地创建第二个支付操作；应以稳定 operation/idempotency key重新查询或确认目标状态。

推荐状态轴：

```text
platform_receipt = not_sent | sent_unknown | accepted | rejected | timeout | error
external_effect  = absent | committed | unknown
reconciliation   = not_required | pending | confirmed | conflict | manual_review
```

`unknown` 只有在目标权威查询、幂等查询、服务端 receipt 或对账证据后，才能收敛到 `committed` 或 `absent`。`timeout`、`canceled`、客户端 5xx、日志缺失均不能单独证明外部副作用没有发生。[verified + inferred]

Stripe 页面直接证明“独立检索 PaymentIntent 可确定支付状态”这一查询路径；它不证明任意第三方 HTTP API 都提供同等查询能力，也不证明 PaymentIntent 查询与其他业务数据库变更是原子的。[verified]

### 1.5 Agent 多步工具调用必须每步拥有 durable state 与可重放边界

对多步 Agent 工作，不应只保存最终自然语言结果。每个有副作用的 step 应拥有：`run_id`、`step_id`、`attempt`、目标指纹、规范化参数摘要、稳定 operation key、前置状态版本、outbox/inbox 记录、平台回执、外部查询引用、postcondition 与 reconciliation 状态。推荐每步状态：

```text
planned
→ intent_durable
→ dispatched_or_unknown
→ target_query_pending
→ committed | absent | ambiguous
→ receipt_durable
→ next_step_eligible
```

只有前一步状态为 `committed`，且其 durable receipt 已写入，下一步才可执行。`ambiguous` 必须阻断会继续扩大副作用的下一步，进入 query/reconcile；不能因为编排器重放、工具返回成功或队列 ack 就把它升级为 committed。[inferred]

Temporal 官方说明 Workflow Execution 是 durable/reliable/scalable，状态保存在 Event History 中，失败后可从最近记录事件 replay 恢复。该资料证明编排层可恢复，不证明第三方 HTTP、支付、shell 或任意工具副作用已 exactly-once；外部调用仍需自身 operation key、目标查询、幂等约束与 receipt。[verified + inferred]

## 2. 推荐状态机与故障处理

### 2.1 Outbox producer

```text
created
→ local_txn_pending
→ business_and_outbox_committed
→ relay_pending
→ dispatching
→ dispatch_unknown | target_accepted
→ delivery_observed
```

- 事务提交失败：不产生可投递 outbox 事件。
- 事务成功但 relay 尚未运行：保持 `relay_pending`，不可视为丢失。
- relay 发送后崩溃：`dispatch_unknown`，用相同 operation key 查询或重试；禁止生成新操作代替原操作。
- 目标明确拒绝：`target_rejected`，根据错误分类决定重试、人工介入或业务补偿。

### 2.2 Consumer inbox

```text
received
→ inbox_inserted
→ business_txn_committed
→ execution_receipt_written
→ broker_ack_sent
```

`inbox_inserted` 与业务变更应在同一受支持的本地事务边界中；如果跨数据库或跨服务，不能假设原子性，应引入第二个 outbox、事务日志或显式 reconciliation。broker ack 之前崩溃会导致重复投递，预期行为是唯一约束/幂等处理；broker ack 之后业务尚未提交则可能丢失，因此 ack 必须后置。

### 2.3 第三方调用

```text
intent_durable
→ request_sent_or_unknown
→ authoritative_query
→ committed | absent | ambiguous
```

- `committed`：目标权威状态与 operation key/业务参数匹配，并满足 postcondition。
- `absent`：目标权威查询确认操作不存在，且没有异步处理中状态。
- `ambiguous`：目标不可查询、查询最终一致性未收敛、返回与 operation key 不匹配，或存在多个候选结果。
- `manual_review`：无法自动证明且副作用不可逆、金额/权限/安全风险较高。

补偿不是回滚。只对已确认成功、可逆且有幂等保护的步骤执行补偿；对 `ambiguous` 不执行盲目反向操作。

## 3. 能证明与不能证明

| 证据 | 能证明 | 不能证明 |
|---|---|---|
| 业务表+outbox 同事务提交 | 本地状态和通知意图共同持久化 | broker 已接收、消费者已处理、外部副作用已提交 |
| CDC/Outbox Event Router 捕获并发布 | outbox 变化被连接器处理并按事件字段路由 | 目标业务 exactly-once、跨系统原子性、外部 commit |
| inbox 唯一约束命中 | 某个 event_id 已被本地记录/重复被识别 | 目标副作用一定成功，除非同一事务内有业务 receipt |
| broker ack | 平台达到其 ack 定义的边界 | 外部数据库/API/支付提交 |
| HTTP/支付响应成功 | 该 API 响应成功的接口边界 | 其他本地事务、下游异步效果、用户最终可见 |
| 独立目标查询与 postcondition | 在查询时点目标状态满足条件 | 未来不会被撤销、整个多步 workflow 已完成 |
| Temporal Event History/replay | 编排状态/事件历史可恢复 | 外部工具调用 exactly-once 或外部状态正确 |

## 4. 设计不变量

1. 每个外部副作用先有 durable intent，再允许 dispatch。
2. 本地业务变更与对应 outbox 事件必须同事务提交或同事务回滚。
3. relay 可以重复发送；operation key 必须跨 attempt 稳定。
4. consumer 必须用唯一约束/inbox 或目标端幂等契约去重。
5. broker ack/delete/offset commit 只能在业务 commit 与 durable execution receipt 之后。
6. 任何 timeout、断连、崩溃、取消、日志缺失默认不得判为 absent。
7. 查询不到权威状态时保留 UNKNOWN，不以猜测替代证据。
8. 多步 workflow 的下一步必须依赖前一步 committed receipt，不能依赖工具返回文本。
9. `operation_id` 应绑定目标指纹、规范化参数哈希和 policy/schema revision；同 key 参数冲突必须拒绝。
10. exactly-once external effect 只有在目标端明确提供、验证并覆盖整个副作用边界的原子/幂等机制时才能讨论；本切片的官方资料不足以证明通用 exactly-once。

## 5. 研究限制

- AWS Prescriptive Guidance、Debezium、Temporal 与 Stripe 页面均为滚动在线资料；生产实施应记录抓取日期、实际版本、配置和 URL。
- Debezium 文档说明事件 ID 可用于去重，但未承诺 CDC connector、broker 与 consumer 业务提交构成一个跨系统原子事务。
- Temporal 的 durable execution 是编排层语义；不应升级成外部 effect receipt。
- Stripe PaymentIntent 查询语义仅适用于其 API 对象和生命周期；不能推广到任意 HTTP/支付提供商。
- 本切片没有访问真实服务、凭据或生产配置，因此具体数据库隔离级别、CDC offset durability、broker delivery guarantee、支付方查询收敛时间和补偿可逆性均需在目标系统单独核验。

## 6. 总结

Transactional outbox 解决的是“本地业务状态与发送意图的双写一致性”；CDC/relay 解决的是把已提交意图继续向外传播；inbox/唯一约束解决的是重复消费的判定与抑制；目标查询、receipt 和 reconciliation 才能把第三方 UNKNOWN 收敛为 committed/absent。四者不能互相替代，也不能合并成通用 exactly-once external effect。
