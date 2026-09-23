# Summary

## 核心结论

Transactional outbox、CDC/relay、consumer inbox 和 reconciliation 是四个不同层次：

1. **Transactional outbox**：把本地业务变更与发送意图放进同一数据库事务，解决 dual-write；不证明下游已接收。
2. **CDC/relay**：把已提交 outbox 继续投递；relay crash 可能产生重复或 UNKNOWN，必须按至少一次建模。
3. **Consumer inbox/唯一约束**：识别重复 event，并在本地事务中将去重记录、业务变更、execution receipt 绑定；broker ack 后置。
4. **Query/confirm/reconcile**：第三方 HTTP/支付调用超时或断连时，把结果保持为 UNKNOWN，依靠目标权威查询、稳定 operation key、receipt 和 postcondition 收敛。

## 推荐状态链

```text
local business txn + outbox commit
→ relay pending
→ dispatched_or_unknown
→ authoritative query
→ committed | absent | ambiguous
→ durable receipt
→ next step eligible
```

消费者侧：

```text
receive
→ inbox unique insert
→ business commit
→ execution receipt
→ broker ack
```

## 关键边界

- outbox 同事务提交 ≠ broker delivery ≠ consumer processing ≠ external business commit。
- CDC router 的 event ID 可用于去重，但不产生跨系统 exactly-once。
- Temporal Event History/replay 恢复的是编排事实，不是外部副作用事实。
- 支付/HTTP 请求超时、取消、连接断开、日志缺失，均不能直接判定 `absent`。
- 补偿不是回滚；对 UNKNOWN 不得盲目执行反向操作。
- Agent 多步流程的下一步必须依赖前一步的 durable `committed` receipt，而不能依赖工具文本或 broker ack。

## 最小不变量

```text
业务状态 + outbox 意图：同一事务
relay：至少一次、稳定 operation_id
consumer：唯一约束/inbox、业务提交后 ack
UNKNOWN：先 query/reconcile，再决定 retry/compensation/manual review
exactly-once external effect：默认 unknown
```

## 资料限制

本切片只使用 AWS、Debezium、Temporal、Stripe 官方在线资料，访问日为 2026-09-22。具体版本、数据库隔离级别、CDC offset、broker 语义、支付状态收敛时间和补偿可逆性仍须对目标系统单独核验。