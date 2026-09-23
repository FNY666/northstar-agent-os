# Durable backpressure 与 admission control：Agent runtime 研究报告

- 研究目录：`/tmp/A81254C8-BACKPRESSURE-20260922-20260922-031447/`
- 资料范围：仅公开的一手官方文档或官方源码；访问日期统一记为 **2026-09-22（Asia/Shanghai）**。
- 结论级别：`verified` 仅表示来源明确写出；`inferred` 是由多个官方语义组合出的工程推论；`unknown` 表示来源未承诺。

## 1. 执行摘要

Agent runtime 必须把一次工作至少建模为两条不同的收据链：

1. **Admission receipt（准入回执）**：发布端收到平台确认，表示消息/记录已达到该平台规定的接收或持久化边界；它只证明“平台接住了（或至少接受了）输入”，不证明消费者已取走，更不证明业务副作用已提交。
2. **Execution receipt（执行回执）**：消费者在业务代码完成、业务事务提交且幂等状态写入后产生；随后才可向平台发送 ack/delete/offset commit。这是业务完成证明，必须由 runtime 自己生成，不能用 broker 的 publish confirm、producer ack、receive response 或 consumer ack 替代。

跨平台一致的安全边界是：**publish confirm ≠ delivery ≠ processing ≠ business commit**。平台通常只知道相邻的一跳：RabbitMQ 官方明确说 publisher confirms 与 consumer acknowledgements 正交且互不知晓；Kafka producer ack 只覆盖记录写入副本的生产端边界；SQS ReceiveMessage/visibility timeout 只描述取出后暂时不可见，DeleteMessage 才是从队列删除的控制点；JetStream 的 stream publish ack 表示成功存储，consumer ack 表示已被消费者确认，但二者之间仍隔着业务执行。

对 Agent runtime 的默认策略：

- 先在本地 durable inbox/状态库生成 `work_id`、业务幂等键和 admission 状态，再发布；仅在收到平台 admission receipt 后把状态转为 `accepted`。
- worker 取到工作后生成 `delivery_attempt_id`，租约/visibility 到期、连接断开或显式 nack 都按“可能重复”处理。
- 业务事务成功提交后写 execution receipt（含业务提交版本/事务 ID），再 ack/delete/commit offset；顺序反过来会导致丢失。
- 将平台保留期、TTL、AckWait/visibility、最大未确认数、prefetch/poll、rate limit 和 DLQ 当作可观测的准入/延迟状态，而不是业务 SLA。
- 默认至少一次、可能重复；业务 handler 必须幂等。只有消息系统的单项去重或 producer idempotence 不能推导出业务 exactly-once。

## 2. 统一状态模型

建议每个工作持久化以下阶段（平台字段只作为证据，不作为业务完成）：

`created → admission_pending → accepted → delivery_pending → executing → business_committed → execution_receipt_written → broker_ack_sent`；失败路径为 `rejected | delayed | expired | redeliverable | dead_lettered`。

- **accepted**：有可追踪的 `admission_receipt`，记录平台、请求/消息 ID、分区/序号（如有）、确认时间、平台配置快照。
- **delivery_pending**：已接受但尚未被消费者拿到；包括 broker 暂存、延迟投递、消费者背压。
- **executing**：收到 delivery；此时必须设定租约/visibility 或平台 AckWait 观察窗口。
- **business_committed**：业务数据库/外部事务已提交；只有这一阶段可支持完成语义。
- **broker_ack_sent**：平台 ack/delete/offset commit 已发出；它不替代 execution receipt，且 ack 成功与下游事务通常不在同一个原子提交中。

### Admission / rejection / delay 的判定

- `accepted` 必须以平台明确的成功回执或持久化响应为依据。
- `rejected` 是明确错误（容量、超限、权限、无效消息、DiscardNew/OverLimit/节流失败等）；不可把网络超时当作 rejected，必须进入 `admission_unknown` 并用幂等键/查询补偿。
- `delayed` 是已接受但尚未可见/未交付（SQS Delay/visibility、JetStream consumer pull 或 MaxAckPending、RabbitMQ prefetch、Kafka consumer lag）。
- `expired` 是消息因 retention/TTL/MaxAge 等消失；它不是业务拒绝，也不是成功。
- `redelivered` 表示此前交付未得到平台认可的完成性信号，绝不能自动等同于业务未执行：原 worker 可能已提交业务但在 ack 前崩溃。

## 3. 平台核验

### Apache Kafka

**生产端确认（verified）**

官方 `ProducerConfig.java` 写明：`acks=0` 不等待 broker，不能保证 server 收到；`acks=1` 只等 leader 本地写入，leader 在 follower 复制前故障可能丢失；`acks=all/-1` 等待全部 in-sync replicas，是可用选项中最强的持久性保证，但仍只针对 Kafka 记录。官方源码还写明 `enable.idempotence=true` 可保证每条消息在 stream 中只有一份，要求 retries>0、acks=all、in-flight 约束；这消除特定 producer 重试重复，不是业务事务完成证明。

**消费者边界（verified/inferred）**

官方 `ConsumerConfig.java` 说明 auto commit 是“后台定期提交 consumer offset”；`max.poll.interval.ms` 限制两次 poll 间隔。offset commit 是消费进度记录，不是业务数据库提交。由此可验证的安全模式是业务 commit 成功后再 commit offset；若先 commit，crash 会跳过尚未提交的业务；若后 commit，crash 会重复，故 handler 必须幂等（inferred，Kafka 文档没有替 runtime 执行事务的承诺）。Kafka 的 partition 顺序只在对应 partition/offset 语境中成立；跨 partition 或重试后的业务副作用顺序未知（inferred）。

**backpressure / retention（verified/inferred）**

producer 自身会批量、等待 `linger.ms`，并受 buffer、delivery timeout、broker 错误与重试影响；消费者 poll/offset lag 表示消费跟不上，但 Kafka 客户端/集群具体拒绝阈值受版本、配置、配额影响，不能泛化成“满了就拒绝”。topic retention 到期会删除记录，不能把长期排队当永久 durable inbox。平台可证明“记录按配置进入日志/offset”，不能证明“Agent 已执行”。

### Amazon SQS

**取出与执行边界（verified）**

官方 visibility timeout 文档写明：Receive 后消息仍在队列中但暂时不可见；默认 visibility timeout 为 30 秒，可按消息调整；若未在超时前处理并 DeleteMessage，消息重新可见并可被同一或其他消费者再次取到。标准队列 at-least-once 语义意味着即使在 visibility window 内也不保证绝不重复。SQS in-flight 是已 receive 但未 delete；标准队列约 120,000 的 in-flight 上限，short polling 达限返回 `OverLimit`，long polling 则暂不返回新消息。这是明确的消费者侧准入/背压边界，不是业务错误。

**保留、过期、顺序、去重（verified）**

官方 quotas 文档给出消息 retention 默认 4 天、最小 60 秒、最大 14 天；FIFO 按 MessageGroupId 严格串行，但 in-flight 消息未 Delete 或 visibility 到期前，同组后续消息不可用。标准队列可能乱序和重复；FIFO 的去重/顺序范围是队列模型与 MessageGroupId，不等于下游业务 exactly-once。DLQ 的 MaxReceiveCount 是平台转移条件，不是业务执行成功。

**receipt 边界（inferred）**

SendMessage 的成功响应可作为 admission receipt（消息被 SQS 接受/返回 MessageId），不能作为 consumer delivery 或业务完成；ReceiveMessage 是 delivery receipt/租约开始，不是 execution receipt；DeleteMessage 是消费者向 SQS 表示可删除，必须在业务 commit 之后发送。SQS 的 receive/delete 之间没有自动地把业务事务与队列删除原子化，因而应使用幂等业务键与重复安全 handler。

### NATS JetStream

**发布、存储和准入（verified）**

官方 streams 文档明确建议使用 JetStream publish calls，因为服务器返回 ack 表示“成功存储”；stream 配置可设置 MaxAge、MaxBytes、MaxMsgs、MaxMsgSize。达到限制时，`DiscardOld` 删除旧消息腾空间，`DiscardNew` 拒绝新消息；官方 README 明确 DiscardNew 的 publish call 返回 limit-reached error。因此这是最清晰的 admission rejection 例子。stream 还支持以 `Nats-Msg-Id` 和滑动窗口去重；窗口外重复、业务重复和消费者重复仍需处理。

**消费者 ack、redelivery 与背压（verified）**

官方 consumers 文档：stream 负责存储，consumer 负责跟踪 delivery/ack；未 ack 或 nack 会自动 redeliver；JetStream consumer 可提供 at-least-once。`AckWait` 是消息“已经 delivery 给 consumer 后”等待 ack 的时长，超时即 redelivery；`MaxAckPending` 是未确认消息最大数量，push consumer 达限是流控；pull consumer 本身以客户端 fetch 形成一对一流控；push 还可用 FlowControl，RateLimit 以 bit/s 节制投递。故 publish ack 是 admission/storage receipt，consumer delivery 是平台投递，consumer ack 只应在业务 commit 后发送，三者都不能替代 execution receipt（最后一项是工程边界推论）。

**retention/expiry（verified）**

WorkQueuePolicy 在消息 ack 后删除；InterestPolicy 在所有相关 consumer ack 后删除；但 MaxAge/MaxBytes/MaxMsgs 等限制始终生效。WorkQueue 达 MaxDeliver 后消息仍可能留在 stream，需要人工删除。即使 JetStream README 使用“exactly-once consumption”描述 WorkQueue，也不能扩展为 exactly-once external side effect；官方 consumers 同时明确 at-least-once 与 redelivery，Agent 仍须幂等。JetStream 文档还警告非复制 file stream 默认 sync interval 可能导致 OS 故障丢失最近已 ack 消息；版本、复制和磁盘设置必须记录。

### RabbitMQ

**生产与消费回执（verified）**

RabbitMQ 官方 confirms 文档明确区分：publisher confirms 覆盖 publisher 与其连接的 node/queue（或 stream）leader；consumer acknowledgements 覆盖 RabbitMQ 向 consumer 的 delivery；二者“entirely orthogonal and unaware of each other”。publisher confirm 不是 consumer 已消费的证明；consumer ack 也不是 publisher 已发送的证明。官方解释 consumer ack 由应用决定何时告知 broker delivery 已成功接收/处理，并可据此标记待删除。

因此：publisher confirm 可作为 admission receipt（在 RabbitMQ 的定义边界内），delivery + consumer ack 之间是执行窗口；execution receipt 必须由 Agent 在业务事务提交后先落盘/发出，再 `basic.ack`。连接/通道关闭可能自动 requeue，重复处理是正常故障路径；nack/requeue、prefetch 和 TTL/队列上限会形成背压、延迟或过期，但平台回执永远不等于下游 commit。由于 rabbitmq.com 页面受到本次抓取的 Cloudflare 挑战，证据使用 RabbitMQ 官方网站仓库的同页源码（URL 见 sources.md），避免以非官方转载替代。

## 4. Agent runtime 的 durable admission/backpressure 设计

### 4.1 最小回执协议

```text
AdmissionReceipt {
  work_id, idempotency_key, platform, stream_or_queue,
  platform_message_id, partition_or_sequence,
  accepted_at, durability_claim, retention_deadline,
  config_snapshot_hash
}
ExecutionReceipt {
  work_id, delivery_attempt_id, handler_version,
  business_transaction_id_or_commit_version,
  committed_at, result_digest, idempotency_effect,
  broker_ack_intent, completed_at
}
```

`durability_claim` 必须具体到 `acks=all`/SQS SendMessage response/JetStream stored ack/Rabbit publisher confirm 和当时复制、retention、discard policy；不能写“可靠”。平台超时后一律 `admission_unknown`，借助幂等键查询或补偿发布，避免盲目重发制造重复。

### 4.2 准入算法与公平性

1. 先检查本地 durable inbox 容量、租户配额、deadline 和预算；满载时返回可重试 `delayed` 或明确 `rejected`，不要无限接收。
2. 给每个工作设置 absolute deadline，平台 retention/TTL 只是更早的硬上界；deadline 过期的工作不得再执行，转 expired/DLQ 并留审计记录。
3. 按租户/优先级使用 token bucket/rate limit；令牌不足表示 delayed，不应伪装成 successful admission。
4. worker 通过 pull、prefetch、MaxAckPending 或并发信号量控制在途数；设置 visibility/AckWait 大于 p99 handler 时间并允许续租，但不能把无限续租当可靠性。
5. commit 顺序严格为 `business commit → execution receipt durable write → broker ack/delete/offset commit`。若 receipt write 与业务库不能原子化，用 outbox/inbox、事务日志或同一 durable store；否则采用恢复扫描和幂等重放。
6. 监控 `admission_unknown`、accepted-to-delivered、delivered-to-commit、redelivery、expiry、DLQ、inflight、lag、ack latency 和 rejection reason；只报告“业务完成”当 execution receipt 存在。

## 5. 不能从平台语义推出的结论

- 任一 producer/publisher confirm 不能推出 consumer 已收到、handler 已运行或下游 commit。
- 任一 consumer ack/Delete/offset commit 不能反向证明业务外部副作用是原子的、唯一的或已对用户可见。
- “exactly-once”若只出现在 broker 的写入/消费层，不能升级为跨数据库、HTTP、工具调用的 exactly-once。
- retention、TTL、visibility、AckWait 只给出保存/租约边界；到期可能删除、重新投递或 DLQ，不能解释业务结果。
- benchmark 吞吐、默认配额与某一版本的实现细节不能当作生产 SLA；必须记录版本、地域/集群配置、复制、保留与新鲜度。

## 6. 版本与新鲜度限制

本报告访问日为 2026-09-22；网页文档可能滚动更新。Kafka 使用 Apache Kafka `trunk` 官方源码，因而源码是当前分支而非固定发行版；生产应锁定 Kafka 发行版本。AWS 文档是 `latest` Developer Guide，配额可能按 region、queue type 与账号改变。NATS 文档页面显示 2.15 latest，源码仓库 `master`，配置字段标注了引入版本（如 AckWait/MaxAckPending 2.2.0、RateLimit 2.2.0、AckFlowControl 2.14），应按实际 nats-server/client 版本复核。RabbitMQ 使用官方网站仓库 `main` 的 2026 版权页源码，因为公开站点有 Cloudflare challenge；具体 broker release、queue type、quorum/stream、prefetch、TTL 与 policy 必须在部署配置中固定。

## 7. 研究判定总表

| 平台 | admission receipt 能证明 | 不能证明 | 主要重复/丢失边界 | 背压/拒绝/过期 |
|---|---|---|---|---|
| Kafka | producer request 按 acks 写入 leader/ISR 的边界；幂等 producer 防特定重试重复 | consumer delivery、offset 后业务 commit | acks=0/1 风险；acks=all 仍非业务 exactly-once；partition 内顺序 | producer buffer/retry/timeout、consumer lag、topic retention；阈值依版本配置 |
| SQS | SendMessage 成功响应被 SQS 接受并返回 ID | Receive 后执行、Delete 后业务原子性 | standard at-least-once/可能乱序；visibility 到期重投；FIFO 仅 group 顺序 | in-flight ~120k、OverLimit/long-poll 静默等待、retention 1m–14d、DLQ |
| JetStream | publish ack 成功存储；DiscardNew 超限明确拒绝 | consumer ack 前的业务 commit | consumer at-least-once/redelivery；stream 去重仅窗口内；OS fsync限制 | DiscardOld/New、MaxAge/Bytes/Msgs、MaxAckPending、pull/flow/rate limit |
| RabbitMQ | publisher confirm 到 leader/node 的边界 | consumer 已处理；consumer ack 与 publisher confirm互不知晓 | connection close requeue、nack/requeue、应用幂等 | prefetch、consumer ack、TTL/queue policy；具体拒绝需版本/config |
