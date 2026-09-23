# Summary

## 核心结论

对 Agent runtime，必须将 **admission receipt** 与 **execution receipt** 视为两个不可互换的事实：

- admission receipt：Kafka producer ack、SQS SendMessage success、JetStream stored publish ack、RabbitMQ publisher confirm，只证明平台在自身定义的接收/写入边界接受了工作；不证明已投递、已执行、已提交业务副作用。
- execution receipt：runtime 在业务事务提交后生成并持久化，包含 `work_id`、delivery attempt、handler 版本、业务事务 ID/提交版本、结果摘要；随后才 ack/delete/offset commit。

所有四个平台都存在重复或不确定窗口：Kafka consumer offset 与业务 commit 非原子；SQS visibility 到期重投且 standard at-least-once；JetStream AckWait/MaxDeliver 触发 redelivery；RabbitMQ connection/channel 故障可 requeue。默认至少一次、业务幂等，是比“平台 exactly-once”更安全的 runtime 假设。

## 队列准入/背压对照

| 平台 | 已验证的接收/准入边界 | 已验证的背压/过期 | Agent 含义 |
|---|---|---|---|
| Kafka | `acks=0` 无 broker 确认；`acks=1` leader；`acks=all` ISR | buffer/retry/timeout、consumer lag、topic retention（阈值依配置） | producer ack 是记录写入 receipt，不是执行 receipt |
| SQS | Send success；Receive 开始 visibility lease | in-flight ~120k：short poll OverLimit、long poll 暂停；visibility 默认30s；retention 1m–14d | Delete 只能在业务 commit 后；重复安全 |
| NATS JetStream | publish ack=成功存储；DiscardNew 达限明确拒绝 | DiscardOld/New、MaxAge/Bytes/Msgs、MaxAckPending、AckWait、RateLimit、pull/flow control | stored ack/consumer ack 不能证明外部副作用 |
| RabbitMQ | publisher confirm 到 node/leader | consumer ack、requeue、prefetch、TTL/policy（具体数值本次不据未验证页面断言） | publisher 与 consumer confirms 正交；业务完成另建 receipt |

## 推荐最小协议

`created → admission_pending → accepted → delivery_pending → executing → business_committed → execution_receipt_written → broker_ack_sent`。

- 明确拒绝才 `rejected`；网络超时进入 `admission_unknown`，不能盲目重发。
- 以 absolute deadline 统一约束 retention/TTL 与执行预算。
- 限制本地 inbox、租户 token bucket、在途并发；将 delayed、expired、redelivered、dead-lettered 分开计数。
- 业务提交 → execution receipt durable write → broker ack/delete/offset commit；无法原子化时使用 outbox/inbox、事务日志或幂等重放。
- 生产只把 `execution_receipt` 计入完成率；平台确认计入 admission/transport 指标。

## 关键限制

本报告只使用公开官方资料，访问日 2026-09-22。Kafka/NATS/Rabbit 文档或源码为滚动分支/最新页面；AWS 为 latest Developer Guide；数字、默认值、retention、复制与过载行为必须按生产发行版、region、queue/stream 类型和配置复核。RabbitMQ 页面本次受 Cloudflare challenge，因此使用 RabbitMQ 官方网站仓库同页源码，并对未能抓取正文的 queues/TTL 页面标为 unknown。

详见 `report.md` 与 `sources.md`。
