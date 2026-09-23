# Summary — Slice 2

- Temporal 官方明确记录 worker 在外部 Activity 成功后、向服务汇报前崩溃，导致 Event History 没有成功事件、Activity 可能重试；必须由目标服务实施 idempotency key 或让 Activity 幂等。
- Temporal Cancellation 可运行 cleanup/compensation；Termination 不运行 cleanup，部分写入/锁/库存可能保留。
- Temporal/Step Functions/Kubernetes 的 timeout、retry、redrive、rerun、backoff 只能证明编排或控制面状态，不能证明外部效果未发生、已回滚或没有重复。
- Stripe 官方 idempotency 文档提供目标侧模型：结果保存、参数一致性、连接错误安全重试，但 key 可被清理，期限必须纳入协议。
- 统一判定：timeout/cancel/disconnect/partial log 后，缺目标权威 read-back、durable receipt、服务端幂等键/唯一约束或对账时保持 UNKNOWN_NEEDS_RECONCILE。

未触碰真实服务、凭据、共享/P0/事故目录或生产环境；不声称 production 通过。
