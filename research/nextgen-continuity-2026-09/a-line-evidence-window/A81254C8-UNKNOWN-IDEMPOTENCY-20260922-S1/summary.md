# Summary

访问日期：2026-09-22。仅公开一手资料。

核心结论：取消、超时、断流、Worker/Pod 崩溃或编排终止，在外部效果未被权威查询前统一进入 `UNKNOWN_NEEDS_RECONCILE`，不能直接判定未执行或安全重试。

Temporal Activity 默认 at-least-once；Step Functions Retry/redrive 会重跑失败状态，Express at-least-once；Stripe key 在至少24小时后可能清理；Kafka exactly-once 仅限 Kafka 内部事务链路；Kubernetes Job 替代 Pod 和 deadline 不撤销已发出的外部请求。

最小闭环：稳定 operation_id、durable ledger、稳定 provider key、intent_hash、read-back、原操作与补偿分别幂等。只有明确权威 `NOT_ACCEPTED/NOT_FOUND` 才允许新提交；查询失败、权限不足、最终一致性、日志缺失均保持 UNKNOWN。

能证明：平台重试/取消/超时/保留及幂等机制的官方语义。
不能证明：外部请求未接受、外部副作用未发生、补偿已生效、端到端 exactly-once 或生产配置满足要求。

逐源 URL、访问日期、证据窗口、verified/inferred/unknown、能/不能证明边界见 `sources.md`。未声称 production 通过；未触碰受保护目标。


## Callback addendum
The second independent callback confirms and sharpens the same boundaries: cancellation is cooperative, timeout is not non-submission proof, retries may repeat external effects, Stripe keys are not permanent, Kafka exactly-once is scope-limited, Kubernetes replacement/deadline does not revoke remote effects, and compensation requires independent idempotency plus read-back. Detailed source-by-source additions are in `sources.md`.
