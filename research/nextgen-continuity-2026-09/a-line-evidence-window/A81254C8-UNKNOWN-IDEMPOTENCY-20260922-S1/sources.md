# Sources

访问日期：2026-09-22；均为公开官方/一手来源。

1. Temporal Activity Execution — https://docs.temporal.io/activity-execution
   窗口：Activity 发出/执行→timeout/Worker crash→Retry；verified。能证明 task loss 依赖 timeout、重试可能重跑；不能证明外部请求未到达或副作用未发生。
2. Temporal failure detection — https://docs.temporal.io/develop/python/failure-detection
   窗口：Activity success→回报 Temporal 前 Worker crash→再次执行；verified。能证明 at-least-once 与重复副作用风险；不能证明 exactly-once。
3. Temporal activity timeouts/retries — https://docs.temporal.io/develop/python/activities/timeouts#activity-retries
   窗口：Activity attempt→timeout/retry policy；verified。能证明 timeout/retry 机制；不能证明外部效果。
4. Temporal Saga pattern — https://docs.temporal.io/develop/python/failure-detection#implement-saga-pattern
   窗口：步骤失败→应用编排补偿；verified。能证明 Saga 是应用补偿；不能证明补偿自动成功或自动回滚外部系统。
5. AWS Step Functions error handling — https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html
   窗口：Task failure→Retry/Catch→重试或替代状态；verified。能证明编排分支；不能证明失败 Task 无外部效果。
6. AWS workflow types — https://docs.aws.amazon.com/step-functions/latest/dg/choosing-workflow-type.html
   窗口：Standard state execution/Retry 与 Express delivery；verified。能证明 Standard/Express 平台语义；不能证明外部端到端 exactly-once。
7. AWS redrive — https://docs.aws.amazon.com/step-functions/latest/dg/redrive-executions.html
   窗口：failed/aborted/timed out execution→14天内 redrive→失败步骤重跑；verified。能证明 redrive 路径；不能证明外部副作用不重复。
8. AWS StopExecution API — https://docs.aws.amazon.com/step-functions/latest/apireference/API_StopExecution.html
   窗口：StopExecution 请求→execution stopped；verified。能证明编排终止；不能证明已发出外部请求被撤销。
9. Stripe idempotent requests — https://docs.stripe.com/api/idempotent_requests
   窗口：POST + key→保存首次 status/body→保留期内同 key 返回原结果；至少24小时后可能清理；verified。能证明 key 作用域内重试去重；不能证明永久幂等或第三方效果。
10. Stripe low-level errors/idempotency — https://docs.stripe.com/error-low-level#idempotency
    窗口：网络/低层错误→同 key retry；endpoint 未开始的验证/并发错误可能不保存结果；verified。能证明特定重试边界；不能证明客户端异常等于未执行。
11. Apache Kafka Introduction — https://kafka.apache.org/intro/
    窗口：produce/consume/transaction；verified。能证明 Kafka 能力范围；不能证明外部副作用。
12. Apache Kafka semantics — https://kafka.apache.org/documentation/#semantics
    窗口：offset/processing/commit→at-most/at-least/exactly-once 语义；verified。能证明 Kafka 内部交付语义；不能证明外部端到端 exactly-once。
13. Apache Kafka producer idempotence — https://kafka.apache.org/documentation/#producerconfigs_enable.idempotence
    窗口：producer retry→Kafka log 去重；verified。能证明 Kafka producer 级别幂等；不能证明业务/API 幂等。
14. Apache Kafka transactions — https://kafka.apache.org/documentation/#transactions
    窗口：consume-process-produce→Kafka transaction/offset；verified。能证明 Kafka 内部原子链路；不能回滚外部 DB/HTTP/支付。
15. Kubernetes Jobs — https://kubernetes.io/docs/concepts/workloads/controllers/job/
    窗口：Pod fail/delete/node fault→replacement Pod/backoffLimit→Job Failed；verified。能证明 controller 状态；不能证明旧 Pod 外部效果未发生。
16. Kubernetes Pod termination — https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-termination
    窗口：termination request→Pod termination lifecycle；verified。能证明 Pod 生命周期终止；不能证明已发出的外部请求被撤销。
17. Kubernetes Job backoff policy — https://kubernetes.io/docs/concepts/workloads/controllers/job/#pod-backoff-failure-policy
    窗口：失败尝试→backoffLimit/FailureTarget→Job Failed；verified。能证明重试上限/失败判定；不能证明业务效果状态。

统一边界：所有平台的取消、timeout、abort、断流或日志结果只证明平台层观察；外部效果须 operation_id、稳定幂等键、权威 read-back 和业务 postcondition。具体生产配置、外部一致性、幂等缓存实际留存和副作用状态均为 unknown。未访问真实服务、凭据或生产环境；未触碰 shared/P0、事故目录、D10/L12/D14、canonical、140、tri-line、systemd。




## Second independent callback addendum (access date 2026-09-22)

The following first-party sources and boundaries were independently cross-checked and incorporated from the follow-up callback:

18. Temporal Workflow cancellation — https://docs.temporal.io/develop/go/workflows/cancellation
   Window: cancellation request → heartbeat/context delivery → cooperative cleanup; verified. Can prove Temporal cancellation signaling and cleanup pattern; cannot prove an already-issued external request/process was stopped.
19. Temporal Activity failure detection — https://docs.temporal.io/encyclopedia/detecting-activity-failures
   Window: heartbeat/progress → heartbeat timeout → retry; verified. Can prove liveness/timeout mechanics; cannot prove external effect absence.
20. Temporal Retry Policies — https://docs.temporal.io/encyclopedia/retry-policies
   Window: failed Activity attempt → backoff/max-attempt policy → next attempt; verified. Can prove orchestration retry policy; cannot prove exactly-once external effect.
21. AWS Step Functions StopExecution API — https://docs.aws.amazon.com/step-functions/latest/apireference/API_StopExecution.html
   Window: stop request → execution stopped; verified. Can prove state-machine termination; cannot prove issued external work was revoked.
22. Stripe idempotent requests (Markdown) — https://docs.stripe.com/api/idempotent_requests.md
   Window: request + key → first result saved/replayed → key pruning after at least 24 hours may permit a new request; verified. Can prove provider key behavior; cannot prove permanent deduplication or third-party state.
23. Apache Kafka Introduction — https://kafka.apache.org/intro/#intro_guarantees
   Window: produce/retain/consume/transaction; verified for documented Kafka scope. Can prove Kafka processing capabilities; cannot prove arbitrary external exactly-once.
24. Apache Kafka semantics — https://kafka.apache.org/41/documentation.html#semantics
   Window: offset/commit/processing semantics; source page was dynamically rendered and exact static text was not independently extracted, so detailed claims remain unknown pending direct page verification. Do not upgrade to verified beyond the official general scope.
25. Kubernetes Pod termination — https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-termination
   Window: termination request → Pod termination lifecycle; verified. Can prove Kubernetes Pod lifecycle termination; cannot prove an external request or remote job was canceled.
26. Kubernetes Job backoff failure policy — https://kubernetes.io/docs/concepts/workloads/controllers/job/#pod-backoff-failure-policy
   Window: failed Pod/attempt → backoffLimit/failure policy → Job failure; verified. Can prove controller retry/failure boundaries; cannot prove business side-effect state.

### Callback-level synthesis

- `CANCELLED`, `TIMED_OUT`, `HEARTBEAT_TIMEOUT`, `WORKER_CRASH`, `CONNECTION_RESET`, `POD_TERMINATED`, and `JOB_DEADLINE_EXCEEDED` are orchestration observations, not proof of `NOT_SUBMITTED`.
- A compensation action needs its own operation ID, idempotency key, state, and authoritative read-back; Catch/Cleanup/Saga are orchestration patterns, not automatic rollback.
- If the provider key may have expired, do not silently replace it with a new key; use provider object lookup, durable business ledger, reconciliation, or manual review.

The callback did not access real services, accounts, credentials, production environments, or protected targets, and does not establish production verification.
