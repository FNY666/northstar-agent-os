# 取消、超时、断流后的 UNKNOWN、幂等重试与补偿

- 访问日期：2026-09-22（Asia/Shanghai）
- 范围：Temporal、AWS Step Functions、Stripe、Apache Kafka、Kubernetes 官方公开资料
- 结论等级：verified=官方直接支持；inferred=由官方行为边界推导；unknown=官方资料不足
- 环境边界：未访问真实服务、账户、凭据或生产环境；不代表 production 通过。

## 结论

当调用方已经发出请求，但在收到结果前发生取消、超时、断流、Worker/Pod 崩溃或编排器终止时，安全状态不是 FAILED_BEFORE_EFFECT，而是：

```text
SENT_UNKNOWN / UNKNOWN_NEEDS_RECONCILE
```

原因是外部系统可能已经接受请求，平台却没有收到成功回执。取消不等于外部撤销；timeout 不等于未执行；重试不等于幂等；平台完成/失败不等于业务效果已确认。

安全收敛顺序：

```text
stable operation_id
→ durable operation ledger
→ stable provider idempotency key
→ timeout/cancel/disconnect => UNKNOWN
→ authoritative read-back
→ same-key retry only when safe
→ compensation only after original effect is known
→ compensation itself requires idempotency/read-back
```

## 统一状态

```text
NOT_SENT → SENDING → SENT_UNKNOWN
SENT_UNKNOWN → ACCEPTED | SUCCEEDED | FAILED_BEFORE_EFFECT
SENT_UNKNOWN → COMPENSATION_PENDING → COMPENSATED
```

`NOT_FOUND` 只有在外部查询具有权威不存在语义时才可收敛为未执行；查询失败、权限不足、最终一致性延迟和日志缺失仍为 UNKNOWN。

## 跨平台事实

### Temporal

**verified**：Activity 是 at-least-once；Worker 已执行成功但在通知 Temporal 前崩溃时可能重试。Heartbeat 是取消/活性边界；Activity 必须 heartbeat 才能收到取消。Activity timeout 可按 Retry Policy 重试。官方建议用 Workflow Run ID + Activity ID 构造跨 retry 稳定的外部幂等键。Saga/补偿是应用逻辑，不是平台自动回滚。

**inferred**：取消只通知 Activity，不自动杀死已经启动的外部进程、远程作业或 HTTP 副作用；timeout 后必须先查询外部 operation_id；补偿 Activity 也必须幂等。

**unknown**：Temporal 单凭 timeout、cancel 或 Activity history 无法证明外部请求未被接受、未提交或未产生重复效果。

### AWS Step Functions

**verified**：Retry 重新执行失败 state，Catch 可进入替代/补偿路径。Standard 默认 exactly-once 是状态执行语义，显式 Retry 后可再次运行；Express 是 at-least-once。Standard 失败、aborted、timed out execution 可在 14 天内 redrive；redrive 重新调度失败步骤，成功步骤不重跑，retry attempt count 可重置。

**inferred**：Standard exactly-once 不等于 Lambda、HTTP、数据库、支付或其他外部副作用 exactly-once。StopExecution 停止编排，不提供任意已发出外部请求的通用撤销保证。Catch 不证明补偿成功。

**unknown**：外部 Task 是否已接受、异步处理是否完成、redrive 是否将产生重复业务效果，均需外部 read-back。

### Stripe

**verified**：相同 Idempotency-Key 在记录保留期间返回第一次请求的 status/body，包括 500；参数不一致会报错。key 至少 24 小时后可能被清理，清理后复用可能生成新请求。参数验证失败或并发冲突等 endpoint 尚未开始的情况可能不保存结果。

**inferred**：断流/timeout 后应先用同 key 查询或重试；超过 key 生命周期后不能仅依赖旧 key，必须使用对象查询、业务 ledger 或人工对账。Stripe 幂等不替代本地 operation record。

**unknown**：客户端异常或 500 单独不能证明 Stripe 没有产生业务效果；幂等键不是永久业务主键。

### Apache Kafka

**verified**：Kafka 可提供 at-most-once、at-least-once，或在 Kafka 内部事务读-处理-写链路中提供 exactly-once 语义，取决于配置和事务模型。offset 表示 Kafka 消费进度；producer idempotence/transaction 保护 Kafka 内部记录与 offset 协同。

**inferred**：Kafka exactly-once 不覆盖外部数据库、HTTP、支付、邮件或文件系统；consumer 在外部调用后、offset commit 前崩溃会造成重复消费风险。消息 event_id/operation_id 应成为外部幂等关联键。

**unknown**：offset、rebalance 或 Kafka transaction 不能证明外部副作用已完成、未重复或可回滚。

### Kubernetes Job

**verified**：Pod 失败、删除或节点故障可触发替代 Pod；backoffLimit 控制失败尝试，达到后 Job Failed。activeDeadlineSeconds 到期会终止运行中的 Pod并将 Job 标为 `DeadlineExceeded`；失败后没有自动 Job restart。

**inferred**：终止 Pod 不等于撤销已经发出的 HTTP、云任务、事务或消息；替代 Pod 可能与旧 Pod 的外部效果重叠。Job/Pod UID 是追踪标识，不是跨 retry 的业务幂等键。

**unknown**：Job Succeeded/Failed 不能单独证明外部业务效果；需 operation ledger 和目标系统 read-back。

## 重试规则

| 观察结果 | 处理 |
|---|---|
| 明确未发送、参数验证失败且 endpoint 未开始 | 可按官方语义重试 |
| 明确未接受且查询语义权威 | 可用同一 operation/key 重试 |
| 成功或 read-back 已成功 | 禁止重复副作用 |
| timeout、断流、Worker/Pod 崩溃、cancel、abort、deadline | 先进入 UNKNOWN 并 read-back |
| read-back pending | 等待/轮询/回调，不盲重试 |
| read-back 明确不存在且具权威不存在语义 | 才可新提交 |
| read-back 失败、权限不足或最终一致性不明 | 保持 UNKNOWN |

## 幂等键设计

```text
operation_id = stable business operation ID
intent_hash  = hash(canonical request)
provider_key = stable key bound to operation_id + intent_hash
```

禁止把 retry attempt、Pod name、Kafka offset 或进程内随机值作为跨 retry 业务幂等键。参数改变应创建新业务操作，并先处理旧操作 UNKNOWN。记录 key 创建时间、provider retention、过期时间、最近 read-back 和 attempt count。

## 补偿规则

补偿不是“再做一次原操作”，也不是自动回滚。创建资源的补偿可能是删除，扣款的补偿可能是退款，远程任务的补偿可能是取消；每个补偿都有自己的 operation_id、幂等 key、状态和 read-back。

补偿前先查询原操作：

```text
NOT_FOUND/NOT_ACCEPTED → 无需补偿或安全重提交
PENDING                → 等待原操作收敛
SUCCEEDED              → 执行补偿
FAILED_BEFORE_EFFECT   → 无需补偿
PARTIAL/AFTER_EFFECT   → 按业务规则补偿
UNKNOWN                → 默认不直接补偿，除非业务规则明确补偿风险更低
```

## 总结

```text
取消 ≠ 外部撤销
超时 ≠ 未执行
断流 ≠ 失败前未生效
重试 ≠ 幂等
编排成功 ≠ 外部业务成功
编排失败 ≠ 外部业务未发生
补偿完成 ≠ 原操作已被权威逆转
```


## Protection and evidence statement
- Research used only public first-party documentation and source URLs; access date for every source: 2026-09-22.
- No real service, account, credential, production environment, or private data was accessed.
- No shared/P0, incident directory, D10/L12/D14, canonical, 140, tri-line, or systemd was accessed or modified.
- `UNKNOWN_NEEDS_RECONCILE` is the conservative state when platform outcome is known but external effect is not authoritative.


## Callback addendum and source boundaries
The second independent callback was incorporated. It adds Temporal cooperative cancellation, Temporal retry/heartbeat details, Step Functions StopExecution, Stripe Markdown idempotency page, Kafka Introduction/semantics scope, and Kubernetes Pod termination/backoff sources. The Kafka semantics page was dynamically rendered and its detailed static text was not independently extracted; those detailed claims remain unknown rather than upgraded. No production verification is claimed.
