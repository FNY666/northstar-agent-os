# S5：失联、租约过期与副作用回执的可证伪恢复协议

- **研究切片**：C 线 S5（独立公开研究）
- **截止/访问日期**：2026-09-22（Asia/Shanghai）
- **范围**：仅公开官方一手文档；Kubernetes Lease/resourceVersion、Temporal Activity timeout/heartbeat/retry、AWS Step Functions callback/停止、Azure Blob Lease/条件写。
- **不做的断言**：本文不是生产验证、部署建议或 Exactly-once 证明；没有访问任何真实服务、集群、凭据或既有研究目录。

## 1. 结论（先给可证伪边界）

1. **Lease expiry、heartbeat timeout、调度器检测失联、Step Functions 停止/取消都只是协调层的状态/控制信号。** 它们不证明旧 worker/进程已经停止，也不证明外部副作用没有发生。Temporal 官方明确说服务无法直接检测 worker 失去通信或崩溃，而依赖 Start-To-Close timeout 触发重试；AWS 官方明确说取消是 best-effort，可能无法取消集成任务。
2. **资源侧条件写（例如 Kubernetes `resourceVersion` 预期值、Azure Blob lease ID/条件）能拒绝过期或不持有锁的写入，属于并发/所有权边界，不是效果完成证明。** 409/412 说明这一次条件请求被拒绝；成功条件写只证明资源状态满足写入条件并被服务接受，不证明调用者此前的外部 effect 已完成，更不能单独证明 exactly-once。
3. **“调用已发出但回执丢失”必须进入 UNKNOWN，而不是自动当作失败或成功。** 只有资源侧 read-back、幂等业务键/效果记录、下游回执或人工核验等独立证据，才可能把 UNKNOWN 收敛为已完成/未完成；read-back 也只能证明被读到的资源状态，不自动证明所有外部副作用。
4. **安全恢复的核心是 fenced successor + 可重试但不盲重放**：先用新 epoch/owner 获得协调资格；旧 worker 的写入必须因 epoch/CAS/lease 条件被拒；对 UNKNOWN 先查证，再按下游幂等键重试或执行补偿，达到证据阈值仍不能判定则人工升级。

## 2. 术语和状态机

### 2.1 证据状态

- **VERIFIED（已验证）**：官方文档直接支持的机制或边界。
- **INFERRED（推断）**：由 VERIFIED 机制推出的协议设计；不是平台保证。
- **UNKNOWN（未知）**：现有事件/回执不足以判定 effect 是否发生、是否完整或是否只发生一次。
- **CONFLICT（冲突）**：资料对同一断言给出不能同时采纳的结论；本切片未发现官方一手资料的语义冲突，但平台间行为不能混为一谈，列为**范围差异而非冲突**。

### 2.2 事件与单调状态

为每次意图生成稳定 `operation_id`，并记录 `coordination_epoch`、`attempt_id`、目标资源版本/ETag、请求标识、发送时间和回执状态。建议状态（协议推断）：

`PLANNED → LEASED(epoch=e) → SENT(attempt=a) → {ACKED, REJECTED, UNKNOWN}`

- `ACKED`：有平台成功回执，且必要时 read-back/下游效果证据满足门槛。
- `REJECTED`：有明确条件拒绝（如 Kubernetes 409、Azure 条件失败）或明确业务失败；不能把超时直接等同于 REJECTED。
- `UNKNOWN`：请求可能到达并执行，但响应丢失、连接中断、超时，或平台只给 best-effort 停止。
- 旧 epoch 的 worker 即使仍在运行，也只能尝试；资源条件应拒绝它的后续写。**这不撤销已发生的外部 effect。**

## 3. 可证伪恢复协议

### R0 — 先保存事实，不重放

收集协调器事件、worker 日志/心跳、请求/响应（含 HTTP 状态）、平台 request ID、资源当前版本/ETag/lease 状态、下游效果记录。将缺失字段标记 UNKNOWN；禁止以“租约过期”填补“进程已停”。

### R1 — 失联/过期只触发接管候选

新协调器读取资源并 CAS/条件写入新 `epoch`/owner。Kubernetes resourceVersion 过期写应得到 409；Azure 写入 leased blob 未带正确 lease ID 时应得到 412。若旧 owner 仍能写，fencing 条件无效或覆盖范围不足，应立即停止自动恢复并人工升级。注意：Lease/heartbeat 的时间判断是存活/可用性信号，不是 kill/隔离证明。

### R2 — 先 read-back，再决定重试

对 UNKNOWN 的 `operation_id` 进行只读查询：

1. 查询协调资源：epoch、owner、状态、版本/ETag；
2. 查询效果资源/下游的幂等键或业务结果；
3. 以读到的证据和一致性时间界限判断 `COMPLETED`、`NOT_COMPLETED` 或继续 `UNKNOWN`；
4. 若下游没有可查询的效果记录，不能用协调资源写成功替代 effect 证据。

### R3 — 重试门槛

- 有明确条件拒绝，且 read-back 显示效果未发生：可用**同一 operation_id / 幂等业务键**重试（幂等键是协议设计要求，不是 Kubernetes、Temporal、AWS 或 Azure 单独保证）。
- UNKNOWN：只有在下游明确支持去重、或 read-back 明确未完成时才自动重试；否则保持 UNKNOWN/人工确认。
- Temporal retry 是 Activity Task Execution 的重试机制，不是外部 API exactly-once；Activity 可能在 worker 崩溃前已造成 effect，然后超时再被重试。
- Step Functions callback token 只解决工作流等待/继续条件；它不替代业务 effect 的幂等与 read-back。

### R4 — 补偿与人工升级

补偿必须是已定义、可审计、同样带 epoch/operation_id 的反向业务动作；补偿也可能 UNKNOWN，不能循环盲补。以下任一情况升级人工：无法确定 effect 是否发生；下游无查询/去重能力；旧 worker 仍可通过任一写路径生效；epoch 证据不连续；平台停止/取消返回但外部任务状态未知；检测到重复或部分 effect。人工结论必须附证据链，不得声称 exactly-once。

### R5 — 收敛条件（可证伪）

每个 operation 必须最终落在：`CONFIRMED_COMPLETED`、`CONFIRMED_NOT_COMPLETED`、`COMPENSATED` 或 `HUMAN_ESCALATED_UNKNOWN`。若系统永远只能看到协调层，不可观察下游 effect，则最后一个状态是合法终态，而不是强行补全。

## 4. 官方证据与边界矩阵

| ID | 断言 | 状态 | 直接证据/适用边界 |
|---|---|---|---|
| K1 | Kubernetes Lease 用于节点心跳和组件 leader election；kubelet heartbeat 更新 Lease 的 `spec.renewTime`，控制面用时间戳判断 Node availability。 | VERIFIED | Kubernetes Leases 官方文档；它描述可用性/协调，不描述 kill 或外部副作用。 |
| K2 | Kubernetes 客户端提供 stale `resourceVersion` 时，API server 返回 409 Conflict；官方建议用条件 resourceVersion 检测 lost update 并处理重试。 | VERIFIED | Kubernetes API Concepts 官方文档。409 是本次条件更新拒绝边界。 |
| K3 | Lease expiry/heartbeat loss 不证明旧 worker 已停止，亦不证明 effect 未发生。 | INFERRED（协议安全边界） | K1 仅说明时间戳可用性语义；Temporal F1 和 AWS A1 直接揭示失联/取消与实际任务状态可不同。平台均未给出“expiry=process termination/no effect”保证。 |
| T1 | Temporal 用 Schedule-To-Start、Start-To-Close、Schedule-To-Close、Activity Heartbeats 等 timeout 检测 Activity failure。 | VERIFIED | Temporal《Detecting Activity failures》。 |
| T2 | Temporal Server 不检测 worker 失联/崩溃本身，依赖 Start-To-Close timeout 强制 Activity retry；Activity task 丢失可能发生在 worker 调用函数后崩溃。 | VERIFIED | Temporal 官方《Detecting Activity failures》《Activity Execution》。 |
| T3 | timeout/retry 后外部副作用 exactly-once。 | UNKNOWN / 不得断言 | 官方 Activity timeout/retry 语义没有提供任意外部副作用的原子提交或 exactly-once 证明；若请求已到达，重试可能重复，需下游幂等/read-back。 |
| A1 | Step Functions 有 Request Response、`.sync` Run a Job、Task Token Callback 三类集成模式；callback 等 token 返回后再继续。 | VERIFIED | AWS Step Functions《Discover service integration patterns》。 |
| A2 | `.sync` 任务中止时 Step Functions 对集成任务做 best-effort cancel，可能无法取消（例如无权限或临时服务中断）。 | VERIFIED | 同一 AWS 官方文档；明确不能把停止当作旧任务已停止。 |
| A3 | `StopExecution` “Stops an execution”，且不支持 EXPRESS state machines。 | VERIFIED | AWS `StopExecution` API Reference。该 API 描述的是 execution 控制，不是已发出外部 effect 的回滚/去重。 |
| A4 | Step Functions stop/callback/平台回执能证明外部 effect 未发生。 | UNKNOWN / 不得断言 | 官方资料只给 workflow/task 控制与 best-effort 限制；缺少 effect-level 证据时维持 UNKNOWN。 |
| B1 | Azure Blob Lease 支持 acquire/renew/change/release/break；renew 需匹配 lease ID，文档还说明 lease expired 后若未被修改或重新租用仍可 renew。 | VERIFIED | Microsoft Learn《Lease Blob (REST API)》。具体行为受 API version/状态约束。 |
| B2 | 对 leased blob 的写操作需 lease ID；缺失时失败 412 Precondition Failed；GET 有不同规则，且容器操作不一定受 blob lease 阻止。 | VERIFIED | Microsoft Learn 同文“lease ID needed/412”与操作状态矩阵。不能把 blob lease 自动当全资源 fencing。 |
| B3 | Azure lease 条件成功/412 能证明业务 effect 已完成或 exactly-once。 | UNKNOWN / 不得断言 | 文档证明的是 blob lease/请求条件；没有对任意外部 effect 的完成与 exactly-once 保证。 |
| P1 | “资源侧 CAS 成功 ⇒ effect 完成/Exactly-once”。 | INFERRED（错误推断，必须拒绝） | K2/B2 仅约束资源写入条件；资源写与外部 effect 非同一原子事务。必须另取 effect read-back/幂等证据。 |
| P2 | “调用回执丢失 ⇒ 失败，可直接重试”。 | INFERRED（错误推断，必须拒绝） | 网络语义无法区分未到达、已执行后响应丢失、部分执行；协议规定 UNKNOWN + read-back。 |

## 5. 平台映射与实现注意

### Kubernetes

把 Lease 作为协调信号，把业务资源更新作为带预期 `resourceVersion` 的 fencing 写。收到 409 后读取最新对象并重新判断，不要把冲突当作 effect 未发生。若使用 PATCH 而不是条件更新，确认该 patch 是否依赖旧值；官方警告“非条件数据”适合 patch，不能据此宣称所有 patch 都有 lost-update 防护。任何外部 API 调用应在资源更新前后分别记录 operation_id，但这仍不提供跨系统原子性。

### Temporal

为长 Activity 设置合理 Start-To-Close；长任务配 heartbeat/Heartbeat Timeout。heartbeat timeout 使 Activity 被认为失败并可触发 retry，但 worker 可能在最后一次 heartbeat 后继续运行，或在副作用后失联。Activity 的 retry policy 只能保证调度层继续尝试；外部调用使用 operation_id/幂等键，且必须能查询效果或进入人工 UNKNOWN。不要把 cancellation 回调当作已回滚证明。

### AWS Step Functions

把 Request Response 与 Callback 区分：HTTP/服务响应到达只是调用协议回执；Task Token 是工作流续行凭据，不是 effect receipt。`.sync` 停止时采用 best-effort cancellation，必须把集成任务状态重新查询；StopExecution 只结束 execution 控制流程。若集成服务没有可读状态/幂等接口，停止后的 effect 直接进入 UNKNOWN。

### Azure Blob

Blob lease/lease ID 可作 blob 写路径的条件 fencing，但要审查所有写入口、容器操作、源/目标 blob 的规则及 API version。把 ETag/lease ID/read-back 作为资源证据，不把 lease 成功当作业务动作完成；在丢失响应时用同一 operation_id 查询 blob 内容/元数据及业务结果。

## 6. 失败注入与验收（公开机制上的可证伪测试设计，非生产声明）

以下是设计假设，不是已执行的真实平台测试：

1. **旧 worker 仍运行**：让 epoch=e worker 在协调器判过期后继续发写；期望所有带旧 epoch/resourceVersion/lease ID 的写被拒；若任一路径成功，fencing 失败，记录 CONFLICT 并升级。
2. **effect 后丢回执**：在下游确认已受理后丢弃响应；恢复器必须进入 UNKNOWN，不能直接重试；read-back + operation_id 应收敛为 COMPLETED。
3. **effect 前丢回执**：请求尚未到达即断链；若 read-back 显示 NOT_COMPLETED 且下游幂等可用，允许同 operation_id 重试。
4. **Temporal heartbeat timeout**：停止 heartbeat；验证 Activity timeout/retry 发生，但另一路检测应允许证明旧 worker 是否仍执行，不能从 timeout 本身推出“无 effect”。
5. **AWS stop cancel 失败**：撤销取消所需权限/模拟服务异常；验证 Step Functions 记录停止但集成任务仍需独立查询，结论为 UNKNOWN 直到下游证据。
6. **Azure 过期/错误 lease ID**：分别测试写入 412、read-back 规则、lease renew 的版本/状态限制；不能把 blob 之外的资源入口假定为受 fencing。

验收的必要日志字段：`operation_id, epoch, attempt_id, worker_id, request_id, resourceVersion_or_ETag, lease_id_hash, sent_at, response_status, response_received_at, readback_at, effect_evidence, final_state, escalation_reason`。不要记录凭据或完整 lease secret。

## 7. 未决问题与范围差异

- **UNKNOWN 的时间界限**：官方文档没有给出跨平台、统一的“多少秒后可判定未执行”；需由每个下游的可见性、去重窗口和业务 SLA 定义。
- **时间来源/时钟漂移**：Kubernetes Lease 与 Azure lease 的时间语义受服务端/客户端 API 规则影响；本切片不推导跨平台时钟精度。
- **资源侧与效果侧的原子性**：所查官方资料没有提供 Kubernetes Lease/resourceVersion、Temporal retry、Step Functions stop/callback、Azure Blob lease 之间的跨系统事务；Exactly-once 仍是 UNKNOWN，除非下游另有明确的幂等/事务保证。
- **CONFLICT**：未发现所引同一官方文档内部对上述核心机制的直接矛盾；AWS、Temporal、Kubernetes、Azure 的差异是产品语义/适用范围差异，不能拼成统一保证。

## 8. 结论性规则（可直接放进协调器）

```text
if lease_expired or heartbeat_timeout or execution_stopped:
    mark coordination_liveness = SUSPECT
    never infer old_worker_stopped = true
    never infer external_effect_absent = true
    fence successor with epoch/CAS/conditional lease write

if request_response_missing:
    state = UNKNOWN
    read_back(effect_key, resource_version_or_etag, platform_request_id)
    if effect_confirmed:
        state = CONFIRMED_COMPLETED
    elif effect_absent and downstream_dedup_supported:
        retry_same_operation_id()
    else:
        state = HUMAN_ESCALATED_UNKNOWN

if conditional_write_rejected:
    do_not_call_it_effect_failure
    refresh resource and re-evaluate ownership/effect evidence

never claim exactly_once from lease, heartbeat, timeout, stop, callback,
resourceVersion, ETag, 409, 412, or a successful resource-side CAS alone.
```

## 9. 下一独立切片建议

**S6：跨系统 UNKNOWN 收敛与证据保留窗口**——只研究官方一手资料中的幂等键、去重窗口、效果查询一致性、request ID/审计日志保留、补偿幂等与人工升级 SLA（可选 Stripe API idempotency、AWS DynamoDB conditional writes/transactions、Google Cloud task deduplication 等），产出跨系统“何时可从 UNKNOWN 收敛”的证据矩阵；继续禁止把 lease/CAS/timeout 单独升格为 exactly-once 或旧进程停止证明。
