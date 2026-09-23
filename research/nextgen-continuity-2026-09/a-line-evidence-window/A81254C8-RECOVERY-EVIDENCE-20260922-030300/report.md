# Agent runtime 恢复证据与歧义结果后的 reconciliation

- 研究批次：A81254C8-RECOVERY-EVIDENCE-20260922
- 资料范围：仅公开官方一手文档；访问日期统一记录为 **2026-09-22**（按任务指定日期）。
- 目标：明确平台能够记录什么、attempt/identity 如何关联、timeout/cancel/error receipt 的边界，以及如何把“平台已接受/平台失败”与“外部效果已提交/未知”分层。
- 明确排除：不把 lease expiry、heartbeat、fencing token 作为主线；仅在证据边界处点到 heartbeat。未访问私有账号、凭据、真实服务或共享目标。

## 结论（可直接用于 runtime 状态机）

1. **平台证据不是外部提交证据。** Temporal 的官方文档明确给出 worker 已完成 Activity、但在通知 Temporal Service 前崩溃的窗口：Event History 不反映成功，Activity 会重试。AWS Step Functions 的执行事件/状态同样是编排平台记录；Kubernetes Job/Pod status 是集群控制面的对象状态。三者都不能单独证明第三方 API、支付、邮件、写库等外部效果已经 committed。
2. **将 receipt 分成两个正交维度：**
   - `platform_receipt`: 平台是否已接收/持久化该调度、完成、失败、超时、取消或终止证据；带平台对象身份和版本/事件序号。
   - `external_effect`: `committed`（由外部系统自己的可核验 receipt/query 证明）、`not_committed`（外部系统明确拒绝/查询确认不存在）、`unknown`（平台超时、worker 崩溃、网络断裂、取消竞态或只看到启动而没有可核验外部 receipt）。
   平台 `SUCCEEDED`/`ActivityTaskCompleted`/Job `Complete` 只能提升 `platform_receipt`，**不能自动把 `external_effect` 设为 committed**。
3. **恢复的最小关联键不是“最新状态”而是稳定身份链。** Temporal 使用 Workflow ID（应用标识）+ Event History 中的 Activity scheduled/started/completed/failed/timeout 关联；每个 Activity retry 还有 attempt。Step Functions 使用 execution ARN、history event id/type/timestamp，并用 StartExecution name 的 Standard 幂等语义；redrive 复用原 execution ARN。Kubernetes 使用 Job UID、Pod UID、container termination/status、Job condition 和 resourceVersion；不要仅用 Pod 名称或 Event reason。
4. **reconciliation 应先查平台证据，再查外部系统：** (a) 固定平台身份与观察时点；(b) 拉取完整/可用 history 或对象 status，区分 `accepted/running/failed/timed_out/canceled/unknown`；(c) 以外部系统的幂等键/查询 API/业务 receipt 进行确认；(d) 确认不到时保持 `unknown`，不要因 retry 或 redrive 直接重做不可逆动作；(e) 只有外部系统确认提交或可证明的去重命中，才转 `committed`。
5. **日志不是完整历史的替代品。** AWS 明确说 CloudWatch Logs 交付 best effort，不保证完整性和及时性；Express Workflow 不在 Step Functions 中记录 execution history。Kubernetes Event 也明确是有限保留、触发器和消息会演进的 informative/best-effort supplemental data。它们可辅助解释，不能作为唯一完成/未完成证明。

## 按平台的证据模型

### A. Temporal

**平台记录与 identity**

- Temporal Service 通过追加 Events 跟踪每个 Workflow Execution，并把 Events 放入该 execution 的 Event History。官方事件参考列出事件类型及字段。
- Workflow ID 是应用层、Namespace 内对 open execution 唯一的标识；Run ID 是平台生成的全局唯一标识。官方同时警告 Workflow Retry 可能改变当前 Run ID，不应把“当前 Run ID”当逻辑稳定键。对 Activity 的外部幂等，应优先采用官方建议的 Workflow Run ID + Activity ID（同一 retry attempts 保持一致且在 Workflow Executions 间唯一），并由业务侧保存外部 effect key。
- Activity 事件链可包括 `ActivityTaskScheduled`、`ActivityTaskStarted`、`ActivityTaskCompleted`、`ActivityTaskFailed`、`ActivityTaskTimedOut`、取消请求/取消完成。Failure/timeout/cancel 事件通过 scheduled event id、started event id 关联到具体任务。
- 官方 Event reference 定义 `attempt` 为完成该 Task 已进行的尝试次数；这使 retry attempt 可进入 reconciliation 记录，但 attempt 本身仍是**平台执行尝试号**，不是外部系统提交号。

**失败、超时、取消的语义**

- Activity 非 retryable failure 会记录 Started + Failed；retryable failure 会安排 retry，达到最大 attempts 后再记录 Failed。
- Start-to-Close 超时发生在 Activity 返回/抛错前时，服务会安排 retry；Schedule-to-Close 或 Schedule-to-Start 超时则写入 `ActivityTaskTimedOut`。取消请求记录为 `ActivityTaskCancelRequested`，Activity 接受取消后记录 `ActivityTaskCanceled`。
- Activity 只有在 return 或产生 error 时才会记录到 Event History；若完全未向 server 报告，官方说明会 retry。特别关键的官方边界例：worker 完成 Activity 但在通知 Temporal Service 前崩溃，History 不显示成功，Activity 会 retry。这是“外部调用可能已发生、平台 completion receipt 缺失”的明确 `unknown` 分支。
- Heartbeat 只作为 Activity 活性/进度检测机制的边界参考；本报告不把 heartbeat 当提交回执。heartbeat 成功也不等价于外部 effect committed。

**reconciliation 规则（Temporal）**

| 观察到的证据 | `platform_receipt` | `external_effect` 能否直接确定 |
|---|---|---|
| Scheduled，无 Started | accepted/scheduled | 不能；可能尚未执行 |
| Started，无 Completed/Failed | running 或 unknown（取决于 timeout/查询时点） | 不能；可能已调用外部系统 |
| TimedOut / worker 未报告 | timed_out / missing completion | 必须 `unknown`，不能推出未提交 |
| Failed | platform failed | 通常 unknown；失败可能发生在外部调用前、后或响应丢失 |
| Completed | platform completed | 不能单独推出 committed；需外部 receipt/query |
| Canceled | cancellation observed（是否已停止外部副作用取决于 Activity） | 不能单独推出 not_committed |

### B. Kubernetes Job / Pod / Event

**平台对象与身份**

- 官方 Job 文档定义：Job 创建一个或多个 Pod，并持续 retry Pod 执行直到达到指定成功 completions；Job 达到成功 completions 后 complete。Job API 的 `JobStatus` 是对象的 current status，包含 conditions 等 status 字段；Pod API 具有 Pod UID、phase、container state/termination 等对象状态。
- Job status/conditions 是控制面观察到的 workload 状态，不是任意业务副作用的事务 receipt。Pod `Succeeded` 表示容器按成功状态终止，Pod `Failed` 表示容器以失败终止；这不等价于远端系统已接受或未接受请求。
- 使用 Job UID、Pod UID、container ID/termination details 和 API `resourceVersion` 建立证据链；Pod 名称可因替换 Pod 而重复/变化，Event reason 也不应作为稳定 attempt identity。`backoffLimit` 与 Pod replacement 说明“Job 会重试”而不是“业务动作只执行一次”。

**Conditions 与 Events 的边界**

- `JobStatus.conditions` 是控制器写入的状态快照，适合回答“控制面目前判断 Job 是否 Complete/Failed、何时改变、理由是什么”。应保存观察到的 condition、last transition time、Job UID 和 resourceVersion。
- Kubernetes 官方 Event API 明确：Event 是集群某处事件的报告；有**有限保留时间**，触发条件和消息可能随时间变化；消费者不应依赖某个 Reason 的时序对应一致触发器，或依赖该 Reason 的 Event 持续存在；Event 应被视为 informative、best-effort、supplemental data。Event 的 `action` 是针对 involved object 采取/失败的动作，`reason` 是机器可读短字符串，`message` 是人类可读描述——它们不是外部提交凭证。
- 因而 Event 缺失不能证明没发生，Event 存在也只能证明 reporting component 记录/报告了该观察；Job Complete 也只证明 Job 控制面达成其 completion 规则。

**reconciliation 规则（Kubernetes）**

| 观察到的证据 | `platform_receipt` | `external_effect` 能否直接确定 |
|---|---|---|
| API 创建成功并返回 Job metadata/UID | API 对象创建已被服务接受/返回 | 不能；Pod 可能还未调度/启动 |
| Job condition Complete | Job 控制器认为所需 Pod completions 达成 | 不能；业务请求可能超时后仍在远端提交，或容器只完成本地工作 |
| Job condition Failed / Pod Failed | 平台工作负载失败 | 不能推出外部未提交；失败位置可能在外部请求前/后 |
| Pod Running/Started 或 Event Normal | 控制面/报告组件观察到生命周期事实 | 不能；没有业务 receipt |
| Event Warning/Failed | 报告组件产生补充诊断 | 不能单独确定最终状态；Event 可能过期或不完整 |

### C. AWS Step Functions

**执行身份、history 与 API receipt**

- `StartExecution` 返回 execution ARN；官方 API 明确 Standard workflow 的 StartExecution 是幂等的：相同 name 和相同 input 时返回相同 execution ARN；相同 name 但不同 input 在窗口内会抛 `ExecutionAlreadyExists`；name 关闭后 90 天可复用。Express StartExecution 不幂等。此处的幂等是平台 execution admission 语义，不是外部 Task effect 的幂等。
- `GetExecutionHistory` 对指定 execution 返回 events 列表，可分页、正序或 reverse order；分页 token 24 小时过期；不支持 Express state machine。History event detail 可包括 activity failed/scheduled/started/succeeded/timed out 等 event details。应持久化 execution ARN、event id、type、timestamp、detail 与查询时点。
- `DescribeExecution` 返回 execution 元数据、input/output、error/cause、status 等；官方明确操作 eventually consistent，结果 best effort，可能不反映很近的更新。读取到旧状态不能当作最终否定；应重读或结合 history/外部 receipt。
- 状态包括 RUNNING、SUCCEEDED、FAILED、TIMED_OUT、ABORTED 等。StopExecution 返回 stopDate 并停止 Standard execution；停止 receipt 证明编排执行被请求/停止，不证明外部 Task 已回滚或没有提交。

**redrive 与日志**

- `RedriveExecution` 可对最近 14 天内失败、aborted 或 timed out 的 Standard execution 继续执行；成功步骤结果和 execution history 保留、不重跑成功步骤；redrive 使用同一 state machine definition 和原 execution ARN。这是很强的 execution identity continuity，但不构成外部 effect receipt；不成功步骤可能在第一次执行中已触达外部系统后丢响应。
- Standard workflow 具有官方描述的 exactly-once execution model（除非 ASL 明确 Retry）；Express 使用 at-least-once model，可能运行多次。因此 runtime 选择必须按 workflow 类型与 Task 外部幂等性分别设计，不能把“Standard exactly-once 编排”扩大解释成所有外部副作用 exactly-once。
- CloudWatch Logs 对 Express 是查看 execution history/results 的路径，但官方明确 log delivery best effort，完整性和及时性不保证；Standard 已在 Step Functions 记录 history，可选日志。日志丢失/延迟不能改变 execution 的平台状态，也不能证明外部 effect。

**reconciliation 规则（Step Functions）**

| 观察到的证据 | `platform_receipt` | `external_effect` 能否直接确定 |
|---|---|---|
| Standard StartExecution 返回 ARN | execution admission accepted | 不能；尚未执行 Task |
| `ActivitySucceeded`/Task succeeded event | Step Functions 记录 task/event 成功 | 不能；下游服务 receipt 仍需核验 |
| FAILED/TIMED_OUT/ABORTED | 编排状态终结/中断 | 不能推出远端未提交 |
| DescribeExecution status | 当前（可能 eventually consistent）的状态观察 | 不能独立作为最新真相 |
| Redrive accepted / same ARN | 恢复/重驱动请求与身份关联 | 不能推出此前失败步骤未产生外部效果 |
| CloudWatch log line | 日志系统收到一条记录（在可见范围内） | 不能；交付本身 best effort |

## 跨平台 reconciliation 状态机

推荐把一次不可逆外部动作建模为下列元组（字段名可按 runtime 改写）：

```text
platform = {system, object_id, attempt_id, event_or_version, observed_at}
request  = {operation, external_idempotency_key, payload_digest}
platform_receipt = accepted | started | completed | failed | timed_out | canceled | unknown
external_effect  = committed | not_committed | unknown
```

约束：

- `completed`、Job `Complete`、Step Functions `SUCCEEDED` 都只能更新 `platform_receipt`。
- `unknown` 不能被 retry/redrive 自动压成 `not_committed`；如果动作不可逆，先以相同外部幂等键查询/去重，再决定 retry。
- `failed`/`timed_out`/`canceled` 也不能自动压成 `not_committed`；必须考虑“远端已执行但 receipt 丢失”。
- 只有外部服务提供其自己的可验证 committed receipt（或按同一幂等键查询到已提交/去重命中），才设置 `external_effect=committed`。平台 execution ARN、Temporal Event History、Kubernetes UID/status、CloudWatch log line 均不替代它。
- 只有外部服务明确拒绝且语义能排除执行，或按幂等键查询明确不存在并满足其一致性/保留窗口，才设置 `not_committed`；否则保留 `unknown`。
- 记录平台观察的 freshness/consistency：Step Functions DescribeExecution 明确 eventually consistent；Kubernetes watch/list 应保存 resourceVersion；Temporal history 应保存事件序列与查询时间。避免把一次陈旧读取当作最终状态。

## 证据覆盖与限制

已查阅 Temporal、Kubernetes、AWS Step Functions 官方文档与 API reference；没有调用真实云/Kubernetes/Temporal 服务，没有 benchmark，也没有把 vendor marketing 或 production report 当成测量证据。文档定义的是各平台的语义和边界，不证明任何具体部署配置、网络路径、外部系统的事务协议或业务效果。若需要把 `committed` 从 `unknown` 转换为确定状态，下一步必须接入外部目标自身的公开 API/receipt 语义（仍需单独授权与范围控制）。
