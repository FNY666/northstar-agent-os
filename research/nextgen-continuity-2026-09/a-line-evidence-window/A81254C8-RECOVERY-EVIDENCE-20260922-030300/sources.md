# Sources

访问日期：**2026-09-22**（任务指定访问日期）。以下均为公开官方一手资料；状态字段含义：`verified`=页面直接支持；`inferred`=基于多个直接语义作出的受限工程推论；`unknown`=官方资料未证明的边界。

## Temporal

1. **Events and Event History** — Temporal Documentation  
URL: https://docs.temporal.io/workflow-execution/event  
访问日期: 2026-09-22  
状态: verified  
能证明: Service 通过追加 Events 跟踪 Workflow Execution；Activity 的 Scheduled/Started/Completed/Failed/TimedOut/CancelRequested/Canceled 事件及关联 scheduled/started event IDs；retryable failure/timeout 的重试调度语义。  
不能证明: Activity 的平台完成/失败事件不能证明外部服务已经 commit、回滚或未执行；没有外部系统 receipt 时最终外部状态 unknown。

2. **Temporal Events reference** — Temporal Documentation  
URL: https://docs.temporal.io/references/events  
访问日期: 2026-09-22  
状态: verified  
能证明: Event History 事件字段；`attempt` 是完成 Task 的尝试次数；failure、retry_state、timeout 及 scheduled/started event IDs 的定义。  
不能证明: attempt 是平台 attempt identity，不是外部业务提交的唯一成功证明；事件字段不替代下游 receipt。

3. **Workflow Id and Run Id** — Temporal Documentation  
URL: https://docs.temporal.io/workflow-execution/workflowid-runid  
访问日期: 2026-09-22  
状态: verified  
能证明: Workflow ID 是应用层标识；Run ID 是全局唯一平台标识；Workflow Retry 可能改变当前 Run ID；同一 Workflow ID 同时仅一个 open execution。  
不能证明: 当前 Run ID 可永久作为业务稳定键；也不能证明外部 effect 状态。

4. **Activity Definition** — Temporal Documentation  
URL: https://docs.temporal.io/activity-definition  
访问日期: 2026-09-22  
状态: verified  
能证明: Activity 在 return/error 前不会写入 Event History；若未报告给 server 会 retry；worker 完成 Activity 后在通知 Temporal 前崩溃时 History 不反映成功且会 retry；官方建议 Workflow Run ID + Activity ID 作为跨 retry 的幂等键；Activity 可能执行多次。  
不能证明: 任何 retry attempt 的外部调用是否发生、是否提交；幂等键的去重结果必须由外部目标证明。

5. **Detecting Activity failures** — Temporal Documentation  
URL: https://docs.temporal.io/encyclopedia/detecting-activity-failures  
访问日期: 2026-09-22  
状态: verified  
能证明: Schedule-To-Start、Start-To-Close、Schedule-To-Close、Activity Heartbeat 等超时类别与 failure detection 语义。  
不能证明: heartbeat 或 timeout receipt 具有外部提交/未提交语义；超时后远端是否仍完成是 unknown。

6. **Retry Policies** — Temporal Documentation  
URL: https://docs.temporal.io/encyclopedia/retry-policies  
访问日期: 2026-09-22  
状态: verified  
能证明: Activity failure 默认可按 Retry Policy 自动重试；失败-prone API calls 应在 Activity 中；retry 由平台策略控制。  
不能证明: 平台重试是外部副作用 exactly-once；重试前无需外部查询。

## Kubernetes

7. **Jobs** — Kubernetes Documentation  
URL: https://kubernetes.io/docs/concepts/workloads/controllers/job/  
访问日期: 2026-09-22  
状态: verified  
能证明: Job 创建 Pod 并 retry，直到达到成功 completions；达到目标后 Job complete；文档覆盖 Pod/container failure、backoff、terminal conditions。  
不能证明: Job Complete 或 Pod Succeeded 证明外部 API/数据库/支付已 commit；Pod 重试不会重复执行外部动作。

8. **Job API reference (batch/v1)** — Kubernetes Documentation  
URL: https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/job-v1/  
访问日期: 2026-09-22  
状态: verified  
能证明: Job 是 API 对象，具有 metadata/spec/status；JobStatus 是当前 status，JobCondition 等字段用于控制面状态观察；API 支持 status 读取/watch。  
不能证明: status 是业务效果 receipt；单次 status 读取即最终/强一致的外部真相（具体一致性取决于读取方式与时点）。

9. **Pod lifecycle** — Kubernetes Documentation  
URL: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/  
访问日期: 2026-09-22  
状态: verified  
能证明: Pod 从 Pending/Running 到 Succeeded 或 Failed；Failed 表示容器以失败终止，Succeeded 表示成功终止的生命周期语义。  
不能证明: 容器成功终止等同于业务副作用被远端接受；进程可能在远端提交后丢失响应。

10. **Event API reference (core/v1)** — Kubernetes Documentation  
URL: https://kubernetes.io/docs/reference/kubernetes-api/cluster-resources/event-v1/  
访问日期: 2026-09-22  
状态: verified  
能证明: Event 是 cluster 中某处事件的报告；有限保留；触发器/message 会演进；消费者不应依赖 Reason 的一致触发器或持续存在；Events 是 informative、best-effort、supplemental；`action`、`reason`、`message`、involvedObject 等字段含义。  
不能证明: Event 存在证明动作一定发生/成功；Event 缺失证明动作没发生；Event 能证明外部效果 committed。

## AWS Step Functions

11. **StartExecution API reference** — AWS Documentation  
URL: https://docs.aws.amazon.com/step-functions/latest/apireference/API_StartExecution.html  
访问日期: 2026-09-22  
状态: verified  
能证明: StartExecution 返回 executionArn；Standard 按 name+input 的幂等语义处理，冲突可返回 ExecutionAlreadyExists；name 关闭后 90 天可复用；Express 不幂等。  
不能证明: execution admission/ARN 证明 Task 已运行或外部 effect committed。

12. **GetExecutionHistory API reference** — AWS Documentation  
URL: https://docs.aws.amazon.com/step-functions/latest/apireference/API_GetExecutionHistory.html  
访问日期: 2026-09-22  
状态: verified  
能证明: 指定 execution 的 events 列表、排序、分页、24 小时 pagination token、history event details（含 activity failed/scheduled/started/succeeded/timed out）；不支持 Express state machines。  
不能证明: History event 是外部服务的 commit receipt；缺 history event 不能反推外部动作未发生。

13. **DescribeExecution API reference** — AWS Documentation  
URL: https://docs.aws.amazon.com/step-functions/latest/apireference/API_DescribeExecution.html  
访问日期: 2026-09-22  
状态: verified  
能证明: execution 元数据、input/output、error/cause、status、redrive 信息；状态枚举；官方明示操作 eventually consistent，结果 best effort，可能不反映很近更新。  
不能证明: 一次 DescribeExecution 读数就是最终状态；status/error/cause 证明外部副作用是否 commit。

14. **RedriveExecution API reference** — AWS Documentation  
URL: https://docs.aws.amazon.com/step-functions/latest/apireference/API_RedriveExecution.html  
访问日期: 2026-09-22  
状态: verified  
能证明: Standard workflow 最近 14 天内 failed/aborted/timed out 可 redrive；成功步骤结果/history 保留且不重跑；使用同一 state machine definition 和 execution ARN。  
不能证明: 原失败步骤在第一次运行中没有触达外部系统；redrive 不等于外部去重。

15. **Choosing workflow type / execution guarantees** — AWS Documentation  
URL: https://docs.aws.amazon.com/step-functions/latest/dg/choosing-workflow-type.html  
访问日期: 2026-09-22  
状态: verified  
能证明: Standard 的 exactly-once workflow execution model（除非 ASL Retry）；Express at-least-once，可能多次；两者适用场景不同。  
不能证明: Standard exactly-once 编排扩大为所有外部系统副作用 exactly-once；外部服务仍需自己的 receipt/idempotency。

16. **Using CloudWatch Logs to log execution history** — AWS Documentation  
URL: https://docs.aws.amazon.com/step-functions/latest/dg/cw-logs.html  
访问日期: 2026-09-22  
状态: verified  
能证明: Standard 自身记录 execution history；Express 需 CloudWatch Logs 查看 history/results；CloudWatch log delivery best effort，完整性和及时性不保证；可用 Standard 获取 guaranteed workflow history。  
不能证明: CloudWatch 一条日志存在即外部 commit；日志缺失即未执行。

17. **StopExecution API reference** — AWS Documentation  
URL: https://docs.aws.amazon.com/step-functions/latest/apireference/API_StopExecution.html  
访问日期: 2026-09-22  
状态: verified  
能证明: StopExecution 停止 execution（Standard）；返回 stopDate；error/cause 可受 KMS 处理。  
不能证明: stop receipt 回滚已发出的外部请求，或证明外部 effect 未提交。

## 证据状态说明

- `verified` 仅表示对应官方页面直接支持列出的平台语义。
- `inferred` 结论（例如“平台 Completed 不能证明外部 committed”）是由官方记录范围和明确 worker-crash/日志-best-effort/event-supplemental 限定推出的工程边界，而不是平台对任意外部系统作出的保证。
- `unknown` 不是“失败”，而是官方平台资料没有提供外部目标自身的提交证明；必须通过外部目标 receipt、幂等查询或业务一致性协议收敛。
- 所有页面均公开访问；没有使用 benchmark、私有账号、凭据、真实服务调用或共享目录。
