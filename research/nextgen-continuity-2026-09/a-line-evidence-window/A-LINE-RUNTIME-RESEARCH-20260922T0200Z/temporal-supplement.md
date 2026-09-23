# Temporal 官方生命周期研究补充

- 来源：A线子研究结果回传
- 访问日期：2026-09-22
- 资料范围：Temporal 官方文档及 temporalio/api 官方源码
- 证据标签：verified=官方原文/源码直接支持；inferred=工程推论；unknown=官方资料未证明

## 补充核验结论

### 状态与暂停

- **verified**：Workflow Execution 可处于 Open 或 Closed；Open 包含 Running、Paused；Closed 包含 Completed、Failed、Canceled、Terminated、Timed Out、Continued-As-New。
- **verified**：Workflow Pause 不等于终止：暂停后不派发新的 Workflow Task/Activity Task，但已运行 Activity 不会因此自动中断；时间、Timer 与 timeout 仍可能继续推进；Pause/Unpause 会留下带身份、原因和 request ID 的事件记录。
- **verified**：Activity Pause 与 Workflow Pause 是独立机制。Activity Pause 主要阻止后续 retry；有 heartbeat 的运行中 Activity 可在 heartbeat 时感知暂停，无 heartbeat 时可能继续运行至完成或失败。
- **unknown**：Pause 不证明已经发出的 HTTP、数据库、支付或消息请求被取消，也不提供冻结全部外部副作用的原子语义。

### 失败与重试

- **verified**：Workflow Task Failure 通常自动重试并从 Event History replay；Workflow Execution Failure 是该 execution 的失败终态。
- **verified**：官方区分 transient、intermittent、permanent failure；永久失败应标记 non-retryable，避免无意义重试。
- **verified**：Activity 可能在已经完成外部动作、但 Worker 尚未向 Temporal 报告前崩溃时被再次执行；官方建议使用幂等逻辑或目标侧 idempotency key。
- **verified**：Heartbeat 可报告存活/进度并携带 details；重试可从最近 heartbeat details 恢复，但这不是外部事务提交证明。
- **verified**：Signal/Update 有 request/update ID 等去重边界；Update 的去重按 Workflow Run 生效，Continue-As-New 后跨 Run 的业务幂等仍需应用状态维护。
- **inferred**：失败分类仍是业务设计决策，Temporal Service 不能完全自动判断某失败是否永久。
- **unknown**：Temporal 不替代外部系统的唯一约束、去重表、幂等 API 或补偿事务。

### 人工批准与消息

- **verified**：Temporal 核心公开消息机制包括 Signal、Update、Query；本次资料没有证明一个跨 SDK 的独立 Human Approval 原语。
- **verified**：Signal 是异步消息；Update 支持 validator、持久化后 handler 执行及同步结果；Update 可区分 Accepted 与 Completed。
- **inferred**：人工批准可用 Signal/Update 建模，但审批人身份、批准权限、四眼原则和审批证据保全需应用层实现。
- **verified**：仅确认 Signal 已发送不能证明 handler 已完成；Workflow 结束前仍需处理 handler 完成边界。

### 外部 read-back 与最终验证

- **verified**：Visibility 是最终一致搜索索引；针对单个 Workflow 的最新状态应使用 Describe，而不能只依据 List/Count。
- **verified**：Event History 是用于 replay、恢复、调试和审计的持久事件序列。
- **inferred**：若业务要求证明外部目标完成，应显式建模：稳定幂等写入 → 外部 read-back → 业务后置条件断言 → 不一致时 retry/人工介入/明确 failure。
- **unknown**：Workflow Completed、Activity Completed 或 Event History 不能单独证明外部数据库/API/支付系统已经提交且达到预期最终状态。

### 证据保全

- **verified**：Event History 可记录 Activity、Timer、Signal、Update、Pause/Unpause 和最终结果等生命周期事件。
- **verified**：Workflow History Export 采用至少一次投递语义；下游必须去重。
- **verified**：Temporal Cloud Audit Logs 主要记录 Control Plane 操作，不覆盖 Data Plane Workflow 生命周期；异步 API 的 OK 只表示请求被接受，仍需查询异步操作最终结果。
- **unknown**：官方资料未证明普通 Worker 日志、Cloud Export 文件默认具备不可篡改、WORM、法律保全、全量无缺失或独立时间戳属性。

## 补充来源

以下 URL 均为官方来源，访问日期统一为 2026-09-22：

- https://docs.temporal.io/encyclopedia/workflow/workflow-pause.md — verified Workflow Pause/Unpause；unknown 外部冻结语义。
- https://docs.temporal.io/activity-operations/pause.md — verified Activity Pause。
- https://docs.temporal.io/activity-operations/unpause.md — verified Activity Unpause。
- https://docs.temporal.io/references/failures.md — verified Failure 模型。
- https://docs.temporal.io/best-practices/error-handling.md — verified 失败分类与幂等建议。
- https://docs.temporal.io/handling-messages.md — verified Signal/Update/Query 与消息完成边界。
- https://docs.temporal.io/sending-messages.md — verified 消息发送与请求去重边界。
- https://docs.temporal.io/design-patterns/request-response-via-updates.md — verified Update 请求-响应模型。
- https://docs.temporal.io/visibility.md — verified Visibility 最终一致与 Describe 边界。
- https://docs.temporal.io/cloud/export.md — verified History Export 与至少一次投递；unknown 防篡改/法律保全。
- https://docs.temporal.io/cloud/audit-logs.md — verified Control Plane/Data Plane 审计边界。
- https://github.com/temporalio/api/blob/master/temporal/api/enums/v1/workflow.proto — verified Workflow 状态枚举。
- https://github.com/temporalio/api/blob/master/temporal/api/enums/v1/event_type.proto — verified Event 类型枚举。
- https://github.com/temporalio/api/blob/master/temporal/api/failure/v1/message.proto — verified Failure protobuf 边界。

## 总边界

本补充不把 Temporal 平台回执、Workflow Completed、Activity Completed、Visibility、Export 或普通日志升级为外部效果证明；不把 benchmark 当 production 证据。