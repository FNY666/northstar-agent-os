# A线公开一手资料研究：优秀 Agent/CLI 任务生命周期、失败恢复与验证闭环

- 研究日期：2026-09-22
- 范围：仅公开官方文档/官方源码；未接触凭据、真实服务、共享目标或受保护目录。
- 证据标签：verified=一手资料直接支持；inferred=基于已验证机制的工程推论；unknown=资料未证明。

## 一、结论摘要

1. **Temporal**提供最完整的 durable execution 生命周期：Workflow Execution 有明确 Open/Closed 状态、Event History、Replay、Activity Retry 与失败类型；但 Activity 外部副作用可能重复，必须由目标系统幂等/去重，且 Workflow 完成不自动证明外部目标最终状态。
2. **LangGraph**把可暂停任务建模为 thread + checkpoint + interrupt/resume：同一 thread_id 恢复检查点，人工输入可继续；节点在 interrupt 前的代码恢复时会再次执行，因此副作用必须移到 interrupt 后或做幂等。它提供状态持久化与时间旅行能力，但不自动提供外部副作用 read-back 或 exactly-once。
3. **OpenAI Agents SDK**提供 run-wide HITL interruption、可序列化 RunState、approve/reject 后恢复，以及 tracing/guardrails/error handlers；官方资料可证明 SDK 运行控制与记录机制，不能单独证明外部工具副作用已提交、最终目标状态正确或重试安全。
4. 三者共同边界：**平台接受/记录/恢复 ≠ 外部目标已生效**。可靠闭环应分离：请求发出、平台持久化、工具返回、外部 read-back、业务后置条件、最终证据归档。

## 二、横向比较

| 维度 | Temporal | LangGraph | OpenAI Agents SDK |
|---|---|---|---|
| 状态模型 | Workflow Execution；Open/Closed；Run/Chain；Event History | thread-scoped graph state；checkpoint；interrupt 状态 | Run/RunState；工具审批 interruption；trace/span |
| 暂停/恢复 | Workflow/Activity pause；Replay 从已记录事件恢复 | interrupt 保存状态；同 thread_id + Command(resume) 恢复 | tool approval interruption；序列化 RunState 后 approve/reject/resume |
| 失败分类 | Workflow Task、Execution、Activity、Timeout、Cancel、Terminate、Application；transient/intermittent/permanent | 文档强调 fault tolerance/checkpoint；具体失败分类依应用代码，未发现统一生产失败 taxonomy | tool/guardrail/run error handlers；具体故障分类和持久状态语义需应用定义 |
| 重试与幂等 | Activity 自动 Retry；永久错误 non-retryable；Activity 可能多次执行，需目标侧 idempotency key | 文档明确 interrupt 前节点代码恢复会再次执行；副作用需幂等或放到 interrupt 后；通用 exactly-once 未证明 | SDK错误处理/恢复与审批流可组合；外部工具是否重试、幂等、补偿由应用/工具决定 |
| 人工批准 | Signal/Update 可建模；核心资料未证明独立 Approval 原语 | interrupt 是直接人工输入机制 | 工具 needs_approval；pending approval surfaced as interruption；RunState resume |
| 外部 read-back | Activity 可显式执行查询；必须由 Workflow 建模验证 | 可在图节点中显式查询，但不是 persistence 自动能力 | 可在工具/节点中显式查询；SDK未自动验证外部状态 |
| 最终验证 | Describe 单体状态 + Event History；Visibility 最终一致；外部效果仍需 read-back | 最终 state/output 只是图状态；不证明外部目标 | Run result/trace 证明 SDK运行路径；不证明外部提交或目标后置条件 |
| 日志/证据 | Event History 持久追加事件；Cloud export at-least-once；普通日志边界有限 | checkpoint/state/event stream；资料未证明不可篡改或法律保全 | traces/spans覆盖模型/工具/guardrail等运行事件；未证明不可篡改、完整或外部审计等价 |

## 三、按对象的证据笔记

### A. Temporal

- **verified**：Workflow Execution 是 durable/reliable；失败后从 Event History replay，状态从最新已记录事件恢复。
- **verified**：Open 状态含 Running/Paused；Closed 含 Completed/Failed/Canceled/Terminated/Timed Out/Continued-As-New；Execution 由 Namespace、Workflow ID、Run ID 标识。
- **verified**：Activity 默认可自动 retry；Retry Policy支持 backoff、maximum attempts、non-retryable error types；Workflow Task不使用普通 Retry Policy，而按 Workflow Execution Timeout 重试。
- **verified**：官方将 transient/intermittent/permanent failures 区分；永久错误应 non-retryable。
- **verified**：Activity 可能在已完成但结果未上报时再次执行；应使用幂等逻辑或由外部服务执行 idempotency key。
- **verified**：Event History记录调度、开始、完成、失败、超时、消息及最终结果；Cloud Audit Logs不覆盖 Data Plane Workflow 生命周期；异步 API 的 OK 只表示请求接受，需查询异步操作最终结果。
- **verified**：Visibility是最终一致搜索索引；单个 Workflow 的当前状态应以 Describe 为准。
- **inferred**：外部控制器应把 Workflow/Run/Activity/operation/idempotency key/read-back/verification_result 作为分层证据字段。
- **unknown**：Temporal不自动保证外部数据库/API/支付系统 exactly-once、提交与 Event History 原子一致、最终状态等于 Activity 返回值；普通 Worker 日志默认留存/防篡改未知。

来源：
- https://docs.temporal.io/workflow-execution （访问 2026-09-22；verified 状态、Replay、Run/Chain）
- https://docs.temporal.io/encyclopedia/retry-policies （访问 2026-09-22；verified Retry/失败类别边界）
- https://docs.temporal.io/activity-definition （访问 2026-09-22；verified Activity 重试、多次执行、幂等键）
- https://docs.temporal.io/visibility （访问 2026-09-22；verified Visibility 最终一致与 Describe 边界）
- https://docs.temporal.io/workflow-execution/event （访问 2026-09-22；verified Event History 与状态事件）
- https://docs.temporal.io/cloud/audit-logs （访问 2026-09-22；verified Control Plane/Data Plane 边界）
- https://docs.temporal.io/cloud/export （访问 2026-09-22；verified History Export、at-least-once；unknown 防篡改/法律保全）

### B. LangGraph

- **verified**：`interrupt()`可暂停图执行并把可JSON序列化 payload 返回调用者；需 checkpointer 与 thread_id；同一 thread_id + `Command(resume=...)`继续。
- **verified**：生产环境应使用持久 checkpointer；内存 saver 进程重启会丢失 checkpoint。
- **verified**：恢复时从包含 interrupt 的节点开头重新执行；interrupt 前代码会再次运行；官方因此要求副作用在 interrupt 后执行或保证幂等。
- **verified**：checkpointer持久化 thread 状态，支持故障恢复、人机协作和 time travel；store用于跨 thread 长期数据。
- **verified**：事件流暴露 interrupted、interrupts 和最终 output。
- **inferred**：thread_id相当于恢复游标；外部审计应保存 thread_id、checkpoint标识、interrupt payload、resume决定、外部 operation id。
- **unknown**：官方资料未证明通用任务失败 taxonomy、自动 retry policy、外部副作用 exactly-once、read-after-write、不可篡改日志或生产法律证据保全。

来源：
- https://docs.langchain.com/oss/python/langgraph/interrupts （访问 2026-09-22；verified interrupt、resume、节点重跑边界）
- https://docs.langchain.com/oss/python/langgraph/persistence （访问 2026-09-22；verified checkpoint/thread/store；内存持久性限制）
- https://docs.langchain.com/oss/python/langgraph/durable-execution （访问 2026-09-22；页面当前归档/重定向内容为 persistence，内容范围标注 unknown）

### C. OpenAI Agents SDK

- **verified**：官方 HITL 文档规定工具可声明需要 approval；运行结果以 interruption 暴露 pending approvals；RunState可序列化暂停运行并在决定后恢复；审批范围覆盖handoff和嵌套 Agent.as_tool 的外层 run。
- **verified**：官方运行文档将 RunState用于恢复 paused run 或 `cancel(mode="after_turn")`停止的 run；错误和取消路径也有资源处理说明。
- **verified**：guardrails用于输入、输出、工具检查；blocking execution可阻止昂贵模型启动，但并行模式下模型可能已开始，说明控制边界取决于执行模式。
- **verified**：traces代表端到端 workflow；spans记录 LLM generations、tool calls、handoffs、guardrails、自定义事件；可提供 trace_id/group_id/metadata。
- **inferred**：approval interruption + serialized RunState提供应用层人工批准恢复闭环；trace可作为运行路径证据和调试索引。
- **unknown**：官方资料未证明 trace 默认不可篡改、全量无采样、长期保全或等同业务审计；未证明工具调用外部副作用提交、最终 read-back、自动 exactly-once 或统一 retry/idempotency 语义。

来源：
- https://openai.github.io/openai-agents-python/human_in_the_loop/ （访问 2026-09-22；verified approval/interruption/RunState resume）
- https://openai.github.io/openai-agents-python/running_agents/ （访问 2026-09-22；verified RunState、取消/错误恢复相关入口）
- https://openai.github.io/openai-agents-python/guardrails/ （访问 2026-09-22；verified guardrail执行边界）
- https://openai.github.io/openai-agents-python/tracing/ （访问 2026-09-22；verified trace/span覆盖范围；unknown完整性/留存）

## 四、证据等级与使用边界

- **verified**只说明官方资料直接规定或描述了该平台机制；不升级为生产环境效果证明。
- **inferred**是从机制推出的工程建议，不是平台保证。
- **unknown**不得被“平台返回成功”“任务 Completed”“benchmark通过”填补。
- 本报告没有使用 benchmark 证明 production 能力；没有声称任何平台对外部系统提供 exactly-once 或最终一致 read-back。

## 五、下一独立切片（立即派发，不停线）

主题：**任务取消/超时/恢复后的 unknown 判定、幂等重试与补偿**。
边界：继续只查公开一手资料；优先 Temporal/LangGraph/OpenAI Agents SDK 官方资料中取消、超时、恢复、重试、补偿/Saga、外部状态不确定的原文；每源记录 URL、访问日期、verified/inferred/unknown、能/不能证明边界；写入新的隔离 `/tmp/A-LINE-RUNTIME-RESEARCH-NEXT-<timestamp>/`，不得触碰任何共享/受保护目标。
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

本补充不把 Temporal 平台回执、Workflow Completed、Activity Completed、Visibility、Export 或普通日志升级为外部效果证明；不把 benchmark 当 production 证据。# LangGraph 官方生命周期研究补充

- 研究主题：任务生命周期、失败恢复、验证闭环
- 访问日期：2026-09-22
- 范围：仅 LangChain/LangGraph 官方文档与官方 GitHub 源码；未访问凭据、真实服务或共享目标；未写入共享目录。
- 证据标签：verified=官方资料直接支持；inferred=工程推论；unknown=官方资料未证明。

## 核心核验

### 生命周期与状态

- **verified**：LangGraph 按 Pregel superstep 组织节点 task；task 具有 attempt；完成后提交写入并调度后续步骤。
- **verified**：Graph state 由 schema、channels 和 reducers定义；checkpoint 保存 thread 状态、values、metadata、父 checkpoint、tasks 和 pending writes。
- **inferred**：完整工程生命周期可抽象为加载 thread/checkpoint → 执行 task attempt → 捕获状态/异常 → retry、错误路由或暂停 → checkpoint → 后续调度/完成；这不是 LangGraph 强制业务模板。
- **unknown**：图状态或 checkpoint 不等于外部系统真实状态，也不自动提供跨系统事务一致性。

### 暂停与恢复

- **verified**：`interrupt()` 暂停图执行并暴露 JSON 可序列化 payload；使用同一 `thread_id` 与 `Command(resume=...)` 恢复。
- **verified**：需要 checkpointer；生产环境应使用持久化 checkpointer；内存 saver 在进程重启后丢失 checkpoint。
- **verified**：恢复时包含 interrupt 的节点可能从节点入口重新执行；interrupt 前的代码会再次执行。
- **verified**：interrupt 不按普通 retry/error handler处理；可用于人工批准、澄清、外部事件等待。
- **unknown**：LangGraph 不能单独证明恢复者身份、审批权限、批准不可篡改或组织级授权合规；checkpoint 恢复不自动回滚外部副作用。

### 失败分类与重试

- **verified**：官方资料/源码区分普通异常、`GraphInterrupt`/`GraphBubbleUp`、取消、超时、递归限制、非法更新和 `NodeError` 等。
- **verified**：支持 `run_timeout`、`idle_timeout`、`NodeTimeoutError`；`NodeTimeoutError` 默认可重试。
- **verified**：节点支持 `RetryPolicy`，包括 `max_attempts`、退避、最大间隔、jitter 和 `retry_on`；可读取 attempt 信息。
- **verified**：重试耗尽后可以进入错误处理器或传播运行错误；失败 provenance 可以进入 checkpoint。
- **inferred**：LangGraph 是“可能再次执行”的模型，不能单独提供外部副作用 exactly-once。
- **unknown**：业务级“永久失败/外部已提交但本地未知/需补偿/需人工复核”等分类必须由应用定义，框架错误分类不替代业务判定。

### 幂等与外部副作用

- **verified**：官方 Durable Execution/Graph API要求副作用可安全重放或具备幂等性；建议幂等键、upsert、写前读取检查，并把副作用置于安全的 task/节点边界。
- **verified**：interrupt 前副作用尤其需要幂等，因为恢复会重跑该节点前半段。
- **inferred**：安全模式是外部 read-before-write → 带稳定幂等键写入 → 外部 read-back → 将 read-back 写入 graph state/checkpoint。
- **unknown**：LangGraph没有自动 read-back、自动外部一致性判断、自动去重表或跨系统提交协议；不能自动检测重复付款、发信或数据库写入。

### 人工批准与最终验证

- **verified**：人工批准可由 `interrupt()` 暂停、外部输入通过 `Command(resume=...)`恢复；payload可承载待批准动作和风险信息。
- **verified**：图可使用验证节点、条件边和状态字段路由到成功、失败、补偿或人工复核。
- **inferred**：推荐建模：准备动作 → interrupt审批 → 条件路由 → 外部执行 → read-back → verify/finalize。
- **unknown**：没有统一自动 final verification hook；图运行成功或产生最终 state 不等于业务目标已经由外部系统验证成功。

### 日志与证据保全

- **verified**：Streaming提供 `values`、`updates`、`messages`、`custom`、`checkpoints`、`tasks`、`debug`等事件；retry attempt上下文可包含 task、attempt、run_id、thread_id、checkpoint namespace、时间、状态、错误。
- **verified**：LangSmith可用于 tracing、调试和延迟监控。
- **inferred**：保存输入、run/thread/checkpoint ID、attempt、状态更新、interrupt/resume、外部幂等键、read-back、最终验证和错误记录，可构成应用层证据链。
- **unknown**：checkpoint、stream、LangSmith trace不被官方保证为不可篡改、永久保留、全量无采样、WORM或监管级审计证据。

## 结构化比较摘要

| 领域 | verified能力 | 不能单独证明 |
|---|---|---|
| 生命周期 | task、superstep、attempt、提交写入、checkpoint、调度 | 业务任务与外部目标完成 |
| 暂停/恢复 | interrupt、thread_id、Command(resume)、checkpoint | 审批者身份与授权 |
| 失败/重试 | RetryPolicy、attempt、timeout、NodeError、控制流异常 | 业务级补偿分类、exactly-once |
| 幂等 | 官方要求幂等键/upsert/read-before-write/安全重放 | 自动去重与外部事务 |
| read-back | 可由业务节点显式实现 | 内建自动外部状态校验 |
| 最终验证 | 可建验证节点、条件边、状态路由 | 运行成功等于外部成功 |
| 证据 | checkpoint、task/debug/checkpoint stream、trace | 不可篡改、永久留存、合规保证 |

## 官方来源清单

访问日期均为 2026-09-22：

- https://docs.langchain.com/oss/python/langgraph/persistence — verified checkpointer、store、thread、checkpoint、StateSnapshot；不能证明外部一致性/不可篡改审计。
- https://docs.langchain.com/oss/python/langgraph/fault-tolerance — verified RetryPolicy、attempt、timeout、NodeError、错误处理、resume-safe failures；不能证明外部 exactly-once。
- https://docs.langchain.com/oss/python/langgraph/interrupts — verified interrupt、人工介入、resume、interrupt ID和节点重跑边界；不能证明审批身份授权。
- https://docs.langchain.com/oss/python/langgraph/durable-execution — verified durable execution、恢复、可重放、副作用幂等设计；不能提供跨外部系统事务。
- https://docs.langchain.com/oss/python/langgraph/graph-api — verified 状态schema、reducers、节点、边、Command、tasks和确定性；不能自动业务验收。
- https://docs.langchain.com/oss/python/langgraph/streaming — verified values/updates/tasks/checkpoints/debug等运行事件；不能保证日志不可篡改或永久保存。
- https://docs.langchain.com/oss/python/langgraph/use-time-travel — verified 历史checkpoint、回溯和分支；不能保证外部副作用回滚。
- https://github.com/langchain-ai/langgraph/blob/main/libs/langgraph/langgraph/types.py — verified RetryPolicy、StateSnapshot、Interrupt及运行数据结构。
- https://github.com/langchain-ai/langgraph/blob/main/libs/langgraph/langgraph/pregel/_retry.py — verified attempt、retry policy匹配、异常/中断区分、超时处理。
- https://github.com/langchain-ai/langgraph/blob/main/libs/langgraph/langgraph/pregel/_runner.py — verified 并发task、写入提交、异常传播、错误处理器调度。
- https://github.com/langchain-ai/langgraph/blob/main/libs/langgraph/langgraph/pregel/_loop.py — verified superstep、channels、checkpoint、pending writes、恢复机制。
- https://github.com/langchain-ai/langgraph/blob/main/libs/langgraph/langgraph/errors.py — verified GraphInterrupt、GraphBubbleUp、GraphRecursionError、InvalidUpdateError、NodeError、NodeCancelledError、NodeTimeoutError。
- https://github.com/langchain-ai/langgraph/blob/main/libs/checkpoint/langgraph/checkpoint/base/__init__.py — verified checkpoint saver、metadata、pending writes和checkpoint tuple抽象。

## 统一证据边界

平台返回、checkpoint、状态流、trace和图运行成功只能证明相应平台路径/状态被记录或执行；不能单独证明外部目标已经提交、最终状态正确、幂等成立或证据不可篡改。本研究不使用 benchmark 证明 production。
# OpenAI Agents SDK 官方研究补充

访问日期：2026-09-22。资料范围：仅 OpenAI Agents SDK 官方文档；未访问凭据、真实服务或共享目标。

## 证据标签
verified=官方文档直接支持；inferred=基于官方机制的工程推论；unknown=官方资料未证明。

## 生命周期与状态
- **verified**：Runner 执行 agent loop，涉及模型调用、工具调用、handoff、guardrail 与最终输出；RunState 可承载恢复中的运行状态。
- **verified**：RunState 用于恢复暂停的 run，或恢复 `cancel(mode="after_turn")` 后停止的 run；状态可序列化并恢复。
- **inferred**：RunState 是应用层可持久化的恢复游标，不是外部系统事务日志。
- **unknown**：本次官方页面未证明一个跨应用的统一持久任务状态机、外部目标状态或 exactly-once 语义。

## 暂停、恢复与人工批准
- **verified**：工具可以声明需要 approval；运行结果会暴露 pending approval interruption；应用使用 RunState 序列化暂停运行，并在批准或拒绝后恢复原始 top-level run。
- **verified**：审批适用于当前 agent、handoff 到达的 agent 以及嵌套 `Agent.as_tool()`；嵌套审批仍通过 outer run 的 interruption 流程处理。
- **verified**：官方提供 pause → approve/reject → resume 模式；也支持程序化 approval callback。
- **verified**：长期审批场景可把 approval state 保存在服务端。
- **inferred**：外部批准服务需以稳定运行标识和审批记录关联 RunState，避免恢复错误的运行实例。
- **unknown**：SDK 本身不证明审批人身份、权限、四眼原则、批准记录不可篡改或外部业务目标已执行。

## 失败、错误与重试
- **verified**：官方文档区分 guardrail 错误、工具错误、模型/运行错误、handoff 和取消路径；工具错误可通过 formatter 转换为模型可见错误或由应用处理。
- **verified**：guardrail 可在 expensive model 开始前阻塞执行；并行 guardrail 模式下，模型可能已经启动，因此阻塞不等于绝对零副作用。
- **verified**：Runner 在非流式/流式运行的错误和取消路径也会处理 provider 生命周期；RunState 可用于恢复某些暂停/取消后运行。
- **unknown**：本次官方资料未证明一个针对所有工具调用的统一 RetryPolicy、指数退避、服务端重试或业务失败分类框架。
- **unknown**：没有官方保证 SDK 自动识别“外部副作用已发生但响应丢失”的 unknown 状态。

## 幂等与外部 read-back
- **inferred**：工具若执行外部写操作，应由应用自行使用 operation/idempotency key、目标侧查询和去重；RunState、trace 或工具返回不能替代目标侧 read-back。
- **unknown**：官方 SDK 页面未证明自动 exactly-once、外部事务、自动补偿或统一 read-back/final-verification 阶段。
- **verified**：工具审批、工具调用、guardrail、handoff 和 custom events 可进入 tracing/Spans，适合关联运行路径。
- **inferred**：最终成功必须由应用把外部 read-back 与业务 postcondition 纳入工具或后续验证步骤；Runner 返回完成只证明 SDK 运行路径完成其定义的条件。

## 日志与证据
- **verified**：SDK tracing 可记录单次 workflow trace 及 spans；默认覆盖 LLM generation、tool calls、handoffs、guardrails 和 custom events，可用于调试、可视化和生产监控。
- **verified**：trace 可带 trace_id、group_id、metadata；也可禁用记录。
- **inferred**：trace 能证明 SDK 记录了某条运行路径或事件关联，不等于证明外部副作用已经提交。
- **unknown**：官方资料未证明 trace 默认不可篡改、永久保留、全量无采样、具备 WORM/法律保全或自动关联外部目标状态。

## 证明边界汇总

SDK 可证明：运行状态/暂停审批 interruption 被 SDK 暴露；RunState 可序列化恢复；guardrail、工具、handoff 与 trace 事件按 SDK 机制记录。

SDK 不能单独证明：外部写入已提交；数据库/API/支付状态最终正确；审批人真实有权；exactly-once；自动重试安全；补偿已成功；日志不可篡改或满足生产合规要求；benchmark 或 trace 等同于 production 效果。

## 官方来源清单

以下来源均为 OpenAI Agents SDK 官方文档，访问日期统一为 2026-09-22：

- https://openai.github.io/openai-agents-python/human_in_the_loop/ — verified approval、interruption、RunState 序列化恢复；不能证明审批授权及外部效果。
- https://openai.github.io/openai-agents-python/guardrails/ — verified input/output/tool guardrail 及阻塞执行边界；不能证明外部副作用未发生或最终正确。
- https://openai.github.io/openai-agents-python/running_agents/ — verified agent loop、工具执行、错误恢复、取消和 RunState 入口；不能证明统一业务状态机和 exactly-once。
- https://openai.github.io/openai-agents-python/tracing/ — verified traces/spans、LLM/tool/handoff/guardrail/custom event 覆盖；不能证明不可篡改、永久留存或外部提交。
- https://openai.github.io/openai-agents-python/ref/run_state/ — verified RunState API 作为恢复与序列化状态；不能证明外部系统状态。

## 结论

OpenAI Agents SDK 的核心强项是人工批准 interruption、可序列化 RunState 恢复以及运行路径 tracing；其官方机制没有替应用提供外部 read-back、业务最终验收、统一幂等重试或补偿事务。平台运行完成、审批恢复成功和 trace 记录均不能自动升级为外部效果证明。
