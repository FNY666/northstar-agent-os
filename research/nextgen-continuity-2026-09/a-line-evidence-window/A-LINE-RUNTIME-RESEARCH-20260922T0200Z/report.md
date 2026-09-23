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
