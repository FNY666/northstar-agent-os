# A线逐源证据账本

访问日期：2026-09-22。证据标签：verified=官方原文/官方源码直接支持；inferred=基于官方机制的工程推论；unknown=官方资料未证明。所有边界均指该源本身，不把平台回执、benchmark或trace升级为外部效果证明。

## Temporal

| 完整URL | 状态 | 能证明 | 不能证明 |
|---|---|---|---|
| https://docs.temporal.io/workflow-execution | verified | Workflow Execution、Open/Closed状态、Replay、Run/Chain恢复 | 外部副作用已提交、exactly-once、外部最终状态 |
| https://docs.temporal.io/encyclopedia/event-history.md | verified | Event History持久事件、Replay、调试/审计用途 | 外部系统状态、不可篡改/法律保全 |
| https://docs.temporal.io/workflow-execution/event | verified | 生命周期事件、Activity事件、History限制 | 外部read-back、外部事务原子性 |
| https://docs.temporal.io/encyclopedia/workflow/workflow-pause.md | verified | Workflow Pause/Unpause、暂停状态、消息/timeout语义 | 已发出的HTTP/DB请求被取消、冻结全部副作用 |
| https://docs.temporal.io/activity-operations/pause.md | verified | Activity Pause、Retry停止、Heartbeat中断边界 | 无Heartbeat任务立即停止、外部操作回滚 |
| https://docs.temporal.io/activity-operations/unpause.md | verified | Activity恢复、backoff/attempt/heartbeat状态保留 | 恢复后外部状态正确 |
| https://docs.temporal.io/encyclopedia/retry-policies.md | verified | Activity/Workflow Retry Policy及适用边界 | Retry安全、外部exactly-once |
| https://docs.temporal.io/references/failures.md | verified | Failure类型、Failure信息模型 | 业务错误自动分类正确 |
| https://docs.temporal.io/encyclopedia/failures-and-error-handling.md | verified | Failure传播、顶层retryability边界 | 外部副作用状态 |
| https://docs.temporal.io/best-practices/error-handling.md | verified | transient/intermittent/permanent分类建议、non-retryable、Activity幂等 | 平台自动识别全部业务分类、自动补偿 |
| https://docs.temporal.io/activity-definition#idempotency | verified | Activity可重复执行、幂等要求 | Temporal替代外部幂等机制 |
| https://docs.temporal.io/handling-messages.md | verified | Signal/Update/Query handler、去重和完成边界 | Signal发送即业务处理完成 |
| https://docs.temporal.io/sending-messages.md | verified | 消息发送、request/update ID、Signal/Update/Query | 跨系统业务幂等、审批授权 |
| https://docs.temporal.io/design-patterns/request-response-via-updates.md | verified | Update同步请求响应、validator、结果边界 | 外部目标最终成功 |
| https://docs.temporal.io/design-patterns/signal-with-start.md | verified | Signal-With-Start原子启动/发送 | 外部副作用提交 |
| https://docs.temporal.io/visibility.md | verified | Visibility最终一致、Describe单体状态读取边界 | List/Count即时权威、外部效果 |
| https://docs.temporal.io/references/operation-list | verified | Describe等操作参考 | 业务后置条件 |
| https://docs.temporal.io/cloud/export.md | verified | History Export内容、至少一次投递 | 默认防篡改、WORM、法律保全 |
| https://docs.temporal.io/cloud/audit-logs.md | verified | Control Plane审计字段及Data Plane缺口 | Workflow外部效果、异步OK最终成功 |
| https://docs.temporal.io/workflow-execution/workflowid-runid | verified | Workflow ID、Run ID、生命周期标识 | 外部事务一致性 |
| https://docs.temporal.io/workflow-execution/continue-as-new | verified | Run分段、Continue-As-New | 自动跨Run业务幂等 |
| https://github.com/temporalio/api/blob/master/temporal/api/enums/v1/workflow.proto | verified | 官方Workflow状态枚举 | 状态代表外部目标效果 |
| https://raw.githubusercontent.com/temporalio/api/master/temporal/api/enums/v1/workflow.proto | verified | 同上raw源码 | 同上 |
| https://github.com/temporalio/api/blob/master/temporal/api/enums/v1/event_type.proto | verified | 官方Event类型枚举 | 事件即外部提交 |
| https://raw.githubusercontent.com/temporalio/api/master/temporal/api/enums/v1/event_type.proto | verified | 同上raw源码 | 同上 |
| https://github.com/temporalio/api/blob/master/temporal/api/failure/v1/message.proto | verified | Failure protobuf、cause、non-retryable等字段 | 业务分类自动正确 |
| https://raw.githubusercontent.com/temporalio/api/master/temporal/api/failure/v1/message.proto | verified | 同上raw源码 | 同上 |

## LangGraph

| 完整URL | 状态 | 能证明 | 不能证明 |
|---|---|---|---|
| https://docs.langchain.com/oss/python/langgraph/persistence | verified | checkpointer、thread、checkpoint、StateSnapshot、恢复 | 外部一致性、不可篡改审计 |
| https://docs.langchain.com/oss/python/langgraph/fault-tolerance | verified | RetryPolicy、attempt、timeout、错误处理、恢复安全 | 外部exactly-once |
| https://docs.langchain.com/oss/python/langgraph/interrupts | verified | interrupt、resume、人工介入、恢复约束 | 审批身份、授权、不可抵赖 |
| https://docs.langchain.com/oss/python/langgraph/durable-execution | verified | durable execution、重放、副作用幂等建议 | 跨外部系统事务 |
| https://docs.langchain.com/oss/python/langgraph/graph-api | verified | schema、reducer、节点、边、Command、task、确定性 | 自动业务验收 |
| https://docs.langchain.com/oss/python/langgraph/streaming | verified | values/updates/tasks/checkpoints/debug运行事件 | 日志不可篡改、永久保存 |
| https://docs.langchain.com/oss/python/langgraph/use-time-travel | verified | 历史checkpoint、回溯、分支、重新执行 | 外部副作用回滚 |
| https://github.com/langchain-ai/langgraph/blob/main/libs/langgraph/langgraph/types.py | verified | RetryPolicy、StateSnapshot、Interrupt、task/checkpoint类型 | 外部状态 |
| https://github.com/langchain-ai/langgraph/blob/main/libs/langgraph/langgraph/pregel/_retry.py | verified | attempt、retry匹配、异常/中断区分、timeout处理 | 外部副作用去重 |
| https://github.com/langchain-ai/langgraph/blob/main/libs/langgraph/langgraph/pregel/_runner.py | verified | 并发任务、写入提交、异常传播、错误处理器调度 | 外部事务提交 |
| https://github.com/langchain-ai/langgraph/blob/main/libs/langgraph/langgraph/pregel/_loop.py | verified | PregelLoop、superstep、channel、checkpoint/pending writes | 外部read-back |
| https://github.com/langchain-ai/langgraph/blob/main/libs/langgraph/langgraph/errors.py | verified | GraphInterrupt、GraphBubbleUp、NodeError、timeout/cancel等错误类 | 业务级分类自动正确 |
| https://github.com/langchain-ai/langgraph/blob/main/libs/checkpoint/langgraph/checkpoint/base/__init__.py | verified | checkpoint saver接口、metadata、pending writes | 合规级不可篡改保全 |

## OpenAI Agents SDK

| 完整URL | 状态 | 能证明 | 不能证明 |
|---|---|---|---|
| https://openai.github.io/openai-agents-python/human_in_the_loop/ | verified | tool approval、interruption、RunState序列化/恢复、暂停批准恢复 | 审批身份、权限、外部效果 |
| https://openai.github.io/openai-agents-python/guardrails/ | verified | input/output/tool guardrail、阻塞和并行执行边界 | 无副作用、最终业务正确 |
| https://openai.github.io/openai-agents-python/running_agents/ | verified | agent loop、tool/handoff、错误/取消、RunState入口 | 统一业务状态机、统一Retry、exactly-once |
| https://openai.github.io/openai-agents-python/tracing/ | verified | trace/span、LLM/tool/handoff/guardrail/custom event记录 | 外部提交、不可篡改、永久留存 |
| https://openai.github.io/openai-agents-python/ref/run_state/ | verified | RunState恢复与序列化API | 外部系统状态、自动read-back |

## 统一边界

- **verified**：上述官方资料分别证明平台自身的状态、控制流、恢复、重试、审批接口或运行记录。
- **inferred**：稳定operation/idempotency key、外部read-back、业务postcondition、补偿和独立证据保全是跨平台安全闭环所需的工程设计。
- **unknown**：任何对象是否自动保证外部副作用exactly-once、外部最终状态正确、审批授权真实有效、日志不可篡改或benchmark可代表production，均未由本资料证明。
