# LangGraph 官方生命周期研究补充

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
