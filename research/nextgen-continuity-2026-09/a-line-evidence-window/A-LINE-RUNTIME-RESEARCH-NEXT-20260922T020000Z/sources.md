# 来源清单（仅公开官方一手资料）

访问日期统一：2026-09-22。状态词含义：`verified`=直接读取官方页面/源码支持；`inferred`=由多个已核验边界推导的安全设计结论；`unknown`=官方材料不足以判定。

## T1 — Temporal：Cancel a Workflow — Go SDK
- 完整 URL：https://docs.temporal.io/develop/go/workflows/cancellation
- 访问日期：2026-09-22
- 本地核验文件：`temporal-cancellation.md`
- 证据状态：verified
- 直接内容：Workflow 可处理 cancellation；`NewDisconnectedContext` 可执行 cleanup Activity；Activity 需 heartbeat 才能接收取消；取消后 heartbeat 调用可报 context canceled 但 heartbeat 仍可能已发送；reset 从历史点开始新的执行。
- 能证明：Temporal 的取消传播、取消时清理编排、heartbeat/cancellation 与 reset 语义。
- 不能证明：CancelWorkflow 回执代表外部动作未发生；Activity 完成/取消代表目标系统 exactly-once；cleanup 已抵消外部副作用；无响应时目标状态。

## T2 — Temporal：Side Effects — Go SDK
- 完整 URL：https://docs.temporal.io/develop/go/workflows/side-effects
- 访问日期：2026-09-22
- 本地核验文件：`temporal-develop_go_workflows_side-effects.md`
- 证据状态：verified
- 直接内容：SideEffect 的非确定结果写入 Workflow Event History，replay 不再执行；Activity/Local Activity 结果也持久化。
- 能证明：工作流历史记录与 replay 的确定性边界。
- 不能证明：历史记录等于外部服务状态；Activity 被调度或返回等于目标副作用已成功；历史可替代 read-back。

## L1 — LangGraph：Persistence
- 完整 URL：https://docs.langchain.com/oss/python/langgraph/persistence
- 访问日期：2026-09-22
- 本地核验文件：`langgraph-oss_python_langgraph_persistence.md`
- 证据状态：verified
- 直接内容：checkpointer 持久化 thread graph state checkpoints，适用于中断恢复、故障容错和 human-in-the-loop；store 保存图外应用定义数据；InMemorySaver/InMemorySaver 重启丢失。
- 能证明：LangGraph checkpoint/store 的恢复与持久化边界。
- 不能证明：checkpoint 表示外部写入已发生；自动幂等键、目标侧去重、read-back 或补偿成功；UNKNOWN 可自动收敛。

## L2 — LangGraph：Durable execution 页面实际返回 Persistence 内容
- 完整 URL：https://docs.langchain.com/oss/python/langgraph/durable-execution
- 访问日期：2026-09-22
- 证据状态：verified（页面实际内容为 Persistence 文档，故不把 URL 标成额外独立机制）
- 能证明：同 L1 的持久化/恢复说明。
- 不能证明：通用 exactly-once、外部效果、补偿；该 URL 未提供足够独立的目标侧语义。

## O1 — OpenAI Agents SDK：RunState 官方源码
- 完整 URL：https://github.com/openai/openai-agents-python/blob/main/src/agents/run_state.py
- 原始文件 URL：https://raw.githubusercontent.com/openai/openai-agents-python/main/src/agents/run_state.py
- 访问日期：2026-09-22
- 本地核验文件：`openai-run-state.py`
- 证据状态：verified
- 直接内容：`RunState` 是可序列化/恢复 agent run 的状态边界；源码文档涉及恢复时 session append、pending tool calls、并发恢复同一 Session 的限制以及 terminal-unrecoverable runs。
- 能证明：SDK 级暂停/恢复状态模型和若干恢复约束。
- 不能证明：tool 已执行的外部副作用 exactly-once；SDK 恢复成功等于目标状态已收敛；无响应后可安全重试。

## O2 — OpenAI Agents SDK：异常官方源码
- 完整 URL：https://github.com/openai/openai-agents-python/blob/main/src/agents/exceptions.py
- 原始文件 URL：https://raw.githubusercontent.com/openai/openai-agents-python/main/src/agents/exceptions.py
- 访问日期：2026-09-22
- 本地核验文件：`openai-exceptions.py`
- 证据状态：verified
- 直接内容：定义 `ModelTimeoutError`、`ToolTimeoutError`、MCP tool cancellation 等调用层异常。
- 能证明：SDK 暴露调用层 timeout/cancellation 分类。
- 不能证明：timeout/cancel 时目标动作未发生；异常可自动重试；目标侧提供去重或查询。

## R1 — IETF RFC 9110：HTTP Semantics §9.2.2
- 完整 URL：https://www.rfc-editor.org/rfc/rfc9110#section-9.2.2
- 访问日期：2026-09-22
- 本地核验文件：`rfc9110.txt`
- 证据状态：verified
- 直接内容：幂等方法是重复请求的预期效果与单次相同；连接失败后可重试幂等请求；代理不得自动重试非幂等请求。幂等属性只作用于 intended effect，不保证每次日志/计数副作用消失。
- 能证明：HTTP 方法层的幂等定义和规范重试边界。
- 不能证明：业务 POST 或任意 API 的 idempotency-key；目标端原子去重；请求已发出后的执行结果；业务 read-back 或 Saga。

## 证据分级说明

以上官方文档/源码是 primary，但关于生产效果的证据类别属于规范/厂商设计说明（Class D），不是跨系统实测或生产统计（Class C），因此本清单没有把它们升级为 exactly-once 或可靠性证明。未使用 benchmark 作为 production 证据。
