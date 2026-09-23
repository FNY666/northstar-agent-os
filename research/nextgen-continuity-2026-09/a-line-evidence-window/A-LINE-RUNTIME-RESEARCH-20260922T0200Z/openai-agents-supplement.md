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
