# A线来源清单

访问日期统一为：2026-09-22。范围：公开官方文档/官方源码；未接触凭据、真实服务或共享目标。

## Temporal
- https://docs.temporal.io/workflow-execution — 生命周期、Open/Closed、Replay、Run/Chain；verified机制边界。
- https://docs.temporal.io/encyclopedia/retry-policies — Activity/Workflow Retry、失败类型；verified机制边界。
- https://docs.temporal.io/activity-definition — Activity多次执行、幂等键、Retry；verified；不能证明外部 exactly-once。
- https://docs.temporal.io/visibility — Visibility最终一致与Describe单实体状态读取；verified。
- https://docs.temporal.io/workflow-execution/event — Event History与生命周期事件；verified。
- https://docs.temporal.io/cloud/audit-logs — Control Plane/Data Plane审计边界；verified。
- https://docs.temporal.io/cloud/export — History Export、至少一次投递；verified；防篡改/法律保全 unknown。

## LangGraph
- https://docs.langchain.com/oss/python/langgraph/interrupts — interrupt、checkpoint、thread_id、Command(resume)、节点重跑；verified。
- https://docs.langchain.com/oss/python/langgraph/persistence — checkpointer/store、thread状态、生产持久性、内存重启丢失；verified。
- https://docs.langchain.com/oss/python/langgraph/durable-execution — 页面当前内容与 persistence相关，作为入口核验；具体失败taxonomy/外部效果未证明，unknown。

## OpenAI Agents SDK
- https://openai.github.io/openai-agents-python/human_in_the_loop/ — 工具审批、interruption、RunState序列化与恢复；verified。
- https://openai.github.io/openai-agents-python/running_agents/ — RunState、取消/错误恢复入口；verified范围有限。
- https://openai.github.io/openai-agents-python/guardrails/ — 输入/输出/工具guardrail与阻塞执行边界；verified。
- https://openai.github.io/openai-agents-python/tracing/ — trace/span覆盖模型、工具、handoff、guardrail和自定义事件；verified；完整性/留存/防篡改 unknown。

## 统一来源边界
平台回执、Event History、checkpoint、RunState或trace可以证明相应平台记录/运行路径，但不能单独证明外部目标已提交、最终状态正确、exactly-once、不可篡改或production效果。benchmark未用作production证据。
