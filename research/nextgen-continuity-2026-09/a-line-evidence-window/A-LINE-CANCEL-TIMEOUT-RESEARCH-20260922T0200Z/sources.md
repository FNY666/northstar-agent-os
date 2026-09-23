# 来源清单

访问日期均为 2026-09-22。

- https://docs.temporal.io/activity-definition — verified：Activity 可能重复执行，要求幂等；不能证明外部 exactly-once。
- https://docs.temporal.io/encyclopedia/retry-policies — verified：Retry Policy、失败重试范围；不能证明重试安全或外部状态。
- https://docs.temporal.io/encyclopedia/detecting-activity-failures — verified：Activity timeout、Heartbeat 和失败检测；不能证明请求未到达外部系统。
- https://docs.temporal.io/encyclopedia/failures-and-error-handling — verified：Failure 传播与 retryability；不能自动完成业务分类或补偿。
- https://docs.temporal.io/workflow-execution — verified：Workflow replay/recovery；不能证明外部副作用。
- https://docs.temporal.io/visibility — verified：Visibility 最终一致与 Describe 边界；不能把索引当外部效果证明。
- https://docs.langchain.com/oss/python/langgraph/fault-tolerance — verified：节点 timeout/retry/error handler；不能证明外部 exactly-once。
- https://docs.langchain.com/oss/python/langgraph/durable-execution — verified：恢复、重放、副作用幂等边界；不能自动回滚外部系统。
- https://docs.langchain.com/oss/python/langgraph/interrupts — verified：interrupt/resume/checkpoint；不能证明审批身份或外部提交。
- https://docs.langchain.com/oss/python/langgraph/persistence — verified：checkpoint/thread 状态恢复；不能证明 checkpoint 等于外部真实状态。
- https://openai.github.io/openai-agents-python/human_in_the_loop/ — verified：approval interruption、RunState、resume；不能证明工具副作用已提交。
- https://openai.github.io/openai-agents-python/running_agents/ — verified：工具错误、取消、状态与恢复入口；不能证明 exactly-once 或业务验收。
- https://openai.github.io/openai-agents-python/guardrails/ — verified：guardrail 与工具执行控制；不能证明外部目标状态。
- https://openai.github.io/openai-agents-python/tracing/ — verified：运行 trace/span 记录；不能证明完整、不可篡改、永久证据。

## 证据等级说明

verified=官方资料直接支持；inferred=由官方机制和失败窗口推出的工程规则；unknown=官方资料没有证明。取消/超时后保持 UNKNOWN、先 read-back 再重试、补偿需独立幂等和验证，是 inferred，不是任何单个平台的自动保证。
