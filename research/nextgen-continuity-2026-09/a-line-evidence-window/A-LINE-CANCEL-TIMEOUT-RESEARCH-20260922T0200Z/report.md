# 取消、超时、恢复后的 UNKNOWN、幂等重试与补偿

访问日期：2026-09-22。范围：Temporal、LangGraph、OpenAI Agents SDK 官方公开资料；未访问凭据、真实服务或 production。

## 结论

取消/超时/断连只证明控制面或本地执行窗口的状态，不自动证明外部副作用未发生。若请求可能已发出而没有权威目标侧 read-back，应保持 UNKNOWN，并按“可能已执行”设计恢复流程：先用稳定 operation_id/idempotency key 查询或对账，再决定确认、重试、补偿或人工介入。

## Temporal（verified）

官方 Activity 文档明确指出 Activity 可能因完成结果未回报而再次执行，因此 Activity 必须幂等或具备去重能力。Retry Policy 可区分 transient/intermittent/permanent failure；永久错误应 non-retryable。Heartbeat 只证明 worker 仍在报告进度，并可携带恢复细节；Heartbeat timeout 可触发失败/retry，但不是外部提交证明。取消、超时、Pause 不会自动回滚已经发出的外部请求。

**UNKNOWN规则（inferred）：** Activity timeout、worker crash、网络断连、cancel request 无最终回执时，不能判定 NOT_EXECUTED；应标记 UNKNOWN_NEEDS_RECONCILE。先用 operation_id 查询目标状态；已完成则收敛为 VERIFIED_DONE，确认未完成且目标支持幂等时才可重试；无法查询时保持 UNKNOWN 或转人工。补偿动作必须是目标系统支持的明确逆操作，且补偿本身也需幂等和 read-back。

Temporal Event History/Describe 可证明 Temporal 内部记录和单个 Workflow 状态；不能证明外部系统最终状态。Visibility 可能最终一致，不应用作单体最终证明。

## LangGraph（verified/inferred）

官方 fault-tolerance、durable-execution、interrupt 文档支持节点 timeout、retry、checkpoint、interrupt/resume，并明确要求可安全重放的副作用。恢复 interrupt 所在节点可能重新执行，故中断前副作用必须幂等。Checkpoint 能恢复图状态，不能自动回滚外部副作用，也不能确认外部提交。

**UNKNOWN规则（inferred）：** 节点超时、取消或进程中断后，若外部调用已开始但没有目标侧 read-back，应保持 UNKNOWN。恢复节点先执行 read-before-write/查询；用 operation_id 识别既有结果；再决定跳过、重试或补偿。`Command(resume=...)` 只恢复图控制流，不是外部效果证明。

## OpenAI Agents SDK（verified/inferred）

官方 HITL 文档支持工具 approval interruption、RunState 序列化和 resume；running_agents/guardrails 文档区分工具错误、取消、guardrail 和运行状态；tracing 记录模型、工具、handoff、guardrail 等运行路径。SDK 的 RunState、interruption、trace 不能证明外部工具调用最终提交。

**UNKNOWN规则（inferred）：** 工具调用超时、取消、进程断开或 approval 状态丢失时，应保存 operation_id 和参数指纹；重新进入前先 read-back/reconcile，不能直接盲重试。SDK 未证明自动 exactly-once、补偿事务或目标侧幂等。

## 补偿模式（inferred）

推荐状态机：

```text
REQUESTED
 -> DISPATCHED_UNKNOWN
 -> RECONCILE
    -> VERIFIED_DONE
    -> VERIFIED_NOT_DONE -> IDEMPOTENT_RETRY
    -> INCONSISTENT/UNAVAILABLE -> HUMAN_REVIEW
 -> COMPENSATION_REQUESTED
 -> COMPENSATION_UNKNOWN
 -> COMPENSATION_VERIFIED / HUMAN_REVIEW
```

补偿不是回滚保证。只有目标系统定义了可验证的逆操作，且逆操作拥有独立幂等键和 read-back，才能将其作为可接受补偿；否则只能标记为 UNKNOWN/HUMAN_REVIEW。

## 明确边界

- 平台接受取消、返回 timeout、记录 retry 或恢复 RunState：只能证明平台路径，不证明外部副作用不存在。
- retry success：只能证明本次平台执行返回成功，不证明此前 attempt 未成功。
- checkpoint/Event History/trace：能证明平台内部记录，不证明外部最终状态。
- benchmark 或 demo：不能证明 production 行为。
