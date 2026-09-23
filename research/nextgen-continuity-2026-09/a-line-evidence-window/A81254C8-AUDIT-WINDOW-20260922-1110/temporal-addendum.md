# Temporal 官方证据补充（回调研究并入）

访问日期：2026-09-22（Asia/Shanghai）。以下仅为 Temporal 官方文档/API源码；未连接真实 Namespace、凭据或生产服务。

## T1 — Event History
- URL: https://docs.temporal.io/workflow-execution/event
- 原始 Markdown: https://docs.temporal.io/workflow-execution/event.md
- 标题: Events and Event History
- 证据窗口：Temporal Service 在处理外部 occurrence 或 Workflow Command 后创建并记录 Event；Event History 可通过 History API/CLI 查询；闭合 Workflow 的可保留时间受 Namespace Retention 约束；History 有事件数量/大小边界。
- verified：Event History 为 append-only、durably persisted；Workflow 生命周期事件与 Activity Scheduled/Started/Completed/Failed/TimedOut/Cancel 事件属于平台记录。
- inferred：它是平台生命周期审计，不是外部系统全量审计。
- unknown：实际 Namespace retention、管理员删除、密码学完整性、外部副作用。
- 能证明：Temporal 记录了对应平台状态转移。
- 不能证明：Activity 内部每个网络调用、第三方提交或业务不变量已发生。

## T2 — Event History recovery / replay
- URL: https://docs.temporal.io/encyclopedia/event-history/
- 原始 Markdown: https://docs.temporal.io/encyclopedia/event-history.md
- 证据窗口：Command 被 Service 处理后映射成持久 Event；Worker 崩溃后由既有 History Replay Workflow 逻辑。
- verified：History 是 durable recovery input；Replay 使用历史状态，不等于重新执行 Activity 或重新读取外部状态。
- unknown：Worker stdout/stderr、外部 API 事务状态是否被 History 覆盖。
- 能证明：Temporal 状态转移可恢复。
- 不能证明：外部效果已提交或业务状态当前正确。

## T3 — CLI execute/show/follow
- URL: https://docs.temporal.io/cli/command-reference/workflow
- 原始 Markdown: https://docs.temporal.io/cli/command-reference/workflow.md
- 证据窗口：`workflow execute` 阻塞到 Workflow Execution 完成；`--output json` 可包含本次运行的 history；`workflow show` 读取 Event History，`--follow` 实时跟随。
- verified：CLI 可读取平台 History，execute 返回对应平台完成结果。
- unknown：CLI 断网发现时间、自动重连是否无遗漏/无重复、本地 stdout 是否持久化/防篡改。
- 能证明：平台返回了 Workflow 终态/History。
- 不能证明：CLI 返回等于外部系统或业务 postcondition 完成。

## T4 — Visibility 与单实体状态
- URL: https://docs.temporal.io/visibility
- 原始 Markdown: https://docs.temporal.io/visibility.md
- 证据窗口：Visibility 更新异步传播；可数秒或更长，Temporal Cloud 不发布固定 SLA；List/Count/Search 可能 stale。官方建议单 Workflow 当前权威状态使用 `DescribeWorkflowExecution`，进度/完成使用 Event History 或 Child Workflow。
- verified：Visibility 是 eventually consistent search index；Describe 是单实体最新状态路径。
- inferred：Visibility 未找到不能判定不存在，不能用固定等待时长替代 read-back。
- unknown：具体部署传播时延。
- 能证明：查询层存在异步可见窗口。
- 不能证明：Visibility 是完整 History 或外部业务状态。

## T5 — History API 分页、等待新事件、归档标记
- URL: https://github.com/temporalio/api/blob/master/temporal/api/workflowservice/v1/request_response.proto
- 原始源码: https://raw.githubusercontent.com/temporalio/api/master/temporal/api/workflowservice/v1/request_response.proto
- 证据窗口：`GetWorkflowExecutionHistory` 支持 `wait_new_event`，等待匹配的新事件或 timeout；响应以 `next_page_token` 表示还有分页；`archived` 表示本次内容是否来自归档，`skip_archival` 可跳过归档。
- verified：History 查询有分页与等待边界。
- inferred：只有耗尽分页、处理 archived 状态并记录 Run Chain，调用方才能声明本次读取覆盖完整 History。
- unknown：调用方是否正确遍历全部分页、timeout 的业务含义、外部状态。
- 能证明：单页响应不必然是完整 History。
- 不能证明：History 完整读取等于外部效果确认。

## T6 — Retention / closed execution cleanup
- URL: https://docs.temporal.io/temporal-service/temporal-server
- 原始 Markdown: https://docs.temporal.io/temporal-service/temporal-server.md
- 证据窗口：Workflow closed 后按 Namespace Retention Period 保留；到期触发清理；文档称最小 retention 1 day，CLI 创建 Namespace 未设置时默认 3 days；已关闭执行保留原 cleanup timer；可用 `temporal workflow delete` / `DeleteWorkflowExecution` 提前删除。
- verified：闭合 Workflow 数据不是永久保留，Retention 是可查询/保存窗口。
- unknown：具体 Namespace 配置、手动删除是否发生、实际审计存档。
- 能证明：必须把 retention 纳入审计 deadline。
- 不能证明：所有 Namespace 都是 3 天或 retention 到期前数据一定存在。

## T7 — Archival
- URL: https://docs.temporal.io/temporal-service/archival
- 原始 Markdown: https://docs.temporal.io/temporal-service/archival.md
- 证据窗口：Workflow 关闭时调度 History/Visibility archival close-processing；之后异步、随机延迟；默认延迟最多约 5 分钟且受 retention 限制；主 Persistence 在 retention cleanup 前仍可能保留同一执行。
- verified：Archival 可将闭合 History/Visibility 复制至 blob store；它不是关闭瞬间同步完成。
- unknown：是否启用、归档是否成功、blob store retention/完整性、实际延迟。
- 不能证明：默认存在、GA、永久保存、不可篡改或 production 审计通过；文档明确将 Archival 标为 experimental。

## T8 — Heartbeat / Activity timeouts
- URL: https://docs.temporal.io/develop/go/activities/timeouts
- 原始 Markdown: https://docs.temporal.io/develop/go/activities/timeouts.md
- 证据窗口：最后一条被 Service 接收的 Heartbeat 到 Heartbeat Timeout 到期；若未收到，Activity 可被判失败并按 Retry Policy 重试；Heartbeat 可能被 Worker 节流；不 Heartbeat 的 Activity 不能依靠 Heartbeat 接收取消。
- verified：Heartbeat 是 liveness/progress 机制，Timeout 是可配置发现边界。
- inferred：调用方调用 heartbeat 不等于 Service 收到 heartbeat。
- unknown：外部 API 是否在最后 heartbeat 后已提交。
- 能证明：Temporal 在 timeout 边界观察到失活/失败。
- 不能证明：外部事务未发生或取消已撤销外部请求。

## T9 — Task loss / Start-to-Close
- URL: https://docs.temporal.io/activity-execution
- 原始 Markdown: https://docs.temporal.io/activity-execution.md
- 证据窗口：Activity Task 可能在投递到 Worker 时丢失，或函数调用后 Worker 崩溃；Temporal 不直接检测 task loss，依赖 Start-to-Close timeout；timeout 后按 Retry Policy 重试。
- verified：Activity 可靠性边界为执行或 timeout，不是即时到达确认。
- unknown：Worker 崩溃前外部调用是否已生效。
- 能证明：timeout 被平台观察并可触发重试。
- 不能证明：timeout 前没有外部副作用。

## T10 — Standalone Activity
- URL: https://docs.temporal.io/standalone-activity
- 原始 Markdown: https://docs.temporal.io/standalone-activity.md
- 证据窗口：Standalone Activity 无 Workflow Event History；其 Execution/result 在 Namespace Retention 内可由 `activity describe/list` 查询；到期删除且 Activity ID 可复用；默认 at-least-once 重试，直至成功或 Schedule-to-Close 到期。
- verified：Activity ID 去重与业务幂等是不同问题；重试可能重复执行函数。
- inferred：仅 Activity result 不足以证明外部 postcondition。
- unknown：外部系统是否实现同一幂等语义。
- 能证明：Temporal 层执行/结果的保留和重试边界。
- 不能证明：外部副作用 exactly-once。

## T11 — External polling/read-back
- URL: https://docs.temporal.io/design-patterns/polling
- 原始 Markdown: https://docs.temporal.io/design-patterns/polling.md
- 证据窗口：外部请求后，应用按 polling interval、Activity timeout、Retry Policy、deadline 读取外部系统；频繁轮询建议 Activity + Heartbeat，低频轮询可用 Activity retry/backoff。
- verified：官方推荐显式 polling 检查外部系统目标状态。
- inferred：只有 read-back 结果纳入 Workflow 后，才能把外部状态作为一层独立证据。
- unknown：外部 API 的一致性和目标状态语义。
- 能证明：外部 read-back 返回了应用定义的目标状态。
- 不能证明：没有 polling/read-back 时 Workflow Completed 自动代表外部 postcondition。

## T12 — Continue-As-New
- URL: https://docs.temporal.io/workflow-execution/continue-as-new
- 原始 Markdown: https://docs.temporal.io/workflow-execution/continue-as-new.md
- 证据窗口：Continue-As-New 创建同 Workflow ID、不同 Run ID 的新 Workflow Execution，并开始独立 Event History；审计必须遍历 Run Chain。
- verified：单一 Run History 不自动覆盖整个 Workflow ID 生命周期。
- unknown：调用方是否完整跟踪 Run Chain。
- 能证明：新旧 Run 边界。
- 不能证明：单个 Run 的终态就是整个长期任务的业务终态。

## T13 — Reset
- URL: https://docs.temporal.io/workflow-execution/reset
- 原始 Markdown: https://docs.temporal.io/workflow-execution/reset.md
- 证据窗口：Reset 终止原 Workflow Execution 并创建新 Execution；新 History 复制原执行至 reset point（不包含其后的未来事件）。
- verified：Reset 会产生审计边界。
- unknown：新执行后外部副作用和业务结果。
- 能证明：原执行与新执行之间的控制流边界。
- 不能证明：Reset 自动回滚外部副作用。
