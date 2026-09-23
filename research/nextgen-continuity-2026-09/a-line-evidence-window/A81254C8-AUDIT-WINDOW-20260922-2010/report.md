# 审计时间窗、日志覆盖、断流检测与验证闭环

- 切片 ID：A81254C8-AUDIT-WINDOW-20260922
- 研究日期：2026-09-22（访问时间以 UTC 记录；本包生成时间以文件系统为准）
- 范围：仅公开官方/一手文档；Temporal、GitHub Actions、AWS Step Functions/CloudTrail、Kubernetes Jobs、Claude Code；Codex CLI仅在官方仓库可直接核验的范围内纳入。
- 权限边界：只读公开网页/官方仓库；未访问真实服务、凭据、账号或本地受保护目录；未触碰 shared/P0、事故目录、D10/L12/D14、canonical、140、tri-line、systemd。
- 证据等级：`verified`=官方页面直接陈述或可直接观察的官方源码/文档事实；`inferred`=由一个或多个 verified 事实作出的设计推论；`unknown`=官方资料未证明，不能补全。

## 结论

1. **审计时间窗不是单一时间戳。** 至少应拆为：发生（attempt/side effect started）→平台或采集器记录→查询可见→保留截止→验证闭环。各平台对这些边界的保证不同，不能以最终状态或某一条日志替代整条时间链。
2. **日志存在不等于日志覆盖或完整性。** AWS Step Functions 明确 CloudWatch Logs 为 best-effort；Express workflow 依赖 CloudWatch Logs 才能查看执行历史。Claude Code 的 OTLP 是可配置导出，官方提供“发 prompt 后检查事件”的配置验证，但没有在本资料中证明任意后端必然收到每条事件。GitHub 日志可下载/删除，重跑需要分别取得不同 attempt 的日志；因此必须记录 attempt 与缺口。
3. **平台完成不等于外部效果。** Temporal Event History、Step Functions execution history、GitHub conclusion、Kubernetes Job Complete/Failed 和 CloudTrail event 都主要证明平台记录/控制面状态；它们不能单独证明第三方 HTTP、支付、数据库、文件或业务状态已经提交。外部效果必须由目标系统的权威 read-back、postcondition 或业务回执确认。
4. **断流/超时/取消后的初态应是 UNKNOWN，而不是成功或失败。** 官方资料能证明平台会记录 timeout/failure/cancel 或停止重试，但不能在无目标侧查询时证明副作用不存在。对于重试，应以 operation/idempotency key、目标侧条件写或唯一约束、read-back/reconcile 和补偿状态机收口；“重试成功”本身不能证明第一次没有副作用。
5. **保留窗口会形成证据盲区。** CloudTrail Event History 是按区域的最近 90 天管理事件；Step Functions Standard execution history 最近完成 90 天可用，Express 默认从 CloudWatch 查询最近三小时但可调整扫描范围；Kubernetes Job 可用 TTL 自动清理；Claude Code retention sweep 会按 cleanupPeriodDays 清理会话数据；具体 GitHub 日志保留策略必须以仓库/组织/企业设置为准，不能凭默认值假设。

## 逐源证据矩阵

### S1 Temporal Events / Event History
- URL：<https://docs.temporal.io/workflow-execution/event>
- 访问日期：2026-09-22
- 证据窗口（发生→记录→可查询→保留→验证）：Workflow/Activity/Signal 等事件发生后写入 Workflow Execution Event History；官方页面将 Event History 作为 replay 和执行事实的记录。该页面没有为外部系统定义统一的“发生到记录”延迟或最终可见 SLA；查询/可见性取决于 Temporal Service/Visibility 配置；本页未给出可推广的统一保留天数；replay 可验证编排代码对已记录历史的确定性一致性。
- 状态：`verified`（存在 Event History、用于 replay 的官方语义）；`inferred`（它是平台编排事实，不是第三方效果证明）；`unknown`（传输延迟、跨系统完整性、统一 retention、外部 read-back）。
- 能证明：事件被 Temporal 记录后可作为 workflow replay 的输入；事件历史中的编排事实可被平台/客户端按其可见性机制读取。
- 不能证明：第三方副作用已提交；历史没有缺口；worker 已停止；调用超时后外部请求没有到达；workflow 完成等于业务 postcondition 成立。

### S2 Temporal Retry Policies
- URL：<https://docs.temporal.io/encyclopedia/retry-policies>
- 访问日期：2026-09-22
- 证据窗口：失败被判定后，Retry Policy 计算下一次 attempt（默认示例包含 initial interval、backoff、maximum attempts 等参数；非重试错误可阻止重试）；平台可记录 retry attempt/history。官方资料未给出任意外部目标的 commit/read-back 时间窗。
- 状态：`verified`（重试参数和 non-retryable 语义）；`inferred`（重试会扩大“外部请求可能已发生”的不确定窗口）；`unknown`（一次失败是否已产生外部效果、重试是否重复业务动作）。
- 能证明：编排器按策略调度/不调度 retry；重试次数/间隔等属于平台控制语义。
- 不能证明：exactly-once external effect、幂等、补偿完成或业务状态最终一致。

### S3 GitHub Actions Workflow Run Logs
- URL：<https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/using-workflow-run-logs>
- 访问日期：2026-09-22
- 证据窗口：job/step 执行产生 runner log → GitHub 提供查看、搜索、下载；日志可被有权限者删除；workflow run 的不同 attempt 可能需要分别下载对应日志。页面没有证明日志对每一步/每个外部副作用无丢失、无延迟或不可篡改。
- 状态：`verified`（查看/搜索/下载/删除及 attempt 边界）；`inferred`（日志是观测证据而非外部状态证明）；`unknown`（完整覆盖、采集延迟、日志链完整性、外部 postcondition）。
- 能证明：GitHub 控制面有相应 run/job/step 日志可操作；下载到的内容是该平台保存的日志材料。
- 不能证明：没有日志的时间段没有执行；step 输出成功等于远端资源已提交；日志覆盖所有 runner/sidecar/第三方系统；删除前后仍可完整重建事实。

### S4 GitHub Actions Re-running Workflows and Jobs
- URL：<https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-workflow-runs/re-running-workflows-and-jobs>
- 访问日期：2026-09-22
- 证据窗口：原始 run 完成/失败 → 用户可在官方允许的窗口内重跑全部、失败 jobs 或指定 job；官方页面直接说明可在初始运行后最多 30 天重跑，并且重跑使用最初触发 actor 的权限。新 attempt 的日志/结论必须与旧 attempt 分开关联。
- 状态：`verified`（30 天重跑窗口、重跑粒度、权限语义）；`inferred`（重跑会产生重复外部动作风险）；`unknown`（重跑前第一次动作是否提交、外部系统是否具备幂等）。
- 能证明：平台接受/执行重跑请求及其 attempt 语义。
- 不能证明：第一次失败“没有副作用”；重跑安全；两次执行合并后业务只发生一次。

### S5 AWS Step Functions Execution Details
- URL：<https://docs.aws.amazon.com/step-functions/latest/dg/concepts-view-execution-details.html>
- 访问日期：2026-09-22
- 证据窗口：Standard execution events → Step Functions execution history；官方页面说明 Standard executions 在最近完成 90 天内历史始终可用。Express workflow 的控制台执行历史来自 CloudWatch Logs，默认显示最近三小时，可扩大查询范围但扫描成本增加。
- 状态：`verified`（Standard 90 天、Express 默认三小时/可调及数据来源）；`inferred`（查询窗口不是副作用生命周期窗口）；`unknown`（三小时外是否仍能取到完整日志取决于 CloudWatch retention/configuration，外部效果仍需 read-back）。
- 能证明：在规定服务/日志窗口内可查看执行历史材料。
- 不能证明：历史完整覆盖每个外部效果；执行 `SUCCEEDED` 等于业务提交；超时/取消等于外部请求未发生。

### S6 AWS Step Functions CloudWatch Logs
- URL：<https://docs.aws.amazon.com/step-functions/latest/dg/cw-logs.html>
- 访问日期：2026-09-22
- 证据窗口：状态机产生执行事件 → 可选地发布到 CloudWatch Logs；官方明确日志交付是 best-effort，且 logging level 从 ALL 到 ERROR/FATAL/OFF，OFF 不记录事件、较低级别会省略正常事件。日志发布不阻塞或减慢执行。
- 状态：`verified`（best-effort、可选 logging、级别和事件选择）；`inferred`（缺事件不能直接判定未执行）；`unknown`（每条日志是否到达、到达延迟、CloudWatch retention、外部业务效果）。
- 能证明：配置和实际可查询的日志事件所证明的有限平台观测；不能把日志缺失当作否定证据。
- 不能证明：全量、无丢失、严格实时日志；外部服务 commit；业务 postcondition。

### S7 AWS Step Functions GetExecutionHistory API
- URL：<https://docs.aws.amazon.com/step-functions/latest/apireference/API_GetExecutionHistory.html>
- 访问日期：2026-09-22
- 证据窗口：Standard workflow 的历史事件可通过 API 分页查询；API 返回的是服务保存的 execution history，调用者须处理分页/查询边界。该 API 不提供外部目标 read-back。
- 状态：`verified`（API 是 execution history 查询面）；`inferred`（分页查询结果只能作为平台证据）；`unknown`（历史是否足够覆盖外部动作、查询时是否已收敛、外部状态）。
- 能证明：返回的事件在 Step Functions 服务历史中存在。
- 不能证明：事件对应的第三方写入成功、重复次数、外部状态当前值或业务不变量。

### S8 AWS CloudTrail Event History
- URL：<https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html>
- 访问日期：2026-09-22
- 证据窗口：AWS 管理控制面事件发生 → CloudTrail 按发生 Region 记录 → Event History 可查看/搜索/下载 → 官方默认历史窗口为最近 90 天；页面明确为 management events，不等于所有 data-plane/data events。
- 状态：`verified`（90 天、区域、管理事件、查询/下载及 immutable record 的文档描述）；`inferred`（它适合归因/审计索引）；`unknown`（覆盖全部调用、实时性、下游业务提交、数据事件是否已配置）。
- 能证明：在该区域/窗口/事件类型范围内，CloudTrail 保存的管理事件材料。
- 不能证明：没有 CloudTrail 事件就没有动作；资源已达到目标状态；外部系统副作用；所有 data events/第三方调用均被覆盖。

### S9 Kubernetes Jobs
- URL：<https://kubernetes.io/docs/concepts/workloads/controllers/job/>
- 访问日期：2026-09-22
- 证据窗口：Job controller 创建/监视 Pod → Job status/conditions 与 Events 可查询；`backoffLimit` 到达后 Job 标记 Failed 并终止运行中的 Pods；`activeDeadlineSeconds` 到达后运行中的 Pods 终止、Job 进入 Failed/DeadlineExceeded，且 deadline 优先于 backoffLimit。
- 状态：`verified`（Job 控制器状态、失败/截止边界）；`inferred`（Job status 是 Kubernetes 控制面状态）；`unknown`（Pod 进程是否已经完成外部写入、日志是否完整、外部效果）。
- 能证明：Kubernetes controller 观察到的 Job/Pod 状态和其终止原因。
- 不能证明：外部数据库/HTTP/对象存储的业务提交或未提交；日志无缺口；Failed 等于无副作用，Complete 等于 postcondition。

### S10 Kubernetes TTL-after-finished
- URL：<https://kubernetes.io/docs/concepts/workloads/controllers/ttlafterfinished/>
- 访问日期：2026-09-22
- 证据窗口：Job Complete/Failed → TTL controller 在 `ttlSecondsAfterFinished` 到期后将其清理；清理会制造 API 对象及其关联观测的保留边界。具体可查询时间由 TTL、控制器调度和集群配置决定。
- 状态：`verified`（Finished Job 自动清理机制）；`inferred`（过期后仅凭 API 查询可能无法还原原始证据）；`unknown`（日志/事件是否另有独立保留、清理时延、业务状态）。
- 能证明：在对象仍保留时可查询 Job 的控制面状态；TTL 配置导致的清理规则。
- 不能证明：清理后的 Job 未执行；外部效果；证据完整可重建。

### S11 Claude Code OpenTelemetry monitoring
- URL：<https://docs.anthropic.com/en/docs/claude-code/monitoring-usage>
- 访问日期：2026-09-22
- 证据窗口：Claude Code session/prompt/tool activity → 可选 OTLP metrics/logs/traces 导出；官方给出验证方法：发送 prompt 后检查 `claude_code.user_prompt` event，若无则用 `claude --debug` 检查；导出器失败会以 3P telemetry 错误报告。官方还记录 retention sweep event，该 sweep 会按 `cleanupPeriodDays` 清理旧 session transcripts/application data。
- 状态：`verified`（可配置导出、验证探针、失败诊断、retention sweep 语义）；`inferred`（后端收到的事件是观测材料而不是操作效果证明）；`unknown`（采集器/网络/后端完整性、所有事件零丢失、默认具体保留天数、外部副作用）。
- 能证明：在配置有效且后端观察到事件时，该事件被导出/接收；本地 debug 可暴露 exporter failure。
- 不能证明：没有事件即没有操作；所有工具动作均已记录；第三方目标完成；日志后端没有采样/丢失/延迟。

### S12 OpenAI Codex CLI official repository
- URL：<https://github.com/openai/codex>
- 访问日期：2026-09-22
- 证据窗口：官方仓库是源码/项目入口，可核验仓库中实际公开的 CLI 文档和实现；本切片未把仓库 README 的功能说明扩展为审计、保留、断流或外部效果保证。若某项语义未在被核验的官方材料中明确，标记 `unknown`。
- 状态：`verified`（官方仓库存在）；`unknown`（本切片需要的统一 audit retention、日志完整性、断流检测、external read-back contract 未从该入口得到可推广的官方保证）。
- 能证明：仓库中明确存在且可读取的源码/文档事实（需绑定具体版本/提交才可形成更强供应链证据）。
- 不能证明：Codex CLI 任意运行的完整审计覆盖、任务成功等于外部 postcondition、取消/断流后的副作用不存在、exactly-once。

## 跨平台验证闭环（可迁移，但不是任何平台的已实现保证）

应把一次外部动作建模为至少四条独立证据链：

1. **平台链**：run/workflow/job/execution ID、attempt、状态、开始/结束、timeout/cancel/failure reason。
2. **日志链**：source、采集器、event timestamp、ingest timestamp、查询时间、序号/分页、保留截止、是否可能 best-effort/采样/删除。
3. **目标链**：目标系统权威查询、resource version/etag/operation status、幂等键或唯一约束、目标回执；没有目标链不能将平台 SUCCESS 升级为 verified effect。
4. **业务链**：独立 postcondition/invariant/read-back、对账窗口、补偿或人工审核结论。

推荐状态迁移：
- `DISPATCHED`：请求已发出，不能推断目标结果。
- `PLATFORM_RECORDED`：平台有执行/日志记录，仍不能推断外部提交。
- `SUCCEEDED_UNVERIFIED`：平台完成或工具返回成功，但无目标 read-back。
- `VERIFIED_EFFECT`：目标权威 read-back 与 operation_id/幂等键和 postcondition 一致。
- `FAILED`：平台明确失败；若动作可能已发出，外部效果仍为 `UNKNOWN_NEEDS_RECONCILE`。
- `TIMEOUT/CANCELED/DISCONNECTED`：默认 `UNKNOWN_NEEDS_RECONCILE`；禁止无幂等键盲目重试。
- `COMPENSATED`：仅在补偿动作本身也经过目标 read-back/postcondition 后成立。

## 能/不能证明的总边界

- `日志存在`：只能证明保存系统存在一条记录。
- `覆盖范围`：必须知道事件类型、采样/级别、区域、组件、attempt、时间和配置；单条日志不能证明全覆盖。
- `完整性`：必须另有序号/摘要/签名/不可变存储和缺口检查；本文所引平台页面未对所有场景提供统一完整性保证。
- `断流检测`：连接断开、心跳超时、平台 timeout 或 exporter error 只能证明观测/通信失败或平台判定，不证明目标动作没有发生。
- `平台完成`：证明平台状态机进入终态，不证明外部业务 postcondition。
- `外部效果 read-back`：由目标权威接口/资源状态确认，是把 unknown 降级为已确认效果的必要证据之一；本切片没有访问任何真实目标，因此没有 production read-back。
- `业务 postcondition`：应由独立不变量/对账/人工门确认；不能用模型自报、日志文本或“绿色”平台状态替代。

## 未解决问题

1. 各平台具体日志后端的保留配置、采样、删除、区域和访问延迟需按部署实态读取；官方默认/示例不能替代实例证据。
2. GitHub Actions、Claude Code、Codex CLI 均不能仅凭公开文档推出所有外部动作的 exactly-once 或自动补偿保证。
3. 要把 UNKNOWN 收口，必须获得目标系统权威查询、幂等键/唯一约束、操作回执或业务对账；本切片严格未访问真实服务。

## 结论等级

- 官方文档直接描述的平台机制：`verified`。
- 从多个平台边界抽象出的审计/UNKNOWN设计：`inferred`，属于迁移性设计建议，不是任何单个平台的生产保证。
- 无目标 read-back、无完整日志链、无明确 retention/断流合同的地方：`unknown`。

**本报告不声称 production 通过。**
