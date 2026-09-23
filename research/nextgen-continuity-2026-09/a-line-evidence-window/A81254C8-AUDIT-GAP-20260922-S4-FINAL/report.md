# S4 — 审计断流、日志缺口与连续性检测

访问日期：2026-09-22。仅使用官方/一手公开资料；仅在独立 `/tmp` 目录保存本片产物。未访问生产系统、真实服务、凭据、shared/P0、事故目录、D10/L12/D14、canonical、140、tri-line 或 systemd。本研究不是 production 验收。

## 1. 统一证据窗口模型

每个 source/query/subject 应至少记录：

- `subject_id`：workflow/run、trace ID、event UID、repository/run ID、session ID 等
- `source_system`
- `expected_event`：事件谓词与生成前提
- `window_start/window_end`：UTC 事件窗口
- `query_start/query_end`：实际查询区间与查询时间
- `event_time`：源端发生时间
- `observed_time/ingest_time`：采集器或平台观察时间
- `query_scope`：account、region、repository、namespace、workflow、tenant、signal、run ID、filters
- `pagination_complete`：分页/分区是否完整
- `retention_as_of`：保留策略及有效截止点
- `correlation_id`：trace/run/execution/event/workflow/session 标识
- `sequence_or_checkpoint`：单调序列、事件数、游标、checkpoint 或 heartbeat
- `expected_count/observed_count`
- `exporter_state`：启用状态、端点、队列、重试、确认、失败
- `query_errors`：超时、权限、限流、部分响应、截断
- `drop_or_reject_evidence`：显式 drop counter、拒绝批次、序列缺口、服务端拒绝
- `first_seen/last_seen`
- `completeness_attestation`
- `evidence_hash`（可选）
- `classification` 与 `confidence_basis`

## 2. Fail-closed 分类

### `NO_EVENT`
只有同时满足：事件生成前提独立成立；source/query 窗口完整；分页、分区和范围完整；保留期覆盖；exporter/ingestion 健康已验证；允许的延迟上界已经过去；查询仍无匹配事件，才可使用。否则保持 `UNKNOWN`。

### `DELAYED`
必须有源端发生 witness，之后又有观察/摄取 witness，并且两者时间戳可计算延迟。延迟上界未过时，目标端暂时查不到只能是 `UNKNOWN`，不能直接写成 delayed。

### `DROPPED`
必须有显式 drop counter、拒绝批次、服务端拒绝，或在查询范围完整且无保留/查询缺口时发现完整序列/checkpoint gap。下游缺记录本身不能证明 dropped。

### `EXPORTER_FAILURE`
需要 exporter error/retry/timeout/queue 证据，或显式 disabled 状态。只有后端缺记录，不能判定 exporter failure。

### `QUERY_GAP`
范围、分页、分区、filter、region/account/namespace、权限或查询完成状态不完整或不确定时使用。

### `RETENTION_EXPIRED`
只有当平台保留/TTL 策略和 cutoff 已知，且目标事件确实在保留区间外时使用。保留策略未知时仍是 `UNKNOWN`。

### `VERIFIED_CONTINUITY`
需要有界窗口、完整查询、稳定范围、sequence/checkpoint/count/heartbeat 连续性，且没有未解决的 exporter、query、retention 缺口。

### `UNKNOWN`
当至少两种解释与现有证据相容时强制使用。不得把“没有查到”转换为“没有发生”。

## 3. 逐源证据矩阵

### S4-OTEL-01 — OpenTelemetry Logs Data Model

URL：<https://opentelemetry.io/docs/specs/otel/logs/data-model/>  
访问日期：2026-09-22  
证据窗口：规范层的 `Timestamp`（源端发生）→ `ObservedTimestamp`（采集器观察）→ 后端摄取；本页不提供具体运行时保留窗口。

**verified：** `Timestamp` 表示事件在源端发生的时间；`ObservedTimestamp` 表示采集系统观察到事件的时间；外部事件由 Collector 收集时，`ObservedTimestamp` 可表示 Collector 观察时刻；TraceId/SpanId 可用于关联。

**能证明：** 在两个时间戳均存在时测量 source-to-collector 延迟、区分发生与观察、关联 trace/span。  
**不能证明：** 已抵达最终后端、已持久化、无记录即无事件、缺失来自未生成/采集前丢弃/export 丢弃/filter/查询范围/保留期中的哪一种。缺记录默认 `UNKNOWN`，除非另有独立生成 witness 和完整查询链。

### S4-OTEL-02 — OpenTelemetry Protocol Exporter

URL：<https://opentelemetry.io/docs/specs/otel/protocol/exporter/>  
访问日期：2026-09-22  
证据窗口：export attempt → timeout/retry/backoff → server response/ack；具体运行时队列和后端保留取实现配置。

**verified：** exporter 具有 signal-specific endpoint、timeout、request-size 等设置；瞬态错误需要 exponential backoff/jitter 重试；规范定义可重试的传输/服务端失败类型。

**能证明：** 有实现暴露相应指标时，可把 timeout、retry exhaustion、endpoint failure、transport error 作为 exporter-path 证据。  
**不能证明：** 客户端成功发送等于后端持久化；未观察 queue、batch、shutdown flush、backend acknowledgement 时不能证明完整送达；后端缺记录本身不能证明 dropped；所有 SDK 都提供同等 drop counter 或 durable delivery 保证。

### S4-GHA-01 — GitHub Actions workflow events

URL：<https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows>  
访问日期：2026-09-22  
证据窗口：activity/webhook/schedule → trigger eligibility、activity type、branch/path filter → workflow run；本页不提供特定仓库的运行时间窗。

**verified：** workflow 可由指定 GitHub activity、schedule 或外部事件触发；并非所有 webhook 都触发 workflow；部分事件具有 activity type 和 filter。

**能证明：** 给定配置时评估候选事件是否满足触发条件，并识别存在的 run metadata。  
**不能证明：** 相关 webhook 存在就一定应有 run；无 run 不足以区分 trigger mismatch、workflow disabled、branch/path filter、平台延迟、webhook delivery failure 或 query gap；不证明下游部署或外部副作用。

### S4-GHA-02 — Workflow history/logs/artifacts

URL：<https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/viewing-workflow-run-history>  
URL：<https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/viewing-workflow-run-logs>  
URL：<https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/storing-and-sharing-data-from-a-workflow>  
访问日期：2026-09-22  
证据窗口：run 创建/执行 → log/artifact 生成 → 查询/下载 → retention/expiration；artifact 与 log 是不同证据类。

**verified：** GitHub 提供 run history 和 logs；artifact 可用 `retention-days` 配置保留但受组织层限制；artifact retention 不自动证明 log retention；超过保留期限的缺 artifact/log 不能证明 workflow 从未运行。

**能证明：** run ID、status/conclusion、job steps、时间戳和完整日志均可取到时，证明该 bounded run 的平台连续性；已知 retention policy 和过期点时可判 `RETENTION_EXPIRED`；访问受限或取数不完整时判 `QUERY_GAP`。  
**不能证明：** 缺 run 即无 trigger；只有 summary 即无某一步；run 成功即外部效果；无独立 trigger/webhook witness 时不能区分 `DROPPED` 和 `NO_EVENT`。

### S4-AWS-CT-01 — CloudTrail event record contents

URL：<https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html>  
访问日期：2026-09-22  
证据窗口：request completion (`eventTime`) → CloudTrail record/delivery → 查询或目标 destination；具体 delivery delay 由记录上下文决定。

**verified：** `eventTime` 表示请求完成的 UTC 时间；CloudTrail 文档有 `DELIVERY_DELAY` event reason，可指示网络、连通性或 CloudTrail 服务问题导致的延迟。

**能证明：** 在记录含相关字段时区分请求完成时间和交付延迟，并将显式 `DELIVERY_DELAY` 分类为 `DELAYED`。  
**不能证明：** 缺 CloudTrail event 即请求未发生；单一区域查询能证明全账户无事件；Event History 覆盖 data events、Insights events 或 network activity；一个记录证明所有 destination 已收到或下游消费者已处理。

### S4-AWS-CT-02 — CloudTrail Event History limits

URL：<https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html>  
访问日期：2026-09-22  
证据窗口：事件发生 → management event 记录 → account/region Event History 查询 → 90-day retention cutoff；trail/event data store 另行处理持续记录。

**verified：** Event History 提供过去 90 天 management events；按事件发生 region 限定；不显示 data events、Insights events 或 network activity events；查询具有 account/region 和查询限制。

**能证明：** 超过已知 90 天管理事件窗口可判 `RETENTION_EXPIRED`；跨 region/account、data/Insights/network activity 的结论从 Event History 单独得出时判 `QUERY_GAP`。  
**不能证明：** 单账户/单区域 Event History 证明组织级连续性；支持范围外无事件；未验证 trail/event data store 时证明该期间完整无事件。

### S4-AWS-SF-01 — Step Functions history and workflow type

URL：<https://docs.aws.amazon.com/step-functions/latest/dg/concepts-history.html>  
URL：<https://docs.aws.amazon.com/step-functions/latest/dg/choosing-workflow-type.html>  
访问日期：2026-09-22  
证据窗口：execution/state transition → Standard history 或 Express logging → query/retention；workflow type 改变语义。

**verified：** Standard workflow 可审计并提供 execution history；完成后最多 90 天可取完整 history；Standard 使用 exactly-once model，但 ASL retry 可改变执行次数；Express 为 at-least-once，可能多次执行；Express 需要启用 logging 才能获得相应历史证据。

**能证明：** 完整取回 Standard history 且 sequence/state transition 完整时可证明该 execution 的平台连续性；超过 Standard history 窗口可判 retention expired；Express 重复观察不自动等于 drop。

**不能证明：** Express 缺 Step Functions history 即未执行；Express exactly-once；平台 history 单独证明外部 task effect；下游非幂等且配置 retry 时没有重复外部效果。

### S4-K8S-01 — Kubernetes Event API

URL：<https://kubernetes.io/docs/reference/kubernetes-api/events/event-v1/>  
访问日期：2026-09-22  
证据窗口：cluster observation → Event object/series → API query → retention/TTL/cleanup；本页不保证 durable archive。

**verified：** Event 暴露 timing 和 source/object context；`eventTime` 表示首次观察时间；series 有 occurrence `count` 和 `lastObservedTime`。

**能证明：** 在完整 Event series 状态可取到时测 repetition/heartbeat continuity；有独立源端时间时辅助判断 delayed；有完整 count/sequence 时发现 series discontinuity。  
**不能证明：** 缺 Event 即未发生；drop 与过期、压缩、filter、namespace/scope 查询外的事件可仅凭缺失区分；单 namespace 查询证明集群连续性；API 本身提供永久归档。查询范围、resource version/pagination、retention/TTL 未建立时，缺 Event 必须 `UNKNOWN`。

### S4-TEMP-01 — Temporal Event History

URL：<https://docs.temporal.io/encyclopedia/event-history>  
访问日期：2026-09-22  
证据窗口：Workflow Execution event → ordered durable Event History → worker replay；具体 execution retention 需另外核验。

**verified：** Event History 被描述为 Workflow Execution 的 complete、durable、ordered log；commands 映射为 Events 并持久化；worker failure 后可 replay history 重建 workflow state。

**能证明：** 在 Workflow ID/run ID 正确、history 完整、replay/sequence invariant 成立时证明 workflow-state continuity。  
**不能证明：** workflow event 存在即 external Activity exactly-once；错误 run ID、namespace、visibility query 或 retention 下的缺记录原因；旧 history 一定仍可取；跨 Continue-As-New run 的生命周期连续性。

### S4-TEMP-02 — Temporal Continue-As-New

URL：<https://docs.temporal.io/workflow-execution/continue-as-new>  
访问日期：2026-09-22  
证据窗口：旧 run checkpoint → 新 run 创建 → 新 Event History；同 Workflow ID、不同 Run ID。

**verified：** Continue-As-New checkpoint workflow state 并启动新 execution；新 execution 保留 Workflow ID 但有不同 Run ID 和新 Event History；可将长 history 拆分。

**能证明：** 有 checkpoint 和 successor run 证据时，识别 run boundary 为有意历史断点而非 drop。  
**不能证明：** 只查一个 Run ID 就证明全生命周期连续；没有 checkpoint/successor 证据时把跨 run 缺 event 判作 dropped；未覆盖所有 run segment retention/archival 时证明全生命周期完整。

### S4-CLAUDE-01 — Claude Code monitoring and OTel export

URL：<https://code.claude.com/docs/en/monitoring-usage>  
访问日期：2026-09-22  
证据窗口：session/prompt → client telemetry event → exporter → backend；具体 backend retention 由部署决定。

**verified：** Claude Code 可通过 OpenTelemetry 导出 metrics、logs/events 和可选 traces；exporter 可配置为 OTLP、console 或 none；文档建议以 `claude_code.session.count` 验证 metrics，以 `claude_code.user_prompt` 验证 logs-only；`claude --debug` 可报告 `[3P telemetry]` exporter failures；`OTEL_*` 不传给 Bash、hooks、MCP 或 language servers。

**能证明：** client-side session/prompt telemetry witness；显式 debug error 时判 `EXPORTER_FAILURE`；spawned subprocess telemetry 未独立配置时保持 `UNKNOWN`。  
**不能证明：** client verification 等于 backend receipt/durable storage；backend 缺 event 即无 prompt/session；未捕获 debug 时无 exporter failure；子进程共享主程序 exporter；组织级 continuity。

### S4-CLAUDE-02 — Claude Code hooks

URL：<https://code.claude.com/docs/en/hooks>  
访问日期：2026-09-22  
证据窗口：matching lifecycle event → hook handler → handler response/side effect；backend delivery/retention 另行核验。

**verified：** hooks 在定义的 lifecycle point 运行；matcher 命中时 handler 接收 JSON context；文档定义 event types、input schema、exit code、async/HTTP/prompt/MCP hook；包含 `PostToolUse`、`PostToolUseFailure`、`Stop`、`StopFailure`。

**能证明：** handler 收到 lifecycle event 的 witness；捕获到的 handler failure/StopFailure；可按 supplied session/tool context 做关联。  
**不能证明：** unmatched event 从未发生；hook external effect 已完成（除非 handler 发 durable acknowledgement）；backend delivery/retention；缺 hook record 是 drop 而不是 matcher/config/query gap。

### S4-CODEX-01 — OpenAI Codex official source

URL：<https://github.com/openai/codex>  
URL：<https://raw.githubusercontent.com/openai/codex/main/README.md>  
URL：<https://raw.githubusercontent.com/openai/codex/main/AGENTS.md>  
访问日期：2026-09-22  
证据窗口：公开 repository/source reviewed → 文档/源码可查询；本片未建立稳定的 audit/exporter/retention contract。

**verified：** 官方公开仓库和源码指导可访问；审阅材料包含开发/测试和 event-related 实现术语。  
**unknown：** 没有足够稳定的官方 observability/audit contract 来判定 Codex 的事件缺失、exporter 成功/失败、保留、序列连续性或 backend receipt。README/AGENTS 不足以证明 production behavior。

## 4. 判定矩阵

| 观察 | fail-closed 结果 |
|---|---|
| 源端 witness 存在，稍后 destination 出现，且两者均有时间戳 | `DELAYED` |
| 显式 exporter timeout/retry exhaustion/rejected batch | `EXPORTER_FAILURE` 或有明确 drop 时 `DROPPED` |
| 完整边界、无 query/retention gap 的 sequence/checkpoint gap | `DROPPED` |
| query timeout、分页不完整、范围/权限不确定 | `QUERY_GAP` |
| 事件已超出已验证 retention/TTL | `RETENTION_EXPIRED` |
| 有界窗口内 source/destination sequence/count/heartbeat 完整连续 | `VERIFIED_CONTINUITY` |
| 生成前提独立成立、路径健康、延迟上界已过且无匹配事件 | `NO_EVENT` |
| 其他任何缺记录情形 | `UNKNOWN` |

## 5. 结论

跨上述系统，**查询不到事件本身没有独立诊断力**。只有独立证明事件生成前提，同时完成 scope、query、exporter、latency 和 retention 证据，才可谨慎得出 `NO_EVENT`。这仍然只处理日志/事件连续性，不等于外部效果或业务 postcondition 验证；外部效果仍须目标权威 read-back。
