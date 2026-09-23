# S5 — 连续性恢复、缺口检测与恢复验收

访问日期：2026-09-22。仅使用官方/一手公开资料；未访问认证 API、真实服务、凭据或受保护目录；本片不是 production 验收。

## 结论

官方资料支持设计有边界的连续性恢复测试，但不能仅凭文档证明任何具体部署完整、无损或生产通过。应把“恢复成功”拆成：平台恢复路径完成、证据对象连续、目标副作用 read-back、业务 postcondition 四个独立条件。

## 统一证据窗口

每条证据至少记录：`subject_id`、`source_system`、`expected_event`、`window_start/window_end`、`query_start/query_end`、`event_time`、`observed_or_ingest_time`、`query_scope`、`pagination_complete`、`retention_as_of`、`correlation_id`、`sequence_or_checkpoint`、`expected_count/observed_count`、`exporter_state`、`query_errors`、`drop_or_reject_evidence`、`first_seen/last_seen`、`evidence_hash`、`classification`、`confidence_basis`。

允许的结论：`VERIFIED_CONTINUITY`、`DELAYED`、`DROPPED`、`EXPORTER_FAILURE`、`QUERY_GAP`、`RETENTION_EXPIRED`、`NO_EVENT`、`UNKNOWN`。

`NO_EVENT` 只有在独立证明事件生成前提、完整范围/分页、保留期覆盖、Exporter 健康和延迟窗口结束后才允许。仅“查询没有返回”必须保持 `UNKNOWN`。

## 1. OpenTelemetry Collector

官方来源：https://opentelemetry.io/docs/collector/resiliency/

文档区段：`Sending queue (in-memory buffering)`、`Persistent storage (write-ahead log - WAL)`、`Circumstances of data loss`、`Monitor Collector Metrics`；访问日期 2026-09-22。

**verified：** Exporter 可使用内存队列；目标不可用时重试采用指数退避与抖动；文档默认最大重试时间为五分钟（除非配置）；内存队列满会丢弃新数据；`file_storage` 可提供 WAL 持久队列，重启后可重新读取并重试；磁盘故障、磁盘耗尽、队列溢出和重试到期仍可能丢失；文档建议监控 `otelcol_exporter_queue_size`、`otelcol_exporter_queue_capacity`、`otelcol_exporter_send_failed_spans` 及同类 signal 指标。

**inferred：** 连续性验收必须发出唯一 ID 的已知记录，制造目标不可用、重启 Collector、恢复目标，再对账 emitted/exported/accepted/dropped/rejected ID 与队列和失败指标；必须另测内存/持久队列溢出、磁盘满、超过 `max_elapsed_time` 的中断和非正常终止。验收应限定在配置的队列容量与重试窗口内，不能宣称普遍 lossless。

**unknown：** 文档不证明 exactly-once、端到端持久化、所有 exporter 默认值一致、存在通用稳定序列号或某一具体部署已恢复全部记录。WAL 是崩溃恢复支持，不是最终后端收据。

## 2. AWS CloudTrail digest

官方来源：
- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html
- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-cli.html
- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-digest-file-structure.html

文档区段：`Why use it`、`How it works`、`validate-logs`、`Validation results`、`Checking whether a particular file was delivered by CloudTrail`、`Digest file chaining`；访问日期 2026-09-22。

**verified：** 启用完整性验证后，CloudTrail 为日志文件建立 hash，并周期性生成带签名、引用前一 digest 的 digest 文件；链可检测日志或 digest 被修改/删除。`aws cloudtrail validate-logs` 可验证被 digest 引用的对象。缺失或无效 digest 会标出无法验证的时间范围。AWS 还说明交付故障后的 digest 重新交付可能暂时乱序；停止记录或删除 trail 时可产生最终 digest。

**inferred：** 验收应区分 `validated`、`invalid`、`unvalidated`，保存验证起止时间、文件级结果、缺失/无效 digest、链断点和未覆盖时间段；出现重新交付窗口时应等待并复验，不能立即判定篡改。只能对明确被链覆盖的区间作完整性结论。

**unknown：** digest 不能证明事件在源服务端一定生成，不能证明 trail 在整个时间段持续启用，不能证明业务所需每个事件都存在；移动或下载到原 S3 位置之外的文件不能按 CLI 要求验证。

## 3. GitHub Actions

官方来源：
- https://docs.github.com/en/rest/actions/workflow-runs
- https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run
- https://docs.github.com/en/rest/actions/artifacts
- https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api

文档区段：workflow run/job/artifact list、pagination、download logs；访问日期 2026-09-22。

**verified：** run、job、log、artifact 是分离接口；列表分页，`per_page` 最大 100、默认 30；部分过滤搜索最多 1000 条；日志通过单独 endpoint 下载且重定向链接一分钟后过期；artifact 有 `expired`、`created_at`、`expires_at`、`digest`，过期下载可能返回 410。

**inferred：** 审计必须按时间/工作流/分支等确定性分区，遍历所有分页，分别枚举每个 run 的 jobs、logs、artifacts，并立即下载短期日志链接；记录 run/attempt/previous-attempt 关系。超出 1000 条时不能把单次搜索结果当完整集合。

**unknown：** 文档不提供所有计划/仓库统一的日志和 artifact 保留期，不保证日志与 run metadata 同寿命，也不提供单一 endpoint 证明一个 run 的全部执行记录。因此过期或缺失对象应是 `QUERY_GAP`/`RETENTION_EXPIRED`/`UNKNOWN`，不是“从未产生”。

## 4. Kubernetes API

官方来源：
- https://kubernetes.io/docs/reference/using-api/api-concepts/
- https://kubernetes.io/docs/reference/kubernetes-api/cluster-resources/event-v1/

文档区段：`Chunking`、`resourceVersion`、`Semantics of watch`、`410 Gone`、`Watch bookmarks`、Event API；访问日期 2026-09-22。

**verified：** list 可用 `limit` 和 `continue` 分页，客户端应持续取页直到没有 `continue`；list 返回的 `resourceVersion` 可作为 watch 起点。历史版本不可用时 watch 可返回 410 Gone，客户端应清缓存、重新 list，再从新 resourceVersion watch。continue token 过期也可能 410 ResourceExpired。bookmark 不是必然发送。Kubernetes Events 是有限保留、informative、best-effort 的补充数据。

**inferred：** 连续性验收应保存每一页、token、list resourceVersion、对象 key、remainingItemCount；正常断流从最后有效 resourceVersion 重连；410 时 relist 并显式记录“重建区间”。Event 不得作为唯一 durable audit ledger。

**unknown：** 文档不保证任意部署的 resourceVersion 保留时间，不证明某 controller 实际遵守恢复流程，不证明生产集群没有丢 watch 或断流间隔。

## 5. Temporal

官方来源：
- https://docs.temporal.io/workflow-execution/event
- https://docs.temporal.io/workflow-execution
- https://docs.temporal.io/visibility

文档区段：Event History、Event Loop、Replay、Replays、`How current is Visibility data`、Visibility operations；访问日期 2026-09-22。

**verified：** Temporal 将 Events 追加到 Workflow Execution Event History；Event History 支持 durable execution 和 crash recovery；replay 通过比较命令与已记录 history 恢复；Event History 有数量和大小限制。Visibility 是异步更新的搜索索引，可能数秒或更久过时，Temporal Cloud 不给固定传播 SLA，count 近似；单个 execution 的权威读取应使用 Describe，进度/完成应优先跟随 Event History 而不是轮询 Visibility。

**inferred：** 单个 Workflow ID/Run ID 的连续性应以完整 Event History 和 replay/序列不变量为主；Visibility 只作发现/过滤/计数。验收要分别记录 durable history、replay、authoritative describe 和 visibility convergence。

**unknown：** 文档不为所有部署提供统一 history retention，不证明某 worker 已成功 replay，不证明 Visibility 在固定时间内收敛，也不证明 history 外部的副作用恰好一次。

## 6. Claude Code telemetry

官方来源：https://code.claude.com/docs/en/agent-sdk/observability

文档区段：`How telemetry flows from the SDK`、`Enable telemetry export`、`Flush telemetry from short-lived calls`、`Read agent traces`、`Link traces to your application`；访问日期 2026-09-22。

**verified：** Agent SDK 运行 Claude Code CLI 子进程；CLI 有 OTel instrumentation，输出 metrics、structured log events、traces；日志可含 prompts、API requests/errors、tool results；telemetry 需显式开启和配置 exporter；export error 默认静默，可启用 `CLAUDE_CODE_OTEL_DIAG_STDERR=1`；telemetry 批量发送，clean exit 尝试 bounded flush，进程被 kill 时 pending buffer 可能丢失；文档给出的默认 interval 为 metrics 60 秒、traces/logs 5 秒；`session.id` 可用于部分关联；tracing 为 beta。

**inferred：** 成功完成任务不等于 telemetry 完整；短命进程和强制终止必须作为 loss window 测试；应在 collector/backend 边界对账各 signal，而不是根据 CLI 完成推断。必要时接入带 queue/WAL 的 Collector。

**unknown：** 不证明统一序列号、exactly-once、CLI 内 durable replay、所有 prompt/tool/API 事件都送达，或任一具体部署后端收到全部 telemetry。

## 统一恢复判定

- 源端 witness 与后续观测 witness 均有时间戳：`DELAYED`。
- 有显式 exporter timeout/retry exhaustion/rejected batch：`EXPORTER_FAILURE` 或明确 `DROPPED`。
- 有完整边界和序列/检查点断点，且无查询/保留缺口：`DROPPED`。
- 分页、范围、权限、resourceVersion、重定向下载或后端查询不完整：`QUERY_GAP`。
- 已知 retention/TTL 且目标在截止点外：`RETENTION_EXPIRED`。
- 完整 bounded source/destination sequence/count/heartbeat 连续：`VERIFIED_CONTINUITY`。
- 只有在 generation precondition、完整范围、健康路径、延迟边界和无匹配记录均成立时才是 `NO_EVENT`。
- 其余情况：`UNKNOWN`。

最终状态：官方公开证据支持实施连续性验收和缺口恢复测试；不支持宣称任何具体部署生产通过、无中断、无损或历史完整。
