# A线独立研究切片：审计时间窗、日志覆盖、断流检测与验证闭环

- 研究日期：2026-09-22
- 证据范围：公开官方文档/官方源码页面；未访问真实服务、凭据或任何受保护目标。
- 证据等级：官方规范/产品文档属于 primary；结论中的跨平台设计原则是 inferred，不等同于平台承诺。

## 结论

1. **日志存在不是日志覆盖**：Temporal Event History 对 Workflow Execution 的服务端事件提供追加式、持久化记录，但其事件模型是平台生命周期事件；AWS CloudTrail Event history 仅覆盖每个 Region 最近 90 天的 management events；Step Functions Standard 与 Express 的执行历史能力不同；Kubernetes Job 对象还可能按 TTL 被删除。必须同时记录“记录介质、覆盖范围、保留窗、查询时延/可见性、完整性证据”。
2. **平台完成不是外部效果**：Temporal 的 `ActivityTaskCompleted`、Step Functions 的 execution result、Kubernetes Job `Complete` 都是平台/编排状态证据；这些来源未证明第三方 API、支付、文件、数据库等外部 postcondition。外部效果需要目标权威 read-back、业务不变量或独立审计/对账。
3. **断流检测只能证明观测到的失联/超时**：超时、缺少终态事件、worker 不再 heartbeat、日志查询为空，最多支持 `UNKNOWN_NEEDS_RECONCILE`，不能反推“没有发生”。平台可能只记录调度/超时/重试状态，且日志/事件保留或采集配置会产生窗口与覆盖缺口。
4. **验证闭环应是分层的**：`request emitted → platform recorded → tool/platform terminal → external read-back → business postcondition`。每一级都应有独立证据；不得用较低层证据升级成较高层结论。

## 证据矩阵

### S1 — Temporal Events and Event History
- URL：https://docs.temporal.io/workflow-execution/event
- 访问日期：2026-09-22
- 直接证据：文档称 Temporal Service 通过追加事件跟踪 Workflow Execution；所有事件记录在 Event History；Event History 是 append-only log，服务端 durable persisted，可用于崩溃恢复和审计调试；服务端保存整个 Workflow Execution 生命周期的完整 Event History，但有事件数量/大小限制；Activity 的 `Scheduled`、`Started`、`Completed`、`Failed`、`TimedOut`、取消事件在不同阶段写入，运行/重试期间 `Scheduled` 可能是唯一已写入的 Activity 相关事件。
- 证据窗口：事件发生/命令处理后由服务端追加到 History；查询窗口是该 Workflow Execution 的保留期（本页未给出统一天数）；完整 History 受 10,240 警告、51,200 事件等限制，超过限制会终止执行；Reset/Continue-As-New 会改变当前 execution 的历史边界。
- 状态：`verified`（上述文档明确陈述）。
- 能证明：Temporal 服务记录了相应平台事件；在可读取且仍保留的 History 范围内，可重放/审计平台生命周期；某些 timeout/failure/cancel 状态已被服务端记录。
- 不能证明：Activity 的外部副作用一定提交；`ActivityTaskCompleted` 不等于第三方目标已确认；History 没有某事件不等于事件未发生（可能处于运行中的中间窗口、采集/查询边界或已超出当前 execution 语义）；不存在统一保留天数的承诺。
- 关键边界：日志完整性（append-only/durable）不等于业务覆盖完整性；Temporal History 是平台事实，不是任意外部系统的 postcondition。

### S2 — GitHub Actions workflow run logs
- URL：https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/using-workflow-run-logs
- 访问日期：2026-09-22
- 直接证据：官方页面是查看 workflow run、job/step 日志的操作文档，并说明可查看、搜索、下载日志以及使用 debug logging；页面还区分 workflow run、job 和 step 的日志视图。
- 证据窗口：日志能否查询取决于 run 是否存在、权限、日志上传/生成和 GitHub 的保留策略；本次核验未将该页面当作固定保留天数证明。保留天数、删除 run、下载接口应以仓库/组织/企业 retention 设置和对应 API 状态为准。
- 状态：`verified`（能证明有 run/job/step 日志查看与下载入口）；固定 retention 数值为 `unknown`（本轮未采信未经直接核验的数值）。
- 能证明：某个可访问的 GitHub Actions run 具有可供查询的日志对象/界面；日志可以帮助定位 job/step 层发生了什么。
- 不能证明：日志覆盖所有 runner 进程、网络对端或外部服务；日志缺失、截断、未上传或被删除不能证明 step 未执行；run/job 成功不能证明部署目标或外部 API 的业务 postcondition；日志存在也不自动证明未被 runner/应用层改变。

### S3 — AWS CloudTrail Event history
- URL：https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html
- 访问日期：2026-09-22
- 直接证据：官方页面称 Event history 提供每个 AWS Region 最近 **90 天** management events 的可查看、可搜索、可下载、不可变记录；事件记录发生所在 Region；限制部分区分 Event history 与 trail/其他存储能力。
- 证据窗口：事件进入 Event history 后可查询最近 90 天；超过该窗口不能依赖 Event history。Trail 可把选择的事件交付到 S3，并可选 CloudWatch Logs/EventBridge；这属于另行配置的采集/保留路径，而非 Event history 自动覆盖全部事件。
- 状态：`verified`（90 天、Region、management-event 范围及不可变/可下载属性均来自官方页面）。
- 能证明：在覆盖范围内 AWS 控制面操作留下了 CloudTrail 记录；事件记录具备查询/下载和不可变属性。
- 不能证明：没有 Event history 记录就没有操作；data events、未选择的事件、其他 Region 或超过 90 天的操作；CloudTrail 事件本身也不证明目标业务状态最终满足 postcondition。不可变记录证明的是日志对象未被篡改这一层，不是业务正确性。

### S4 — AWS CloudTrail concepts
- URL：https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html
- 访问日期：2026-09-22
- 直接证据：官方概念页区分 Event history（90 天 management events）与 trails / S3 / CloudWatch Logs / EventBridge；并说明 CloudTrail Lake event data store 可按配置保留更长时间（页面给出可配置年限）。
- 证据窗口：事件覆盖依赖 Region、事件类型、trail/event selector、交付配置及目标存储 retention；Lake 查询结果本身另有查询保存/导出边界。
- 状态：`verified`（能力/范围区分）；具体部署是否启用某 trail 为 `unknown`。
- 能证明：审计方案必须显式选择采集与长期保留路径；Event history 不是全量、无限期审计库。
- 不能证明：某一 AWS 账户实际已启用完整 multi-Region、data-event 或长期 trail；未验证的配置不能补齐日志缺口。

### S5 — AWS Step Functions execution history / CloudWatch Logs
- URL：https://docs.aws.amazon.com/step-functions/latest/dg/cw-logs.html
- 访问日期：2026-09-22
- URL：https://docs.aws.amazon.com/step-functions/latest/apireference/API_GetExecutionHistory.html
- 访问日期：2026-09-22
- 直接证据：官方文档明确 Standard Workflows 记录 execution history，可选 CloudWatch Logs；Express Workflows 不在 Step Functions 中记录 execution history，需要 CloudWatch Logs 查看执行历史和结果。`GetExecutionHistory` 是读取 execution history 的 API，并有分页/反向查询等 API 语义。
- 证据窗口：Standard 的服务端 execution history 与 Express 的日志路径不同；CloudWatch Logs 的可见性和保留由 log group/日志级别/配置决定。日志级别与日志交付不是外部系统的最终状态证明。
- 状态：`verified`（Standard/Express 差异）；具体 log group retention、是否启用 logging、日志是否完整为 `unknown`，除非读取实际配置。
- 能证明：Step Functions 编排器记录/输出了某些状态转换或 execution 结果；在配置的 CloudWatch Logs 中可能查询 Express 执行信息。
- 不能证明：任务调用的外部系统已提交、未重复或满足业务不变量；Express 没有 Step Functions 原生 execution history 时，CloudWatch 日志缺口不能被假设为“未执行”；CloudWatch log existence 不等于完整日志覆盖或低延迟可见。

### S6 — Kubernetes Jobs
- URL：https://kubernetes.io/docs/concepts/workloads/controllers/job/
- 访问日期：2026-09-22
- 直接证据：官方 Job 文档定义 Job 代表一次性任务，持续追踪直到成功完成指定数量的 Pods；Job status conditions 可表示 Complete/Failed，并说明可通过 Job/Pod 状态与日志诊断。
- URL：https://kubernetes.io/docs/concepts/workloads/controllers/ttlafterfinished/
- 访问日期：2026-09-22
- 直接证据：TTL-after-finished controller 在 Job status 变为 Complete 或 Failed 后开始计时；TTL 到期后 Job 可被级联删除。官方 caveat 还说明，即使延长 TTL 的 API response 成功，也不保证已过期 Job 会被保留。
- 证据窗口：Job 对象的 status 可在对象仍存在且 API 可查询时读取；`ttlSecondsAfterFinished` 会缩短可查询窗口；Pod/log 生命周期还受日志系统和清理策略影响。删除后的对象不能依赖 live API read-back。
- 状态：`verified`（Job 完成/失败与 TTL 删除语义）；实际集群是否配置 TTL、日志后端 retention 为 `unknown`。
- 能证明：Kubernetes controller 对 Job/Pod 的编排状态作出判定；对象存在时可读取其 status；TTL 删除解释了为何事后查询可能出现缺口。
- 不能证明：Job Complete 就证明外部系统成功；Job/Pod 缺失就证明没有运行；容器退出码或 Pod 日志存在就证明外部副作用 exactly-once；API 删除或 status 的时间戳不是业务 postcondition。

### S7 — Kubernetes audit logging
- URL：https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
- 访问日期：2026-09-22
- 直接证据：官方审计文档定义 audit policy、事件级别与审计 backend；审计记录的是 API server 处理的请求/响应相关活动，能力取决于 policy/backend 配置。
- 证据窗口：请求是否被记录、记录到何处、保留多久取决于 policy、backend 与后端存储；本轮未读取任何真实集群配置，因此实际覆盖与保留为 `unknown`。
- 状态：`verified`（定义与配置依赖）；实际完整性/覆盖 `unknown`。
- 能证明：审计日志可作为 API 操作证据层；没有启用或没有命中的 policy/backend 时不能假设有记录。
- 不能证明：API 请求成功等于控制器已完成目标状态，更不等于外部副作用已完成；缺审计记录不等于请求未发生。

## 统一验证闭环

| 层级 | 证据示例 | 可判定 | 不可判定 |
|---|---|---|---|
| E0 请求发出 | client/runner 发起记录 | 客户端尝试发出 | 服务端收到、提交、完成 |
| E1 平台接收/记录 | Temporal History、CloudTrail event、Step Functions history、K8s audit | 平台记录了某个事件/请求 | 外部效果 |
| E2 工具/编排终态 | ActivityCompleted、workflow/job/run succeeded | 平台认为该步骤终态成功 | 第三方 commit、业务不变量 |
| E3 外部权威 read-back | 目标 API 按 operation/idempotency key 查询、资源版本/状态读取 | 外部目标状态（需时间/权限/一致性边界） | 业务整体 postcondition（若不变量未检查） |
| E4 业务 postcondition | 独立账本/数据库不变量/对账结果 | 业务结果与预期一致 | 未来不会被异步回滚/补偿（需持续监测） |

### 断流与 UNKNOWN 判定

- `timeout`、worker 断连、heartbeat 超时、日志缺失、平台 API 查询超时、execution 被取消：只能判定“当前观测窗口无法得到终态”，初始标记 `UNKNOWN_NEEDS_RECONCILE`。
- 只有权威目标查询明确返回“此 operation_id 未发生/未提交”，且该查询具有足够一致性与保留窗口，才可把 UNKNOWN 收敛到 NOT_COMMITTED；否则按“可能已发生”处理，禁止无幂等键盲重试。
- 平台的 `Failed`/`TimedOut`/`Canceled` 与外部 `not committed` 不是同义词；平台 `Succeeded` 与外部 `committed` 也不是同义词。
- 日志完整性要单独验证：对象存在、内容覆盖、不可变/哈希/签名、采集链路完整、查询时间窗不是同一件事。



## Temporal 官方补充证据（回调研究并入）

补充来源与逐项窗口见同目录 `temporal-addendum.md`；以下结论已对官方 URL 做 HTTP 200 可访问性复核。

- **Event History**：Temporal Service 维护 append-only、durably persisted 的 Workflow 平台事件；History 有事件数量/大小边界。它覆盖 Temporal 状态机，不自动覆盖 Activity 内部每个外部调用。
- **CLI 与查询**：`workflow execute` 返回平台完成；`workflow show`/`--follow` 可读取或跟随 History。History API 支持 `wait_new_event`、分页 token 与 `archived` 标记，因此单页响应不能声称覆盖完整 History。
- **Visibility**：是异步搜索索引，传播可能数秒或更久且无固定 SLA；单 Workflow 当前状态应优先用 `DescribeWorkflowExecution`，不能把 Visibility 未找到判定为不存在。
- **保留与归档**：Namespace Retention 决定闭合 Workflow 数据的主存储窗口；可提前删除。Archival 异步运行，默认延迟最多约 5 分钟且文档标为 experimental；不能据此声称生产审计已通过。
- **断流边界**：Heartbeat Timeout、Start-to-Close Timeout 是可配置的失活发现边界；Heartbeat 可能被 Worker 节流。Temporal 不直接即时发现所有 task loss，timeout 前外部副作用保持 UNKNOWN。
- **重试与外部验证**：Standalone Activity 默认 at-least-once；Activity ID 去重不等于外部业务幂等。官方 polling 模式要求显式读取外部目标状态；Workflow/Activity 完成仍不能替代 external read-back 或业务 postcondition。
- **Run 链**：Continue-As-New 使用同 Workflow ID、不同 Run ID 和独立 History；审计必须追踪 Run Chain，不能把单个 Run 当作整个长期任务的完整历史。

- 本片未接入任何真实 Temporal namespace、GitHub repository、AWS account、Kubernetes cluster，故不判断实际配置、实际保留期、实际缺日志或生产状态。
- GitHub 固定 retention 数值未作为本片 verified 事实；只采信日志查看/搜索/下载能力，避免把未直接核验的默认设置写成保证。
- 官方文档说明能力和边界，不自动证明该系统在每次故障下都完整记录；“日志缺失→未执行”的推理均不成立。

## 下一片（立即续接，不停线）

主题：取消/超时/断流后的 UNKNOWN、重试幂等与补偿。研究对象优先 Temporal cancellation/Activity retry/heartbeat、AWS Step Functions retry/catch/redrive、Stripe idempotency、Kafka/消息投递语义、Kubernetes Job backoff/retry；仍仅公开官方/一手资料，单独 `/tmp` 目录落盘，重点核验：取消是否停止外部进程、重试是否可能重复副作用、幂等键生命周期、补偿是否有权威 read-back，以及 UNKNOWN 如何收敛。


## 外部回调研究补充（Actions / AWS / Kubernetes）

第二个研究代理已完成独立官方资料核验，未访问生产或受保护目标。其结果纳入 `report.md` 的主结论范围；重要可采信边界如下：

- GitHub Actions workflow/job/step success 仅是平台执行状态；日志按 job/step，不能覆盖 runner、对端服务或部署目标。partial re-run 需要结合不同 attempt 才能形成完整运行记录；workflow log 可删除，artifact retention 还受仓库/组织/企业上限约束。
- Step Functions Standard 有原生 execution history；Express 依赖 CloudWatch Logs。日志交付是 best effort，不能把 CloudWatch 日志缺失当作未执行；ExecutionSucceeded/Failed/TimedOut 仍是编排层证据。
- CloudTrail Event History 是最近90天、按 Region 的 management events；CloudTrail Lake/trail/S3 是另行配置的保存路径，事件选择器影响覆盖。查询结果自身也有查询/导出边界。
- Kubernetes audit 覆盖依赖 audit policy/backend；webhook backend 可能批量缓存，缓冲溢出可丢事件。容器日志受文件轮转、Pod/节点生命周期和外部后端 retention 影响；Job Complete/Failed 与对象存在不等于外部 postcondition。
- 上述回调材料的统一“平台状态≠外部效果”结论标为 inferred；具体账户、仓库、集群配置和生产覆盖仍为 unknown。


## 外部回调研究补充：GitHub Actions / AWS / Kubernetes

### GitHub Actions

**GHA-1 — Workflow run logs**  
URL: https://docs.github.com/en/actions/how-tos/monitor-workflows/use-workflow-run-logs  
访问日期：2026-09-22；verified。  
窗口：workflow run → job/step 日志生成、查看、搜索、下载；partial re-run 下载归档可能只包含本次重跑 jobs，必须合并不同 attempt 才能形成完整运行记录。日志可删除；页面未为所有仓库提供统一永久 retention。  
能证明：GitHub 平台层的 run/job/step 状态与可查询日志。  
不能证明：runner 全部行为、外部 API/部署目标状态、业务 postcondition。

**GHA-2 — Workflow artifacts**  
URL: https://docs.github.com/en/actions/tutorials/store-and-share-data  
访问日期：2026-09-22；verified。  
窗口：artifact 可用 `retention-days` 配置，但不得超过 repository/organization/enterprise 上限；v4 artifact immutable；上传 digest 为 SHA-256，下载时自动校验。  
能证明：上传内容与下载内容的 digest 一致。  
不能证明：内容语义正确、外部系统已应用、永久保留或业务结果正确。

**GHA-3 — Workflow syntax / skipped runs**  
URL: https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax  
访问日期：2026-09-22；verified。  
窗口：branch/path/activity/message filters 可能导致 workflow 不运行而关联 check 保持 Pending。  
能证明：触发/过滤层状态；不能把 Pending 当作执行失败或外部目标未变化。

### AWS Step Functions

**SF-1 — Standard/Express 与 CloudWatch Logs**  
URL: https://docs.aws.amazon.com/step-functions/latest/dg/cw-logs.html  
访问日期：2026-09-22；verified。  
窗口：Standard 在 Step Functions 中保留 execution history；Express 不保留原生 execution history，需要 CloudWatch Logs；日志交付 best-effort，完整性与及时性不保证；日志级别 ALL/ERROR/FATAL/OFF 改变覆盖，payload 可能截断。  
能证明：编排器/日志管道的记录边界；不能证明 CloudWatch 缺失即未执行，也不能证明外部业务效果。

**SF-2 — Service quotas / history retention**  
URL: https://docs.aws.amazon.com/step-functions/latest/dg/service-quotas.html  
访问日期：2026-09-22；verified。  
窗口：Standard 单次最多 25,000 events；执行关闭后 history 默认保留 90 天，官方支持申请降低至 30 天；Standard 最长运行 1 年；Express 最长运行 5 分钟。  
能证明：原生 execution history 的时间/大小边界；不能把该窗口当成 CloudWatch Logs 或外部系统的保留窗口。

**SF-3 — Task state**  
URL: https://docs.aws.amazon.com/step-functions/latest/dg/state-task.html  
访问日期：2026-09-22；verified。  
窗口：Task 从启动到 success/failure/TimeoutSeconds；超时形成 `States.Timeout`。  
能证明：Step Functions 对 worker/API 协议层的终态判断；不能证明异步外部服务已最终提交或 read-back 成功。

### AWS CloudTrail

**CT-1 — Event history**  
URL: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html  
访问日期：2026-09-22；verified。  
窗口：每个 account/Region 最近 90 天 management events；不覆盖 data events、Insights events、network activity events；查询有单 account/Region 与过滤边界。  
能证明：限定窗口内的 API 管理活动记录；不能证明窗口外、其他 Region/account、未覆盖事件类别或业务最终状态。

**CT-2 — CloudTrail Lake**  
URL: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake.html  
访问日期：2026-09-22；verified。  
窗口：event data store 的 retention 由选项决定，最长约 2,557 或 3,653 天；selector 决定哪些事件持久化；query result 在 CloudTrail 中最多查看 7 天，可导出 S3；事件通常平均约 5 分钟交付但不保证。  
能证明：配置正确时的长期事件存储机制；不能证明 selector 未选事件、尚未交付事件或发送方描述的业务效果。

### Kubernetes

**K8s-1 — Jobs**  
URL: https://kubernetes.io/docs/concepts/workloads/controllers/job/  
访问日期：2026-09-22；verified。  
窗口：Job controller 从创建到满足 successful completions 或 Failed；失败/删除 Pod 可触发替换/重试；删除 Job 会清理其 Pods。  
能证明：Job/Pod 编排状态；不能证明外部数据库、队列、API 已提交或 exactly-once。

**K8s-2 — Logging architecture**  
URL: https://kubernetes.io/docs/concepts/cluster-administration/logging/  
访问日期：2026-09-22；verified。  
窗口：本地容器日志受 restart、eviction、节点生命周期和 kubelet rotation 影响；默认 `containerLogMaxSize` 10 MiB、`containerLogMaxFiles` 5，`kubectl logs` 只提供最新日志文件；集群级长期保存需要独立 backend。  
能证明：本地日志的查询/轮转边界；不能证明读不到日志即未输出，也不能证明外部 backend 收到全部日志。

**K8s-3 — Auditing**  
URL: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/  
访问日期：2026-09-22；verified。  
窗口：API request 从 `RequestReceived` 至后续阶段，内容与阶段由 policy 决定；无 audit policy 时不记录；log backend 受轮转，webhook batching/throttling/retry/overflow 影响，buffer overflow 可丢事件。  
能证明：API 层审计事件及配置边界；不能证明控制器已收敛、容器业务完成或缺记录即未执行。

## Cross-platform synthesis

平台完成只能判定 `platform-complete`，不能直接升级为 `external-effect-confirmed`。审计证据应分为：

```text
E0 request emitted
→ E1 platform recorded
→ E2 platform/tool terminal state
→ E3 authoritative external read-back
→ E4 business postcondition
```

初始状态规则：客户端断流、平台 timeout、worker 断连、日志缺失、审计查询超时、对象已 TTL 删除或 Pod 已 eviction，均先标记 `UNKNOWN_NEEDS_RECONCILE`；不得将日志空白、平台失败或对象不存在直接解释为 `NOT_COMMITTED`。具体仓库/account/cluster 配置及任何 production 覆盖保持 unknown。
[CONTEXT OFFLOADED] Content (~1754 tokens, 5524 bytes) saved to: /var/minis/offloads/tools/file_write_20d599ff4869.txt
Use file_read tool to retrieve if needed.

## 逐源字段合规与保护边界（最终）
- 逐源完整字段不以内文缩写为准，以同目录 `source-matrix.md` 为准；共 28 个条目，均含完整 URL、访问日期 `2026-09-22`、证据窗口、状态分类、能证明/不能证明边界。
- 研究对象仅为公开官方/一手资料；未访问真实服务、账户或凭据；未声称 production 通过。
- 未访问或写入 shared/P0、事故目录、D10/L12/D14、canonical、140、tri-line、systemd。
