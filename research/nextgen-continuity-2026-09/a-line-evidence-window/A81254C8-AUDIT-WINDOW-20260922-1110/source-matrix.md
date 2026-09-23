# Source compliance matrix — A线审计时间窗切片

访问日期统一为 **2026-09-22**。所有来源均为公开官方文档或官方源码；`verified` 表示来源直接支持的平台事实，`inferred` 表示跨来源设计推论，`unknown` 表示未由公开材料或本研究实例验证。

## 1–11

### 1. Temporal Events and Event History
- URL: https://docs.temporal.io/workflow-execution/event
- 日期/窗口: 2026-09-22；外部事件/Command 被 Service 处理→Event History 追加→History API/CLI 可读→Namespace retention/大小限制清理。
- 状态: verified（平台事件/append-only/durable）；unknown（具体 retention 与外部效果）。
- 能证明: Temporal 平台事件被记录，且在可读窗口内可用于平台审计/恢复。
- 不能证明: Activity 外部副作用、业务 postcondition、无事件即未发生。

### 2. GitHub Actions — workflow run logs
- URL: https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/using-workflow-run-logs
- 日期/窗口: 2026-09-22；run→job/step 日志生成、查看、搜索、下载；删除/保留取决于平台策略与对象状态。
- 状态: verified（日志入口）；unknown（具体 retention、完整覆盖）。
- 能证明: 可访问 run 的平台状态及 job/step 日志。
- 不能证明: 所有 runner/对端活动、外部目标状态、日志缺失即未执行。

### 3. AWS CloudTrail Event history
- URL: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html
- 日期/窗口: 2026-09-22；每 account/Region 最近 90 天 management events；单 Region/account 查询边界。
- 状态: verified（90天/Region/事件类别）；unknown（其他类别、窗口外、具体账户配置）。
- 能证明: 覆盖窗口内相应 AWS 控制面活动有事件记录。
- 不能证明: data/Insights/network events、其他 Region、90天外操作或业务最终状态。

### 4. AWS CloudTrail concepts
- URL: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html
- 日期/窗口: 2026-09-22；Event history→trail/Lake→目标存储，覆盖/保留由 selector 与配置决定。
- 状态: verified（能力边界）；unknown（具体账户是否启用）。
- 能证明: Event history、trail、Lake 是不同证据路径。
- 不能证明: 未核验账户已启用完整 multi-Region/data-event/长期采集。

### 5. AWS Step Functions CloudWatch Logs
- URL: https://docs.aws.amazon.com/step-functions/latest/dg/cw-logs.html
- 日期/窗口: 2026-09-22；Standard 原生 history；Express→CloudWatch Logs；log level、payload 截断、best-effort 交付影响可见窗口。
- 状态: verified（Standard/Express/日志交付边界）；unknown（具体 logging/retention）。
- 能证明: 编排/日志管道的记录能力与限制。
- 不能证明: CloudWatch 缺事件即未执行，或外部业务效果已提交。

### 6. AWS GetExecutionHistory API
- URL: https://docs.aws.amazon.com/step-functions/latest/apireference/API_GetExecutionHistory.html
- 日期/窗口: 2026-09-22；Standard execution history 的 API 查询窗口，分页等查询语义。
- 状态: verified（API 边界）；unknown（具体执行数据是否仍保留）。
- 能证明: 可按 API 读取服务端 execution history。
- 不能证明: 外部系统 read-back、业务 postcondition 或 Express 原生 history。

### 7. Kubernetes Jobs
- URL: https://kubernetes.io/docs/concepts/workloads/controllers/job/
- 日期/窗口: 2026-09-22；Job 创建→Pod 成功 completions/Failed；失败/删除 Pod 可触发替换，删除 Job 可清理 Pods。
- 状态: verified（controller 状态）；unknown（具体集群清理/日志配置）。
- 能证明: Job controller 认定的 Complete/Failed 与 Pod 编排状态。
- 不能证明: 外部数据库/API/队列提交、业务批次正确、exactly-once。

### 8. Kubernetes TTL-after-finished
- URL: https://kubernetes.io/docs/concepts/workloads/controllers/ttlafterfinished/
- 日期/窗口: 2026-09-22；Job Complete/Failed→TTL 计时→可级联删除；过期后更新 TTL 不保证保留。
- 状态: verified（TTL 机制）；unknown（实际集群是否启用）。
- 能证明: 对象被删除可解释为 TTL 造成的证据窗口结束。
- 不能证明: 对象不存在即未运行或外部效果不存在。

### 9. Kubernetes Auditing
- URL: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
- 日期/窗口: 2026-09-22；API request stages→audit policy→log/webhook backend；policy、rotation、batch、overflow 决定覆盖。
- 状态: verified（定义/配置依赖）；unknown（实际覆盖与保留）。
- 能证明: API 层审计事件的策略与 backend 边界。
- 不能证明: 审计缺失即无 API 请求、控制器已收敛或容器业务完成。

### 10. Temporal Event History encyclopedia
- URL: https://docs.temporal.io/encyclopedia/event-history/
- 日期/窗口: 2026-09-22；Workflow Command→Service Event→durable History→Replay/恢复。
- 状态: verified（平台恢复语义）；unknown（外部系统状态）。
- 能证明: 已持久化的 Workflow 状态转移可作为 Replay 输入。
- 不能证明: Replay 重新验证外部资源或重新执行已完成 Activity。


### 12. Temporal Visibility
- URL: https://docs.temporal.io/visibility
- 日期/窗口: 2026-09-22；状态变更→异步索引传播→List/Count/Search 可见；通常秒级但可更久且无 SLA；单实体 Describe 为权威路径。
- 状态: verified（eventual consistency）；unknown（具体延迟/实例配置）。
- 能证明: 搜索索引可能 stale，单实体需 read-back。
- 不能证明: 未找到即不存在、查询返回即最新外部状态。

### 13. Temporal History API source
- URL: https://raw.githubusercontent.com/temporalio/api/master/temporal/api/workflowservice/v1/request_response.proto
- 日期/窗口: 2026-09-22；History 请求→分页响应/next_page_token；可 wait_new_event；可标记 archived。
- 状态: verified（官方源码字段）；unknown（调用方是否遍历完分页）。
- 能证明: 单页不等于完整 History，客户端有明确续页机制。
- 不能证明: 外部效果、调用方已正确耗尽 token。

### 14. Temporal Retention
- URL: https://docs.temporal.io/temporal-service/temporal-server
- 日期/窗口: 2026-09-22；Workflow close→Namespace Retention→清理；最小1日，CLI 未设置时默认3日；可提前 delete，具体实例 unknown。
- 状态: verified（机制）；unknown（具体 Namespace）。
- 能证明: 闭合执行不是永久主存储证据。
- 不能证明: 具体部署保留时长或窗口内未被删除。

### 15. Temporal Archival
- URL: https://docs.temporal.io/temporal-service/archival
- 日期/窗口: 2026-09-22；close→异步 close-processing→归档；默认 delay 最多约5分钟且受 retention 约束；文档标 experimental。
- 状态: verified（机制）；unknown（实例启用/归档成功）。
- 能证明: 归档可成为延长保存路径，且不是关闭瞬间可用。
- 不能证明: 某部署已启用、归档成功或具备不可篡改性。

### 16. Temporal Activity timeouts/heartbeat
- URL: https://docs.temporal.io/develop/go/activities/timeouts
- 日期/窗口: 2026-09-22；最后已接收 Heartbeat→Heartbeat Timeout；可能 throttle；未 heartbeat 的 Activity 不依赖此机制接收取消。
- 状态: verified（平台边界）；unknown（外部副作用）。
- 能证明: 配置 timeout 后可形成 Activity liveness 发现边界。
- 不能证明: timeout 前没有外部请求或副作用。

### 17. Temporal Activity Execution
- URL: https://docs.temporal.io/activity-execution
- 日期/窗口: 2026-09-22；Task 丢失→Start-to-Close timeout→Retry Policy；不是即时 task-loss 检测。
- 状态: verified。
- 能证明: timeout/重试是平台处理路径。
- 不能证明: timeout 代表外部请求未到达。

### 18. Temporal Standalone Activity
- URL: https://docs.temporal.io/standalone-activity
- 日期/窗口: 2026-09-22；Activity execution/result→Namespace Retention；默认 at-least-once；无 Workflow History。
- 状态: verified。
- 能证明: result 可在保留窗口内查询，重试可能再次运行函数。
- 不能证明: Activity ID 等于外部幂等或副作用只发生一次。

### 19. Temporal Polling
- URL: https://docs.temporal.io/design-patterns/polling
- 日期/窗口: 2026-09-22；外部请求→按 interval/retry/deadline polling→目标状态 read-back。
- 状态: verified（模式）；unknown（外部 API 一致性）。
- 能证明: 应用可显式把外部 read-back 纳入完成判定。
- 不能证明: 任意外部服务返回状态都强一致。

### 20. Temporal Continue-As-New
- URL: https://docs.temporal.io/workflow-execution/continue-as-new
- 日期/窗口: 2026-09-22；旧 Run close/checkpoint→新 Run；同 Workflow ID、不同 Run ID、独立 History。
- 状态: verified。
- 能证明: 长任务审计需追踪 Run Chain。
- 不能证明: 单 Run History 覆盖整个 Workflow ID 生命周期。

### 21. GitHub Actions artifact
- URL: https://docs.github.com/en/actions/tutorials/store-and-share-data
- 日期/窗口: 2026-09-22；upload→artifact retention（受 repo/org/enterprise 上限）→download digest 校验；v4 artifact immutable。
- 状态: verified（平台机制）；unknown（具体仓库配置）。
- 能证明: 上传内容可在下载时做 SHA-256 一致性校验。
- 不能证明: 内容正确、外部系统已应用或永久保留。

### 22. GitHub Actions workflow syntax/skipped checks
- URL: https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax
- 日期/窗口: 2026-09-22；事件/过滤规则→可能 skipped→关联 check Pending；其他自动化仍可能改外部目标。
- 状态: verified（跳过语义）；inferred（外部效果不由该 check 决定）。
- 能证明: 未运行需区分过滤跳过与失败。
- 不能证明: Pending 或未运行即外部目标未变化。

### 23. AWS Step Functions service quotas
- URL: https://docs.aws.amazon.com/step-functions/latest/dg/service-quotas.html
- 日期/窗口: 2026-09-22；Standard execution→最多25,000 events→关闭后 history 默认90日（可申请30日）；Express 最长5分钟。
- 状态: verified（配额/保留）；unknown（具体账户调整）。
- 能证明: Standard history 有事件数与保留时间边界。
- 不能证明: 90日内具体历史必然存在或外部效果。

### 24. AWS Step Functions Task state
- URL: https://docs.aws.amazon.com/step-functions/latest/dg/state-task.html
- 日期/窗口: 2026-09-22；Task start→success/failure/TimeoutSeconds→平台状态；外部 async/最终一致性另行处理。
- 状态: verified（Task 语义）；inferred（成功不等于外部 postcondition）。
- 能证明: Task timeout/success/failure 是编排层状态。
- 不能证明: 外部资源已持久化、可读或已最终收敛。

### 25. AWS CloudTrail Lake
- URL: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake.html
- 日期/窗口: 2026-09-22；API call→事件交付（平均约5分钟但不保证）→selector 过滤→event data store retention（约7/10年选项）；query result 在 CloudTrail 最多7日可见。
- 状态: verified（官方机制）；unknown（实例 selector/retention）。
- 能证明: 查询窗口、事件数据保存窗口与交付延迟是不同边界。
- 不能证明: 缺事件即未发生或 CloudTrail 事件即资源最终状态。

### 26. Kubernetes Logging Architecture
- URL: https://kubernetes.io/docs/concepts/cluster-administration/logging/
- 日期/窗口: 2026-09-22；container stdout/stderr→kubelet rotation/Pod/node 生命周期→kubectl logs 最新文件；外部 backend 另行配置。
- 状态: verified（日志边界）；unknown（具体 cluster backend）。
- 能证明: `kubectl logs` 不是无限历史，eviction/rotation 会缩短窗口。
- 不能证明: 读不到日志即没有输出或未执行。

### 27. Kubernetes TTL-after-finished（补充实例）
- URL: https://kubernetes.io/docs/concepts/workloads/controllers/ttlafterfinished/
- 日期/窗口: 2026-09-22；Job Complete/Failed→TTL→级联删除；具体启用 unknown。
- 状态: verified（机制）。
- 能证明: 对象缺失可能是清理造成的证据窗口结束。
- 不能证明: 缺失即未执行或业务未提交。

### 28. Kubernetes Auditing（backend 细节）
- URL: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
- 日期/窗口: 2026-09-22；API request stages→policy→log/webhook；batch/backoff/overflow/rotation 影响交付与保留。
- 状态: verified（定义）；unknown（实际策略、backend、丢失情况）。
- 能证明: API 层审计覆盖受 policy/backend 限制，overflow 可丢事件。
- 不能证明: audit 缺失即无 API 动作或业务未完成。
[CONTEXT OFFLOADED] Content (~2331 tokens, 7576 bytes) saved to: /var/minis/offloads/tools/file_write_00e9d0c74b19.txt
Use file_read tool to retrieve if needed.