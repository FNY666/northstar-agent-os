# Sources — A线审计时间窗切片

访问日期统一：2026-09-22。以下均为公开官方一手资料；原始抓取副本位于本目录 `raw/`，但 `raw/` 为研究过程材料，不作为结论的唯一依据。

1. Temporal Documentation — Events and Event History
   URL: https://docs.temporal.io/workflow-execution/event
   窗口：服务端事件追加到 Workflow Event History；完整 history 覆盖 execution 生命周期，但受事件数量/大小限制；本页未给统一天数 retention。
   级别：verified（平台事件/持久 history 语义）；unknown（具体 namespace retention、外部效果）。

2. GitHub Documentation — Viewing logs to diagnose failures
   URL: https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/using-workflow-run-logs
   窗口：run/job/step 日志的查看、搜索、下载；固定 retention 数值与实际仓库策略不由本次页面核验，标 unknown。
   级别：verified（日志操作入口）；unknown（实际覆盖、删除/保留配置、外部 postcondition）。

3. AWS CloudTrail User Guide — Working with CloudTrail event history
   URL: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html
   窗口：每个 AWS Region 最近 90 天 management events；可查看、搜索、下载、不可变；不等于 data events/全 Region/无限期覆盖。
   级别：verified。

4. AWS CloudTrail User Guide — CloudTrail concepts
   URL: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html
   窗口：Event history、trails、S3、CloudWatch Logs、EventBridge、Lake event data store 的能力与保存路径不同；实际启用需配置验证。
   级别：verified（概念）；unknown（具体账户配置）。

5. AWS Step Functions Developer Guide — Using CloudWatch Logs to log execution history
   URL: https://docs.aws.amazon.com/step-functions/latest/dg/cw-logs.html
   窗口：Standard Workflows 记录 execution history；Express Workflows 不在 Step Functions 中记录 execution history，需 CloudWatch Logs；log group retention/采集级别需实际配置。
   级别：verified。

6. AWS Step Functions API Reference — GetExecutionHistory
   URL: https://docs.aws.amazon.com/step-functions/latest/apireference/API_GetExecutionHistory.html
   窗口：读取 execution history 的 API，具分页等查询语义；不是外部效果 read-back。
   级别：verified（API 边界）。

7. Kubernetes Documentation — Jobs
   URL: https://kubernetes.io/docs/concepts/workloads/controllers/job/
   窗口：Job controller 追踪一次性任务至 Complete/Failed；对象与 Pod/log 可查询窗口受集群清理和后端策略影响。
   级别：verified（Job 状态语义）；unknown（实际集群配置）。

8. Kubernetes Documentation — Automatic Cleanup for Finished Jobs
   URL: https://kubernetes.io/docs/concepts/workloads/controllers/ttlafterfinished/
   窗口：Job status 变 Complete/Failed 后 TTL 计时；到期可级联删除；过期后成功更新 TTL 也不保证保留。
   级别：verified。

9. Kubernetes Documentation — Auditing
   URL: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
   窗口：API server audit policy/backend 决定哪些 API 活动被记录及送往何处；实际 retention/coverage/configuration unknown，未接入真实集群。
   级别：verified（定义与配置边界）；unknown（实例状态）。

## Source-matrix index

The file `source-matrix.md` is the per-source compliance matrix for all 28 cited first-party sources. Each entry includes: complete URL, access date 2026-09-22, evidence window, verified/inferred/unknown classification, and explicit can-prove/cannot-prove boundaries.



10. Temporal — Event History
   URL: https://docs.temporal.io/encyclopedia/event-history/
   原始 Markdown: https://docs.temporal.io/encyclopedia/event-history.md
   窗口：Command→Service Event→Replay；证明平台状态转移可恢复，不证明外部提交。
   级别：verified；外部效果 unknown。

11. Temporal CLI workflow command reference
   URL: https://docs.temporal.io/cli/command-reference/workflow
   原始 Markdown: https://docs.temporal.io/cli/command-reference/workflow.md
   窗口：execute 阻塞至平台完成，show/follow 读取或跟随 History；CLI 本地断流、重连完整性 unknown。
   级别：verified。

12. Temporal Visibility
   URL: https://docs.temporal.io/visibility
   原始 Markdown: https://docs.temporal.io/visibility.md
   窗口：Visibility 异步传播，可数秒或更久，无固定 SLA；单实体使用 Describe。
   级别：verified。

13. Temporal Workflow Service API source
   URL: https://raw.githubusercontent.com/temporalio/api/master/temporal/api/workflowservice/v1/request_response.proto
   窗口：History 支持 wait_new_event、next_page_token、archived/skip_archival；单页不等于完整读取。
   级别：verified（一手官方源码）。

14. Temporal Server / Retention
   URL: https://docs.temporal.io/temporal-service/temporal-server
   原始 Markdown: https://docs.temporal.io/temporal-service/temporal-server.md
   窗口：闭合 Workflow 按 Namespace Retention 清理；最小1天，CLI未设置时默认3天；可提前删除；具体部署 unknown。
   级别：verified。

15. Temporal Archival
   URL: https://docs.temporal.io/temporal-service/archival
   原始 Markdown: https://docs.temporal.io/temporal-service/archival.md
   窗口：关闭后异步归档，默认延迟最多约5分钟，受 retention 约束；实验性；是否启用/成功 unknown。
   级别：verified（机制）；生产配置 unknown。

16. Temporal Activity timeouts / heartbeat
   URL: https://docs.temporal.io/develop/go/activities/timeouts
   原始 Markdown: https://docs.temporal.io/develop/go/activities/timeouts.md
   窗口：最后服务端收到 Heartbeat→Heartbeat Timeout；heartbeat 可能节流；未 heartbeat 的 Activity不能依靠 heartbeat 收取消。
   级别：verified；外部副作用状态 unknown。

17. Temporal Activity Execution
   URL: https://docs.temporal.io/activity-execution
   原始 Markdown: https://docs.temporal.io/activity-execution.md
   窗口：task loss 依赖 Start-to-Close timeout 发现；超时后按 Retry Policy 重试。
   级别：verified。

18. Temporal Standalone Activity
   URL: https://docs.temporal.io/standalone-activity
   原始 Markdown: https://docs.temporal.io/standalone-activity.md
   窗口：无 Workflow History；执行/result 受 Namespace Retention；默认 at-least-once，Activity ID 不替代业务幂等。
   级别：verified。

19. Temporal Polling External Services
   URL: https://docs.temporal.io/design-patterns/polling
   原始 Markdown: https://docs.temporal.io/design-patterns/polling.md
   窗口：应用按 polling interval、timeout、retry、deadline 读取外部目标；read-back 是独立证据层。
   级别：verified（模式）；外部 API 一致性 unknown。

20. Temporal Continue-As-New
   URL: https://docs.temporal.io/workflow-execution/continue-as-new
   原始 Markdown: https://docs.temporal.io/workflow-execution/continue-as-new.md
   窗口：同 Workflow ID、不同 Run ID、独立 History；必须追踪 Run Chain。
   级别：verified。

完整补充摘录与逐项“能证明/不能证明”说明见 `temporal-addendum.md`。


## 外部回调来源补充（访问日期均为 2026-09-22）

21. GitHub Actions — Using workflow run logs  
URL: https://docs.github.com/en/actions/how-tos/monitor-workflows/use-workflow-run-logs  
窗口：run/job/step 查询；partial re-run archive 可能只含重跑 jobs；日志可删除，固定永久保留 unknown。verified；外部效果 unknown。

22. GitHub Actions — Store and share data with workflow artifacts  
URL: https://docs.github.com/en/actions/tutorials/store-and-share-data  
窗口：artifact `retention-days` 受 repository/organization/enterprise 上限；v4 immutable；SHA-256 digest 上传/下载校验。verified；语义正确性和外部应用 unknown。

23. GitHub Actions — Workflow syntax  
URL: https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax  
窗口：filters 可使 workflow skipped，associated check 保持 Pending。verified；Pending 不等于执行失败或外部未变化。

24. AWS Step Functions — CloudWatch Logs execution history  
URL: https://docs.aws.amazon.com/step-functions/latest/dg/cw-logs.html  
窗口：Standard 原生 history；Express 依赖 CloudWatch；日志 best-effort，完整性/及时性不保证；级别与 payload 截断影响覆盖。verified。

25. AWS Step Functions — Service quotas  
URL: https://docs.aws.amazon.com/step-functions/latest/dg/service-quotas.html  
窗口：Standard 25,000 events、关闭后默认90天 history（可申请30天）、最长1年；Express最长5分钟。verified。

26. AWS Step Functions — Task workflow state  
URL: https://docs.aws.amazon.com/step-functions/latest/dg/state-task.html  
窗口：Task 启动到 success/failure/`States.Timeout`；协议终态不等于外部 read-back。verified。

27. AWS CloudTrail — Working with event history  
URL: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html  
窗口：每 account/Region 最近90天 management events；不含 data/Insights/network events；查询有账户/Region/filter边界。verified。

28. AWS CloudTrail Lake  
URL: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake.html  
窗口：event data store 最长约2557/3653天（选项决定）；selector 决定持久化覆盖；query result 在 CloudTrail 最多7天，可导出S3；交付平均约5分钟但不保证。verified。

29. Kubernetes — Jobs  
URL: https://kubernetes.io/docs/concepts/workloads/controllers/job/  
窗口：Job 创建至 successful completions/Failed；失败或删除 Pod 可替换重试；删除 Job 清理 Pods。verified；外部效果 unknown。

30. Kubernetes — Logging Architecture  
URL: https://kubernetes.io/docs/concepts/cluster-administration/logging/  
窗口：容器重启、eviction、节点生命周期、kubelet rotation；默认10MiB×5，`kubectl logs`仅最新日志文件；长期保存需外部 backend。verified。

31. Kubernetes — Auditing  
URL: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/  
窗口：policy 决定审计级别/阶段；无 policy 不记录；backend 轮转、batch/throttle/retry，webhook buffer overflow 可丢事件。verified；实际配置 unknown。

统一判定：平台记录/平台终态不能直接证明外部业务效果；日志缺失、timeout、断流、TTL/eviction 后不可查询均先 `UNKNOWN_NEEDS_RECONCILE`。
[CONTEXT OFFLOADED] Content (~1228 tokens, 3903 bytes) saved to: /tmp/A81254C8-AUDIT-WINDOW-20260922-1110/sources.md
Use file_read tool to retrieve if needed.
## Completeness and protection statement
- The per-source matrix is `source-matrix.md`; all 28 entries have complete URL, access date 2026-09-22, evidence window, status, and proof boundaries.
- Research was limited to public first-party documentation/source URLs. No production claim is made.
- No shared/P0, incident directories, D10/L12/D14, canonical, 140, tri-line, systemd, real service, or credential was accessed or modified.
