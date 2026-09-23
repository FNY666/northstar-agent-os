# S5 官方一手来源

访问日期：2026-09-22。以下均为公开官方页面；页面内容可能随官方更新，报告中的直接支持按访问时版本记录。

1. Kubernetes Authors, **Leases**（Kubernetes Documentation，updated 2026-03-31）  
   URL: https://kubernetes.io/docs/concepts/architecture/leases/  
   支持：Lease 用于节点 heartbeat 与 leader election；kubelet heartbeat 更新 `spec.renewTime`，控制面据此判断 Node availability。范围边界：availability/coordination，不是进程终止或 effect 回滚。

2. Kubernetes Authors, **Kubernetes API Concepts — Resource versions / updates**  
   URL: https://kubernetes.io/docs/reference/using-api/api-concepts/  
   支持：stale `resourceVersion` 会导致 API server 返回 `409 Conflict`；官方建议用条件 `resourceVersion` 检测 lost updates，并处理冲突重试。范围边界：条件资源更新，不是外部副作用完成证明。

3. Temporal Technologies, **Detecting Activity failures**  
   URL: https://docs.temporal.io/encyclopedia/detecting-activity-failures  
   支持：Activity 的 Schedule-To-Start、Start-To-Close、Schedule-To-Close、Heartbeat timeout；Temporal Server 不直接检测 worker 失联/崩溃，而依赖 Start-To-Close timeout 触发 retry。范围边界：Activity 调度/失败检测；不提供任意外部 API effect exactly-once。

4. Temporal Technologies, **Activity Execution**  
   URL: https://docs.temporal.io/activity-execution  
   支持：task 可能在 delivery 或 Activity function 已调用后 worker 崩溃而丢失；timeout 后按 retry policy 重试；Activity task either runs or timeouts 的调度语义。范围边界：不等于外部 effect 未发生。

5. AWS, **Discover service integration patterns in Step Functions**  
   URL: https://docs.aws.amazon.com/step-functions/latest/dg/connect-to-resource.html  
   支持：Request Response、Run a Job (`.sync`)、Wait for Callback with Task Token；`.sync` 中止时 Step Functions 对任务做 best-effort cancel，可能因权限或临时服务中断无法取消。范围边界：不能将停止/取消当作外部任务已停止。

6. AWS, **StopExecution API Reference**  
   URL: https://docs.aws.amazon.com/step-functions/latest/apireference/API_StopExecution.html  
   支持：`StopExecution` stops an execution；不支持 EXPRESS state machines。范围边界：execution 控制 API，不是外部 effect 回滚或 exactly-once 证明。

7. Microsoft, **Lease Blob (REST API)**（Microsoft Learn）  
   URL: https://learn.microsoft.com/en-us/rest/api/storageservices/lease-blob  
   支持：acquire/renew/change/release/break；renew 要求匹配 lease ID，某些条件下过期 lease 仍可 renew；leased blob 写缺失 lease ID 时返回 `412 Precondition Failed`；GET 与容器操作有不同规则。范围边界：Blob lease/写条件，不覆盖所有资源入口，也不是业务 effect 完成证明。

## 来源使用说明

- 仅使用上述官方一手资料；未引用博客、论坛、搜索摘要或本地既有 C 线产物。
- “UNKNOWN”“旧 worker 可能仍运行”“资源 CAS 不等于 effect 完成/Exactly-once”是对官方边界的协议化推断，报告中逐项标注，不冒充平台直接保证。
- 未发现上述同一官方来源对核心语义的直接冲突；平台之间是范围差异，未合并为统一强保证。
