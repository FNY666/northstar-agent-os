# Summary

## 一句话结论
Temporal、Kubernetes Job/Pod、AWS Step Functions 都能提供可关联的平台执行证据，但平台回执只回答“编排/工作负载控制面记录了什么”，不回答外部副作用是否 committed；超时、取消、worker 崩溃、陈旧/缺失日志时必须保留 `external_effect=unknown`，再用外部系统自己的 receipt 或幂等查询 reconciliation。

## 最重要的官方证据

- Temporal Event History 记录 Activity scheduled/started/completed/failed/timed out/cancel 及关联 ID，并有 attempt；Temporal 官方明确 worker 在完成 Activity 后、通知 service 前崩溃时，History 不显示成功且 Activity 会 retry——这是“外部可能已发生、平台 completion 缺失”的直接证据。
- Kubernetes Job 会创建并重试 Pods，Job conditions/status 描述控制面判断；Kubernetes Event 官方明确有限保留、best-effort、supplemental，不能当最终 receipt。
- Step Functions `StartExecution` 返回 execution ARN，Standard name+input 幂等；`GetExecutionHistory` 提供事件列表，`DescribeExecution` 明确 eventually consistent；Redrive 保持原 execution ARN 并保留成功步骤；CloudWatch log delivery best effort。

## 操作性规则

1. 平台状态与外部效果分开存储：`platform_receipt` 和 `external_effect` 两轴。
2. `Completed`、Job `Complete`、Step Functions `SUCCEEDED` 只能证明平台层，不自动推出 `committed`。
3. `Failed`、`TimedOut`、`Canceled`、日志缺失、平台读数陈旧，也不自动推出 `not_committed`。
4. 稳定关联键：Temporal Workflow ID + Activity ID（attempt 为平台尝试号）；Kubernetes Job UID + Pod UID + resourceVersion/conditions；Step Functions execution ARN + history event id/type/timestamp。
5. 进入 retry/redrive 前，以同一外部幂等键向外部目标查询；确认提交/去重命中才设 `committed`，明确拒绝且排除执行才设 `not_committed`，其余保持 `unknown`。

## 覆盖限制

仅公开官方一手文档；访问日期 2026-09-22。未做任何真实服务调用，未将 benchmark 或生产报告作为证据。官方平台文档不可能替代外部目标自身的提交语义，因此“外部 committed”在没有该 receipt 时保持 unknown。
