# 下一独立切片建议（S6）

## 题目
**幂等键与效果账本的跨平台可验证契约：从 UNKNOWN 到安全补偿的状态机**

## 为什么独立
S5 只建立 freshness/watermark/cursor/replay 的判定边界，没有测量或规定业务效果账本。S6 应只研究公开官方文档中的“请求 ID/幂等 token/重复请求冲突/状态查询/补偿”契约，不读取 S5 以外本地产物，不访问真实服务或凭据。

## 建议范围（官方一手）
- AWS Step Functions `StartExecution`、`DescribeExecution`、`GetExecutionHistory`：相同 name+input、关闭执行、ExecutionAlreadyExists、状态核对。
- Kubernetes API create/update/patch、UID/name、resourceVersion、preconditions 与冲突响应：仅研究 API 契约，不触碰集群。
- GitHub REST Actions rerun/cancel/delete 与 workflow run attempt：区分查询、触发、重跑和删除。
- Temporal Activity retry/idempotency/heartbeat/history 官方文档：明确 Activity 重试与外部效果记录的边界。

## 预期交付
1. 状态机：`NOT_SENT → SENT_UNKNOWN → CONFIRMED_ABSENT/CONFIRMED_PRESENT → COMPENSATED/MANUAL`。
2. 字段契约：`idempotency_key`、请求摘要、服务端 request/run ID、attempt、effect receipt、查询时间、冲突证据。
3. 决策表：何时 query-only、何时 safe retry、何时禁止重试、何时人工升级。
4. 每条结论标 `verified/inferred/unknown/conflicting`，并明确“服务端历史/状态 ≠ 外部效果”。

## 不应做
不得声称 production、exactly-once、零重复副作用；不得用博客或 SDK 经验替代官方文档；不得访问任何真实账户、集群、仓库、namespace、服务、凭据或已有 A 线目录。
