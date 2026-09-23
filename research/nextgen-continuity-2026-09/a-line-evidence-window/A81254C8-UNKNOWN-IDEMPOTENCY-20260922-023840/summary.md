# 摘要

## 核心发现

- 取消是控制平面请求，不是外部世界撤销证明；平台最终状态和外部副作用状态必须分离。
- 超时、断连、Worker 崩溃、无最终 receipt 默认进入 UNKNOWN；只有独立 read-back 证明 absent 或 committed 后才能收敛。
- 重试依据是显式错误分类 + 目标服务幂等契约。Temporal 提供 retry/error taxonomy/heartbeat/replay，但要求 Activity 幂等；Stripe 给出明确 key→首次结果契约；DynamoDB 条件写可防止覆盖和重复更新。
- 补偿不是回滚。只对已确认 committed 且可逆的步骤做幂等补偿；UNKNOWN 禁止盲反向操作。
- Claude Code 的公开 CLI 文档证明恢复/继续命令存在，未证明任意工具调用 exactly-once 或自动 reconcile；SWE-bench 仅是 benchmark，不能外推生产可靠性。

## 推荐状态

`REQUESTED_CANCEL` → `CANCEL_ACKED` → `RECONCILE_REQUIRED` → `COMMITTED | ABSENT | AMBIGUOUS`。平台回执单独记录；外部事实必须独立查询。AMBIGUOUS 保持 UNKNOWN，退避、告警并人工介入。

## 下一切片

Agent runtime 的 lease/租约过期、心跳与 fencing token：防止 Worker 重启后旧执行者继续写入。范围仍限公开 Temporal、Kubernetes、AWS Step Functions 等官方资料，不重复本片。
