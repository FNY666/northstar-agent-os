# S8 摘要

## 直接结论

[verified] 供应商的“接受请求”与“对象已达到目标状态”是不同事实：Stripe 明确把 webhook 快速 2xx 与异步处理分开；AWS EC2 明确 mutating request 可能在异步工作完成前返回；Step Functions callback 需等 task token；Temporal 默认重试 Activity；Kafka offset/事务只覆盖 Kafka 语义。

[inferred] 通用 reconciliation 闸门应至少保存：供应商 request ID、业务/幂等键、对象 ID、事件 ID+type+对象 ID、原生版本（若有）、观察状态、attempt、退避/窗口和独立外部效果证据。其阶段为 `accepted → observed → settled → external_effect_committed`。

[verified] Stripe：POST 用 Idempotency-Key（最长 255，至少 24h 后可能清理）；Webhook 事件可能重复/乱序，需 event ID 去重并可 retrieve 对象；生产失败投递尽量重试三天。 [unknown] 通用 Retry-After、资源 ETag、统一状态/删除语义未在本切片确认。

[verified] EC2：ClientToken 最长 64 ASCII；同 token 同参数重试不再执行，参数变化报 IdempotentParameterMismatch；RunInstances 幂等域可按 Region/AZ。 [unknown] 通用 Retry-After、ETag、统一 Describe 窗口未确认。

[verified] Step Functions：Retry/Catch 基于大小写敏感错误名；Heartbeat/Timeout 是显式失败边界；.waitForTaskToken 通过 SendTaskSuccess/Failure 回调，取消可能 best-effort。 [unknown] token 重复回调的通用业务幂等语义未确认。

[verified] Temporal：Activity 默认指数退避重试（1s、2.0、最大 100×、attempts 默认无限），Workflow 默认不重试；外部 Activity 应自行设计业务幂等。 [unknown] Temporal 不提供第三方资源 ETag/删除语义。

[verified] RFC：If-Match/If-None-Match、412/409 可作为 HTTP 条件层；428 来自 RFC 6585；Cache-Control 属 RFC 9111。 [inferred] vendor 未声明支持时不得强加这些字段。

[verified] Kafka：producer 幂等/transactions/read_committed/offset 是 Kafka 内部语义；外部副作用需额外合作。 [inferred] 单 offset 绝不是外部完成证明；不声称 exactly-once 或零重复副作用。

## 预算校准

[inferred] 预算按 read、mutation、event delivery、window、external effect、manual review 六类计数；重试预算须包含供应商和客户端两侧 attempt、read-back 次数与事件重投递。所有未由官方文档给出的金额、秒数、SLA 均为 unknown 或系统推断。

## 禁止过度证明

[inferred] 不把 2xx、单次 query、单 webhook、单 offset 当独立完成证据；不声称 production、exactly-once 或无重复副作用。

详表与引用：[report.md](report.md)；来源：[sources.md](sources.md)。
