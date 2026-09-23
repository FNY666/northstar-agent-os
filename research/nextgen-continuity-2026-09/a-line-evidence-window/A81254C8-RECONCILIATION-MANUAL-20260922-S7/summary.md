# S7 摘要

## 核心判断

read-back 的证明对象是“同一资源、同一意图、同一版本/代次满足业务后置条件”，不是 HTTP 状态码。2xx、单次 query、单个 webhook、单个 callback heartbeat、单个 Kafka consumer offset 均不能单独证明外部效果，也不能据此声称 production、exactly-once 或无重复副作用。

## 证据结论

- **Stripe（VERIFIED）**：live webhook 最多三天指数退避重试；事件可能乱序；用 event ID 去重，不要用 created 排序；可 API 补取缺失对象；webhook 应快速 2xx。Event API 可按唯一 event ID 查询最近 30 天事件，并保留创建时 API 版本。
- **AWS EC2（VERIFIED）**：最终一致性会导致刚创建资源的 ID 尚未传播，Describe 可能暂时 NotFound；官方建议从数秒到数分钟指数退避，并在后续命令间继续等待。
- **Step Functions（VERIFIED）**：waitForTaskToken 只有原 token 的成功/失败回调才继续；HeartbeatSeconds 防止无限等待，但 heartbeat 是活性而非业务完成证据。
- **Temporal（VERIFIED）**：Activity heartbeat/timeout/retry 用于检测 worker/执行失败；retry 只再次执行 task，不等于外部效果确认。
- **HTTP RFC 9110/9111（VERIFIED）**：ETag/条件请求/304 属于表示验证；缓存有 freshness、Age、validation、stale、must-revalidate 语义。
- **Kafka（VERIFIED）**：事务和 offset 的 exactly-once 边界在 Kafka 链路内；外部系统副作用不自动纳入同一原子边界。

## 自动闸门

1. 保存 intent_id、tenant/account、resource_id、request/idempotency key、event_id、事件类型与版本、目标后置条件、observed ETag/版本、每次 query 时间/HTTP 状态/缓存信息、webhook 验签、offset 与重试历史。
2. 同 ID + 同版本/ETag + 后置条件匹配：确认并结束。
3. 404、旧状态或 webhook 先到：传播窗口内标记 UNKNOWN/PENDING_PROPAGATION，指数退避查询；不要立即补偿或把负结果永久缓存。
4. 资源未绑定、缓存无法 revalidate、webhook/read-back 同版本冲突、身份/租户可疑、预算耗尽、资金/权限/删除等高风险未知：冻结自动动作并人工升级。
5. 每个副作用重试均假设前次可能已生效；只使用 provider 明确支持的幂等机制，并在动作前 read-back。不得声称无重复副作用。

## 未知与冲突

官方资料没有给出跨平台统一最终一致性上界、统一 p99 或 Kafka-to-external 原子性。webhook 与 read-back 同资源同版本不一致时是 CONFLICT，不能简单“最后写入胜出”或继续重试；必须保留完整证据并人工对账。

完整分析见 `report.md`，逐源证据见 `sources.md`。