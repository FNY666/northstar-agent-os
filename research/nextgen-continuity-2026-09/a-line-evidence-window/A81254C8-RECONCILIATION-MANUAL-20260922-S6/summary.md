# S6 摘要

## 一句话结论

幂等键只解决“重复请求如何识别/处理”的一部分；安全闭环必须把**业务意图、参数指纹、平台回执、外部效果账本、read-back、补偿和人工决策**分开记录，并将超时/失联先视为 `UNKNOWN`，不可直接重放或宣称未生效。

## 已验证（verified）

- Stripe：同一 key 保存首次 status/body（成功或失败，含 500）并重放；参数变更报错；至少 24h 后可能清理，清理后复用是新请求；执行尚未开始的校验失败/并发冲突不保存结果。
- AWS EC2：client token + 相同参数重试不再执行；参数变更返回 `IdempotentParameterMismatch`；Regional/Zonal 作用域不同。
- RFC 9110：幂等是相同请求的预期服务器效果相同；允许服务器逐次有日志等副作用；连接失败后可重试真正幂等方法。
- Temporal：Activity 失败自动按 Retry Policy 重试；Heartbeat detail 可为下一次 attempt 提供 checkpoint；官方建议 Activity 幂等。
- Step Functions：callback/task token 等待外部/人工；heartbeat 超时会失败，task token 超时后会生成新 token。
- Kafka：producer 网络错误无法知道提交前后；Kafka 内特定事务拓扑可 exactly-once，外部系统通常需要合作，否则默认 at-least-once。

## 核心推论（inferred）

状态路径：`NEW → RECORDED_PENDING → PLATFORM_ACKED / UNKNOWN`；`UNKNOWN → read-back → EFFECT_CONFIRMED | NOT_APPLIED | MANUAL_REVIEW`。确认外部效果后若需要撤销/修复，创建新 compensation intent/key，并再次 read-back。相同 key 的参数冲突永不覆盖原意图。

## 必须保持未知（unknown）

跨供应商 key 的永久保留、统一指纹算法、read-back 一致性/等待阈值、效果账本标准 schema、人工 SLA 与证据留存没有被上述官方一手资料统一规定。

## 绝对边界

幂等键、效果账本、平台成功回执都不能单独证明 exactly-once 或外部效果；本切片不声称 production。

详见 `report.md` 和 `sources.md`。
