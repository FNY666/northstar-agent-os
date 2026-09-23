# 下一独立切片建议：S8｜供应商特定 read-back 合同与预算校准

## 目标
在不读取 A 线既有目录、不访问真实服务或凭据的前提下，继续一个与 S7 独立的公开官方研究切片：逐供应商抽取“资源状态字段、版本/ETag、幂等键、Retry-After、错误码、事件到对象映射、查询窗口、删除/取消语义”，用于把 S7 的通用闸门参数化。不得把本切片的建议写回其他目录。

## 只允许的公开官方一手资料
- Stripe：Idempotent requests、各目标资源 retrieve/update、Event Destinations/webhook delivery 与 API versioning 官方文档。
- AWS：EC2 API reference（Describe/Run/Modify 的错误与 request ID）、Retry behavior、服务 quotas/状态码官方文档。
- AWS Step Functions：API reference（SendTask*、HeartbeatSeconds、Retry/Catch 状态字段）。
- Temporal：官方 retry policy、Activity execution、failure converter/idempotency 相关文档。
- HTTP：RFC 9110/9111 中 If-Match/If-None-Match、412/409/428、Cache-Control、Retry-After 语义。
- Apache Kafka：官方 producer/consumer configs、transactions、read_committed、offset commit 与外部系统合作说明。

## 预设交付物
`report.md`、`sources.md`、`summary.md`、`research-manifest.json`、`SHA256SUMS`、`next-slice-dispatch.md`。每条声明继续使用 verified/inferred/unknown/conflict 四分法；运行 manifest validator 与 `sha256sum -c`。

## 关键问题
1. 哪些 provider 字段可作为“同一代次”硬绑定，哪些只是提示？
2. Retry-After、429、5xx、网络超时在各官方合同中的优先级如何？
3. 何时可安全重放幂等写，何时必须先 query/人工升级？
4. 删除、取消、退款等负向效果如何区分“未生效”“已生效但未传播”“对象已不存在”？
5. 如何从官方公开信息定义最小证据包，而不声称 exactly-once 或无重复副作用？

## 成功标准
形成 provider-by-provider 参数表与冲突矩阵；所有数值预算标注来源或标为系统推断；明确禁止把 2xx、单次 query、单 webhook、单 offset 当独立完成证据。