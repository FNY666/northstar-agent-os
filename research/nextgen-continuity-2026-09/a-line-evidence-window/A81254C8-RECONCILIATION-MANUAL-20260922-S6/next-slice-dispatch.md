# 下一独立切片建议（S7）

## 题目
**效果 read-back 的证据新鲜度与补偿闸门：跨平台最终一致、事件延迟和人工升级的可验证测试契约**

## 为什么独立
S6 已确定：幂等键/平台回执不等于外部效果，`UNKNOWN` 必须先查询；但官方资料没有统一定义 read-back 的等待窗口、证据新鲜度、负结果缓存和人工 SLA。S7 应只研究这一缺口，不重复 S6 的 key 生命周期。

## 公开一手资料优先
1. Stripe：对象查询、webhook/event delivery、resource 状态字段的官方文档。
2. AWS：EC2 eventual consistency、Describe/read-after-write、Step Functions callback/heartbeat 与服务 API 查询语义。
3. Temporal：Activity heartbeat、timeouts、retry policy、failure detection 官方文档。
4. HTTP RFC 9110 及相关 RFC：缓存、条件请求、ETag/If-Match、重试语义。
5. Kafka：transactions、consumer offsets、read_committed、Kafka Connect 外部系统合作约束。

## 要回答的单一问题
给定一个 `UNKNOWN` 效果，什么可观测证据（查询结果、事件、版本/ETag、供应商资源 ID、时间窗）足以把它转为 `EFFECT_CONFIRMED`、`NOT_APPLIED` 或 `MANUAL_REVIEW`？

## 交付要求
- 逐条标 `verified/inferred/unknown/conflict`。
- 设计证据 freshness、查询重试上限、负结果保护、事件与 read-back 不一致时的升级规则。
- 明确不得把 2xx、单次 query、单个 webhook 或 consumer offset 单独当作外部效果证明。
- 只用官方公开一手资料；新建独立目录，不读取既有 A 线目录及受限目录。
- 运行 research manifest validator 与 `sha256sum -c SHA256SUMS`，在报告中保留完整输出。
