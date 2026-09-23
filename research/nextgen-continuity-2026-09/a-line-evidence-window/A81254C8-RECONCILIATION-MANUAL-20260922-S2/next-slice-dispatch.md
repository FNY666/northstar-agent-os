# 下一切片派发：reconciliation 关闭证据与补偿安全性

## 目标
在不访问真实服务、凭据或受限目录的前提下，继续研究：当外部结果未知时，哪些“查询证据”足以支持成功/失败关闭，补偿何时安全，人工审核如何处理冲突证据。

## 严格边界
- 只使用公开官方一手资料；优先 AWS、Temporal、Kubernetes、GitHub Actions、Stripe/Google Cloud 等官方文档中可公开访问的语义说明。
- 不读取任何本地研究目录或历史产物；不得访问 shared/P0、事故目录、D10、L12、D14、canonical、staging、140、tri-line、systemd、真实服务或凭据。
- 使用新的隔离目录，不复用本切片目录。
- 不声称 production、exactly-once 或任意供应商的端到端副作用保证。

## 要回答的单一问题
什么样的外部权威证据、稳定观察窗口、冲突处理和人工批准，才能使 reconciliation 从 UNKNOWN 安全转为 CONFIRMED_SUCCESS、CONFIRMED_FAILURE、COMPENSATED 或 CLOSED？

## 计划来源
1. AWS 官方：各服务关于 read-after-write / eventual consistency、API 幂等令牌、CloudTrail/EventBridge 交付和事件重复/乱序边界的文档。
2. Temporal 官方：Activity retry/heartbeat、workflow signals/queries、timeouts 与 idempotency 文档。
3. Kubernetes 官方：controller status conditions、generation/observedGeneration、finalizers 与 deletion/compensation 语义。
4. GitHub 官方：deployment status、environment protection、rerun/rollback 与 audit log 语义。

## 输出要求
生成 `report.md`、`sources.md`、`summary.md`、`research-manifest.json`、`SHA256SUMS`，并运行 evidence-first validator 与 `sha256sum -c SHA256SUMS`。每项结论标注 verified/inferred/unknown/conflict，并明确“日志存在不等于外部效果”。