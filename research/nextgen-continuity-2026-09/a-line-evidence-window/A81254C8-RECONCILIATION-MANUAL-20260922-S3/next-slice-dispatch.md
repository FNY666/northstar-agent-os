# 下一独立切片建议：S4

## 建议主题
**Evidence envelope 与 reconciliation 状态机的可执行数据契约**：定义 correlation/idempotency key、attempt、version/generation、observed_at/event_time、source freshness、空查询语义、冲突类型、人工批准记录与关单证据的最小 schema；研究如何让审计、read-back、补偿和 reviewer 决策可关联而不越权。

## 为什么独立
S3 只研究控制判断和关闭门槛，没有针对任一平台或业务实现字段 schema，也没有评估事件排序、分页、跨区域、权限错误与读模型延迟如何进入证据包。S4 不应读取 S3 之外的本地历史目录、真实服务或凭据。

## 建议公开官方范围
- AWS CloudTrail event record 与 Step Functions execution history 官方文档；
- Temporal workflow/activity history、signals/query 官方文档；
- Kubernetes API object `resourceVersion`、conditions、Events/Audit 官方文档；
- GitHub Actions run/deployment/environment protection 官方文档。

## 交付物与验证
沿用全新隔离目录；交付 `report.md`、`sources.md`、`summary.md`、`research-manifest.json`、`SHA256SUMS`、下一切片 dispatch；逐条标注 VERIFIED/INFERRED/UNKNOWN/CONFLICT；执行 manifest validator 与 `sha256sum -c SHA256SUMS`。不得把 schema 完整性误报为外部效果证明。

## 首要问题
1. 最小证据 envelope 如何表示“请求已接受但效果未知”？
2. 如何用版本与事件时间区分旧 read-back、缓存和真正冲突？
3. 哪些字段缺失必须自动升级人工审核？
4. 关闭记录如何证明曾经观察过窗口且没有把空结果误读为不存在？
