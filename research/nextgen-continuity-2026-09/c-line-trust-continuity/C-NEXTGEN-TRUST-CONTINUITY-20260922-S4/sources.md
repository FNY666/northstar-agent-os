# S4 官方一手来源

访问日期：2026-09-22。以下均为公开官方文档；页面未声明发布日期时不猜测。

1. Kubernetes — API Concepts（Kubernetes 官方）
   URL: https://kubernetes.io/docs/reference/using-api/api-concepts/
   直接证据：`resourceVersion` 表示底层持久化层保存的对象版本；PUT 应携带读到的版本；若版本已变，API server 检测 lost update 并返回 409 Conflict；watch 历史版本可能不可用并返回 410 Gone。
   用途：K1、K2；tier=primary；访问 2026-09-22。

2. Kubernetes — Server-Side Apply（Kubernetes 官方）
   URL: https://kubernetes.io/docs/reference/using-api/server-side-apply/
   直接证据：不同 field manager 改变另一 manager 所拥有的字段会 conflict；Apply 冲突默认拒绝；`force` 可覆盖并转移 ownership；字段管理信息在 `managedFields`。
   用途：K3；tier=primary；访问 2026-09-22。

3. Amazon S3 — Add preconditions to S3 operations with conditional requests（Amazon Web Services 官方）
   URL: https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-requests.html
   直接证据：条件读可按 ETag 限制特定对象版本；条件写可在更新前检查 ETag 未改变、避免无意覆盖；条件读/写/删在条件不满足时失败。
   用途：K4；tier=primary；访问 2026-09-22。

4. Google Cloud Storage — Object metadata（Google Cloud 官方）
   URL: https://cloud.google.com/storage/docs/metadata#generation-number
   直接证据：每对象有数字 generation 和 metageneration；generation 标识对象版本且同名替换对象获得不同 generation；metageneration 标识该 generation 的元数据版本。
   用途：G1；tier=primary；访问 2026-09-22（页面重定向至 docs.cloud.google.com，内容为 Google Cloud 官方）。

5. Google Cloud Storage — Request preconditions（Google Cloud 官方）
   URL: https://cloud.google.com/storage/docs/request-preconditions
   直接证据：`ifGenerationMatch`/`ifMetagenerationMatch` 匹配才继续，不匹配返回 412；generation-match=0 仅在当前不存在对象时允许；官方示例用读取的 generation 防止删除错误世代、用 0 限制重复上传竞态。
   用途：G2、G3；tier=primary；访问 2026-09-22。

6. Microsoft Learn — Specifying conditional headers for Blob service operations（Microsoft 官方）
   URL: https://learn.microsoft.com/en-us/rest/api/storageservices/specifying-conditional-headers-for-blob-service-operations
   直接证据：`If-Match` 仅在 ETag 相等时执行；`If-None-Match` 仅在不相等时执行；不满足条件时使用 412 Precondition Failed（按操作/条件组合的 HTTP 规则）。
   用途：A1；tier=primary；访问 2026-09-22。

7. Microsoft Learn — Lease Blob（Microsoft 官方）
   URL: https://learn.microsoft.com/en-us/rest/api/storageservices/lease-blob
   直接证据：lease 管理 blob 写/删锁；时长 15–60 秒或无限；写入需活动 lease ID；缺失/错误 lease ID 的受保护写入失败 412；支持 acquire/renew/change/release/break；break 后不能 renew，过期与状态转移有明确限制。
   用途：A2、A3；tier=primary；访问 2026-09-22。

8. Amazon EC2 — Ensuring idempotency in Amazon EC2 API requests（Amazon Web Services 官方）
   URL: https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html
   直接证据：client token 是最多 64 ASCII 字符的区分大小写字符串；同 token、同参数的成功重试不执行进一步动作；参数变化报 `IdempotentParameterMismatch`；幂等范围可为 Region 或 Availability Zone。
   用途：E1、E2；tier=primary；访问 2026-09-22。

## 访问与可复核说明

- 本切片通过官方网页正文读取并记录了上述直接证据；未依赖搜索结果摘要或第三方转载。
- 未把页面未声明的发布日期写成日期。
- 本文件不包含凭据、cookie、私有 URL 或本地既有研究产物内容。
