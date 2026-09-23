# S7 sources（仅官方一手资料）

访问日期：2026-09-22。以下 URL 为公开官方文档；报告中的 verified 仅指文档直接支持的边界事实，不把平台文档扩展成业务 fencing 保证。

1. **Kubernetes — API Concepts**
   - URL: https://kubernetes.io/docs/reference/using-api/api-concepts/
   - Publisher: Kubernetes project
   - 直接证据：对象 `metadata.resourceVersion` 表示持久化层版本，可用于 watch/change tracking；提供过期 resourceVersion 的更新会得到 `409 Conflict`；需要有效检测 lost updates 的客户端应使用 resourceVersion 条件并处理重试；dry-run 不持久化且无其他 side effects。
   - 状态：verified（上述事实）；“因此外部旧副作用不存在”不支持，unknown/inferred。

2. **Amazon S3 User Guide — Add preconditions to S3 operations with conditional requests**
   - URL: https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-requests.html
   - Publisher: Amazon Web Services
   - 直接证据：条件 header 不满足会使 S3 操作失败；ETag 可用于条件读、复制和条件写，避免意外覆盖。
   - 状态：verified。

3. **Amazon S3 API Reference — PutObject**
   - URL: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html
   - Publisher: Amazon Web Services
   - 直接证据：`If-None-Match: *` 在 key 已存在时返回 `412 Precondition Failed`；上传期间发生 conflicting operation 时返回 `409 ConditionalRequestConflict`，文档明确建议 retry；S3 versioning 并发写可能保存多个版本。
   - 状态：verified；具体语义受 API/存储类型和条件影响。

4. **Google Cloud Storage — Object metadata / Generations and preconditions**
   - URL: https://cloud.google.com/storage/docs/generations-preconditions
   - Publisher: Google Cloud
   - 直接证据：generation 标识对象版本；metageneration 对同一 generation 的 metadata 更新递增，不能脱离 generation 比较；precondition 不满足时请求失败，避免作用于意外版本。
   - 状态：verified。

5. **Azure Blob Storage — Concurrency control**
   - URL: https://learn.microsoft.com/en-us/azure/storage/blobs/concurrency-manage
   - Publisher: Microsoft
   - 直接证据：Blob ETag 每次写更新；`If-Match` 不相等返回 HTTP 412，客户端应重新获取内容和属性；活动 lease 未携带 lease ID 的写也返回 412。
   - 状态：verified。

6. **Temporal — Workflow Execution**
   - URL: https://docs.temporal.io/workflow-execution
   - Publisher: Temporal Technologies
   - 直接证据：Workflow Execution 是 durable/reliable/scalable 执行单位；Replay 根据 Event History 恢复进度；Worker 将 command generation 与 Event History 对照；每个 execution 对本地状态有 exclusive access。
   - 状态：上述 workflow 事实 verified；把它外推为外部资源 exactly-once/fencing 是 inferred，不能作为官方直接承诺。

7. **AWS Step Functions — Choosing workflow type**
   - URL: https://docs.aws.amazon.com/step-functions/latest/dg/choosing-workflow-type.html
   - Publisher: Amazon Web Services
   - 直接证据：Standard Workflows 遵循 exactly-once model，但 ASL 配置 Retry 时任务/状态可能再次运行；Express Workflows 为 at-least-once，执行可能多次，适合幂等动作。
   - 状态：workflow 类型事实 verified；把其作为资源写入或业务副作用 fencing 证明是 inferred。

## 来源使用与限制

- 没有使用搜索摘要、第三方文章、私有资料、凭据、账户或真实服务。
- 本次仅下载/解析上列官方公开文档用于定位段落；原始下载文件保留在本隔离目录，作为研究过程材料，不应被视为额外来源。
- 官方文档没有统一定义本报告的四命题、确认窗口 W 或跨平台端到端缓存/网络语义；这些是显式标记为 inferred 的记录/安全策略。
