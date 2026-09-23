# S4 来源清单

仅列公开官方一手资料；访问日期：2026-09-22。直接摘录/核验点采用“页面明确描述”的最小表述，未使用搜索摘要、博客或二手转述。

| ID | 官方来源 | 直接核验点 | 用途/状态 |
|---|---|---|---|
| AWS-CT-1 | AWS CloudTrail User Guide, [CloudTrail record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html) | 记录字段包含 `eventTime`、`userIdentity`、`requestParameters`、`eventID`、`readOnly`、`resources`、`sharedEventID` 等；页面还说明 requestParameters 可因大小被省略，API event 的字段并非所有时候都完整。 | primary；verified 字段/完整性边界 |
| AWS-SF-1 | AWS Step Functions API Reference, [GetExecutionHistory](https://docs.aws.amazon.com/step-functions/latest/apireference/API_GetExecutionHistory.html) | execution history 返回按 `timeStamp` 升序的事件；`reverseOrder` 可倒序；有 `nextToken` 时仍有更多结果。 | primary；verified 排序/分页/完整性 |
| AWS-SF-2 | AWS Step Functions API Reference, [HistoryEvent](https://docs.aws.amazon.com/step-functions/latest/apireference/API_HistoryEvent.html) | HistoryEvent 结构包含 `id`、`previousEventId`、`timestamp` 等。 | primary；verified 事件链字段 |
| TEMP-1 | Temporal Documentation, [Event History walkthrough with Python SDK](https://docs.temporal.io/encyclopedia/event-history/event-history-python) | 官方说明 Event History 是生命周期中事件的详细日志，持久化于 Temporal Service 数据库；Commands 映射到 events；Activity 可见 scheduled/started/completed 等事件；replay 用历史恢复 workflow 状态。 | primary；verified durable history/replay 语义 |
| K8S-1 | Kubernetes Documentation, [API Concepts](https://kubernetes.io/docs/reference/using-api/api-concepts/) | 官方 API 概念页涵盖 list/watch、一致性、`resourceVersion`、watch bookmark 与 `410 Gone`/版本窗口语义；resourceVersion 用于观察/并发与 watch 语义。 | primary；verified version/watch 边界 |
| K8S-2 | Kubernetes Documentation, [Field Selectors](https://kubernetes.io/docs/concepts/overview/working-with-objects/field-selectors/) | 默认不设置 selector 等价于空 selector，选择指定类型的所有资源；支持字段因资源类型不同，未支持字段会报错。 | primary；verified 空查询/选择器语义 |
| GH-1 | GitHub Docs, [Managing environments for deployment](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments) | 环境保护规则包括 required reviewers、wait timer、custom rules；受环境保护的 job 必须先通过规则；部署会产生 deployment 与 deployment status 对象；状态可通过 API/webhook 访问。 | primary；verified 批准/部署状态 |
| GH-2 | GitHub Docs, [Deployments and environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments) | required reviewer 可批准 job 才能继续；可防自审；管理员 bypass 可配置禁用；环境 secrets 在规则通过后才可访问。 | primary；verified 人工批准边界 |
| GH-3 | GitHub Docs REST API, [Workflow runs](https://docs.github.com/en/rest/actions/workflow-runs) | workflow run 有唯一 `run_id`；示例含 `run_number`、`status`、`conclusion`、`created_at`、`updated_at`；`waiting/pending/requested` 可表达中间状态。 | primary；verified attempt/run 与中间状态 |
| GH-4 | GitHub Docs REST API, [Deployments](https://docs.github.com/en/rest/deployments/deployments) | 官方 REST 页面定义创建/删除 deployments 与 deployment environments，并提供部署对象/状态访问入口。 | primary；verified deployment record 用途 |

## 研究方法与覆盖

已针对四个官方生态各抓取上述公开页面的正文/官方 markdown 或官方 API 文档，并以页面可见字段和语义建立证据映射。没有访问：私有 GitHub 仓库、AWS 账户/CloudTrail 实例、Temporal 服务、Kubernetes 集群、任何凭据或本地既有 A 线产物。

## 关键证据与限制

1. AWS CloudTrail 的 `eventID` 是事件身份；来源没有把它定义为业务 idempotency key，因此报告将二者分开（verified + inferred）。
2. Step Functions 的 `nextToken` 和 Temporal 的持久 history 证明历史可分段/重建，但不证明目标外部副作用已发生（verified boundary）。
3. Kubernetes 的 resourceVersion 是平台对象/观察的版本语义，不被提升为所有业务实体的 generation；报告显式分列（verified + inferred）。
4. GitHub 的 reviewer approval 是保护规则门槛，不能被转译为部署效果证明；批准字段绑定 scope 和证据引用（verified + inferred）。
5. 未找到官方跨平台统一 schema、统一 freshness SLA 或 exactly-once 承诺；这些项在报告中标为 unknown，而不是补齐为事实。
