# S3 来源清单

仅列入公开官方一手资料；访问日期：2026-09-22。所有页面均通过 HTTPS 获取；未使用搜索摘要、博客或二手资料。

| ID | 官方来源 | 用途 | 结论边界 |
|---|---|---|---|
| S1 | AWS Step Functions — Choosing workflows: https://docs.aws.amazon.com/step-functions/latest/dg/choosing-workflow-type.html | Standard exactly-once、Express at-least-once、幂等动作与执行语义 | 仅说明 Step Functions workflow execution，不扩展为端到端外部副作用 |
| S2 | AWS Step Functions — Error handling: https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html | Retry、Timeout、Heartbeat、redrive retry count | 重试/重放需考虑再次执行；不提供业务 API 幂等证明 |
| S3 | AWS Step Functions — Service integration patterns: https://docs.aws.amazon.com/step-functions/latest/dg/connect-to-resource.html | Request Response、`.sync`、`.waitForTaskToken`；外部 job/callback/人工等待 | 等待完成/回调不等于外部业务效果已独立证实 |
| S4 | AWS Step Functions — Redrive executions: https://docs.aws.amazon.com/step-functions/latest/dg/redrive-executions.html | 重启/redrive 的官方行为 | redrive 可能再次执行失败路径；不能当作无重复证明 |
| S5 | AWS CloudTrail — Concepts: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html | CloudTrail、事件历史与审计概念 | 事件记录是审计证据，不是任意业务外部效果的普遍证明 |
| S6 | AWS CloudTrail — Event record contents: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html | eventTime、userIdentity、resources 等关联字段 | 字段可用于关联，不能替代目标系统 read-back |
| S7 | Temporal — Activity definition: https://docs.temporal.io/activity-definition | Activity 适合外部/不确定操作的官方定义 | Activity retry 后仍可能有未知提交结果；需业务幂等与查询 |
| S8 | Temporal — Retry policies: https://docs.temporal.io/encyclopedia/retry-policies | Activity 默认 retry、Workflow Task retry、backoff 边界 | retry 提高成功机会，不等于外部效果唯一发生 |
| S9 | Kubernetes — Controllers: https://kubernetes.io/docs/concepts/architecture/controller/ | controller control loop、观察状态与调节状态 | 控制面收敛不普遍证明第三方效果 |
| S10 | Kubernetes — Jobs: https://kubernetes.io/docs/concepts/workloads/controllers/job/ | Job one-off 运行至完成的 workload | Job completion 是 Kubernetes 语义，不等于业务系统效果 |
| S11 | GitHub Actions — Environments: https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment | required reviewers、wait timer、secrets gate、self-review 保护选项 | 审批门控不证明审批对象或外部结果事实 |

## 来源选择与排除

- 选择：官方产品文档，直接描述执行、重试、控制器、审计或人工门语义。
- 排除：搜索引擎摘要、社区文章、厂商博客、论坛、真实系统日志、凭据、生产配置和本地历史研究资料。
- 时间：文档页面未统一提供发布日期时，manifest 标注 `official documentation; date not stated`，不伪造发布日期。
