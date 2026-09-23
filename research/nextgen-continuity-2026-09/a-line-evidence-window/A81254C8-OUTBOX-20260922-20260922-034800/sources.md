# Sources

访问日期：2026-09-22（Asia/Shanghai）。仅使用公开一手官方资料。`verified`=来源明确陈述；`inferred`=由官方语义组合出的工程结论；`unknown`=资料未承诺。

## 1. AWS Prescriptive Guidance — Transactional outbox pattern

- URL: https://docs.aws.amazon.com/prescriptive-guidance/latest/cloud-design-patterns/transactional-outbox.html
- 状态：verified；推论部分标为 inferred。
- 证明：该模式解决数据库写入与消息/事件通知的 dual-write 问题；业务表与 outbox 表可在同一事务更新；事务失败时整体回滚；relay 读取已提交 outbox 行并向 SQS 等下游发送；标准队列可能重复，消费方应幂等跟踪已处理消息。
- 不能证明：relay 发送与 relay 状态更新跨系统原子；第三方业务副作用 exactly-once；broker 接收等于业务提交；发生超时后副作用不存在。
- 版本/新鲜度：AWS Prescriptive Guidance latest 在线页面，访问日 2026-09-22；AWS 服务行为、队列类型与区域配置需按生产环境复核。

## 2. Debezium — Outbox Event Router

- URL: https://debezium.io/documentation/reference/stable/transformations/outbox-event-router.html
- 状态：verified；跨系统边界为 inferred/unknown。
- 证明：Debezium connector 捕获 outbox 表变更并应用 Outbox Event Router SMT；event id 可作为事件唯一 ID，例如用于移除重复消息；aggregate type/id 与 payload 等字段可路由到事件消息。
- 不能证明：CDC connector、broker、consumer 业务事务和第三方目标之间的分布式原子性；重复事件在所有下游都被安全抑制；外部副作用 exactly-once；崩溃窗口不会产生重复或 UNKNOWN。
- 版本/新鲜度：stable 文档在线滚动更新，访问日 2026-09-22；应按实际 Debezium connector、数据库日志和 broker 版本核验 offset/重启语义。

## 3. Temporal — Workflow Execution overview

- URL: https://docs.temporal.io/workflow-execution
- 状态：verified + inferred。
- 证明：Workflow Execution 是 durable/reliable/scalable；状态由 Event History 持久化；失败后可从最近记录事件 replay 恢复；Workflow 状态和平台事件有持久化语义。
- 不能证明：外部 HTTP、支付、shell、数据库或任意工具副作用 exactly-once；Event History 中的编排事件是外部目标 receipt；Worker 在外部调用后、平台记录前崩溃时，外部结果自动可判定。
- 版本/新鲜度：Temporal 在线文档，访问日 2026-09-22；产品版本、SDK、Activity retry/timeout 与部署配置需固定并复核。

## 4. Stripe — Payment status updates

- URL: https://docs.stripe.com/payments/payment-intents/verifying-status
- 状态：verified；扩展到通用 HTTP 为 inferred/unknown。
- 证明：集成方应监测并验证支付状态；可独立 retrieve PaymentIntent 以检查权威状态；PaymentIntent 状态覆盖需要进一步处理、客户动作、成功/失败等生命周期边界；边缘情况需使用 API 或 Workbench Inspector 获取 authoritative state。
- 不能证明：客户端超时意味着支付未发生；Stripe PaymentIntent 查询与调用方本地数据库事务原子；其他 HTTP/支付提供商提供同样的查询和收敛保证；补偿天然等于回滚。
- 版本/新鲜度：Stripe 在线文档，访问日 2026-09-22；PaymentIntent 状态和 API 行为应按实际 API version、支付方法和账户配置复核。

## 5. AWS Prescriptive Guidance — Saga pattern（补充）

- URL: https://docs.aws.amazon.com/prescriptive-guidance/latest/cloud-design-patterns/saga.html
- 状态：verified/inferred。
- 证明：跨服务事务可拆成局部事务，并通过协调和补偿处理跨服务一致性；这是长事务/跨服务场景的补偿设计入口。
- 不能证明：补偿是数据库级回滚；对 UNKNOWN 操作盲目执行反向动作安全；所有步骤都可逆或补偿一定成功。
- 版本/新鲜度：AWS latest 在线页面，访问日 2026-09-22；应按业务步骤的可逆性、幂等性和失败策略单独验证。

## 证据边界总表

| 来源 | 能证明 | 不能证明 |
|---|---|---|
| AWS transactional outbox | 本地业务更新与 outbox 意图可同事务提交；重复消费需幂等 | 跨系统原子、第三方效果 exactly-once |
| Debezium Outbox Router | 捕获 outbox 变更、路由消息、提供 event ID | 下游副作用唯一、无 crash duplicate |
| Temporal Workflow Execution | 编排状态持久、可从 Event History replay | 外部工具/支付/API 已提交或恰好一次 |
| Stripe PaymentIntent | 可独立查询权威支付状态 | 客户端未收到响应即未支付；本地业务事务已完成 |
| AWS Saga | 可用局部事务+补偿协调跨服务流程 | 补偿等同回滚；UNKNOWN 可盲目补偿 |

## 统一限制

所有数字、默认值、重试/保留/收敛行为均受版本、区域、账户、数据库、connector、broker 和实际配置影响。资料只证明来源明确描述的边界；本研究没有访问真实服务、凭据或生产配置。