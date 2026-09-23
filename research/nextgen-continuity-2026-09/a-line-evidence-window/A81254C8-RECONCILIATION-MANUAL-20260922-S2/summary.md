# 摘要：A 线 reconciliation

## 一句话

外部结果无法确认时，最安全的默认不是“失败”，而是可重放的 `UNKNOWN`：耐久化意图，使用稳定业务键，继续以权威状态查询；高风险、冲突或超出窗口则进入人工审核，补偿动作也必须重新核验，只有证据满足关闭条件才关闭。

## 官方事实（verified）

- Temporal：Activity 可能重试并执行多次，需设计幂等；Workflow ID 有运行期唯一性约束，Run ID 标识具体 execution。
- AWS Step Functions：支持 Retry/Catch、退避和 redrive；这只是状态机编排语义。
- AWS CloudTrail：事件是账户活动记录，但日志不是按顺序的公共 API 调用 stack trace。
- AWS IAM：分布式模型有 eventual-consistency 延迟，应用应为延迟设计。
- Kubernetes：controller 通过观察 current state 使其接近 desired state，是 reconciliation 的控制循环模型。
- GitHub Actions：environment 可配置 required reviewers、wait timer 和其他保护规则；workflow 可受限重跑。

## 推导（inferred）

建议状态：`INTENT_DURABLE → DISPATCHING → OUTCOME_UNKNOWN → RECONCILING → CONFIRMED_SUCCESS/CONFIRMED_FAILURE/MANUAL_REVIEW → COMPENSATION_PENDING/CLOSED`。

`OUTCOME_UNKNOWN` 应覆盖 timeout、断连、响应丢失、最终一致读模型尚未出现、查询不完整。不能由“本地日志存在”“workflow success”“retry exhausted”“查询空结果”单独推出外部成功或失败。

自动关闭成功要求外部权威状态与业务键、目标资源及关键字段匹配，并满足新鲜度/完整性规则；自动关闭失败要求明确外部拒绝且确认无成功副作用，或补偿已由外部确认。否则进人工门。

## 明确未知（unknown）

本切片不提供具体业务的幂等键语义、读模型延迟窗口、补偿可逆性、SLA、人工审核准确率或生产验证；不声称 production，不声称 exactly-once。

## 交付物

完整证据账本与关闭判定表见 `report.md`；来源和访问边界见 `sources.md`。