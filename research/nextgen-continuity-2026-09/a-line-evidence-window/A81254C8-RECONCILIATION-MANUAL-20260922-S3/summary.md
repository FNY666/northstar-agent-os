# S3 一页摘要

## 核心判断

- **稳定窗口**：没有跨系统固定时长。以最后一次可能产生副作用的 attempt 为起点，窗口至少覆盖目标传播、审计摄取、读模型刷新、剩余重试/redrive/controller 重投与时钟误差上界；上界没被目标契约验证时保持 **UNKNOWN**。
- **证据冲突**：同一相关键/版本/时间边界下权威来源互斥，或身份/新鲜度/覆盖不可验证时，保持 **CONFLICT/UNKNOWN**；冻结高风险自动动作，采集同键证据并进入人工审核。
- **人工门**：GitHub required reviewers/wait timer 与 Step Functions callback 都能提供门控，但审批只是授权，不是外部效果证明。
- **补偿**：补偿自身要有稳定幂等键、条件写/版本约束、明确停止条件和独立 read-back。补偿成功不证明原副作用从未发生，也不证明没有重复。
- **禁止过度声明**：日志存在、平台成功、空查询、单次 read-back、无错误 retry 都不能单独证明外部效果；不声称 production、端到端 exactly-once 或无重复副作用。
- **关单**：窗口已过；至少两次时间分离的权威读回一致；审计链能关联每次尝试；重试/重投已停止或已纳入证据；冲突解决；补偿可证明；风险触发时 reviewer 明确批准。否则 OPEN/UNKNOWN，必要时 CLOSED_WITH_EXCEPTION 而非“无重复”关闭。

## 官方依据

AWS Step Functions Standard/Express、Retry/Timeout/redrive、`.sync`/`.waitForTaskToken`；AWS CloudTrail 概念与事件字段；Temporal Activity/retry policies；Kubernetes controller/Job；GitHub Actions Environments。完整引用见 `sources.md` 与 `research-manifest.json`。

## 状态词

- **VERIFIED**：官方文档直接支持的平台行为。
- **INFERRED**：基于官方机制提出的治理/控制策略。
- **UNKNOWN**：本切片未测量或来源边界不明。
- **CONFLICT**：同一对象的权威证据互斥，未人工裁决。

本切片没有真实业务对象，因此没有实际冲突样本，也没有生产验证结论。
