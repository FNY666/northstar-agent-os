# Summary — Slice 3

- Temporal Visibility 是最终一致、可延迟的搜索索引；特定执行的当前权威状态应读 DescribeWorkflowExecution，且二者都不等于外部目标状态。
- Step Functions DescribeExecution 明确存在 eventual-consistency/best-effort 边界；GetExecutionHistory 是平台历史，不是外部 receipt。
- CloudTrail digest 可验证已交付日志文件在验证流程下未被篡改/删除，但不补足未采集事件、不证明全覆盖或业务提交。
- GitHub run conclusion、artifact 和 Kubernetes Job/Event 是平台/集群证据；artifact 可按保留策略过期，Kubernetes Event 是有限保留的补充性 best-effort 记录。
- Stripe webhook retry 证明的是投递尝试，不证明接收端 exactly-once 或业务 postcondition。
- 审核门：成功 read-back+postcondition 才能升级 verified；超时、断流、过期/冲突/最终一致窗口内的空结果统一 UNKNOWN/manual review；补偿本身也须独立 read-back。
