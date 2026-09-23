# A线研究摘要

## 结论
Temporal的生命周期与证据模型最完整；LangGraph以thread/checkpoint/interrupt实现可恢复人工协作；OpenAI Agents SDK以RunState/interruption/trace实现审批恢复与运行观测。三者都不能把平台回执自动升级为外部效果证明。

## 共同设计原则
1. 分离平台状态、工具返回、外部目标状态和业务后置条件。
2. 暂停/恢复必须有持久游标或状态（Run ID、thread_id、RunState）。
3. 重试可能重复外部副作用；稳定operation/idempotency key和目标侧去重是必要边界。
4. 最终成功需显式外部read-back与业务校验；缺 read-back 保持 unknown。
5. 日志/trace/checkpoint适合记录路径和上下文；不可篡改、全量、长期保全不能凭平台默认语义推断。

## 三个对象的最小差异
- Temporal：durable replay、明确状态与failure/retry taxonomy、Event History；外部验证需显式Activity。
- LangGraph：checkpoint + thread_id + interrupt/resume；节点恢复会重跑 interrupt 前代码，副作用需幂等/重排。
- OpenAI Agents SDK：审批中断覆盖嵌套运行，RunState可序列化恢复，trace可观测；业务幂等/read-back由应用负责。

## 证据标记
verified=官方原文直接支持；inferred=工程推论；unknown=官方资料未证明。未使用benchmark证明production。

下一切片已派发：任务取消/超时/恢复后的unknown判定、幂等重试与补偿。
