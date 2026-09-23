# 摘要

**切片**：取消请求无响应、超时后可能存在外部副作用、恢复/重试中的 UNKNOWN、幂等键/目标侧去重、read-back/reconcile、Saga/补偿、人工边界。

**一句话判定**：发送后取消/超时/断连且没有目标侧权威读回时，外部效果永远先保持 `UNKNOWN`；平台取消回执、SDK 异常、工作流 checkpoint、重试成功都不能单独证明外部效果。恢复必须先使用原业务意图和原幂等键做 reconcile；补偿也要单独记录和判定，无法证明时升级人工。

**核验结论**
- Temporal：官方 Go 文档直接支持取消传播、heartbeat、取消时 cleanup、reset 和 workflow history/replay；不支持把这些编排事实当成外部副作用证明。
- LangGraph：官方 persistence 文档直接支持 checkpointer/store 用于中断/故障恢复；不支持 checkpoint 证明外部写入或自动去重。
- OpenAI Agents SDK：官方源码直接支持 RunState 暂停/恢复边界、恢复写入和 tool/model timeout/cancellation 异常分类；不支持外部工具 exactly-once 或安全重试证明。
- RFC 9110：官方规范支持 HTTP 幂等方法定义和幂等请求的连接失败重试边界；不定义业务 idempotency-key、目标去重或 read-back。

**推荐门槛**
1. 发出前能证明未发送，才可判定 `CONFIRMED_NOT_APPLIED`。
2. 已发送/发送不确定 + 无响应，判定 `UNKNOWN`。
3. 先 read-back/reconcile；只有目标侧明确的 key 记录/结果才可收敛。
4. 重试固定原 key；参数冲突、证据冲突、去重窗口不明或目标不可查，禁止自动新 key 重放。
5. forward 和 compensate 都是独立动作，各自有幂等键、证据和 UNKNOWN 状态。
6. 高影响或不可收敛场景转人工，记录证据而非只改状态。

**不能声称**：本研究未连接任何实例，未进行真实写请求；没有证明任何平台提供通用跨系统 exactly-once、取消即未发生或补偿已完成。
