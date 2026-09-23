# Summary

## Bottom line

**批准暂停 ≠ 批准真实性 ≠ 审计日志 ≠ 外部效果。**

- Temporal 的强项是以 Event History 持久记录工作流事件并支持 replay/recovery；Approval Pattern 可将 Signal 载荷中的批准决定、身份、理由、时间戳纳入历史。Cloud Audit Logs 是控制平面操作日志，官方明确不覆盖若干数据平面 Workflow 事件。
- LangGraph 的 interrupt + checkpointer 能保存暂停时图状态并用 thread_id/Command(resume)恢复；checkpoint 是状态恢复证据，不是平台认证批准凭证或独立不可篡改审计。
- OpenAI Agents SDK 的 needs_approval + interruption + RunState 支持人工批准恢复；官方明确序列化 RunState 不认证快照或提交者，要求服务端认证 reviewer、使用服务端 pending items、原子消费以阻止重放。Tracing/Session 是可观测性/会话历史，不自动升级为批准审计或外部效果证明。

## 证据判定规则

1. **平台批准回执/ACK**只证明平台接收/处理某请求，不证明批准人身份、权限或外部完成。
2. **Event History / checkpoint / RunState / trace**分别是执行事件历史、图状态快照、可恢复运行状态、可观测运行记录；不能互换，也不能统称审计日志。
3. **审计日志**必须按其覆盖范围解释。Temporal Cloud Audit Logs 只覆盖控制平面范围，不能替代业务批准记录。
4. **外部 read-back**是证明外部效果的必要设计层：用外部事务/幂等 ID 回读权威系统状态，再把回读结果及时间写入独立审计记录。

## 最小生产级证据链（设计建议）

`request_id → authenticated reviewer + authorization decision → immutable approval event → platform pause/resume record → idempotent external submission → external read-back (status/version/transaction ID) → linked audit event`

任何缺口都只能报告“未证明”，不能用示例、benchmark、trace 截图或 resume 成功替代。

## 文件与范围

- 仅公开官方一手资料；访问日 2026-09-22。
- 未触碰受保护目标：`shared/P0`、事故目录、`D10/L12/D14`、`canonical`、`140`、`tri-line`、`systemd`、凭据、真实服务、`production`、共享目标均未读取、写入或调用。
- 研究仅写入本次独立 `/tmp` 目录。
