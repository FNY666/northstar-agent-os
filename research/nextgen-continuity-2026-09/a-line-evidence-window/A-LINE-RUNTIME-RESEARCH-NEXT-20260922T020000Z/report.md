# A线下一独立公开研究切片：取消/超时/恢复后的 UNKNOWN、幂等重试与补偿

- 访问日期：2026-09-22
- 范围：仅公开、官方一手资料；核验 Temporal、LangGraph、OpenAI Agents SDK，并补充 RFC 9110。
- 隔离目录：`/tmp/A-LINE-RUNTIME-RESEARCH-NEXT-20260922T020000Z/`
- 明确排除：未访问私有账号、凭据、真实服务或共享目标；未把 benchmark 当 production 证据。

## 结论（先给判定）

1. **取消请求已发出但没有响应：业务动作结果必须保持 `UNKNOWN`，不能从“取消 API 返回/本地任务取消”推断目标侧没有发生。** Temporal 官方资料证明的是取消请求传播、Activity heartbeat 与工作流内 cleanup 的编排语义；它不证明外部 HTTP/支付/邮件/数据库副作用的最终状态。RFC 9110 只说明在“方法语义本身幂等”时，客户端可在连接失败后重试；它不把任意业务 POST 或平台回执变成外部效果证明。
2. **外部副作用可能在超时前后发生且响应丢失时，恢复/重试入口应继承 UNKNOWN，而非自动改成 FAILED 或 NOT_DONE。** 只有目标侧 read-back/reconcile（查询目标状态、操作记录、幂等键结果或等价的受信证据）能将 UNKNOWN 收敛为 `CONFIRMED_APPLIED`、`CONFIRMED_NOT_APPLIED` 或仍为 `UNKNOWN`。本结论是跨来源安全推断（`inferred`），不是任一平台的端到端保证。
3. **幂等重试的最小契约：同一业务意图固定、唯一、可重放的 idempotency key；目标侧原子去重/结果复用；重复请求不得再次执行副作用；请求参数冲突必须报错；回执需能关联该 key。** RFC 9110 对 HTTP 方法的幂等性提供规范定义，但没有定义通用 idempotency-key header 或目标业务去重实现，因此应用层契约部分为 `inferred`。
4. **read-back/reconcile 必须先于对 UNKNOWN 写操作的再次执行。** 若无法读取目标状态或目标不提供可验证去重，不能把“重试成功”当作一次执行；应进入补偿/人工队列或保持 UNKNOWN。该操作顺序为安全设计推断，官方资料没有给出完整跨系统证明。
5. **Saga/补偿不是撤销事实的同义词。** Temporal 官方示例证明取消时可用 disconnected context 执行 cleanup Activity；这证明了编排 cleanup 的能力，不证明 cleanup 已抵消外部副作用。补偿本身也可能超时、部分成功或再次变成 UNKNOWN，应拥有独立幂等键、状态和 reconcile。
6. **人工介入边界：** 只要仍是 UNKNOWN、read-back 不可用/互相矛盾、补偿不可证明完成、金额/权限/删除/通知等高影响动作可能重复，就禁止自动“猜测收敛”，转人工核对目标侧证据；人工确认也应记录证据、时间、操作者和决定，而非仅改一个状态字段。

## 状态机与恢复规则

建议把“编排状态”和“外部效果状态”分开，至少记录：`intent_id`、目标资源、固定幂等键、payload/hash、尝试次数、平台回执、目标侧证据、最后 reconcile 时间与证据版本。

| 场景 | 编排可知事实 | 外部效果判定 | 恢复动作 |
|---|---|---|---|
| 请求未发出且本地可证明 | 未越过发送边界 | `CONFIRMED_NOT_APPLIED` | 可用同一 intent/key 发起 |
| 已发出，取消/超时/连接断开，无目标 read-back | 请求不确定；响应未知 | **`UNKNOWN`** | 不改变 key；先 reconcile，不盲重放 |
| 目标返回幂等键已存在且结果可验证 | 目标去重记录与业务状态一致 | `CONFIRMED_APPLIED` 或 `CONFIRMED_NOT_APPLIED` | 记录证据，禁止再次副作用 |
| read-back 明确不存在，且目标保证该 key 未执行/已过期 | 目标侧负向证据可信 | `CONFIRMED_NOT_APPLIED` | 仍用同一 key 重试；重新进入 UNKNOWN 仍按上表处理 |
| read-back 不可用、冲突或超出保留窗口 | 无法排除已发生 | **`UNKNOWN`** | 延后 reconcile、补偿或人工，不自动重复 |
| 补偿请求无响应 | 补偿是否发生未知 | **补偿动作自身 `UNKNOWN`** | 用补偿 key reconcile；不能声明已回滚 |

### 关键不变量

- 平台的 `cancel accepted`、任务 `Cancelled`、SDK `CancelledError`、本地 timeout、网络 200/重试成功都只是**平台/调用路径事实**，不是目标外部效果证明。
- 同一业务意图恢复时复用原 `intent_id`/幂等键；新业务意图才生成新键。重试计数不能替代去重。
- 只要无法证明“未执行”，就不能用新的 key 规避冲突后再做一次；那会把 UNKNOWN 变成潜在双写。
- read-back 需要目标侧权威记录、版本/时间界限和一致性假设；本地 checkpoint/event history 只能证明编排已记录什么。
- 所有补偿和人工决策都要可重入、可审计，并把“无法证明”保留为 UNKNOWN。

## 来源到结论的证据表

| ID | 来源 | 直接核验内容 | 状态 | 能证明 | 不能证明 |
|---|---|---|---|---|---|
| T1 | Temporal Go cancellation | workflow cancellation、heartbeat、`NewDisconnectedContext` cleanup；取消后 heartbeat 仍可能发送但调用可返回 context canceled；reset 会从历史点重启 | verified（官方文档原文，2026-09-22 访问） | 取消传播/cleanup 编排语义、重启历史语义 | 取消请求是否到达目标；外部副作用是否发生/只发生一次；cleanup 是否成功抵消 |
| T2 | Temporal Go side effects | SideEffect 结果写入 Event History，replay 不再执行；Activity/Local Activity 结果也持久化 | verified | Temporal 编排历史/replay 的记录与确定性 | Event History 不等于外部系统状态；Activity 已调用不等于外部写入成功 |
| L1 | LangGraph persistence | checkpointer 保存 thread graph state；支持中断恢复/故障恢复；内存 saver 重启丢失；store 用于图外应用数据 | verified | checkpoint/store 的持久化边界与恢复载体 | checkpoint 不证明外部副作用；没有通用目标侧幂等/回读保证 |
| O1 | OpenAI Agents SDK `run_state.py` | `RunState` 是可序列化暂停/恢复边界；源码强调恢复中的 session append、pending tool calls、并发恢复约束与 terminal-unrecoverable runs | verified（官方 GitHub 源码，2026-09-22 访问） | SDK 的暂停/恢复状态与并发约束 | 模型/工具或外部服务副作用的 exactly-once；SDK 状态不是外部效果收据 |
| O2 | OpenAI Agents SDK `exceptions.py` | `ModelTimeoutError`、`ToolTimeoutError`、MCP tool cancellation 等异常类型存在 | verified | SDK 能区分调用层 timeout/cancel 异常 | timeout/cancel 后工具外部动作是否已发生；可安全重试与否；目标侧去重 |
| R1 | RFC 9110 §9.2.2 | 幂等方法定义；重复请求预期效果相同；连接失败时可重试幂等请求；代理不得自动重试非幂等请求 | verified（IETF RFC，2026-09-22 访问） | HTTP 方法层的规范定义与通用重试边界 | 任意业务操作的幂等性；POST 的业务去重；请求发送后目标是否执行 |

## 实施判定（非平台保证）

- 发送边界前：可证明未发出才可 `NOT_APPLIED`；否则进入 UNKNOWN。
- 发送后无响应：记录 request-attempt、平台回执（若有）与发送不确定性；禁止依据客户端取消异常覆盖外部效果状态。
- 恢复：先用原 key read-back；目标返回同 key 的原结果则复用；参数 hash 不一致则拒绝并人工处理。
- 重试：只在 `CONFIRMED_NOT_APPLIED` 或目标方明确支持同 key 去重时自动进行；重试仍可能因响应丢失重新进入 UNKNOWN。
- Saga：每个 forward/compensate step 独立状态和幂等 key；补偿不是物理回滚承诺，补偿 UNKNOWN 不得标记已撤销。
- 人工：高影响副作用、证据冲突、目标不可查询、去重窗口不明、补偿失败/未知时升级；人工结论需附证据，不得仅凭平台状态。

## 局限与未知

- 本次只使用公开官方文档/源码和 IETF RFC；没有连接任何 Temporal/LangGraph/OpenAI 实例，也没有发送测试写请求。
- 官方资料主要描述编排器/SDK 的状态与恢复，不提供跨任意外部系统的 exactly-once 或“取消即未发生”证明。
- 未找到足以证明通用 Saga、通用 idempotency-key、目标侧 read-back 一致性的单一官方规范；相关部分明确标为推断/设计要求。
- 所有 production 可靠性结论都需要目标系统自身的去重、查询一致性、保留期限与审计契约；不能从 benchmark、示例或 SDK 绿色返回外推。
