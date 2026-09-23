# 取消/超时/恢复后的 UNKNOWN：幂等重试与补偿

- 研究切片目录：`/tmp/A-LINE-CANCEL-UNKNOWN-RESEARCH-20260921T192728Z/`
- 资料截止/访问日：2026-09-22（UTC；本运行环境显示时间为 2026-09-22 Asia/Shanghai）
- 范围：仅公开一手官方资料；核心来源为 Temporal、LangGraph、OpenAI Agents SDK，另加 IETF RFC 9110。没有把平台回执、benchmark、checkpoint、trace 视作外部生产效果。

## 结论

当取消、超时或断连发生在请求已经可能被服务端接受之后，客户端不能把“没有响应”解释为“未发生”。在恢复前应将该操作标为 **UNKNOWN**，保留原始 `operation_id`/业务幂等键，并先对同一标识做 read-back/reconcile；只有得到明确的终态（或由受控人工裁决）后才结束 UNKNOWN。盲目用新 key 重试会把一次可能已经成功的操作变成第二次独立操作，尤其危险于扣款、发货、发信、删除等非幂等副作用。

这是对可靠协议的综合建议，不是三家 SDK 都已经内置的端到端 UNKNOWN 状态机。官方资料证明的是：Temporal 的取消传播/心跳/清理与 Workflow ID/Run ID 语义，LangGraph 的 checkpoint 恢复和“interrupt 前副作用必须幂等”，OpenAI Agents 的可序列化 RunState/HITL 恢复与模型调用超时异常；它们不能单独证明外部生产系统在丢失响应时已完成或未完成。

## 状态机与决策表

| 事件 | 客户端判定 | 恢复前动作 | 允许的下一步 |
|---|---|---|---|
| 取消请求已发出，响应丢失/连接断开 | UNKNOWN（取消请求的投递和处理结果均未知） | 用原始 operation_id + 原始幂等键 read-back；查询取消请求和目标资源的终态；记录证据 | 已确认 CANCELED/NOT_FOUND/终态后收敛；仍未知则退避重查或人工；不得换新 key 盲重副作用 |
| 调用超时、网关 504、传输断连 | UNKNOWN（除非协议明确证明请求未到达） | read-back/reconcile；检查服务端状态、业务流水/去重记录；保留原 key | 明确失败且可安全重试时用**同一** key；明确成功则不重做；无法判定进入人工边界 |
| 从 checkpoint/RunState 恢复 | 运行游标已恢复，不等于外部副作用已知 | 在继续节点前核对副作用的幂等记录/资源状态 | 以同一操作标识重入；将重复调用设计为 upsert/去重/安全查询 |
| 补偿/Saga 动作自身超时或断连 | 补偿也为 UNKNOWN，不能假定已回滚 | 对补偿 operation_id read-back；核对正向与反向状态 | 继续同一补偿（幂等）或人工裁决；禁止再造独立补偿 key 造成双重反向动作 |

## 必须比较的要点

### 1. 取消请求“已发出但无响应”
Temporal 官方 Go 文档明确展示 `CancelWorkflow` 可按 Workflow ID 发送，也可提供 Run ID 以确保针对正确执行；取消会传播到 Workflow/Activity，Activity 依靠 heartbeat 接收取消，Workflow 可用 disconnected context 做清理。文档还说明取消后 heartbeat 调用可能返回 `context canceled`，但 heartbeat 仍已发送。这说明“调用方看到错误/无响应”与“服务端没有接收”不能等同；但 Temporal 页面没有承诺一个通用的外部取消 ACK 或 read-back 协议，因此应用仍应查询 Workflow/业务状态。

### 2. 超时/断连后的未知状态
RFC 9110 将幂等方法定义为：同一请求多次执行的预期效果与执行一次相同；并明确幂等性允许客户端在通信失败后重试。该规范只覆盖方法语义，不会替应用证明 POST/工具调用/外部副作用的完成状态。504/408 等响应也不是“外部动作一定未发生”的证明。OpenAI Agents SDK 文档定义 `ModelTimeoutError`（模型调用尝试超过配置的 timeout）以及工具超时行为；它没有把超时异常等价为远端副作用未执行。

### 3. 恢复前 read-back/reconcile
LangGraph 官方持久化文档把 checkpointer 定位为线程级 graph state 快照，用于故障容错、恢复和检查；中断文档说明恢复会从包含 `interrupt()` 的节点开头重新执行，而不是从原行继续。因此 checkpoint/RunState 只能恢复编排游标，不能替外部系统确认一次写入。应在恢复点前 read-back 外部资源或去重表，以资源版本/operation_id/业务状态进行 reconcile；若没有可查询的事实源，UNKNOWN 必须保留。

### 4. 原始 operation_id / idempotency key
RFC 9110 支持“同一幂等请求安全重试”的协议原则，但不规定一个跨 API 的 `Idempotency-Key` 头或业务 operation_id。Temporal 官方资料提供 Workflow ID（逻辑执行标识）和可选 Run ID（指定具体运行），Workflow reset 会产生新的执行并要求监控新执行；这可作为编排层的稳定关联标识，但不是任意外部支付/邮件/仓储 API 的幂等保证。应用须把原始 operation_id、幂等键、目标资源和补偿 operation_id 持久化，并让服务端按该键去重或返回既有结果。

### 5. 盲目新 key 重试风险
新 key 表示新操作；在原请求可能已落地时会产生双写/双扣/双发/错误删除。官方 LangGraph 文档直接要求 `interrupt()` 前的副作用必须幂等，并以 upsert 为正例、创建新记录为反例，因为恢复会重跑节点。将同一原则推广到超时重试是工程推论（`inferred`），不是 LangGraph 对任意服务的保证。正确顺序是同 key read-back → 明确结果 → 同 key 安全重试（若仍允许）或人工，而非生成新 key。

### 6. Saga/补偿自身 UNKNOWN
三家所查页面没有一个统一的 Saga 补偿协议，也没有证明“补偿调用超时即已回滚”。补偿是新的外部副作用，必须拥有自己的稳定 compensation_operation_id/幂等键、状态表和 read-back。正向成功而补偿 UNKNOWN 时，应同时保留正向事实与补偿事实，避免以“再发一个新补偿 key”制造过度回滚。若目标系统支持查询，以状态收敛；不支持查询或状态不可逆时，进入人工边界。

### 7. 人工介入边界
LangGraph interrupt 和 OpenAI Agents HITL 官方资料都支持暂停、保存状态、之后用相同 thread/checkpoint 或序列化 RunState 恢复；OpenAI 文档将审批状态保存在 RunState，并要求用原始 top-level agent 恢复。它们证明“把决策暂停并恢复”可作为编排模式，但不证明人可以安全猜测外部 UNKNOWN 的结果。人工介入应在以下情况触发：read-back 不可用或互相矛盾；操作不可逆/高价值/涉及安全或合规；重复重试的代价高于等待；补偿链本身 UNKNOWN；超过重试/查询截止时间。人工动作也要使用原 operation_id，形成审计记录，不得随意新建 key。

## 建议的最小协议

1. **创建**：先生成并持久化 `operation_id`、业务幂等键、目标、正向/补偿关系及状态 `PENDING`。
2. **发送**：请求携带同一 key；服务端原子记录“已接受/结果/版本”（若能实现）。
3. **异常**：发送后任何 timeout、断连、取消无响应、非确定性 transport error → `UNKNOWN`，不写 `FAILED`。
4. **恢复**：使用原 key read-back；优先查操作记录，再查目标资源/版本，再查外部账务或审计事实。
5. **收敛**：明确成功/明确取消/明确失败分别落终态；不明确则延迟重查或人工。
6. **重试**：仅在同 key、服务端去重语义明确且 read-back/策略允许时重试；新 key 只代表业务上确认要创建第二次操作的全新意图。
7. **补偿**：补偿独立编号但可关联正向编号；补偿 UNKNOWN 走同样状态机，不能用“补偿请求发出”推断“已回滚”。

## 证据等级与限制

- `verified`：来源页面可直接支持所述官方功能/定义。
- `inferred`：由多个官方语义推导出的协议建议；不是供应商承诺。
- `unknown`：所查官方页面未证明，不能据此宣称生产效果。
- 没有进行真实服务、生产 API、私有账户、凭据、benchmark 或事故数据验证。
