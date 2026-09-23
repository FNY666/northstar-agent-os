# S6：取消/失联/租约过期后的资源 fencing 与证据连续性

**研究切片**：C 线下一独立公开研究切片 S6  
**截止时间**：2026-09-22（Asia/Shanghai）  
**范围**：仅公开、官方一手文档；Kubernetes API/SSA、Azure Blob、Amazon S3、Google Cloud Storage，以及 AWS Step Functions、Azure Logic Apps 工作流的取消/重试语义。本文是协议与证据设计研究，不是生产验证，也没有访问任何集群、桶、账户、服务、凭据或既有 C 线材料。

## 0. 结论（先给可操作答案）

取消、失联或租约过期后，资源侧 fencing 的**可证明目标**不是“旧进程已经停止”，而是：旧 writer 再次到达资源时，其请求携带的条件/epoch 不再满足，资源拒绝该次条件写；随后由新 writer 用新 epoch/版本做条件写，并通过同一资源的 read-back 得到 postcondition 证据。写请求的返回结果若丢失，必须把“是否已提交”当作独立问题处理，而不能由超时、取消或 read-back 缺失推断。

最小证据链：

1. **Fence record**：记录旧 epoch/token、撤销/租约过期时间、资源 key、预期旧 writer 身份。
2. **Fresh read**：读取资源当前版本（Kubernetes `resourceVersion`/managedFields；Blob ETag；S3 ETag/版本语义；GCS generation/metageneration）。
3. **Conditional write**：旧 writer 必须带旧版本/epoch；新 writer 必须带新版本/epoch（或创建时的“不存在”前提）。
4. **结果分类**：明确拒绝（如 HTTP 409/412/conditionNotMet）与传输未知（timeout/reset/失联）分开。
5. **Postcondition read-back**：读取并核验 payload、writer/epoch、业务 idempotency key、服务端版本变化；需要时连续观察/审计日志补强。
6. **状态机**：只有“拒绝证据”能把旧 writer 标为 `FENCED_CONFIRMED`；只有新写成功响应**或**足够强的匹配 read-back 才能把新 writer 标为 `NEW_COMMITTED_CONFIRMED`。任何“未发现”或“请求被取消”都不能自动升级为已拒绝/未提交。

### 必须保留的边界

- **verified**：条件不满足时资源拒绝该次条件写（各产品的具体状态/语义见下表）。
- **inferred**：若拒绝发生在资源条件检查并返回明确条件错误之前，则该次条件写没有提交；这是对该次资源操作的协议推断，不是对旧 writer 进程此前副作用的证明。
- **unknown**：旧 writer 是否在 fencing 之前已造成外部副作用；请求在网络超时/取消前是否已经提交；read-back 未见匹配对象是否仅表示不可见、被覆盖、读错版本、生命周期清理，还是从未应用。
- **conflict/范围冲突**：AWS Step Functions Standard 的工作流执行语义“exactly-once”与 Express 的“at-least-once”并存；这只描述工作流执行/步骤语义，不能外推为业务资源写 exactly-once。Kubernetes SSA 的 field conflict 与 `resourceVersion` 的 lost-update conflict 也是不同的拒绝维度，不能混为一个 epoch。

## 1. 资源协议比较（只比较 stale-writer rejection 与 postcondition）

| 资源 | 条件写/版本材料 | 旧 writer 被拒绝的 verified 证据 | read-back 证据 | 不可推出的结论 |
|---|---|---|---|---|
| **Kubernetes PUT/patch + `resourceVersion`** | GET 得到对象的 `metadata.resourceVersion`；PUT 带该值。API server 用它检测过期客户端并拒绝 stale update；官方文档明确 HTTP 409 Conflict。也可让 PUT/PATCH 条件于当前 `resourceVersion`。 | **verified**：响应 409 Conflict + 对应请求/对象 key + 服务端返回体，是 stale version rejection 证据。它证明该次带旧版本的更新没有按该条件提交（**inferred from atomic conditional update semantics**）。 | **verified**：GET 返回目标 key、预期 payload、业务 epoch/writer marker、更新后的 `resourceVersion`；watch 可从已知版本跟踪后续变化。 | 不能从 409 推断旧客户端此前没有别的 side effect；不能从 GET 没有看到 marker 推断 not-applied；`resourceVersion` 是 server internal version，不等同业务 epoch；普通 GET 的新鲜度、缓存/观察窗口需明确。 |
| **Kubernetes SSA** | Apply patch 必须指定 `fieldManager`；API 记录 managedFields。未 force 时，Apply 改动另一个 manager 所管理字段会 field conflict 并失败；可 force 覆盖。 | **verified**：Apply 返回 field conflict（通常 API 错误/409 语义）且没有 force，是 field-ownership fencing 证据；它不是任意 stale `resourceVersion` 的替代品。 | **verified**：GET（必要时 `--show-managed-fields`）核验字段值、`managedFields.manager/operation`、业务 epoch marker 与 `resourceVersion`。 | SSA 不处理依赖当前值的所有更新；成功 Apply 不等于外部 side effect exactly-once；field conflict 不保证旧 writer 没有先写其它资源；force 成功会消除拒绝保护。 |
| **Azure Blob ETag / lease** | GET/HEAD 返回 ETag；更新带 `If-Match: <ETag>`，服务端比较当前 ETag。Blob lease 是另一种 lease-ID 条件，过期/缺 lease ID 的受保护操作会失败；本切片只把它当资源侧条件，不泛讲 lease。 | **verified**：ETag 不同返回 HTTP 412 Precondition Failed；官方解释为另一个进程已更新。对受 lease 保护的操作，缺/错误 lease ID 也可得到 precondition failure。 | **verified**：GET/HEAD 核验 ETag、内容、metadata（建议写入 writer/epoch/idempotency marker）。成功写响应的新 ETag 与 read-back 一致时，是 postcondition evidence。 | 412 只证明本次条件不满足/被拒；不证明旧 writer 无先前副作用。ETag/lease-ID 不自动形成跨资源事务或 exactly-once。 |
| **Amazon S3 conditional writes** | 官方文档：条件请求在 header 中声明；不满足条件使操作失败；`If-Match` 可按 ETag，`If-None-Match: *` 可防止同 key 已存在（用于 create-if-absent 类 fencing）。条件读也可限制 ETag。 | **verified**：明确条件失败的 HTTP/API 错误（实现/操作对应的 Precondition Failed/conditional request failure）证明该 S3 操作未以该前提完成。具体错误码依 API/操作，应保存完整响应，不能只靠字符串。 | **verified/inferred**：HEAD/GET 读取 ETag、版本标识（若启用 versioning）、payload 与业务 marker；匹配新 writer marker 才可确认为 postcondition。 | S3 ETag 不是普遍的内容 hash（尤其 multipart/加密等场景），不能只凭 ETag 断言 payload；“条件写失败”不证明未发生外部副作用；GET 未找到/未匹配不等于 not-applied。 |
| **Google Cloud Storage generation/metageneration** | 官方文档：对象有唯一 numeric `generation`（版本/对象世代）和 `metageneration`（metadata 世代）；request preconditions 令请求仅在目标资源满足条件时继续。典型 `if-generation-match`：已有对象的 generation 必须匹配；`if-generation-match:0` 用于不存在时创建。 | **verified**：条件不满足时请求不继续（API 返回 precondition/condition-not-met 类失败；应保存 HTTP/JSON 完整错误）。generation-match 使旧 generation 的 writer 成为 stale。 | **verified**：GET/HEAD 核验 generation/metageneration、payload、writer/epoch marker。使用 generation 作为后续 read-back 的精确对象版本，比仅看 ETag 更适合证据。 | “没有匹配 generation”不能单独证明 never applied；跨 API 的 ETag 一致性不是保证（官方提示 generation/metageneration 跨 API 更一致而 ETags 不同）；条件写成功不等于业务 exactly-once。 |

### 重要区分：取消/失联与拒绝

`cancel()`、进程死亡、连接断开、客户端超时都只改变调用者能否继续等待，并不构成资源端拒绝证据。只有资源返回明确的条件失败，或后续 read-back/审计以足够强的绑定证明了新 epoch 已提交并取代旧 epoch，才能升级证据状态。若请求返回未知，必须执行 read-back；若 read-back 也未知，则保留 `COMMIT_UNKNOWN`，不要自动重试非幂等副作用。

## 2. 证据状态机（建议作为实现契约）

状态与晋级条件：

```text
NEW
 ├─ fence record durable + old token/version identified
 │     -> FENCE_REQUESTED
 ├─ old conditional write returns explicit condition failure
 │     -> OLD_WRITER_REJECTED_CONFIRMED
 ├─ old request timeout/reset/cancel OR process disappeared
 │     -> OLD_WRITER_OUTCOME_UNKNOWN
 ├─ new conditional write success + response id/version captured
 │     -> NEW_COMMIT_RESPONSE_RECEIVED
 ├─ write timeout/reset after send
 │     -> NEW_COMMIT_UNKNOWN

FENCE_REQUESTED
 ├─ fresh read proves current epoch/token != old and accepted by fencing record
 │     -> OLD_WRITER_FENCED_BY_STATE (inferred for future writes, not proof of past side effects)
 ├─ explicit stale-condition rejection
 │     -> OLD_WRITER_REJECTED_CONFIRMED
 └─ read unavailable / contradictory -> FENCE_UNKNOWN

NEW_COMMIT_UNKNOWN
 ├─ read-back exact key + exact epoch + idempotency key + payload digest + server version
 │     -> NEW_COMMITTED_CONFIRMED
 ├─ read-back finds old epoch, no object, or mismatching payload
 │     -> COMMIT_NOT_CONFIRMED (not `NOT_APPLIED`)
 └─ read-back unavailable/ambiguous -> COMMIT_UNKNOWN

NEW_COMMITTED_CONFIRMED
 └─ compensation/retry only if operation's business semantics permit it and
    a new conditional precondition is established; never infer exactly-once.
```

`OLD_WRITER_FENCED_BY_STATE` 比 `OLD_WRITER_REJECTED_CONFIRMED` 弱：它说明未来带旧 token/version 的条件写应失败（基于当前资源状态），但没有捕获一次真实旧 writer 请求的拒绝响应。若资源条件写成功响应丢失，不能凭“随后读到新值”断言是哪一次尝试提交；应使用业务 idempotency key/唯一提交记录，并把证据绑定到 key、epoch、payload digest、server version 和时间窗。

## 3. postcondition read-back：什么算强证据

**强（可将 new writer 置为 confirmed）**：同一资源 key 的 fresh GET/HEAD（或官方支持的精确版本读取）同时满足：

- payload/digest 与意图相符；
- writer identity、epoch/generation、operation idempotency key 与本次意图相符；
- 服务端版本值是本次写的响应值，或严格符合写前/写后关系；
- 读取路径、认证主体、区域/桶/命名空间、时间戳和响应原文均记录；
- 没有并发新 writer 造成“碰巧相同内容”的歧义，或该歧义已由唯一提交记录消除。

**中（只能 inferred）**：内容匹配但没有 epoch/operation marker；或者只看到新 resourceVersion/ETag/generation 变化，不知道是谁提交。

**弱/UNKNOWN**：未找到对象、读到旧值、读超时、读到不同版本、缓存未刷新、只看客户端内存、只看 workflow 状态。尤其：**read-back 未发现 ≠ not-applied**；可能是写已提交但读路径不一致、随后被覆盖/删除、对象版本查询不对、生命周期规则清理，或请求从未到达。

## 4. retry / compensation decision table

| 观测结果 | 旧 writer 结论 | 新 writer 结论 | 动作 | 禁止的推断 |
|---|---|---|---|---|
| 条件写明确 409/412/condition-not-met；请求 key/旧版本可核对 | `OLD_WRITER_REJECTED_CONFIRMED`（本次资源写） | 未知 | 不重试旧写；记录证据；新 writer 重新读资源并以新 epoch 条件写 | 旧 writer 没有任何先前副作用 |
| 条件写成功响应 + 新版本/ETag/generation | 未涉及 | `NEW_COMMIT_RESPONSE_RECEIVED`，read-back 后 confirmed | 记录 response；做 read-back；幂等重试只在协议允许时 | 成功=exactly-once |
| 请求 timeout/reset/客户端取消（发送前不确定或发送后） | `OLD_WRITER_OUTCOME_UNKNOWN` | `NEW_COMMIT_UNKNOWN` | 停止盲目非幂等重试；先 fresh read/审计；以 idempotency key 重试可安全确认的操作 | timeout=未提交、取消=被资源拒绝 |
| read-back 精确匹配 key+epoch+payload+版本 | 只能说明当前已被新状态取代（若有顺序证据） | `NEW_COMMITTED_CONFIRMED` | 可继续后续步骤；保留写与读原文 | 证明无旧副作用、证明恰好一次 |
| read-back 无对象/旧 epoch/错误 payload | 未证明 | `COMMIT_NOT_CONFIRMED` | 不标 `NOT_APPLIED`；补充读取/审计；按业务决定 compensation 或人工 | 未发现=从未应用 |
| 新 writer 遇到冲突/条件失败 | 旧 writer 仍依赖独立证据 | `NEW_COMMIT_NOT_CONFIRMED` | 重新 GET，判断是否已有匹配提交；若无则新 epoch/版本重建条件；冲突不可盲重试 | 所有冲突都可 retry |
| fence state 已更新但未捕获旧请求响应 | `OLD_WRITER_FENCED_BY_STATE`（inferred） | 未知 | 让旧写带旧条件再做受控探针（若安全），否则保持未知 | fence record=旧进程已停止/无副作用 |
| workflow 显示 cancelled/stopped/failed | 仅 workflow-level 状态 | 资源提交仍未知，除非有资源证据 | 进入资源 read-back/补偿流程；为重试定义 epoch/idempotency | workflow 取消=资源 rollback |

补偿（compensation）不是“撤销原写”的同义词。只有业务定义了可逆操作、其本身有条件前提和幂等 key，才可执行；否则应隔离、人工核验并保留 UNKNOWN，而不是用一次无条件覆盖掩盖证据缺口。

## 5. 官方工作流文档如何约束结论

- **AWS Step Functions** 官方概览区分 Standard 与 Express：Standard “exactly-once workflow execution”，Express “at-least-once workflow execution”；同时提供 Retry/Catch。这里的 exactly-once 是工作流执行语义，不是下游资源副作用的 exactly-once。任务调用可能已到达下游而 workflow 被 stop/cancel，仍要按 `COMMIT_UNKNOWN` 处理，除非下游 postcondition 可证。
- **Azure Logic Apps** 官方异常处理文档说明：支持 retry 的 trigger/action 在 408、429、5xx 等失败/超时时按 retry policy 重发；默认策略通常会进行多次指数退避重试，也可以设 `None`。因此 timeout/failure 是重发策略输入，不是资源写入是否发生的证明；条件写和 idempotency 必须由下游资源提供。
- 本切片未把“取消”泛化为回滚。公开工作流页面通常定义 workflow/execution 状态与 retry，而资源提交状态需要由资源 API 的条件写和 read-back 单独证明。对未提供资源级 postcondition 的工作流步骤，结论必须保持 `UNKNOWN`。

## 6. Claim ledger（逐条状态）

| ID | 状态 | 结论 |
|---|---|---|
| C1 | **verified** | Kubernetes stale `resourceVersion` 的 PUT 可被 API server 以 409 Conflict 拒绝；API 文档明确其用于检测 lost update。 |
| C2 | **verified** | Kubernetes SSA 跟踪 field manager/managedFields；未 force 的 field ownership conflict 会使 Apply 失败。 |
| C3 | **verified** | Azure Blob If-Match 比较当前 ETag；不相等时返回 412 Precondition Failed。 |
| C4 | **verified** | S3 条件请求在条件不满足时失败；官方支持按 ETag 的条件读/写及 create-if-absent 类 If-None-Match。具体错误码须按 API 原文记录。 |
| C5 | **verified** | GCS generation/metageneration 是对象版本材料；request preconditions 令请求仅在前提满足时继续，`if-generation-match:0` 可表达不存在前提。 |
| C6 | **verified** | Step Functions Standard/Express 的 exactly-once/at-least-once 是两种工作流交付语义；不能外推为业务资源写 exactly-once。 |
| C7 | **verified** | Logic Apps retry policy 会针对支持的 408/429/5xx 失败/超时重发，策略可配置。 |
| C8 | **inferred** | 资源返回明确条件失败时，该次带该条件的资源写未提交；这是基于官方条件检查语义的协议推断，并不覆盖其它副作用。 |
| C9 | **inferred** | 新 epoch + 精确 marker + 服务端版本的 read-back 可构成新 writer 提交的强 postcondition；强度依赖读路径新鲜度、marker 唯一性和版本关系。 |
| C10 | **unknown** | 旧 writer 在 fence 前是否执行过不可逆外部副作用。资源条件拒绝不能回答。 |
| C11 | **unknown** | timeout/reset/cancel 后该次写是否已经在资源侧提交。需资源 read-back、审计或幂等提交记录。 |
| C12 | **unknown** | read-back 未发现对象/marker 是否等于 never-applied；可能存在可见性、覆盖、删除、读错版本或读取失败。 |
| C13 | **conflict** | Kubernetes SSA field conflict 与 resourceVersion lost-update conflict 都能拒绝写，但保护维度不同；不可互换。 |
| C14 | **conflict** | Step Functions Standard 工作流 exactly-once 与 Express at-least-once 不能合并为统一工作流保证；下游资源仍需自己的证据链。 |

## 7. 覆盖、局限与非生产声明

已检索并引用官方产品文档；未进行真实写入、未连接账户/集群/桶、未测试错误码、未测量跨区域一致性或 workflow cancellation race。文档中的“条件失败即该条件操作不继续”被用于协议级推断；任何跨资源、跨服务、跨区域 exactly-once、回滚、旧进程无副作用结论均保持 UNKNOWN。版本/默认策略可能变更，实施时应固定 API 版本并保存响应原文。

## 8. 下一独立切片建议（不停止研究线）

**S7 建议：`UNKNOWN -> CONFIRMED` 的最小可审计 evidence bundle 与故障注入矩阵**。仅使用各官方 API 的模拟器/文档样例，设计 request-id、idempotency-key、epoch、pre-read、write response、read-back、审计日志的统一 schema；逐项注入 send-before-cancel、response-lost、stale-token、new-writer-race、overwrite/delete、跨区域读延迟，输出“哪一条证据足够晋级、哪一条仍只能 UNKNOWN”的可复现测试计划。不得声称生产结果。
