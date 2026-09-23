# S3 durable reconciliation 研究报告

**研究编号**：S3  
**隔离目录**：`/tmp/A81254C8-RECONCILIATION-MANUAL-20260922-S3/`  
**研究日期**：2026-09-22（Asia/Shanghai）  
**证据范围**：仅公开官方一手资料；AWS、Temporal、Kubernetes、GitHub 官方文档。未访问本地研究目录、历史产物、shared/P0、事故目录、D10/L12/D14/canonical/staging/140/tri-line/systemd、真实服务或凭据。

## 1. 结论摘要

1. **观察窗口没有通用固定时长。** 只能依据目标系统声明的传播、事件摄取、缓存/读模型刷新、重试/backoff、异步作业完成上界建立窗口。上界未被验证时，结论必须是 **UNKNOWN**，不是“等待一会儿就成功”。窗口结束后仍要做至少两次、时间分离且相关键一致的权威 read-back；一次 read-back 不足以证明稳定。
2. **平台完成不等于外部完成。** Step Functions 的 Standard exactly-once 是工作流执行模型；Express 是 at-least-once；Temporal 的 Activity 会自动重试；Kubernetes controller/Job 反映其控制面/工作负载状态。它们都不能自动证明第三方系统副作用恰好发生一次、未重复或已被外部权威系统接受。
3. **冲突证据保持 UNKNOWN/CONFLICT。** 若 CloudTrail/平台事件、目标 API、资源读模型或业务账本在相同相关键、版本与时间边界下互斥，或者来源的身份、覆盖、时间新鲜度无法验证，不得用较“乐观”的证据覆盖较“悲观”的证据；暂停可能产生副作用的自动动作并升级人工批准。
4. **人工批准是风险门，不是事实证明。** GitHub Environments 的 required reviewers/wait timer 可提供门控；Step Functions callback 可等待人工或第三方回调。审批只能授权下一步，不能将未知外部效果变成已证实效果。
5. **补偿也必须按可能重复执行设计。** 补偿请求要有稳定幂等键/条件写/去重语义，重试后用独立、具备来源与新鲜度证明的 read-back 验证；补偿“成功”只证明补偿目标被观察为目标状态，不证明原副作用从未发生或系统全局没有重复。
6. **关闭工单须有证据链。** 目标或批准的补偿状态在窗口后连续确认；冲突已解决或经明确批准接受例外；请求、尝试、重试、查询、证据版本和批准记录可关联；没有未解释副作用风险。任一缺项都保持 UNKNOWN/OPEN。

## 2. 证据分类规则

- **VERIFIED（对应 manifest `confirmed`）**：官方文档直接陈述的平台行为，且只在其明确边界内使用。
- **INFERRED（对应 manifest `inferred`）**：由多个官方机制推导出的操作控制规则；是本研究建议，不冒充平台承诺。
- **UNKNOWN（对应 manifest `unverified`/限制）**：本切片没有测量、没有可靠来源，或证据新鲜度/覆盖范围不能验证。
- **CONFLICT（对应 manifest `conflicting`/本报告状态）**：独立权威证据对同一相关键与状态互斥；在人工裁决前不降级为成功或失败。

本切片的官方平台语义均可 **VERIFIED**；窗口、冲突处理、补偿安全和关单门槛是 **INFERRED** 控制策略；具体系统延迟和外部效果均 **UNKNOWN**。本报告没有发现可在具体业务对象上裁决的实际证据冲突，因此没有把事实伪装成“已解决”。

## 3. 稳定观察窗口

### 3.1 窗口组成

为一次 reconciliation 建立 `t0`（最后一次可能产生副作用的 attempt/重试/补偿请求的时间），并记录：

- `L_action`：目标 API 或队列接受后，业务效果可见的最大传播时间；
- `L_event`：审计/事件系统可摄取并可查询的最大延迟；
- `L_read`：权威读模型或索引刷新上界；
- `L_retry`：编排器、controller、Job、Activity 的剩余重试/backoff 或 redrive 可能性；
- `L_clock`：时钟偏差、事件时间与查询时间边界；
- 安全余量与连续观察次数。

若这些上界没有来自目标系统的可核验契约，`window_sufficient` 为 **UNKNOWN**。建议最早的稳定判定时间不早于 `t0 + max(L_action, L_event, L_read, L_retry, L_clock) + margin`；这只是控制公式，不是任何平台的 SLA。

### 3.2 窗口后的最低证据

每一次查询必须包含稳定相关键（request/idempotency key、资源 ID、目标版本/generation 或业务账本 ID）、查询时间、来源身份、读模型版本/更新时间、原始响应摘要和错误/空结果语义。至少需要：

- 目标权威源返回期望状态；
- 独立审计证据能关联请求/资源/身份/时间（若该系统承诺提供此证据）；
- 在一个重新分离的观察点再次 read-back 仍为期望状态；
- 没有活动中的 retry、redrive、controller 对账、队列重投或补偿；
- 对“空查询”说明查询是否真的覆盖了目标资源和时间范围。空集合不是“不存在副作用”的证明。

### 3.3 明确禁止的自动推论

- workflow/platform `SUCCEEDED` ≠ 外部业务状态已完成；
- CloudTrail 单个事件 ≠ 业务效果完整发生；
- Job `Complete` 或 controller 已收敛 ≠ 第三方 API 效果被确认；
- 空查询 ≠ 未发生；
- 单次 read-back ≠ 稳定；
- retry 没报错 ≠ 第一次请求没成功；
- callback 到达 ≠ 回调方提供的外部状态真实、最新且未被重放；
- Standard exactly-once ≠ 端到端外部副作用 exactly-once；
- 本切片 ≠ production 观察、验证或上线批准。

## 4. 外部权威证据冲突处理

### 4.1 证据记录

每份证据保存：`source_kind`、`issuer/identity`、`resource_id`、`correlation_id`、`observed_at`、`event_time`、`version/generation`、`fresh_until`、查询条件、原始状态、签名/权限上下文（如有）、是否为缓存或最终一致读模型。

### 4.2 冲突判定

下列任何一种情况保持 **CONFLICT/UNKNOWN**：

- 同一 correlation/resource/version 下，一个权威源为 applied/active，另一个为 absent/reverted；
- 平台完成与业务账本状态互斥，且没有已验证的传播延迟解释；
- 事件显示 request accepted，但权威 read-back 显示目标未达成，且窗口上界未过；
- 两个“权威”来源无法证明哪个拥有更高版本、更新时间更晚或更大覆盖范围；
- 空结果与此前已确认存在的目标对象冲突；
- 证据的身份、时间、租户/区域、分页、过滤器或新鲜度不能验证。

### 4.3 处置顺序

1. 冻结会产生不可逆、重复收费、重复通知、权限扩大或数据覆盖的自动 retry/compensation；只保留安全查询与证据采集。
2. 在同一相关键和版本边界下重新读取两个来源，记录查询时间，不覆盖旧证据。
3. 查明是否是延迟、缓存、分页、区域、权限、版本或事件摄取问题；没有可验证解释就不“择一相信”。
4. 升级人工 reviewer；批准内容须明确“继续原动作 / 执行补偿 / 接受风险并关闭 / 维持 UNKNOWN”，而非只有一个模糊的 approve。
5. 若风险高或证据永久不可裁决，保持 OPEN/UNKNOWN，转入例外处理，不以超时自动关闭。

## 5. 人工批准门

**触发条件**：互斥权威状态、不可逆补偿、权限/金钱/数据覆盖风险、重复副作用概率不明、窗口上界不明、或关单证据链不完整。

**批准包**至少含：事件时间线、相关键、每次 attempt/retry/redrive、外部查询原文摘要、证据新鲜度与覆盖、拟执行动作、预期副作用、幂等键、回滚/补偿方案、停止条件、批准人身份和时间。

GitHub 官方文档验证 required reviewers、wait timer 和保护规则通过后才暴露 environment secrets；Step Functions 官方文档验证 `.waitForTaskToken` 可等待人工/第三方 callback。可借鉴这些平台的门控模式，但本研究不声称任何特定部署已启用它们，也不把审批本身当作效果证据。禁止 self-approval、禁止“发起者自动批准”（若平台支持此保护），并尽量将审批人和执行人分离。

## 6. 补偿安全性与 read-back

补偿动作的安全前提：

1. **业务幂等**：使用原始请求关联的补偿幂等键；重复提交返回同一逻辑结果而不重复副作用，或由目标系统条件写/唯一约束保证。
2. **目标限定**：按资源 ID、版本/generation、业务账本/租约条件执行，避免“按当前状态盲目撤销”误伤新一轮合法变更。
3. **可停止**：补偿也有超时、重试上限、人工门和冲突升级，不因平台 retry 默认行为无限扩大副作用。
4. **独立验证**：补偿请求完成后，在新的观察点从权威读模型和必要的审计记录 read-back；查询必须能区分“未找到”“尚未可见”“权限/过滤错误”。
5. **重复未知保留**：若原请求 timeout/断连后状态未知，不能先假定失败再无保护地补偿；先用幂等查询/状态查询，仍未知则人工判断。

“补偿完成”只可写成 `compensation_observed=true`（并附来源、时间、版本），不可写成 `original_effect_never_happened=true` 或 `no_duplicate_side_effect=true`，除非目标系统有明确、可验证的全局证明契约（本切片没有这样的具体系统证据）。

## 7. 关单条件与状态机建议

建议状态：`OPEN → OBSERVING → VERIFIED_TARGET`；或 `OPEN → CONFLICT → HUMAN_REVIEW → COMPENSATING → VERIFYING_COMPENSATION → CLOSED_WITH_EXCEPTION/VERIFIED_CLOSED`。任一新冲突回退 `UNKNOWN`。

只有在以下条件**全部**满足时允许正常关闭：

- 窗口上界已由目标契约覆盖，且窗口已过；
- 连续两次或以上相关、时间分离的权威 read-back 一致；
- 相关审计证据可定位请求、身份、资源、版本、时间和每次尝试；
- 所有重试/redrive/controller/队列重投已停止或已纳入证据；
- 若做补偿，补偿的幂等键、条件和独立 read-back 完整；
- 权威来源没有未解释冲突，空查询已证明查询语义而非被误读；
- reviewer（当风险触发门槛时）明确批准关闭，并记录其依据。

若目标状态已达成但原始路径存在无法排除的重复副作用，不能标为“无重复”关闭；只能 `CLOSED_WITH_EXCEPTION`，附残余风险、负责人和后续观察任务。若来源不可用、窗口未知或冲突未裁决，保持 `UNKNOWN/OPEN`。

## 8. 逐项可核验结论

- **VERIFIED**：Step Functions Standard/Express 的执行交付模型；Task retry/timeout/redrive 机制；`.sync` 与 `.waitForTaskToken` 等待语义；Temporal Activity retry；Kubernetes controller control loop 与 Job 完成语义；GitHub environment reviewer/wait timer/secrets gate。
- **INFERRED**：窗口必须覆盖全部已知延迟上界；冲突不得自动择优；补偿按可重复执行设计；关单须连续权威 read-back 与完整审计链；人工批准是风险闸门。
- **UNKNOWN**：任何具体外部系统的真实传播延迟、CloudTrail/事件摄取延迟、读模型刷新上界、业务 API 的幂等保证、外部效果是否已发生、是否有重复副作用、是否为 production。
- **CONFLICT**：本切片没有实际业务证据样本，故没有裁决实例；若未来出现同一相关键的互斥来源，按第 4 节保持 CONFLICT/UNKNOWN 并升级。

## 9. 限制

本研究是公开文档切片，不进行真实服务调用，不读取凭据，不验证配置，不提供 production 结论，不承诺端到端 exactly-once，不承诺无重复副作用。所有“稳定窗口”“冲突升级”“关单条件”属于控制策略推论，需由具体目标系统契约和风险负责人批准。
