# A 线 reconciliation 研究报告

- **研究切片**：durable reconciliation / 人工审核门 / 补偿 / 关闭条件
- **研究日期**：2026-09-22（Asia/Shanghai）
- **证据边界**：只使用公开官方一手文档；未读取任何本地研究目录或历史产物，未访问 shared/P0、事故目录、D10、L12、D14、canonical、staging、140、tri-line、systemd、真实服务或凭据。
- **语义约定**：`verified`=官方原文直接支持；`inferred`=由一项或多项官方事实推导的设计建议；`unknown`=官方材料没有证明；`conflict`=来源或适用范围存在未消解冲突。

## 1. 结论（先给可执行答案）

### 1.1 主结论

当调用者不能确认外部效果时，系统不应把“本地 workflow/event/log 已写入”当成“外部动作已经发生”。应把请求持久化为可重放的 durable intent，保留稳定业务键，反复查询外部事实；在确认成功、确认失败、或经过明确的人工/业务决策后才关闭。对“请求可能已到达但结果不可见”的区间，默认状态应是 **UNKNOWN / NEEDS_RECONCILIATION**，而不是自动判定失败并盲目补发。

这是一条**综合设计结论（inferred）**，不是任何单一产品的 exactly-once 保证。它受到以下 verified 事实约束：Temporal 明确说明 Activity 可能重试、多次执行，要求幂等；Step Functions 提供 Retry/Catch 和 redrive，但这描述的是编排行为，不是外部副作用的 exactly-once；Kubernetes 控制器通过观测 current state 使其接近 desired state；CloudTrail 记录活动但日志不是有序 API stack trace。

### 1.2 状态机建议（inferred）

`INTENT_DURABLE → DISPATCHING → OUTCOME_UNKNOWN → RECONCILING → {CONFIRMED_SUCCESS | CONFIRMED_FAILURE | MANUAL_REVIEW} → {CLOSED | COMPENSATION_PENDING} → CLOSED`

- **INTENT_DURABLE**：意图、业务键、参数摘要、策略版本、创建时间已持久化。
- **DISPATCHING**：可有多次尝试；每次带同一业务键/幂等键，并记录尝试号。
- **OUTCOME_UNKNOWN**：超时、连接断开、响应丢失、查询不完整，或审计/外部读模型尚未可见；禁止仅凭本地错误判断外部未发生。
- **RECONCILING**：按退避和截止时间查询外部权威状态；查询本身也要记录证据和时间点。
- **CONFIRMED_SUCCESS/FAILURE**：必须由规定的外部事实、可验证响应，或受控人工决定支持。
- **MANUAL_REVIEW**：高风险、状态长期未知、冲突、不可逆动作或补偿失败时进入；审核人要看到正反证据、最后查询时间、尝试记录和预期/实际差异。
- **CLOSED**：只在关闭条件满足时关闭，且保存证据引用；关闭不等于永久证明外部系统没有迟到事件。

### 1.3 关闭条件（inferred；产品策略需自行批准）

允许自动关闭为成功：外部权威查询返回与业务键、目标资源、版本/金额/数量等相符的成功事实，并且该事实满足新鲜度和完整性要求；若查询源是最终一致读模型，需达到规定的稳定观察窗口或由更权威源确认。

允许自动关闭为失败：外部权威源明确返回不可重试的业务失败，且已确认没有成功副作用；或补偿动作已被外部权威源确认完成。仅有 timeout、5xx、连接断开、空结果、单条日志、任务失败，不满足此条件。

必须人工审核：仍为 UNKNOWN 超过 SLA/最大重试窗口；同一业务键出现互相冲突的外部证据；补发可能产生重复/不可逆副作用；查询源不完整；或补偿本身失败/结果未知。人工“批准重试”“批准补偿”“批准关闭”应成为独立、可审计决策，而不是把未确认事实改写成成功。

### 1.4 明确禁止的表述

本切片**不能声称 production、exactly-once、无重复副作用、日志即外部效果**。官方文档支持的是特定产品的重试、唯一运行标识、控制循环、审计记录或人工保护门；这些都不等价于端到端 exactly-once。

## 2. 证据账本

| ID | 结论 | 状态 | 直接证据与边界 |
|---|---|---|---|
| C1 | Temporal Activity 可能重试并执行多次；应设计为幂等。 | verified | Temporal《Activity Definition》明确写明 Activity 可能被 retry，函数可能执行多次；若 Activity 完全未向 server 报告也会重试；并定义 idempotent。该页没有给出外部系统 exactly-once。 |
| C2 | Temporal Workflow ID 可作为业务含义标识；同一 Namespace 同时最多一个同 ID 的 Open execution，Run ID 唯一标识一次 execution。 | verified | Temporal《Workflow Id and Run Id》原文直接说明这些约束；闭合后同 Workflow ID 可以再次有 Open execution，因此不能把 Workflow ID 当全生命周期唯一事件号。 |
| C3 | Step Functions 对部分状态提供 Retry/Catch；redrive 会重置某些状态的 retry attempt count。 | verified | AWS《Handling errors in Step Functions workflows》直接描述 Task/Parallel/Map 的 Retry、Catch、退避与 redrive 行为。该机制只约束状态机执行，不证明被调用外部动作未重复。 |
| C4 | CloudTrail event 是账户活动记录；CloudTrail 日志不是有序公共 API 调用 stack trace。 | verified | AWS《CloudTrail concepts》直接如此说明，并区分 event history/trails 等交付形态。由此单条日志的存在只能证明记录存在，不能单独证明业务外部效果已达到目标。后半句是受边界约束的 inferred。 |
| C5 | 分布式系统可能有 eventual consistency 延迟，调用者应为延迟设计。 | verified | AWS IAM《Troubleshoot IAM》明确说明 IAM 使用 distributed computing model called eventual consistency，并要求 global applications account for delays。该页不规定本项目具体等待窗口。 |
| C6 | Kubernetes controller 是 control loop，观察 current state，使其靠近 desired state；与外部状态交互时会读取并报告状态。 | verified | Kubernetes《Controllers》直接描述 desired/current state、控制循环、最终完成及外部状态控制器。它是 reconciliation 的官方概念模型，不是第三方 API 的成功保证。 |
| C7 | GitHub Actions environment 可设置 required reviewers；规则通过前 job 不运行/不取得 environment secrets；可配置 wait timer、分支限制和自定义保护规则。 | verified | GitHub《Managing environments for deployment》直接描述 required reviewers、最多 6 人/团队、任一 reviewer 批准即可继续，以及保护规则和 secrets 的门控。适合作为人工审核门的官方实例，不证明审核决定正确。 |
| C8 | GitHub Actions rerun 使用原始触发 actor 的权限、原 GITHUB_SHA/GITHUB_REF，并有最多 50 次 rerun 限制。 | verified | GitHub《Re-running workflows and jobs》直接说明；重跑是恢复/人工操作能力，不是幂等或外部效果确认。 |
| C9 | Durable intent + 查询外部权威状态 + UNKNOWN 状态 + 人工门 + 补偿闭环，是本研究推荐架构。 | inferred | 由 C1/C3/C4/C5/C6/C7 综合推导；不是任一供应商承诺，也未经本切片做 production 测试。 |
| C10 | 仅凭日志存在、workflow 完成、retry exhausted 或查询空结果即可关闭。 | unknown / 不成立为 verified | 所查官方资料没有给出这种一般保证；相反 C1、C3、C4、C5 表明重试、记录、延迟均可能与外部最终状态分离。 |
| C11 | 端到端 exactly-once 外部副作用可由上述产品自动提供。 | unknown | 官方页面未证明该命题；Temporal 明确提醒多次 Activity execution 的风险，Step Functions 仅说明编排重试/redrive。 |
| C12 | 本切片的推荐阈值、SLA、查询稳定窗口、补偿资格矩阵在所有部署中都正确。 | unknown | 未访问真实服务、部署配置、业务风险分类或供应商账号；必须由系统所有者定义和验证。 |
| C13 | 资料之间存在可直接裁决的矛盾。 | conflict 未发现 | 没有找到同一产品、同一版本、同一语义上的直接冲突；不同产品的保证范围不可横向当作同一保证。 |

## 3. 操作设计

### 3.1 Durable record 最小字段（inferred）

`reconciliation_id`、稳定 `business_key`、目标系统/资源、期望状态摘要、不可变请求摘要或哈希、幂等键、策略/代码版本、当前状态、尝试次数、最后发送时间、最后响应分类、最后查询时间、外部证据引用、证据新鲜度、人工决策记录、补偿记录、关闭理由和关闭人/自动规则版本。敏感凭据不得进入研究或运行日志。

Temporal 的 Workflow ID/Run ID 可作为编排侧关联标识（C2），但业务幂等键仍需由应用定义；Run ID 变化不应使同一业务意图变成新意图。Activity 重试意味着外部动作必须接受重复尝试（C1）。

### 3.2 查询不完整与外部结果未知

1. 发送前先落盘 intent；发送后无论响应如何都追加 attempt。
2. 将 timeout、断连、响应截断、读模型空、审计事件未到达标为 `OUTCOME_UNKNOWN`，不标为 failed。
3. 查询权威外部状态，按退避查询；保存每次查询的时间、游标/分页范围、结果摘要和来源。
4. 若查询是最终一致读模型，等待窗口只作为“再查”策略，不能当成成功/失败证明；若窗口到期仍未知，进入人工门。
5. 只有匹配业务键且字段满足校验的外部事实才可转 CONFIRMED；日志是证据之一，不是效果本身（C4）。

### 3.3 重试与补偿

- 对可安全重试的动作使用固定业务键和外部幂等语义；若外部系统无此能力，不自动补发不可逆操作。
- 退避、最大尝试数、抖动和异常分类可借鉴 Step Functions Retry 的参数模型（C3），但阈值是系统策略而非 AWS 的普适保证。
- 补偿不是“撤销历史”而是另一项外部动作；必须有自己的 intent、幂等键、查询和 UNKNOWN 状态。
- 先查询再补偿：若原动作已发生，避免重复正向动作；若业务允许，用明确的反向动作修复；如果反向动作不可安全执行，转人工。
- 补偿完成必须由外部权威状态确认，不能由“补偿任务成功写日志”确认。

### 3.4 人工审核门

审核包至少包含：业务意图与风险、期望状态、所有发送/响应/查询时间线、正反外部证据、证据新鲜度与覆盖缺口、可能重复的副作用、建议动作（查询/重试/补偿/关闭）及回滚后果。审批与执行分离，审批者/时间/理由/策略版本不可变记录。GitHub required reviewers 是“规则通过前 job 不运行/不取得环境 secrets”的官方模式（C7）；本项目将该模式抽象为人工门，但不得声称 GitHub 的门能验证其他系统的外部事实。

## 4. 关闭与审计判定表

| 情形 | 自动动作 | 关闭？ | 理由 |
|---|---|---|---|
| 外部权威源返回匹配成功，关键字段一致 | 记录证据，转 CONFIRMED_SUCCESS | 是 | verified 外部事实，满足预设新鲜度/完整性 |
| 明确业务拒绝且确认无副作用 | 记录拒绝，转 CONFIRMED_FAILURE | 是 | 失败是外部事实，不是网络推断 |
| timeout/断连/5xx/响应丢失 | 转 OUTCOME_UNKNOWN，查询 | 否 | 可能已到达，C1/C3 的重试模型不能证明未执行 |
| 查询空或读模型暂未出现 | 继续查询/等待窗口 | 否 | C5 的 eventual consistency 风险；空不等于不存在 |
| 达到重试上限仍未知 | 转 MANUAL_REVIEW | 否（自动） | 需要人为决定是否查询、补偿或有条件关闭 |
| 外部证据互相冲突 | 冻结自动补发，转 MANUAL_REVIEW | 否（自动） | 防止重复/不可逆副作用 |
| 补偿有明确外部确认 | 转 CLOSED，保留原动作和补偿链 | 是 | 关闭的是业务目标，不是抹除历史 |
| 仅有本地日志/workflow success | 保持待核验 | 否 | 日志记录与外部效果不是同一命题（C4） |

## 5. 覆盖、限制与未知

- 已查官方一手来源：Temporal、AWS Step Functions、AWS CloudTrail、AWS IAM、Kubernetes、GitHub Actions。
- 未做：生产验证、真实服务调用、账号操作、凭据访问、性能/故障注入、exactly-once 实验、供应商合同/SLA 解读。
- 未验证：任何具体外部 API 的幂等键语义、读模型延迟分布、审计日志完整性、业务补偿可逆性、人工审核误判率。
- “最终一致性”在不同服务上的具体窗口不应从 AWS IAM 文档外推到所有 AWS 或第三方服务；本报告只使用它证明“延迟需要被设计”。
- GitHub 文档的计划/仓库可用性条件可能随计划变化；本报告只抽取 required reviewers 等机制的语义，不做可用性承诺。

## 6. 结论等级

- **Verified**：C1–C8 的产品文档事实。
- **Inferred**：C9，以及状态机、字段、关闭表和补偿流程；它们是基于官方事实的设计推导。
- **Unknown**：C10–C12 所列未证明命题和部署相关阈值。
- **Conflict**：本次来源集中未发现同语义直接冲突（C13）；若把不同产品的重试/日志/控制循环误拼成端到端保证，则是适用范围冲突，不应“平均”成一个结论。

**最终判断**：可交付的安全闭环不是“任务结束”，而是“意图可重放、外部事实可查询、未知可停留、风险动作有人审、补偿也可核验、关闭有证据”。这仍不构成 production 或 exactly-once 声明。
