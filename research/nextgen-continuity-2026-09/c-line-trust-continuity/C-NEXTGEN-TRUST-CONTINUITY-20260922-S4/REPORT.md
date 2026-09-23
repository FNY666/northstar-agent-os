# S4：资源侧 CAS/ETag、epoch/fencing token 与幂等键的语义边界

- 研究切片：C 线下一独立公开研究切片 S4
- 截止/访问日期：2026-09-22（Asia/Shanghai）
- 证据范围：仅 Kubernetes、Amazon、Google Cloud、Microsoft 的公开官方一手文档；未读取既有 C 线目录、其他本地研究产物、shared/P0、事故目录、D10、L12、D14、canonical、staging、140、tri-line、systemd、真实服务或凭据。
- 术语约定：本文把“verified”对应清单中的 `confirmed`；“unknown”对应 `unverified` 或 `inaccessible`。结论只在各厂商文档明确的服务边界内成立。

## 1. 结论（先给边界）

1. **资源版本/CAS/ETag 是并发裁决（conditional write/read）机制，不是授权机制。** Kubernetes `resourceVersion` 让 API server 发现过期写并以 409 拒绝；S3 的 ETag 条件写、GCS 的 generation/metageneration 前置条件、Azure Blob 的 `If-Match` 都是在服务端比较资源状态后决定该次请求是否继续。它们不替代身份认证、授权、审计或业务权限判断。
2. **epoch/fencing token 的核心是拒绝旧持有者；本文找到的 Azure lease 是租约/互斥写删除权，不是一个由服务端递增、并在下游资源上比较的通用 fencing epoch。** Azure lease ID 必须带入受保护写入，过期/错误 ID 会失败；但 lease 可过期、可 break，且文档没有把它定义成跨下游系统的单调 epoch。Kubernetes `resourceVersion` 是存储版本，AWS/GCS/Azure ETag/generation 是各自资源版本/验证器；不能未经额外协议就叫“生产 fencing token”。
3. **幂等键是请求去重/重试语义，和 CAS 不同。** AWS EC2 官方文档定义 client token：同 token、同参数的成功重试不再执行动作；参数变化会 `IdempotentParameterMismatch`，且作用域可为 Region 或 Availability Zone。它解决“同一 API 请求重试不要重复创建”的问题，不证明某个外部副作用已经完成，也不替代资源版本条件。
4. **任何单项机制都不能单独宣称 exactly-once、生产 fencing 或外部副作用完成。** CAS/ETag/generation 只能回答“本次操作相对于资源观察值是否被接受”；lease 只能在其服务与有效期/ID规则内限制写删除；token 只能在规定的键、参数、作用域、保留期和 API 实现内去重。网络响应丢失、下游副作用、授权变更、租约失效、服务重试与跨系统原子性都仍需单独设计和证明。
5. **推荐组合：**（a）先做身份/授权；（b）读取资源及版本/ETag/generation；（c）以条件写或 API 明确的 `resourceVersion`/field ownership 做并发裁决；（d）若存在租约，带 lease ID 写入并设计续租、过期、break、交接；（e）对会产生请求级重复风险的 API 使用有范围与生命周期定义的幂等键；（f）把外部副作用放在有独立幂等记录/事务性 outbox/回执或对账的协议中。最后一项是设计推论，不是这些官方文档承诺的跨系统 exactly-once。

## 2. 逐条证据账本

| ID | 命题与标签 | 官方直接证据 | 边界/判定 |
|---|---|---|---|
| K1 | **verified**：Kubernetes `resourceVersion` 表示对象在底层持久化层的版本；PUT 携带旧版本时，API server 可检测 lost update，过期时返回 409。 | Kubernetes API Concepts 明确称其为 persisted version，并明确 stale `resourceVersion` 的 PUT 返回 HTTP 409 Conflict。 | 这是资源存储层的乐观并发控制；不是身份授权，也不是下游 fencing。 |
| K2 | **verified**：Kubernetes `resourceVersion` 也有 GET/list/watch 语义；历史版本不一定保留，过旧 watch 可能 410，客户端须重列/重建 watch。 | API Concepts 说明 watch 从指定版本开始、历史窗口有限、不可用版本返回 410 Gone。 | “版本”并不等于永久单调租约；拿 watch 游标当写者 epoch 是语义错误。 |
| K3 | **verified**：SSA 按 field manager 记录字段所有权；改变别的 manager 所拥有的不同值会冲突并拒绝，`force` 可覆盖并转移所有权。 | Server-Side Apply 文档明确定义 field-level conflict、`managedFields`、force override 与 ownership transfer。 | SSA 是字段级声明式并发/所有权模型；普通 update 与 SSA 的冲突行为不同，不能泛化成所有 Kubernetes 写入的 fencing。 |
| K4 | **verified**：S3 条件请求可用 ETag 限制 GET/HEAD/COPY，也可用条件写检查 ETag 未变，避免无意覆盖；条件不满足则操作失败。 | S3 “Add preconditions…” 文档明确列出 conditional reads/writes/deletes 与 “ETag unchanged before updating”。 | 它是对象请求的条件裁决；文档没有把 ETag 变成授权凭证、租约或跨服务 fencing token。 |
| G1 | **verified**：GCS `generation` 标识对象版本且替换同名对象会得到不同 generation；`metageneration` 标识该 generation 的元数据版本。 | Cloud Storage 对象元数据文档明确区分 generation 与 metageneration。 | generation 是对象/元数据版本标识，不是通用持有者 token。 |
| G2 | **verified**：GCS `ifGenerationMatch`/`ifMetagenerationMatch` 不匹配返回 412；值 0 对“当前不存在对象”有特殊 create-only 语义。 | Cloud Storage 请求前提条件文档明确列出 match 条件、412 与 generation-match=0。 | 这是服务端条件请求；可帮助安全重试/防覆盖，但不自动覆盖外部副作用。 |
| G3 | **verified**：GCS 官方示例说明先读 generation，再把它放进删除/写入的 match 前置条件，可拒绝删除其他 generation；上传使用 0 可避免重复写入竞态的一类情况。 | 请求前提条件文档直接描述这两种场景。 | 这是有范围的请求安全性说明，不应升级为跨系统 exactly-once。 |
| A1 | **verified**：Azure Blob `If-Match` 仅在资源 ETag 匹配时执行，失败返回 412；`If-None-Match` 是不匹配时执行。 | Microsoft Learn “Specifying conditional headers…” 表格给出判断和 412。 | ETag 是 HTTP 条件验证器；不是权限、租约或跨资源 epoch。 |
| A2 | **verified**：Azure Blob lease 为 blob 写/删创建和管理锁；期限可 15–60 秒或无限；写入需带活动 lease ID，错误/缺失 ID 对受保护写入返回 412。 | Microsoft Learn “Lease Blob” 明确 acquire/renew/change/release/break、期限、写入要求与状态码。 | lease ID 证明当前服务端租约条件，但不自动使旧客户端在任何外部系统失效。 |
| A3 | **verified**：Azure lease break 后不能 renew；break 期间新租约不可立即取得；lease 过期后旧 ID 的 renew/release 是否成功取决于 blob 自上次有效租约以来是否被修改或重新租用。 | Lease Blob 的 remarks/state/outcome 表直接给出这些转移和结果。 | 这是有时序/状态机的租约，不是永不复用、由服务端递增的 fencing epoch。 |
| E1 | **verified**：AWS EC2 client token 是最多 64 个 ASCII 字符的唯一、区分大小写字符串；同 token、同参数的成功重试不再进行额外动作；参数变化会 `IdempotentParameterMismatch`。 | EC2 “Ensuring idempotency…” 逐字定义 client token 和重试行为。 | 这是请求去重/重试语义，不能替代条件写或资源版本判断。 |
| E2 | **verified**：EC2 幂等范围依 API 既可为 Region 也可为 Availability Zone；同 token 在另一 scope 可能再产生一次动作。 | 文档的 Regional/Zonal idempotency 与 RunInstances 示例明确说明。 | 幂等键必须连同作用域、参数等一起建模；“全局唯一且永不过期”不是官方保证。 |
| X1 | **inferred**：要同时防止“旧状态覆盖”和“请求重试重复创建”，通常需要条件版本（CAS/ETag/generation/resourceVersion）与幂等键两层组合。 | 推论基于 K1/K3/K4/G2/A1/E1 的功能分工：前者比较资源状态，后者识别同一请求。 | 这是架构推论；具体 API 是否允许同时携带两者、键保留多久、失败后如何重试必须查该 API 合约。 |
| X2 | **inferred**：真正的 fencing 需要下游资源在每次写入时比较令牌/epoch，并拒绝旧令牌；仅在协调器中“持有 lease”不足以约束不受该 lease 检查的下游。 | 官方材料分别定义 Azure blob lease 的本服务写保护和各资源版本条件；没有给出跨系统 fencing 承诺。 | 这是分布式系统语义推论，不把任何供应商字段冒充为已证明的通用 fencing token。 |
| X3 | **inferred**：可对外宣称的 exactly-once 范围最多是某个 API 在其 idempotency scope/参数/状态保留规则下的请求行为；不能从“成功响应”单独推导外部副作用已完成。 | AWS 文档只承诺同 token 重试不再执行进一步动作；其他文档只承诺条件裁决/锁。均未承诺跨系统副作用。 | 应用必须有副作用回执、可查询结果、事务性 outbox/去重表或对账等额外证据。 |
| U1 | **unknown**：这些文档没有统一规定 ETag、generation、resourceVersion、lease ID 的跨厂商格式、寿命、可比较性或可跨资源复用性。 | 各文档均以本服务、本资源 API 描述；未见跨产品标准承诺。 | 不得将不同服务的“版本字符串/数字/ID”直接互换。 |
| U2 | **unknown**：在网络超时、服务端已提交但响应丢失、客户端崩溃、租约过期与外部副作用并发时，具体业务流程能否恢复到唯一可证明结果。 | 本次官方材料未提供该业务的完整跨系统协议或副作用回执定义。 | 需要针对目标 API/业务补充状态查询、审计和恢复实验；不能凭这些资源条件器作结论。 |
| C1 | **conflict（概念不可合并）**：把所有 ETag/版本字段统一解释为“内容 hash”或“生产 fencing token”，与供应商各自合同的用途不一致。 | S3 文档把 ETag作为对象条件；Azure 文档把 ETag作为 HTTP 条件验证值；Kubernetes/GCS 文档分别给出存储版本/generation 语义。 | 这不是声称官方页面互相矛盾，而是跨厂商抽象发生语义冲突；正确做法是保留 provider-specific contract。 |

## 3. 语义矩阵：谁解决什么问题

| 机制 | 授权 | 并发裁决 | 拒绝旧写者 | 请求去重 | 外部效果证明 | 可否单独 exactly-once/fencing |
|---|---|---|---|---|---|---|
| Kubernetes `resourceVersion` | 否；仍需认证/RBAC等 | 是，特定资源写入的版本匹配；watch 另有游标语义 | 对“旧 resourceVersion 的该次 API 写”通常是 409；不是跨系统旧持有者失效 | 否 | 否 | 否 |
| Kubernetes SSA `managedFields` | 否 | 是，字段所有权冲突；可 force | 只约束 API server 记录的字段 ownership；force 可覆盖 | 否 | 否 | 否 |
| S3 ETag conditional request | 否 | 是，按对象 ETag 条件成功/失败 | 对不满足条件的对象请求拒绝；不是租约 | 否（单独） | 否 | 否 |
| GCS generation/metageneration precondition | 否 | 是，版本/元数据版本匹配；失败 412 | 对不匹配 generation 的目标请求拒绝 | 某些 create/retry 竞态可被 0 或 match 限制，但不是通用请求去重 | 否 | 否 |
| Azure Blob ETag `If-Match` | 否 | 是，HTTP 条件裁决 | 对 ETag 不匹配的请求 412 | 否 | 否 | 否 |
| Azure Blob lease ID | 请求仍需授权 | 对同一 blob 的租约受保护写/删提供互斥条件 | 活动 lease 要求匹配 ID；过期/破坏状态有明确限制；非跨系统 | 否 | 否 | 否；须额外 epoch/fencing 检查 |
| AWS EC2 ClientToken | 不是权限 | 不是资源版本 CAS（除非 API 另有条件） | 不是旧 writer fencing | 是，在 API 规定 scope/参数内 | 否；只说明请求是否重复执行/结果可再查询 | 否 |

## 4. 组合方式与反模式

### 4.1 建议的请求路径

1. **授权层**：先由服务认证调用方并执行资源级权限检查；不要把 ETag、generation、lease ID 或 client token 当 bearer credential。
2. **观察层**：读取资源、当前版本/ETag/generation（以及需要时 metageneration、SSA managed field ownership），连同业务操作意图形成工作项。
3. **裁决层**：更新时附带相应条件：Kubernetes 用合约要求的 `resourceVersion`/SSA field manager；S3 用 ETag 条件；GCS 用 generation/metageneration；Azure 用 `If-Match`。条件失败属于冲突/过期，应重新读取并重算，不是盲目重复旧写。
4. **互斥/交接层（可选）**：若确需单写者，使用 Azure lease 或业务协调器；把 acquire、renew、expiry、break、release、交接和失联恢复写成状态机。受保护下游每次写必须验证仍有效的 lease/epoch；否则“拥有协调器 lease”不能证明下游不会接受旧写者。
5. **重试层**：对 API 支持的 client token 使用稳定键；同一语义请求必须保持相同参数，改变参数应生成新键；把 API 的 Region/AZ/项目/资源作用域纳入键命名和去重表。网络超时后优先查询服务端状态，再按 idempotency 合约重试。
6. **副作用层**：若请求还会发消息、扣款、调用另一个系统或执行不可逆动作，在副作用接收端建立自己的幂等键/版本条件和结果查询；使用事务性 outbox、去重记录、可重放事件或对账回执等额外机制。资源 CAS 的成功不能替代这些证据。

### 4.2 常见错误

- 将 Kubernetes watch 的 `resourceVersion` 当作“当前 writer 的租约 epoch”；watch 版本会因历史保留/410 而失效，且其基本用途是变更观察。
- 将 ETag 当作密码、授权票据或跨对象可比较的全局序号；官方合约只给出对应资源的条件判断。
- 将 GCS generation 读值缓存很久后无条件使用；正确模式是 match precondition，并处理 412、重新读取和对象版本生命周期。
- 将 Azure lease ID 写在协调器里但下游不检查；租约过期、break 或网络分区后，旧客户端仍可能继续尝试下游，除非下游执行 fencing 检查。
- 将 AWS client token 当作跨 Region/AZ 的全局去重 ID；官方文档明确 scope 可能是 Region 或 AZ，且不同参数会 mismatch。
- 将 HTTP 200/201 或一次成功响应解释为外部动作完成；响应只证明对应 API 在其自身合同内返回了该结果，不能证明旁路副作用。

## 5. 证据与覆盖说明

本次使用的官方一手来源、直接支持摘录和访问时间见 `sources.md`。网页没有统一发布日期时标为“页面未声明发布日期；访问 2026-09-22”，不伪造发布日期。没有使用搜索摘要、博客、论坛或二手评论。没有发现所纳入官方页面之间针对同一 API 行为的直接冲突；`C1` 是跨厂商抽象的概念冲突，已保留而未强行平均化。

未研究：具体业务 API 的 token 保留期/垃圾回收窗口、跨 Region 复制一致性、Kubernetes 各资源类型/子资源的版本细节、Azure Blob lease 与所有 SDK 的重试实现、目标系统的外部副作用协议。这些属于 unknown，不能从本文代替验证。

## 6. 下一独立切片建议（不要停线）

**S5：失联、租约过期与副作用回执的可证伪恢复协议。** 仅选一个公开官方 API（建议 AWS EC2 client token 或 Azure Blob lease），逐项建立时间线测试：请求已提交/响应丢失、token 重试、参数变化、lease 到期、lease break、旧 writer 延迟到达、下游副作用已执行但资源提交未知。只使用官方 API 文档和公开 SDK/规范，产出状态机、可观测字段、恢复决策表，并明确哪些结果仍只能标为 unknown；重点验证“查询后重试”是否能证明外部效果，而不是把 2xx 或 lease 存在当作证明。
