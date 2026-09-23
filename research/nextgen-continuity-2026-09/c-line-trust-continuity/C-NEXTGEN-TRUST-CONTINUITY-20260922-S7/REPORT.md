# S7：资源侧 stale-writer rejection 证据包与状态机

- **研究切片**：C 线 / S7（独立公开研究）
- **研究目录**：`/tmp/C-NEXTGEN-TRUST-CONTINUITY-20260922-S7/`
- **资料截止/访问日**：2026-09-22（仅官方一手资料）
- **边界**：只讨论资源 API/工作流平台公开语义及如何记录证据；不声称任何平台自动提供业务级 fencing、exactly-once 或旧 writer 的所有副作用清除。
- **隔离声明**：本切片只在上述全新 `/tmp` 目录生成文件；没有读取或修改既有 C 线目录、其他本地研究产物、shared/P0、事故目录、D10、L12、D14、canonical、staging、140、tri-line、systemd、真实服务或凭据。

## 1. 结论（先给可操作答案）

资源侧的条件写拒绝只能直接证明：**本次被该资源端条件检查拒绝/未提交**（命题 P1），且证明范围必须绑定目标资源、条件值、请求身份、请求唯一 ID、服务响应、服务时间和客户端观测时间。它不能单独证明：旧 writer 在此前没有产生外部副作用（P2），新 writer 已提交（P3），或目标最终状态已达到期望（P4）。

推荐的证据状态不是一个布尔 `success`，而是四个独立命题的四值状态：`VERIFIED`、`INFERRED`、`UNKNOWN`、`CONFLICT`。在没有足够证据时保持 `UNKNOWN`，而不是把 HTTP 失败、超时、缓存命中、权限错误、空结果或租约状态解释为成功/失败。

安全的最小流程是：

1. 读目标，保存**强版本/代际条件**（Kubernetes `metadata.resourceVersion`；S3 `ETag`/适用的 `If-Match`；GCS `generation`/`metageneration`；Azure Blob `ETag`/lease 条件）。
2. 为每次写生成不可复用的 `request_id`，记录 writer 身份和 `target_version`（期望写入的业务版本/epoch，而不是把平台版本号冒充业务版本）。
3. 发送带条件写；明确记录请求是否到达资源端、HTTP/SDK code、响应 request ID、服务端时间（若有）及重试次数。
4. 对明确的 stale/precondition rejection，允许判定 P1=`VERIFIED`、P2/P3/P4 仍=`UNKNOWN`；不要原样重放旧 payload。先重新读并重新计算条件。
5. 对平台文档明确建议重试的**冲突型**失败（例如 S3 `409 ConditionalRequestConflict`），仅以同一意图、幂等键/版本安全、重新获得条件后重试；对 `412`/Kubernetes `409 Conflict` 作为 stale/竞争信号，先 read-back/reconcile，不盲重试。网络超时、5xx、响应丢失、权限错误、缓存或空结果均保持相应命题 `UNKNOWN`，除非另有独立证据。
6. 只有 read-back 与请求绑定、读到目标版本/内容与写入意图一致，且在定义的确认窗口内、来源是可信的未过期读，才能把 P4 标为 `VERIFIED`；单次 read-back 仍不证明 P2 或 exactly-once。

## 2. 四个不可混淆的命题

| ID | 命题 | 允许的直接证据 | 明确不能由其单独推出 |
|---|---|---|---|
| **P1 拒绝本次写入** | 资源端检查了条件且本次操作没有提交 | 官方定义的 precondition/stale 响应（如 K8s 409、Azure 412、S3 412），响应与本次 request_id/目标相符 | 旧 writer 没有在资源外做副作用；新 writer 成功；目标最终状态 |
| **P2 旧副作用从未发生** | 旧 writer 在资源写前后以及资源外没有任何不可逆副作用 | 需要端到端、可审计的副作用日志/事务或设计证明；资源端拒绝通常只覆盖该资源操作 | 任意资源条件拒绝、租约、单次读回、工作流状态 |
| **P3 新 writer 已提交** | 新 writer 的特定请求已被资源接受并提交 | 成功响应且与 request_id/目标版本绑定，或独立审计/提交记录；最好再用版本化 read-back 关联 | 旧 writer 被拒绝；租约持有；新 writer“打算写”；缓存返回新值 |
| **P4 目标最终状态已确认** | 在确认窗口和一致性/新鲜度条件下，目标读回与期望版本/内容相符 | 可信 read-back（必要时重复/观察窗口），含版本、内容校验和时间边界 | P1、P3 的单次响应；平台 lease；工作流完成；缓存命中 |

**重要限制（verified/inferred）**：Step Functions 官方仅对 Standard workflow 的状态/任务执行模型给出 exactly-once（除非在 ASL 配置 Retry），Express 是 at-least-once；这不是资源写入或副作用的普遍 exactly-once 证明。Temporal 官方描述 durable execution、Event History replay 和 workflow execution 的本地状态隔离，但这些是工作流编排语义，不等于外部资源提交、fencing 或旧副作用消失。上述边界是基于平台边界的安全推论，标为 `inferred`，不能当作平台明确承诺。

## 3. 记录格式（每次尝试一条 append-only 记录）

建议每条记录包含以下字段；敏感 token 不写入报告，身份采用稳定不可逆标识或审计主体 ID。

```json
{
  "event": "resource_write_attempt",
  "schema": "s7.resource-write.v1",
  "request_id": "uuid-or-platform-request-id",
  "operation_id": "stable-business-intent-id",
  "attempt": 1,
  "resource": {"platform":"kubernetes|s3|gcs|azure-blob", "account_scope":"redacted", "container_or_bucket":"redacted", "key_or_uid":"redacted"},
  "request_identity": {"principal":"stable-audit-id", "role_or_service":"…", "auth_context_hash":"…"},
  "writer_epoch": "opaque-business-epoch",
  "target_version": {"business_version":"v-N", "payload_digest":"sha256:…", "expected_state":"…"},
  "precondition": {"kind":"resourceVersion|ETag|generation|metageneration|lease", "operator":"match|not-match|lease-id", "value":"redacted-or-safe-version"},
  "sent_at": "RFC3339 with offset", "client_received_at":"RFC3339 with offset",
  "service_time":"RFC3339 if supplied", "request_deadline":"RFC3339",
  "response": {"transport":"connected|timeout|unknown", "http_status":412, "provider_code":"…", "provider_request_id":"…", "body_digest":"…"},
  "cache": {"path":"direct|proxy|unknown", "age":"…", "validator":"ETag/Last-Modified/unknown"},
  "read_back": {"attempted":true, "at":"…", "source":"authoritative|cache|unknown", "version":"…", "payload_digest":"…", "freshness_proof":"…"},
  "classification": {"p1":"VERIFIED|INFERRED|UNKNOWN|CONFLICT", "p2":"…", "p3":"…", "p4":"…"},
  "action":"reconcile|safe-retry|compensate|manual-escalation|closed",
  "notes":"bounded factual note"
}
```

### 3.1 必填的版本/代际字段

- **Kubernetes**：从 GET/List 对象保存 `metadata.resourceVersion`（官方定义为该资源在持久化层的版本；可用于 watch）。更新请求把读到的值作为条件；过期值由 API server 以 `409 Conflict` 拒绝。记录对象 UID、`resourceVersion`、resource kind/namespace/name、API server response/request ID（如客户端可得）。不要把 `resourceVersion` 当业务 generation；业务版本应在 spec/annotation 等明确字段中单独记录。

- **S3**：保存对象 key/versioning context、读到的 ETag 以及实际发送的 `If-Match`/`If-None-Match`（只在该 API/存储类型支持且语义适用时）。官方说明条件请求不满足会导致操作失败；PutObject 的 `If-None-Match: *` 在对象已存在时返回 412，在上传冲突时返回 409，文档明确对 409 retry。记录 ETag 不要默认解释为内容 MD5（S3 文档对 multipart/加密等场景有限制）。
- **GCS**：保存 object name、`generation` 和（若更新 metadata）`metageneration`，以及 `ifGenerationMatch`/`ifMetagenerationMatch` 等实际条件（REST/SDK 表达可能不同）。官方说明 generation 标识对象版本、metageneration 随同一 generation 的 metadata 更新递增；不满足 precondition 时请求失败，避免作用于意外版本。generation 与 metageneration 不可混为一个字段。
- **Azure Blob**：保存读回的 ETag、请求的 `If-Match` 条件和 lease ID（若使用 lease），以及 blob/container 标识。官方说明 ETag 每次写后更新；If-Match 不匹配返回 412，活动 lease 未提供 lease ID 的写也返回 412。lease 是并发控制条件，不是 P2/P3/P4 证据。

### 3.2 身份、目标版本、时间窗口

- **身份**：记录实际授权主体（principal/role/managed identity/service account）、调用链/trace ID、writer epoch、客户端版本和重试器版本；权限错误不能被归类为 stale。
- **目标版本**：至少包括业务 `target_version`、payload digest、预期 resource version/generation/ETag；写入后 read-back 必须比较业务版本和 digest，不能只比较 HTTP 200。
- **时间**：记录 monotonic duration（用于客户端顺序）与 RFC3339 wall-clock（用于跨系统关联）；至少有 `read_started`, `write_sent`, `response_received`, `read_back_started`, `read_back_received`，以及服务端时间/日志时间（若有）。确认窗口 `W` 应在系统设计中预先定义，覆盖最大允许传播/缓存 TTL、重试退避、watch/event 延迟和审计落盘延迟；未定义 W 时 P4 只能 `UNKNOWN`。

## 4. 状态机

```
READ_BASELINE
  ├─ read error / permission / empty / cache freshness unknown ─> UNKNOWN_BASELINE
  └─ authoritative version V0 + identity + digest ─> ARMED(V0)

ARMED ── conditional write ─> WRITE_OUTCOME
WRITE_OUTCOME
  ├─ explicit precondition/stale rejection ─> P1_VERIFIED; P2/P3/P4 UNKNOWN
  │                                      └─ authoritative read + reconcile -> ARMED(V1) or ESCALATE
  ├─ success bound to request and target ─> P3_VERIFIED (not P4 yet)
  │                                      └─ read-back in W -> CONFIRM or UNKNOWN/CONFLICT
  ├─ conflict explicitly retryable by provider ─> RETRY_GATE
  ├─ timeout/connection reset/5xx/response lost ─> UNKNOWN_COMMIT
  ├─ auth/permission (401/403) ─> UNKNOWN_COMMIT + permission escalation
  └─ malformed/validation/not-found/empty ambiguous ─> UNKNOWN (classify, don't infer)

RETRY_GATE ── same intent is idempotent, new condition read, bounded budget ─> ARMED(Vnew)
           └─ any uncertainty about prior commit / non-idempotent effect ─> MANUAL/COMPENSATE

CONFIRM ── read-back authoritative + version/digest + W ─> P4_VERIFIED
         ├─ old/contradictory version ─> UNKNOWN or CONFLICT, continue observation/escalate
         └─ cache/permission/empty/partial read ─> UNKNOWN
```

状态机是控制记录和决策的设计建议；它不是某一个平台的额外保证（`inferred`）。

## 5. 失败分类、重试、补偿和升级矩阵

| 观测 | 可标为 | 安全动作 | 不得做的推断 |
|---|---|---|---|
| K8s 条件 `resourceVersion` 过期，HTTP 409 | P1 `VERIFIED` | GET 最新对象，重算 patch/目标版本；只在业务意图仍适用时限次重试 | 旧 handler 无副作用；新 writer 已成功 |
| S3 条件不满足，HTTP 412 | P1 `VERIFIED` | 不重放旧 payload；重新 HEAD/GET 取 ETag，按业务决策合并或人工处理 | 目标最终是什么；旧副作用不存在 |
| S3 PutObject 条件冲突 HTTP 409 | 该次提交结果按响应记录；可将 P1 记为 `UNKNOWN`（除非响应明确是 precondition rejection） | 按 S3 官方建议在有界预算内 retry；每次保留新 request_id，payload 必须幂等/同意图 | 409 一律等同 412；上次一定未提交 |
| GCS generation/metageneration precondition failure | P1 `VERIFIED`（若响应与条件绑定） | 重新获取对应 generation/metageneration；只重算同一意图 | generation 相等即业务目标完成 |
| Azure Blob ETag mismatch / lease missing 412 | P1 `VERIFIED` | GET 最新 ETag/状态；lease 场景先确认 lease 生命周期及身份；重新取得合法条件 | lease holder 一定是新 writer；旧副作用不存在 |
| 成功 2xx/SDK success | P3 `VERIFIED`（仅请求/目标绑定） | 在 W 内 read-back 版本+digest；必要时持续观察 | P4 自动成立；exactly-once 成立 |
| 网络超时、连接重置、响应丢失、5xx | P1/P3/P4 `UNKNOWN` | 不确定提交时，使用幂等键/条件重读；非幂等写转人工/补偿；有限次重试且记录每次 | “没收到响应=没写入” |
| 401/403、K8s RBAC、租户/region 权限错误 | `UNKNOWN`（另记 `permission_error`） | 停止盲重试；核验身份/权限/目标后升级；修复权限后重新读状态 | 权限失败等于 stale rejection 或未提交 |
| 404/空对象/空列表/空 watch、缓存命中但 freshness 不明 | `UNKNOWN` | 确认 scope/key/版本、绕过或验证缓存、做权威 read；空结果需再次界定 | 不存在、已删除、未创建、新状态三者可互换 |
| read-back 得旧值或与新值冲突 | `CONFLICT` 或 `UNKNOWN` | 保留所有证据，停止破坏性重试；补偿/人工升级 | 单次旧读足以证明写失败 |
| lease/锁/平台 workflow “running/completed” | 仅记录平台状态 | 仍须资源提交和目标 read-back；租约过期/转移需 fencing 条件 | 租约或工作流状态证明 P2/P3/P4 |

**安全重试门槛**：请求语义必须是幂等或有服务端条件/幂等键；先明确上一尝试是否可能提交；重试使用新的 `request_id`、当前条件和同一 `operation_id`，有总次数/时间预算；不得用旧 ETag/resourceVersion/generation 盲写。若旧 writer 可能已触发不可逆副作用、payload 非幂等、目标状态互相矛盾，转 `COMPENSATE` 或 `MANUAL_ESCALATION`。

**补偿不是删除历史**：补偿动作本身也要使用条件写、身份和 request_id；记录它只把目标恢复到设计的安全状态，不能把 P2 改成“旧副作用从未发生”。

## 6. 官方证据与逐条状态

### C1 — Kubernetes resourceVersion 用于避免 lost update
- **状态**：`verified`（官方文档直接支持）
- **证据**：Kubernetes API Concepts；对象的 `resourceVersion` 表示持久化层版本，可用于跟踪变化；客户端提供的版本过期时 API server 返回 HTTP 409 Conflict；文档建议需要有效检测 lost update 的客户端让请求以现有 resourceVersion 为条件并处理冲突重试。
- **边界**：覆盖 Kubernetes 该资源 API 的条件/版本检查，不覆盖资源外副作用、所有 controller 行为或 exactly-once。

### C2 — Kubernetes dry-run 不持久化，也不产生副作用
- **状态**：`verified`
- **证据**：同一官方页面说明 dry-run 执行通常处理阶段但不进入最终存储；Kubernetes 保证 dry-run 不会持久化或有其他 side effects。
- **边界**：这是 dry-run 的保证，不能反推真实请求的旧 writer 没有副作用；dry-run 也不是生产 fencing。

### C3 — S3 条件请求与 412/409 语义
- **状态**：`verified`
- **证据**：S3 User Guide “Add preconditions…”说明条件 header 不满足会使 S3 操作失败，ETag 可用于限制读/复制/更新，条件写可避免意外覆盖。S3 API `PutObject` 文档说明 `If-None-Match: *` 在对象已存在时返回 412；若上传期间发生 conflicting operation 返回 409，并明确写“On a 409 failure, retry the upload”。
- **边界**：412/409 的具体含义依 API、条件和存储类型；S3 versioning 下并发写可能保存多个版本，不能将任一成功/失败响应等价于最终业务状态。

### C4 — GCS generation/metageneration 是对象版本/元数据代际，precondition 失败阻止意外版本操作
- **状态**：`verified`
- **证据**：Cloud Storage 官方 “Object metadata”/“Generations and preconditions”说明 generation 标识对象版本，metageneration 随该 generation 的 metadata 更新递增；preconditions 不满足时请求失败，避免对意外版本读取/修改。该页面还明确 metageneration 离开 generation 没有意义。
- **边界**：generation 不是业务版本；一次 precondition failure 不证明旧 writer 未做资源外副作用。

### C5 — Azure Blob ETag/If-Match 和 lease 缺失可返回 412
- **状态**：`verified`
- **证据**：Azure 官方 “Concurrency control”说明 ETag 每次写更新；If-Match 要求当前 ETag 相等，否则 HTTP 412，客户端应重新取内容和属性；活动 blob lease 未带 lease ID 的写也失败并返回 412。
- **边界**：lease/ETag 只说明该资源操作的并发条件；不能单独证明生产 fencing、旧副作用不存在或最终目标状态。

### C6 — Temporal execution/replay 是 durable workflow 语义，不是外部资源 fencing 证明
- **状态**：前半 `verified`，后半 `inferred`
- **证据**：Temporal 官方 Workflow Execution 页面说明 workflow execution 是 durable/reliable/scalable 的执行单位；Replay 会根据已记录 Event History 恢复进度，Worker 将 command 与 Event History 对照；每个 execution 对本地状态有 exclusive access，并与其他 execution 并发。
- **推论/边界**：这些事实支持记录 workflow/run/event history 作为编排证据，但官方页面并未因此承诺任意外部写入 exactly-once、旧 worker 外部副作用不存在或资源端 fencing 已完成，故后半只能 `inferred`。

### C7 — Step Functions Standard/Express 的执行模型有明确区别
- **状态**：`verified`（模型区分）；将其外推为资源 fencing 则 `inferred`
- **证据**：AWS 官方 “Choosing workflow type”说明 Standard Workflows 是 durable/auditable，遵循 exactly-once model，但配置 ASL Retry 时任务/状态可能再次运行；Express 使用 at-least-once，执行可能运行多次，适合幂等动作。
- **边界**：Standard/Express 的 workflow/task 运行模型不是对象存储提交协议；无论平台工作流状态为何，都要独立记录资源响应和 read-back。

### C8 — “单次条件拒绝=旧副作用从未发生/新 writer 成功/最终状态确认”
- **状态**：`inferred`（安全边界推理，不是单一官方句子）
- **推导**：各官方资料把 precondition/ETag/generation/resourceVersion 定义在特定资源操作的版本或条件上；工作流文档则定义编排执行模型。它们没有把资源条件拒绝扩展为调用链上其他副作用或目标最终状态证明。因此本报告把 P1、P2、P3、P4 拆开，并要求独立证据。

### C9 — 所有冲突/延迟/缓存/权限错误/空结果默认 UNKNOWN
- **状态**：`inferred`（状态机/风险控制规则）
- **依据与限制**：官方资料分别描述版本条件、错误码、workflow delivery semantics，但没有对本项目的端到端网络、缓存、审计延迟作统一保证；在缺乏绑定证据时把状态保持 UNKNOWN 是保守的记录规则，不是声称平台必然行为。

## 7. 证据包验收标准

关闭一次 stale-writer 事件，至少需要：

- 目标资源的完整 scope/key/UID（按最小披露原则脱敏）；
- writer principal、epoch、operation_id、每个 attempt 的 request_id；
- 读到的条件类型和值、发送的条件、payload/目标业务版本 digest；
- 服务响应 code/provider code/request ID，以及 transport 是否确定；
- P1/P2/P3/P4 四个独立状态和每个状态的证据链接/日志 ID；
- 权威 read-back 的版本、digest、来源/缓存新鲜度、读取窗口；
- 冲突、重试、补偿或人工决策及其条件；
- 若任何字段为空、权限不足、缓存无法证明新鲜、响应丢失或读回不一致，保持 UNKNOWN/CONFLICT，不用“最终看起来正确”覆盖缺口。

## 8. 覆盖、冲突与未知

- **覆盖**：Kubernetes API Concepts；Amazon S3 conditional requests 与 PutObject；Google Cloud Storage generations/preconditions；Azure Blob concurrency；Temporal Workflow Execution；AWS Step Functions workflow type。均为官方域名/官方文档。
- **未覆盖**：具体 SDK 的自动重试默认值、代理/CDN 缓存配置、组织内部审计系统、数据库/消息队列副作用、EC2 instance fencing、业务 payload schema、各区域服务事件窗口；未查到的内容不伪装成已证实。
- **资料冲突**：本切片未发现官方资料之间对上述基础版本条件语义的直接冲突；Step Functions Standard 的 exactly-once 与 Express 的 at-least-once是不同 workflow 类型，不能合并为冲突或普遍承诺。任何第三方/非官方说法未纳入证据。
- **未知（必须保留）**：API 响应丢失后一次写是否已提交；缓存/代理是否返回最新值；权限错误时目标是否发生变化；空结果究竟代表不存在/删除/延迟；资源外旧副作用是否发生；新 writer 是否在另一个路径成功；最终状态是否持续满足 W。

## 9. 下一独立切片建议（完成后不要停线）

**S8：端到端“响应丢失—重试—read-back”证据演练与跨平台对照。** 仅使用官方文档和可审计的合成测试，固定相同 operation_id/payload digest，在 Kubernetes、S3、GCS、Azure Blob 各构造：明确 412/409、响应丢失、缓存/旧读、权限拒绝、重复重试五类轨迹；输出跨平台字段映射、最小确认窗口 W 的测量方法，以及何时必须转人工/补偿。不得接触真实服务、真实凭据或既有事故目录。
