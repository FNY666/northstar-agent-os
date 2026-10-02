# Northstar Run Evidence 模块设计方案

**状态：** 提案（Proposed；尚未实现）
**源码基线：** `origin/main`，提交 `cef3607`（session replay UI 合并版）
**建议组件名：** `northstar-run-evidence`
**设计目标：** 为一次 Northstar run 建立可离线复核、可识别篡改、并可由受信任宿主签封的证据包。

## 1. 决策摘要

建议下一步新增独立组件 **`northstar-run-evidence`（运行证据账本）**。它把现有分散在 runtime、host、durable-run、interop 与 verifier 中的 run 身份、授权决策、事件摘要、会话/检查点、handoff receipt、验证结果及工件摘要，关联到同一个 run，并提供统一的离线验证入口。

这不是另一个日志导出器：仓库已经有 canonical NDJSON audit feed；新组件要提供的是 **跨来源关联、追加式哈希链、完整性检查、受信任签名锚点和明确的不完整状态**。它也不是“证明 Agent 一定正确执行”的机制；它证明的是证据包内声明和文件之间的关系，以及这些数据自签封后是否改变。

建议先实现轻量、离线、默认不复制敏感正文的 MVP。生产签名密钥的存放、轮换及公钥分发由宿主或部署环境负责，不由该组件托管。

## 2. 为什么现在做：从源码看到的缺口

| 已有能力 | 源码事实 | 尚未解决的问题 |
|---|---|---|
| Runtime transcript | [sessions.py](../../components/northstar-agent-runtime/sessions.py#L145-L191) 以 `O_APPEND` 写入并按配置 `fsync`；[load_jsonl](../../components/northstar-agent-runtime/sessions.py#L264-L297) 可跳过合理的末尾 torn write。 | 每行没有前序摘要或外部签名。JSON 可解析不代表历史未被改写；读入时也不校验完整的跨来源 run 身份链。 |
| Resume checkpoint | [checkpoints.py](../../components/northstar-agent-runtime/checkpoints.py#L16-L35) 和 [prepare_resume](../../components/northstar-agent-runtime/checkpoints.py#L206-L234) 通过 transcript 前缀摘要绑定续跑边界与预算计数。 | 这是局部恢复校验，不是对最终 transcript、授权、durable event 和输出工件的统一签封。 |
| Canonical audit feed | [audit_export.py](../../components/northstar-agent-runtime/audit_export.py#L59-L100) 将 transcript 转为 audit NDJSON；[run-contract audit.py](../../components/northstar-run-contract/audit.py#L67-L177) 提供 envelope 校验和 NDJSON 编解码。 | 导出是格式转换，没有 ledger、签名、跨来源关联或最终 sealed receipt。host 与 durable-run 也分别独立导出。 |
| Durable-run events | [EventContract](../../components/northstar-durable-run/durable_contract.py#L326-L402) 保存 `payload_digest`，而非事件 payload；[runner.py](../../components/northstar-durable-run/runner.py#L372-L421) 在生成事件时仍能访问这些 payload；[event_store.py](../../components/northstar-durable-run/event_store.py#L167-L199) 持久化并验证事件序列与状态迁移。 | 事件序列有效，但离线审查者无法仅从 EventStore 重算原始 payload 摘要；事件之间也没有前序哈希链或签名根。 |
| 独立验证 | [verifier.py](../../components/northstar-durable-run/verifier.py#L80-L170) 可检查私有 workspace、必需工件摘要和测试退出码；[make_final_receipt](../../components/northstar-durable-run/verifier.py#L173-L195) 生成普通 dict。 | 验证结果依赖调用者当时传入的工件清单与 `test_exit_code`，receipt 未自动持久化或签封；它记录观察，不证明测试观察者可信。 |
| Host 授权 | [authorization.py](../../components/northstar-host/authorization.py#L179-L242) 对短期 grant 做 HMAC 签名/验证；[host_audit.py](../../components/northstar-host/host_audit.py#L27-L55) 只把已验证 claims 映射为一条 audit record。 | 授权、执行、验证和最终工件没有自动绑定为一个 run 的证据闭环；grant token/secret 也不应被复制进证据包。 |
| Agent interop | [AdapterReceipt](../../components/northstar-agent-interop/interop_adapter.py#L110-L186) 有严格 schema；[BackendAdapter](../../components/northstar-agent-interop/interop_adapter.py#L189-L278) 的 idempotency receipt 缓存在进程内。 | receipt 退出进程后没有统一的 run-level 持久证据，也未与根 run 的最终收据绑定。 |

现有组件已经有大量可信边界和本地校验。优先级最高的缺口不是再加一种 UI，而是让这些边界产出的证据 **能够被聚合、关联、封存并在另一环境离线复核**。

## 3. 目标与非目标

### 目标

1. 以 `run_id` 为主键，严格关联可用的 `task_id`、`thread_id`、`trace_id`、`session_id`、`step_id`、`actor_id`、`workspace_id` 与 `policy_revision`；跨来源身份不匹配时拒绝签封。
2. 提供本地追加式 evidence ledger：连续序号、previous-entry digest、entry digest、幂等重试和崩溃恢复检查。
3. 生成自描述 bundle，能在不运行 Agent、不联网、不访问原 workspace 的条件下执行完整性与引用检查。
4. 明确区分 **内容完整性、证据完整性、签名真实性、运行完成状态**；缺少信任锚点或来源时返回 `unknown/incomplete`，不得显示成成功。
5. 默认 digest-first、最小化存储敏感正文；只通过显式 allowlist 加入工件或经批准的脱敏数据。
6. 保持现有 transcript、`EventContract`、audit envelope 和工具权限语义兼容。

### 非目标

- 不提供 scheduler、队列、远程 worker、HA 数据库或分布式事务。
- 不证明模型输出真实、测试具有语义正确性，或宿主/观察者没有撒谎。
- 不替代 OS sandbox、postcondition verifier、权限决策或 Session Replay UI。
- 不自动上传 SIEM、云对象存储，不管理数据保留策略。
- 不实现 KMS/HSM、密钥轮换、撤销服务或身份目录；只定义可接入的签名接口。
- 不默认封存 raw prompt、system prompt、tool output、环境变量、API key、grant token 或私钥。

## 4. 组件与依赖边界

新增独立目录 `components/northstar-run-evidence/`，采用 Python 3.10+、无硬性第三方依赖的平铺组件形态，与现有组件测试/打包方式一致。

建议模块职责：

- `evidence_contract.py`：严格 schema、canonical JSON、typed references、digest 和 verdict 类型。
- `evidence_store.py`：本地私有目录、append-only ledger、幂等追加、对象存储和原子 manifest 写入。
- `evidence_adapters.py`：将 runtime、host、durable-run、interop、verifier 的已验证对象转换为显式 evidence entry。
- `evidence_verify.py`：离线验证 schema、链、来源引用、工件摘要、跨来源 run identity 和签名。
- `evidence_cli.py`：`pack`、`verify`、`inspect` 的命令行入口。

依赖仅允许指向 `northstar-run-contract` 的 canonical audit/schema 能力；**runtime 不得反向硬依赖此组件**。现有 runtime 对离线和 scripted provider 保持零硬依赖的目标见 [runtime pyproject.toml](../../components/northstar-agent-runtime/pyproject.toml#L24-L40)。集成通过可选 `EvidenceSink` protocol / bridge 注入，由 host 或产品层组合组件。

命令行建议先提供独立入口 `northstar-evidence`，避免普通 `northstar` 安装被迫依赖证据组件。若未来希望使用 `northstar evidence ...`，用 lazy optional dispatch 调用同一 API；未安装组件时给出明确安装提示，而不是静默降级。

## 5. 核心数据模型

### 5.1 EvidenceEntry

每个 ledger entry 只写一个经过校验的来源声明；原始正文只有在 capture policy 显式允许时才以 object 形式保存。

```json
{
  "schema_version": "northstar.evidence-entry.v1",
  "run_id": "run-...",
  "sequence": 12,
  "source": "durable",
  "kind": "step.finished",
  "occurred_at": 1790899200,
  "subject_digest": "sha256:<64 lowercase hex>",
  "refs": [
    {"kind": "durable-event", "ref_id": "event-...", "digest": "sha256:<...>"}
  ],
  "source_id": "event-...",
  "previous_entry_digest": "sha256:<...>",
  "entry_digest": "sha256:<...>"
}
```

- Entry body 先按固定规则 canonicalize：UTF-8、ASCII JSON object key 排序、无多余空白、整数限于跨语言安全范围；v1 拒绝浮点数（十进制值用字符串表达）。
- `entry_digest = SHA-256(domain_separator || canonical_json(entry_without_entry_digest))`；`previous_entry_digest` 必须指向同一 run 的上一条 entry，首条使用 `null`。
- `subject_digest` 绑定原来源对象的 canonical bytes。每个 adapter 必须明确规范化算法与版本，不能因 dict 顺序、时区格式或语言运行时差异产生含糊结果。
- `refs` 按 `(kind, ref_id)` 排序并作为 typed digest reference，不接受任意路径。对象路径由 store 内部按 digest 派生，不允许来源提供路径穿越字符串。
- 重试使用 `source_id`/idempotency key：相同 key、相同 digest 返回既有 entry；相同 key、不同 digest 拒绝。

### 5.2 EvidenceManifest 与 SealedRunReceipt

manifest 至少包含：

- manifest schema/version、bundle id、创建时间和 capture policy revision/digest；
- run identity（可选字段应显式标注缺失，不推断）；
- ledger entry count、首尾 sequence、ledger root digest；
- 按类型列出的来源对象引用（session transcript/checkpoint、durable event/payload、host authorization claims、handoff receipt、verifier receipt、artifact digest）；
- completion status、独立 verifier verdict、observed test exit code（若有）、未解决缺项；
- signer algorithm/key_id/signature（signature 不参与自身签名输入）。

签名对 `manifest_without_signature` 的 canonical bytes 计算。**不允许把签名 secret 写进 bundle。** `key_id` 必须由外部可信 key resolver 解释；未知 key、无签名、过期/撤销 key 的状态都不能等同于已认证。

### 5.3 分层 verdict

Verifier 返回结构化报告，而不是一个易混淆的布尔值：

- `integrity`: `verified | failed | unknown`（本地对象/摘要/ledger 链）；
- `completeness`: `complete | incomplete`（策略要求的来源是否齐全）；
- `authenticity`: `verified | unknown | failed`（签名、key_id 和信任根）；
- `run_verdict`: `verified | failed | unknown`。

只有 **完整 + 完整性通过 + 有效可信签名 + 运行最终状态及 postconditions 通过** 才可给 `run_verdict=verified`。无签名但 digest 自洽的 bundle 最多是 `unknown`（可说明 `integrity=verified, authenticity=unknown`），不能宣传为不可抵赖或已认证。

## 6. Bundle 存储与生命周期

### 6.1 建议目录布局

```text
<bundle>/
  manifest.json
  ledger.jsonl
  objects/sha256/ab/<full-digest>   # 仅限显式 allowlist 的小型对象/工件
```

本地活动账本位于 workspace 的 `.northstar/evidence/<safe-run-id>/ledger.jsonl`。当前 `EvidenceStore` 要求 root 由当前用户所有且不可被 group/world 写入；目录组件通过 `O_NOFOLLOW` 逐级打开，run directory 以 pinned dirfd 操作，防止路径替换重定向。每个 run 目录为 `0700`，lock/ledger/temp 文件为 `0600`；拒绝 symlink、非 regular file、路径逃逸和非 canonical ledger 行。追加在 `flock` 下重写最多 64 MiB 的 ledger 到同目录临时文件，fsync 后通过原子 rename 替换，并 fsync 目录。该实现为 O(n) append，要求支持 `flock`/fsync/原子 rename 的本地 POSIX 文件系统；bundle manifest 和对象存储仍未实现。bundle 是普通目录；压缩格式可稍后加入，避免 MVP 引入 archive traversal 风险。

### 6.2 状态机

```text
open ── append entries ──> open ── completeness check + sign ──> sealed
  └── crash/missing required source ───────────────────────────> incomplete
sealed ── digest / signature / identity mismatch ──────────────> invalid
```

- `open` 账本通过 copy-on-write 替换实现原子追加：崩溃时 ledger 保留为旧的完整版本或新的完整版本，孤立 temp 文件在后续加锁操作时清理。当前不自动修复历史 torn/malformed 文件（缺少最终换行也会 fail closed）；未来若增加 tail recovery，必须记录 warning，且不得直接签成 complete。
- 持久化 `append` 与 `append_entry` 必须携带稳定 `source_id`。若 rename 成功但目录 fsync 失败，抛出 commit-outcome-uncertain 错误；调用者以相同 ID 重试，可在条目已可见时幂等返回、在崩溃回滚到旧账本时安全追加。
- `sealed` bundle 中任何 ledger 行损坏、摘要不匹配、对象缺失、source link 不一致或签名校验失败均视为失败，不得通过“忽略坏行”降级成功。
- 所有来源均为多文件写入；MVP **不宣称跨 EventStore/session/ledger 有原子事务**。中途崩溃保留为 incomplete，并通过 source idempotency 与恢复扫描进行对账。
- seal 操作仅在所选 capture policy 所要求的证据全部到齐且跨来源 identity 一致时成功。缺少签名适配器时可生成仅供本地诊断的 incomplete/unsigned bundle，但 `verify` 必须标出未知真实性。

## 7. 集成流程与 API 草案

### 7.1 组件生命周期

1. **Run start**：由 host/product orchestration 建立 run identity 和 capture policy snapshot；只记录已验证的 claims 摘要与 `policy_revision`，不记 authorization token 或 secret。
2. **事件采集**：durable-run 在 `runner._append` 仍持有 payload 时，将 event identity、payload digest 和 event ref 交给 EvidenceSink；默认只存摘要/白名单 metadata，原始 payload 作为可选受限 object。
3. **运行期间**：runtime bridge 按 policy 记录 session id、checkpoint index/digest、permission denials、工具结果摘要；原 transcript 保持现有格式与 owner-only 权限。
4. **handoff**：interop adapter 记录 grant claims digest、context/input digest、receipt digest、target agent、step/run/trace identity；不得保存 handoff secret。
5. **验证**：记录 verifier 实际使用的 required file digest、测试进程的 observed exit code、verdict 及验证器版本；同时明确该观察来源本身是否可信。
6. **完成/封存**：收集 final status、artifact refs 和所有 source roots；检查 identity 与 completeness；由宿主注入的 signer 对 canonical manifest 签名。
7. **离线复核**：在任何机器上执行 schema、hash chain、object digest、身份关联、artifact 和签名检查；结果为结构化 `EvidenceReport`。

### 7.2 API 草案

```python
class EvidenceSink(Protocol):
    def append_claim(
        self, *, run_id: str, source: str, kind: str,
        occurred_at: int, subject: Mapping[str, Any] | bytes,
        refs: Sequence[EvidenceRef] = (), source_id: str | None = None,
    ) -> EvidenceEntry: ...

    def capture_file(
        self, *, run_id: str, logical_name: str, path: Path,
        expected_digest: str | None = None, include: bool = False,
    ) -> EvidenceRef: ...

class EvidenceLedger:
    def seal(
        self, *, run_id: str, completion: CompletionEvidence,
        signer: SealSigner, required_sources: Sequence[str],
    ) -> SealedRunReceipt: ...

class EvidenceVerifier:
    def verify(
        self, bundle: Path, *, trusted_keys: TrustedKeyResolver | None = None,
        expected_run_id: str | None = None,
    ) -> EvidenceReport: ...
```

API 的调用要由显式 adapter 完成，例如 `capture_runtime_session(...)`、`capture_verified_authorization(...)`、`capture_durable_event(event, payload)`、`capture_adapter_receipt(...)` 和 `capture_verification(...)`。禁止通用的“扫描 workspace 并把所有文件收进包”行为。

### 7.3 CLI 草案

```text
northstar-evidence pack --run-id RUN --session SESSION_ID --output ./run-evidence
northstar-evidence inspect ./run-evidence --json
northstar-evidence verify ./run-evidence --trusted-key-dir ./trusted-keys
```

`pack` 只接受显式来源路径/IDs 和可选 artifact allowlist；`verify` 是纯离线只读操作。建议退出码：`0` 已验证并可信，`1` 检测到损坏/不匹配/无效签名，`2` incomplete 或真实性未知，`64` 参数/格式使用错误。

## 8. 安全、隐私与失败策略

1. **完整性不等于真实性**：链能检测签封后修改；签名证明 manifest 与可信 key 绑定；二者都不能证明签名前 host 给出的观察为真。
2. **密钥边界**：Signer 由 host/部署层注入；本模块不读取环境中任意 key、不生成生产 key、不落盘 secret。HMAC 等共享密钥签名不具备公钥意义上的非抵赖性，算法和 assurance 必须在 receipt 中明示。
3. **最小化数据**：默认仅保存 digest、schema 化 metadata 和事件类型。raw prompt、tool output、policy 文件正文、grant/handoff token、API key 和环境变量默认禁止进入对象存储。敏感字段采用 allowlist，而不是 denylist。
4. **Hash 仍可能泄露信息**：低熵数据的 digest 可被字典猜测；bundle 及其 manifest 仍按敏感操作数据保护，不能公开默认上传。
5. **文件系统边界**：目录私有、禁止 symlink 和非 regular file；验证每个 object 的实际字节数和 digest；拒绝 manifest 中的绝对路径、`..` 和重复逻辑名称。
6. **EvidenceSink 故障**：默认观察模式不得改变既有 run 的业务结果，但 final receipt 必须为 incomplete/unknown。若 host 配置 `evidence_required=true`，失败时必须阻止后续受控副作用；已发生的副作用无法回滚时，记录明确的 partial/incomplete 状态，而不是伪装成原子失败。
7. **资源上限**：限制 entry 大小、bundle 总大小、文件数、嵌套对象深度和验证时间；拒绝超限输入，不静默截断后仍标记完整。

## 9. MVP 范围、实施顺序与验收

### 阶段 A：独立数据核心

- 严格 schema、canonical digest、hash-linked ledger、private filesystem store、idempotent append、manifest 和离线 verifier。
- 测试 signer 仅用于测试；签名接口独立于 key storage。
- 为 torn write、sealed bundle 损坏、非法路径和 unknown-key 提供不同而明确的 verdict。

### 阶段 B：最小闭环集成

- 先接 durable-run：在 `runner.py` payload 仍在内存时写 evidence claim，不改现有 `EventContract` schema。
- 再接 runtime session/checkpoint digest、host verified authorization claims、durable verifier receipt/工件摘要。
- interop receipt 的持久化和跨进程恢复作为 MVP 后段；其现有 process-local cache 行为见 `interop_adapter.py`。
- 提供 CLI pack/inspect/verify 和一条完全离线的端到端 fixture/demo。

### 阶段 C：产品接入

- 新增 `components/northstar-run-evidence/tests/` 与独立 `pyproject.toml`；把该组件加入根 [Makefile](../../Makefile#L31-L43) 的 test/install 目标和文档/API freshness gate。
- 保证 runtime 未安装 evidence 组件时现有 `agent`、`run`、`sessions` 和 offline demo 行为不变。
- 与 `northstar sessions replay/ui` 通过 evidence refs 关联，不让 UI 自行决定可信状态。

### 验收标准

- 同一输入序列在不同进程/运行中得到相同 canonical entry/manifest digest。
- 修改、删除、重排任一 sealed ledger entry 或 object 均被检测；不能通过重算单个 entry 绕过可信 manifest 签名。
- 错误 run_id/trace_id、policy revision、session/checkpoint、handoff receipt 或 artifact digest 会导致 seal 拒绝或 verify 非 `verified`。
- 缺少要求来源、签名 key 不可用或来源结果冲突时返回 `unknown/incomplete`，不得宣称成功。
- 默认 bundle 不含 raw prompt、工具正文、authorization/handoff token 和 key material；权限为目录 `0700`、文件 `0600`。
- 崩溃恢复不修改现有 transcript/EventStore；sealed bundle 中坏尾行必须失败。
- 在无 API key、无网络、bare interpreter 下运行组件单测、CLI verify 和离线 integration demo。
- `make test` 与 `make demo` 继续通过，且 runtime 没有新增对 evidence 包的硬依赖。

## 10. 风险与后续决策

- **多文件一致性**：ledger 与现有 stores 不在同一事务中。MVP 必须把缺记录、重复重试和崩溃窗口显式建模为 incomplete；不能用“哈希链”掩饰该事实。
- **payload 可复核性**：只存 `payload_digest` 能绑定声明，不能在缺原文时独立重算。每条 source 应标注 `digest_only` 或 `object_included`；只有后者可离线重算内容摘要。保存对象必须受 privacy allowlist 控制。
- **信任根部署**：算法接口可以先定义，但真正的公钥算法、key rotation、revocation 和跨组织信任需部署决策；在完成前，产品只能准确表达完整性/真实性的实际等级。
- **观察者可信度**：`test_exit_code` 是调用者传入的值。未来可增加受控 test runner 的 process metadata、stdout/stderr 摘要和 sandbox attestation，但不属于 MVP。
- **现有存量数据**：旧 session、event store 没有 ledger entries；应支持以 `legacy_import` 事件导入并标为未签封，禁止把事后生成的摘要误称为运行时原生证据。

## 11. 优先级较低的备选方向

1. **生产级 scheduler/remote worker plane**：能扩展吞吐与恢复能力，但会把当前多组件证据分散的问题扩大。先有 evidence identity/root，再引入跨进程调度更稳妥。
2. **授权生命周期控制面（撤销、key rotation、policy watch）**：生产化价值高，但主要覆盖 host grant 一条链；Run Evidence 同时绑定授权、执行、handoff、验证和最终工件，可先建立共同复核基础。
3. **更多 session 分析或可视化**：最近已有全文 search 与离线 replay UI；继续扩展 UX 的边际价值低于把输出变成可信、可交接的审计材料。

---

**建议结论：** 先实现 `northstar-run-evidence` 的独立 ledger/verifier，再逐步挂接 durable-run、host、runtime 和 interop。任何未签封或来源不完整的 run 都必须明确显示为 `unknown/incomplete`，这是该模块最重要的产品不变量。
