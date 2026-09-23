# A-P0-TCONTRACT-REVIEW-2

- 身份：A
- 审查对象：`/tmp/t-contract-0-20260920/`
- 审查范围：T-Contract-0 条件 GO 的纯 schema 边界；生产 NO-GO 的 authority、registry、producer、readback、fencing、time、secret boundary；D1 opt-in 与真实接入前门槛。
- 写入范围：仅 `/tmp/A-P0-TCONTRACT-REVIEW-2/`。
- 禁止面核对：未访问 140、canonical、tri-line、systemd、凭据；未修改输入树或共享 P0 事故目录。

## 结论

### Conditional GO

仅可对树外或树内的**纯 contract/schema 校验**给 Conditional GO，且结果只能表示 schema/输入状态，不表示生产授权、执行成功或真实目标效果。允许的能力是：

- 严格 JSON 解析：重复键拒绝、非有限常量拒绝、NFC 规范化与键冲突拒绝；
- 固定 schema version、未知字段拒绝、字段类型/状态枚举/必填字段校验；
- canonical operation fingerprint 的计算与身份一致性校验；
- 时间字符串的格式、顺序与窗口形状校验；
- observation/postcondition/effect/receipt 的状态形状投影；
- 纯本地 fixture、负向样例、幂等投影的确定性回归。

这些能力的最终语义应标成 `schema_valid`、`structurally_invalid` 或 `effect_unknown`；不能把离线 `verified` 直接升级为生产 effect verified。

### Production NO-GO

真实副作用、真实远端接入、生产 authority 或把该 prototype 的 `verified` 当成效果证明，当前均 NO-GO。缺口不是 schema 字段数量问题，而是权威来源和外部状态闭环未成立：

1. authority 不是生产可验证的授权根，缺 scope、撤销、过期、policy revision 及 KMS/HSM 绑定；
2. registry 只是可选的进程内 Python `dict`，没有持久唯一约束、原子 CAS、重启恢复、attempt 状态或 reconcile；
3. producer/receipt 的标签没有 authenticated registry，执行者可以提交形似成功的报告；
4. `raw_ref` 只检查 `evidence://sha256/<64 hex>` 形状，不读取或核对证据内容；
5. 没有目标侧 fencing，旧 owner/旧 token 的迟到写入无法被资源端拒绝；
6. `trusted_now` 由调用者传入，代码没有可信时钟或时间服务边界；
7. prototype 使用 test-only 本地 HMAC key，不能作为生产 secret boundary；
8. 没有生产级 append-only audit、durable commit、crash/unknown/retry/reconcile 闭环。

### D1 结论

D1 可以作为**显式、默认拒绝、一次性、范围绑定的接入能力开关**，但 `--allow-remote` 或同类 opt-in 只是一道用户意图闸门，绝不是生产安全闸门。真实接入前必须先通过下节的全部门槛；任一项为 `unknown`，保持 NO-GO，不靠重试或本地 `verified` 绕过。

## 证据等级

- **E1 / 直接复核**：A 自有副本重跑 `run_tests.py` 两轮；每轮 37 fixtures，`rc=0`、`fail=0`、`error=0`、`idempotency=true`，两轮输出一致。每轮分类为 `failed=6, invalid=20, unknown=9, verified=2`。这证明 prototype 的离线确定性，不证明生产正确性。
- **E1 / 直接探针**：独立探针显示：缺 binding -> `unknown`；旧 binding 被篡改 -> `invalid`；重新使用本地 test key 签名后 -> `verified`；未注册 producer label 仍可 `verified`（仅 warning）；不存在的 content-address-shaped `raw_ref` 仍可 `verified`；任意 authority 重新用本地 test key 签名后仍可 `verified`；同一进程 `dict` 可 deduplicate，冲突可 reject。
- **E2 / 静态原始材料**：T-Contract validator/schema、T-Contract report、OpenBot 架构审计、集成架构分析、D1 v2 审计报告均只读核对。架构文档描述了 gateway policy/audit、credential vault、RouteLedger/Experience 集成点，但没有证明 T-Contract 的生产 authority/registry/readback/fencing 已接通。
- **E3 / 工程推断**：下面的生产前门槛是由上述边界推出的必要条件，不宣称目标系统已经具备。
- **Unknown**：没有访问生产目标或凭据，也未作任何远端动作；因此生产状态、真实读回、真实授权、实际 secret rotation、目标侧 fencing 均保持 unknown，而不是通过。

## 纯 schema 边界审查

### 可接受的纯校验

验证器的 strict loader、canonicalizer、时间解析器、字段枚举和 projection 属于纯函数面。重复 JSON key、NFC collision、有限整数、未知字段和状态不一致可以在无服务、无网络、无凭据的条件下确定判定。operation fingerprint 是输入对象的 canonical digest，适合作为候选身份指纹，不等于目标资源版本或授权凭证。

离线重跑结果为 2 轮完全一致，说明此边界适合做 deterministic fixture gate。`trusted_binding` 缺失时返回 `unknown` 而不是冒充成功，这一点符合认识边界。

### 必须明确排除的语义

- `trusted_binding` 的签名只是 prototype 本地 HMAC 校验；它没有证明签名者是生产 authority，也没有 key id、轮换、撤销、scope 或审计链。
- `raw_ref` 是不透明引用的语法检查。没有读取该引用指向的 bytes、没有重新计算 hash、没有独立 channel，因此不能称作 readback。
- `source`、`channel`、`producer` 的错误值在当前 prototype 中主要产生 warning；warning 不是 authenticated producer boundary。
- `trusted_now` 是 validator 参数，不是可信时间服务；同一输入在不同调用者提供的 clock 下可能得到不同边界判定。
- `registry` 只有在调用者显式传入时才启用；实现是内存 dict。`dedupe` 顶层字段虽被列入 allowed fields，但没有等价的 durable registry 语义。
- 本地 `verified` 是 projection 的结果，不能向上游暗示副作用完成。建议生产适配层改名或分层为 `schema_verdict` 与 `effect_status`，禁止同名跨层传递。

## 生产 NO-GO 门槛

| Gate | 必须证明 | 当前判断 |
|---|---|---|
| G0 owner/target | 目标、owner、真实接口、scope、policy revision 和责任边界均闭合 | NO-GO / unknown |
| G1 schema | 版本固定、strict parser、canonical fingerprint、负向测试全绿 | Conditional GO，仅纯校验 |
| G2 authority | 独立 authority 签发；签名 key 有 KMS/HSM、key id、scope、expiry、revocation、policy revision | 未证明 |
| G3 producer/verifier | producer 身份经 authenticated channel 验证；producer 不能自报 effect verified；verifier 独立于 producer | 未证明 |
| G4 registry | durable unique `(target, operation_id/idempotency_key, fingerprint)`；原子 CAS；attempt/lease/reconcile 可恢复 | 当前只有进程内 dict |
| G5 readback | 独立 observer 读取权威目标状态；读取原文/摘要可复核；postcondition 与目标版本绑定 | 当前只有 ref 形状 |
| G6 fencing | 目标侧验证单调 fencing token/lease/version，旧 owner 写入硬拒绝 | 未证明 |
| G7 time | 权威 clock、expiry、事件顺序和 skew policy；不能信 caller-supplied now | 未证明 |
| G8 secret | secret 只经 vault/KMS/HSM 引用；最小权限、轮换、不可进入 prompt/log/report；测试 key 永不进入 production | 未证明 |
| G9 recovery | crash、timeout、unknown、重复执行、迟到回执、补偿和 reconcile 有可验证状态机 | 未证明 |
| G10 audit | append-only、持久 sequence、request/decision/producer/readback/fencing 关联，且外部状态可查 | 文档描述有 audit，但 T-Contract 闭环未证明 |
| G11 canary | 隔离目标、专用身份、无生产副作用的真实接口 smoke + 独立 readback + 回滚演练 | 未执行，保持 NO-GO |

G2-G11 任一项不能以 schema `verified`、工具返回成功、audit row 存在或一次请求被接收替代。

## D1 opt-in 设计与真实接入前门槛

### D1 必须满足的行为

1. 默认路径只允许 parse/validate/rejudge；默认不创建 socket、subprocess、远端请求或副作用。
2. 真实接入须由单次显式 opt-in 触发，不能由普通 config、环境变量或模型输出隐式打开。
3. opt-in 必须绑定 `target_fingerprint`、`operation_id`、`idempotency_key`、授权 scope、policy revision、expiry、producer identity 和本次 attempt；缺任一项拒绝。
4. opt-in 只覆盖一个已登记 target/operation，禁止“全局 remote enabled”；结束、超时或崩溃后自动失效。
5. 真实接入前先执行 dry-run/preview，独立打印 normalized args hash、目标摘要和 gate 结果，不打印 secret；用户确认不能代替 G2-G10。
6. 任何 `unknown`、readback 缺失、fencing 未闭合、时间源不可信、secret boundary 未闭合，都必须硬 NO-GO。
7. 生产首次接入必须专用低权限身份、隔离 canary target、独立 observer、可回滚清单，并完成重复调用和中断恢复演练。

### 推荐状态机

`OFFLINE_SCHEMA` -> `CANDIDATE_ONLY` -> `AUTHORIZED_CANARY` -> `READBACK_VERIFIED` -> `PRODUCTION_ENABLED`。

状态只能由独立 gate evidence 推进；`CANDIDATE_ONLY` 不能执行副作用；`AUTHORIZED_CANARY` 也不能因为 producer receipt `ok` 直接升到 `READBACK_VERIFIED`；readback、fencing、audit 和 reconcile 缺一不可。任意 gate 失败回到 `CANDIDATE_ONLY` 或 `BLOCKED`，不得盲重试。

## 架构审计对照

OpenBot 架构资料把 server gateway 定义为 action boundary：解析目标、评估 policy、写 audit、再转发或拒绝；凭据由 vault/加密存储引用，audit 不记录 secret plaintext。该资料能支持“生产应有 gateway/policy/audit/secret boundary”的设计要求，但没有把本 T-Contract 的 binding、registry、readback、fencing、trusted clock 接入证明。

集成架构分析提出 BackendRouter 的 admission 与 RouteLedger 的 failure/Experience 记录，并在接口示例中出现 `fencing_token`。这只能证明一个可能的集成点；参数名或 `record_lost()` 调用不构成资源端 fencing、durable registry 或真实 readback。特别是“routing decision”与“真实 target postcondition”必须保持两条证据链，不能用 route ledger 代替目标读回。

D1 v2 审计材料证明了离线 `rejudge` 默认拒绝远端执行、无网络/无子进程的测试路径，以及证据强度和 groundtruth channel gate 的设计方向；它不能替代本轮缺失的生产 authority、registry、fencing 和真实目标验收。

## Findings

- **P0 F-01：authority/producer 混淆风险。** 本地重签 binding 或使用未注册 producer label 仍可得到 `verified`。若上游把这个值当 effect 证明，属于严重语义越界。
- **P0 F-02：readback 假闭环风险。** `raw_ref` 只做格式检查；一个不存在的引用形状就足以通过观察条件。必须把 hash reference、实际 bytes、独立读取和目标版本绑定起来。
- **P0 F-03：registry 非 durable。** 可选进程内 dict 只能覆盖同一进程的演示 dedupe；重启、并发、崩溃、CAS、迟到 attempt 和 reconcile 均未覆盖。
- **P0 F-04：fencing/time/secret 未闭合。** 没有目标侧 stale-writer rejection、可信 clock 或生产 secret root；不得接真实副作用。
- **P1 F-05：`dedupe` 不是 registry。** 顶层字段允许存在不等于结构和语义被实现；应将 schema hint 与运行时 registry 分离并明确标注。
- **P1 F-06：D1 opt-in 不应被当作最终批准。** `--allow-remote` 类开关只能表达用户意图；必须由 G2-G11 的机器可验证 gate 共同决定。

## 最小后续动作

1. 保留本 prototype 作为 offline schema fixture gate，不接生产 effect。
2. 在实现层拆分 `schema_verdict` / `authorization_status` / `execution_receipt` / `readback_status` / `effect_status`，禁止 producer 自己写最终 effect。
3. 先独立设计 durable registry、authority envelope、readback adapter、target fencing 和 trusted clock，再做 canary；每层先有负向测试和 crash/reconcile 证据。
4. 在所有 gates 闭合前，D1 保持默认关闭；本报告不构成授权书、部署批准或真实接入批准。

## 资产与核验

输入树只读副本与 A 证据均位于 `/tmp/A-P0-TCONTRACT-REVIEW-2/`。现场重跑输出、独立探针、源代码锚点、输入哈希和审计材料哈希见 `evidence-capture.txt`；独立探针脚本见 `independent_probes.py`。
