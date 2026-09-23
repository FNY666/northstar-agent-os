# P0-1 T-CONTRACT-0 离线树外 contract/schema 纯校验预演报告

## 范围与边界

- 交付目录：`/tmp/t-contract-0-20260920/`。
- 本预演只使用标准库、只处理本地 fixture；不连接真实服务，不执行任何副作用，不修改正式 contract/adapter/schema/test。
- 输入依据仅为指定的 v0.4.1 离线材料与两份 research-round-1 只读材料；共享 P0 事故目录未访问。本报告中的“未访问”是边界声明，不是对该目录的检查。
- `RUNNING.marker` 记录身份 `B-T-CONTRACT-0-PROTOTYPE` 与“只/tmp”边界。

## 交付与实现

`t_contract_validator.py` 实现 strict JSON（exact duplicate key、递归 NFC collision、NaN/Infinity 拒绝）、canonicalization（NFC、排序、有限整数上限 10**18）、schema unknown-field 拒绝、RFC3339 UTC 秒级时间窗口/事件顺序、operation fingerprint、trusted binding HMAC（仅原型测试密钥）、identity binding、raw_ref 内容地址及路径穿越拒绝。

决策链为：`decision → execution → observation → postconditions → effect → receipt`，并返回 projection 与 state trace。`verified` 必须同时具备 accepted decision、有效 trusted binding、succeeded execution、healthy returned observation、非空且全 verified postconditions、verified effect、ok receipt；failed/not_started/started/timeout/cancelled 不得为 verified。缺 groundtruth、空 postconditions、缺/篡改 binding 为 unknown（结构非法则 invalid）。同 idempotency key + 同 fingerprint dedupe；同 key + 不同 fingerprint reject。expected 字段仅用于 match，不参与 security verdict。

## 证据分层

### verified（本地运行证据）

- 运行器与验证器均为标准库、树外、无网络/服务调用的确定性代码。
- `run_tests.py` 定义 37 个 fixture，运行两轮；覆盖正常 verified、effect failed、无 groundtruth、空 postconditions、illegal receipt、五类禁止 verified 的执行状态、fingerprint/trusted binding 篡改、expected 改变不改变 verdict、raw_ref 路径穿越、relative/opaque evidence scheme、非对象 sections、缺失 trusted_binding、duplicate JSON、NFC collision、NaN/Infinity、非整数、unknown fields、身份/时间窗、idempotency。
- 每一轮通过条件是所有 fixture expected match、无异常、无 `ERROR_VERIFIED`，并完成同 key 同 fingerprint dedupe 与同 key 不同 fingerprint reject 断言。实际统计写入 `TEST-RESULTS-FINAL.txt`；旧 `TEST-RESULTS.txt` 保留。
- 修正后的两轮每轮 37 fixtures：`rc=0`、`verified=2`、`failed=6`、`unknown=9`、`invalid=20`、`ERROR_VERIFIED=0`、`error=0`、`fail=0`；idempotency=true。正常 raw_ref 为 `evidence://sha256/<64 lowercase hex>`，作为 opaque reference 只校验形状，不访问证据内容或网络。
- 缺失 trusted_binding 分类为结构化 `unknown`；非对象 sections、非对象 trusted_binding、解析/数值/边界异常均返回结构化 `invalid`，不向调用方抛出 `KeyError` 或未处理异常。

### inferred（设计推断）

- 独立 observation/effect/postcondition/receipt 通道与可信绑定是可审计的最小闭环；这种分层来自指定 backlog/study 的设计建议，不是生产效果证明。
- fail-closed 的 invalid/unknown 分界可减少把“未证实”误报为 verified，但真实 producer、认证、密钥管理、时钟与跨进程 registry 尚未接入。

### unknown（尚未验证）

- 真实 authority/KMS/HSM、producer 身份认证、密钥轮换/撤销、时钟同步与 replay resistance。
- raw_ref 是否真实绑定不可变证据内容；真实 observation 独立性；真实 receipt/audit 不可抵赖。
- 跨进程/跨设备 idempotency、崩溃恢复、exactly-once/at-most-once、副作用状态与并发冲突。
- schema 与正式 adapter/sidecar 的兼容性、性能、生产部署与升级迁移。

## Go / No-Go

**GO（仅限本地 T-Contract-0 测试口径收口，不是生产 Go）：** 修正后的两轮 runner 均 `rc=0`，每轮 37 fixtures 全部按预期分类，无未处理异常，`ERROR_VERIFIED=0`，同 key 同 fingerprint dedupe 与不同 fingerprint reject 均真实断言通过。保持 fail-closed 校验规则；不代表真实服务、可信根或生产副作用安全。

之前失败原因=runner/fixture口径：旧入口 `expected` 沿用 base 的 `verified`，使正确的 failed/unknown/invalid 被计为失败；同时旧 fixture 目录入口与缺失 binding 的处理造成 `KeyError`/无法运行。该旧失败记录保留在历史 `TEST-RESULTS.txt` 与本报告原有记录中，未删除。

若要求生产接入或真实证据/可信根，仍为 No-Go：当前结果只证明树外标准库原型和本地 fixture 口径。

## 残余 P0 / P1

- P0：真实 trusted authority 与密钥生命周期；独立 postcondition/effect producer；observation/raw evidence 内容-地址绑定；effect 与 agent-turn status 分离；sandbox fallback 显式 fail-closed；跨进程幂等与副作用恢复。
- P1：统一 task/run/event/artifact identity；不可变 receipt/audit 与 checkpoint/replay/recovery；最终 hash/manifest 生成顺序；并发外部修改与重放故障注入；生产 adapter/schema 兼容性测试。

## 真实接入前置条件

1. owner 批准正式 schema/adapter 变更并锁定版本、迁移与回滚方案。
2. 配置硬件/服务可信根（KMS/HSM 或等价）、producer 身份认证、签名验证、轮换/撤销、时钟策略和 replay 防护；原型 key 禁止复用。
3. 定义并独立部署 observation、postcondition、effect、receipt producer，明确 groundtruth、source/channel、time-window、证据强度与不可变 raw_ref。
4. 在隔离环境完成跨进程幂等、崩溃/超时/取消/重复请求、并发冲突、恢复、审计和安全负例测试；验证不得触发真实业务副作用。
5. 完成正式 contract/adapter/schema/test 的 owner review、兼容性/性能/升级回滚验收；本交付不得直接作为生产批准。

## 结论

该交付包含树外、无服务、无副作用的 P0-1 T-CONTRACT-0 原型代码；本地测试口径已收口并通过两轮（见 `TEST-RESULTS-FINAL.txt`）。生产接入仍为 No-Go：尚不存在可认证的真实 trusted binding 与独立 groundtruth/effect producer，且副作用幂等/恢复未被证明。
