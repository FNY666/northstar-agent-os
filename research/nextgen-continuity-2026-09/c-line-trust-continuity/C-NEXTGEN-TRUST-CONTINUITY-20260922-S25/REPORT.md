# S25：多区域/多观察者 trust-continuity 合成切片

## 结论（仅限离线合成模型）

本切片建立了一个 fail-closed 判定模型：`RECOVERED`、`UNKNOWN`、`REJECT` 三态互斥。只有在至少两个独立观察者一致、证据处于新鲜度窗口内、时钟偏差不超过界限且没有回拨、交叉签名完整且无冲突、身份/epoch/fence 连续未撤销，并且平台 receipt、持久日志、外部效果三类证据闭合且相互一致时，才允许产生 `RECOVERED`。缺一项不会被“推断为成功”；一般落入 `UNKNOWN`，对回拨、fence 撤销、身份/epoch/fence 断裂和交叉签名冲突则 `REJECT`。

本模型中使用的合成门槛是：独立观察者数 ≥ 2；证据新鲜度 ≤ 30 秒；最大时钟偏差 ≤ 5 秒。门槛是研究切片参数，不是生产建议或外部标准。

## 交叉签名及时钟偏差矩阵

| 观察/证据情形 | 时钟/新鲜度 | 签名与身份连续性 | 三类证据闭合 | 判定 |
|---|---|---|---|---|
| ≥2 观察者一致；receipt、log、外部效果一致 | 新鲜且偏差在界内 | 完整、无冲突；epoch/fence 连续 | 是 | RECOVERED |
| 观察者分歧 | 可有效 | 即使签名完整 | 是/否 | UNKNOWN |
| 缺少交叉签名或签名无法交叉验证 | 可有效 | 不完整 | 可能是 | UNKNOWN |
| 交叉签名冲突 | 任意 | 冲突 | 任意 | REJECT |
| 时钟偏差超过 5 秒 | 过界 | 其他可能完整 | 可能是 | UNKNOWN |
| 发生时钟回拨 | 无效时间序 | 任意 | 任意 | REJECT |
| 新鲜度超过 30 秒 | 过期 | 其他可能完整 | 可能是 | UNKNOWN |
| fence 已撤销或 identity/epoch/fence 断裂 | 任意 | 不连续 | 任意 | REJECT |
| 平台回执与日志不一致 | 可有效 | 可能完整 | 不闭合 | UNKNOWN |
| 平台与日志看似一致、但外部效果未确认 | 可有效 | 可能完整 | 不闭合 | UNKNOWN |
| exporter failure、query gap、retention expired | 不足/不可验证 | 任意 | 不闭合 | UNKNOWN |
| NO_EVENT、DROPPED、DELAYED | 不能由缺失推成功 | 任意 | 不闭合或延迟 | UNKNOWN |

“REJECT”表示当前证据包含不可接受的硬冲突或连续性破坏，不等同于证明业务事件绝对未发生；“UNKNOWN”表示证据不足或不一致但尚未达到硬拒绝条件。

## 观察者分歧与证据新鲜度

观察者记录必须按独立身份、region、epoch 和 fence 进行去重与连续性检查。相同 payload 的重复抄录不增加独立观察者计数。分歧、过期、回拨和偏差过界都阻断恢复。时间窗口只约束合成事件记录的观察时刻与核验时刻；它不证明任意真实时钟同步机制。

## 覆盖与实验结果

`fixtures/cases.json` 包含 14 个本地合成案例，覆盖全部要求的分类字段：`NO_EVENT`、`DELAYED`、`DROPPED`、`EXPORTER_FAILURE`、`QUERY_GAP`、`RETENTION_EXPIRED`、`VERIFIED_CONTINUITY`、`UNKNOWN`，并覆盖观察者分歧、freshness、clock skew/rollback、fence 撤销、交叉签名缺失/冲突、平台回执与日志/外部效果不一致。

实验状态分布：

- `RECOVERED`: 1
- `UNKNOWN`: 10
- `REJECT`: 3

结果由 `harness.py` 确定性生成。两次运行的 `outputs/results.json` 以字节比较一致；本地 validator、manifest validator、官方离线 `validate_research.py` 和 SHA256 校验均应通过。

## 来源与限制

本切片**无外部来源**，`sources.md` 明确记录仅本地合成证据；manifest 中所有 claims 均为 `status=inferred` 且 `sources=[]`。没有网络访问、真实服务、SDK、凭据或生产数据。

因此本切片不能证明：

- 生产耐久性或跨区域持久化能力；
- exactly-once 语义；
- 真实回滚、恢复或 fence 实现安全性；
- 任意外部效果已经发生；
- 生产 readiness、可用性、性能或故障率。

完成本切片不代表停线。下一独立切片建议在仍保持 synthetic-only 的前提下，专门做“证据撤销后的迟到 receipt 与 epoch/fence 重放窗口”矩阵，并增加模型级 property-based 生成、状态转换覆盖与最小反例收缩；仍不得将结果表述为 production verified。
