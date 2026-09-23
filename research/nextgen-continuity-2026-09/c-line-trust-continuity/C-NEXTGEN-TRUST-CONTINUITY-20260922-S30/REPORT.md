# S30 离线合成研究报告：跨分区 fence 证据合并与 bounded replay 分页重叠

## 结论

本切片只验证一个**确定性的合成判定器**：跨分区证据只有在 retention 窗口完整、分页没有游标跳跃或缺页、query gap 与 replay 截断均不存在、fence 证据已合并且 epoch 连续、且不存在同一 `event_id` 的冲突 payload 或 fence 分叉时，才可判定 `RECOVERED`。任何证据不完整或闭合条件不足均保持 `UNKNOWN`；明确不可调和冲突才 `REJECT`。该结论不外推至生产。

## 判定契约

- **RECOVERED**：全部必要证据闭合，跨分区 fence merge 成功，epoch 连续，retention 完整，bounded replay 可覆盖且无 cursor jump、缺页、query gap、截断；重叠页、乱序、重复仅在可去重且不破坏闭合条件时可容忍。
- **UNKNOWN**：分页游标跳跃、重叠但无法闭合、缺页、query gap、replay 截断、retention 边界不完整、exporter failure、未合并 fence、epoch 不连续等。`NO_EVENT`、`DELAYED`、`DROPPED` 不凭空恢复。
- **REJECT**：同一 `event_id` 跨分区 payload 冲突，或 fence epoch 分叉等明确不可调和冲突。REJECT 优先于 UNKNOWN。

## 覆盖矩阵

| 主题/分类 | 代表 case | 结果 | 规则 |
|---|---:|---|---|
| VERIFIED_CONTINUITY | S30-01, S30-08 | RECOVERED | 全闭合；重叠/乱序/重复可在闭合条件下容忍 |
| NO_EVENT | S30-02 | UNKNOWN | query gap 未闭合，不把无观察当作无事件 |
| DELAYED | S30-03 | UNKNOWN | cursor jump 破坏分页连续性 |
| DROPPED | S30-04 | UNKNOWN | missing page 不能证明缺失语义 |
| EXPORTER_FAILURE | S30-05 | UNKNOWN | fence merge 未完成 |
| QUERY_GAP | S30-06 | UNKNOWN | 查询证据有 gap |
| RETENTION_EXPIRED | S30-07 | UNKNOWN | retention 不完整，无法闭合边界 |
| replay truncation | S30-09 | UNKNOWN | bounded replay 截断 |
| same event_id payload conflict | S30-10 | REJECT | 明确冲突，不可调和 |
| fence epoch fork | S30-11 | REJECT | 明确 fence 分叉 |
| overlap only / incomplete merge | S30-12 | UNKNOWN | 重叠页本身不是闭合证据 |
| cursor skip + retention | S30-13 | UNKNOWN | 多重不完整保持 fail-closed |

## 测试与验证

- 固定 fixtures：13 cases，覆盖三态及全部要求的异常分类。
- property sweep：8 个布尔维度，`2^8 = 256` 组合；预期违规 0。
- 单门 minimizer：逐一关闭/触发 cursor jump、missing page、query gap、replay truncation、retention、fence merge、fence continuity，以及 payload conflict/fence fork；不完整门均为 UNKNOWN，冲突门均为 REJECT。
- harness 两次运行后对 `outputs/results.json` 做字节比较，必须一致。
- 已设计并运行本地 `validator.py`、`manifest_validator.py`、官方 `validate_research.py` 及 `sha256sum -c SHA256SUMS`；刷新 SHA256 后再次校验。

## 合成边界与局限

`synthetic_only=true`、`production_verified=false`。manifest 中所有 claims 均为 `status=inferred` 且 `sources=[]`；没有网络、服务、SDK、凭据、生产数据或外部效果。不能推出生产耐久性、exactly-once、回滚语义、真实外部效果或 production readiness，也不能证明具体 exporter/query/replay 实现正确。

## 下一独立切片建议

S31：专门测试“跨分区同一 event_id 的可证明关联键与冲突隔离”，加入相同 payload/hash、版本化 payload、event-time 与 ingest-time 交叉排序，以及 epoch 边界的最小反例；保持新目录、离线 synthetic-only、三态 fail-closed，不读取 S1–S30。
