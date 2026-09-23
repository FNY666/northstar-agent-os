# C 线信任连续性 S31：跨分区关联键与冲突隔离

## 结论（离线合成、推断）

跨分区关联必须将 `tenant/source/event_id/epoch/version` 作为身份域；`partition` 仅作为定位域，不能单独扩大关联。`payload_digest`、`causal_parent`、`event_time`、`ingest_time` 是证据域：同身份域且摘要一致、时间关系与保留范围闭合时可判 `RECOVERED`；查询或保留缺口只能判 `UNKNOWN`；同身份域异摘要、跨 tenant/source 误合并、跨 epoch fence 穿透属于 `REJECT`。三态互斥并 fail-closed。

本片仅使用本地 fixtures，`synthetic_only=true`、`production_verified=false`、claims `status=inferred`、`sources=[]`。未读取或修改 S1-S30。

## 键域与反例

| 检查 | 结论 |
|---|---|
| 键过窄：只用 event_id 或 event_id+partition | 会跨 tenant/source/epoch/version 误合并 |
| 键过宽：把 partition 纳入身份 | 同一事件迁移分区或重复投递时被错误拆分 |
| 正确身份域 | tenant、source、event_id、epoch、version；partition 留在 locator |
| 同摘要不同时间 | 合法：event-time 与 ingest-time 可不同，延迟不等于冲突 |
| 重复投递 | 合法：同身份域、同摘要、不同定位可归并 |
| 同身份域异摘要 | 不可调和冲突，`REJECT` |
| 版本迁移 | version 显式化，并要求 causal_parent/迁移边闭合；缺边为 `UNKNOWN` |
| epoch fence | fence 阻断跨周期穿透；明确穿透为 `REJECT` |

## 判定规则

1. 若 `payload_conflict` 或 `fence_conflict` 为真，或跨分区场景中身份域不一致，输出 `REJECT`。
2. 否则若身份域不一致但缺少足够的跨分区冲突证据，或存在 `query_gap`、保留期过期、排序/迁移链不完整或摘要证据缺失，输出 `UNKNOWN`。
3. 只有身份域正确、摘要一致、事件/摄取时间交叉排序闭合且在保留范围内，输出 `RECOVERED`。
4. `NO_EVENT`、`DROPPED`、`EXPORTER_FAILURE` 不证明未发生；证据不足统一 `UNKNOWN`。
5. `VERIFIED_CONTINUITY` 仅在闭合证据链下映射到 `RECOVERED`，不是第四种状态。

## 覆盖与结果

16 个 cases 覆盖：`NO_EVENT`、`DELAYED`、`DROPPED`、`EXPORTER_FAILURE`、`QUERY_GAP`、分页范围不足、`RETENTION_EXPIRED`、`VERIFIED_CONTINUITY`、`UNKNOWN`、同 payload、冲突 payload、重复投递、版本迁移、epoch fence、跨 tenant/source。harness 对 8 个布尔门执行完整 `2^8=256` 组合，并输出每个状态的 single-gate minimizer。

运行后结果写入 `outputs/results.json`，其中包含状态分布、逐 case 匹配、256 组合计数与最小反例。

## 证据限制

- 所有结论均为本地合成夹具上的 `inferred`，没有生产验证。
- 没有真实分区重平衡、时钟漂移、哈希碰撞、并发版本迁移或 exporter 重试数据。
- 保留期、分页边界和 query gap 仅以离散布尔门建模，无法量化实际漏检概率。
- payload_digest 的算法、规范化规则和密钥/盐策略未在本片定义；真实系统需先固定规范化与算法版本。
- causal_parent 只验证存在性与链闭合抽象，不验证真实因果语义。

## 下一片建议

S32 建议保持离线 synthetic-only，专门做“digest 规范化/算法版本 + 分页边界与保留窗口”的组合切片：加入 canonicalization version、hash algorithm、page cursor、watermark、fence token，构造哈希算法迁移和边界恰好落在 page/retention cutoff 的最小反例；维持同一三态互斥判定，避免触及历史切片。
