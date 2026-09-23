# C 线信任连续性 S40：跨系统 evidence-window schema 与互斥验收状态机

## 结论（离线合成、推断）

跨系统状态不能把 `NO_EVENT`、`DELAYED`、`DROPPED`、`EXPORTER_FAILURE`、`QUERY_GAP`、`RETENTION_EXPIRED` 和 `VERIFIED_CONTINUITY` 当成同一维度或任意成功/失败标签。只有 evidence window、source scope、平台 receipt、durable log、external effect 三轴、时间/水位、retention、pagination、export 状态与各类缺口全部闭合，且状态声明互斥时，才可判 `RECOVERED`。可解释的延迟、丢弃策略或故障补偿在证据链闭合后可恢复；未解释的延迟/丢弃、export 状态未知、查询缺口、保留期过期或只具备单一证据轴保持 `UNKNOWN`；同一窗口的不可调和终态、身份冲突或 receipt 与外部效果冲突判 `REJECT`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S39 产物。

## 判定门

1. `identity_conflict` 或 `state_conflict` 任一为真，输出 `REJECT`。
2. evidence window、source scope、三类证据轴、时间/水位、retention、pagination、export attempt/failure、delay/drop/no-event contract 任一门未闭合，或存在 `unknown_commit`，输出 `UNKNOWN`。
3. 只有完整窗口、三轴证据和状态分类语义均闭合，才输出 `RECOVERED`。
4. `NO_EVENT` 不是第四种成功状态；它只有在完整查询窗口和明确契约下才可成为闭合结果。`DELAYED`、`DROPPED` 和 `EXPORTER_FAILURE` 只有在各自解释、重试和最终 read-back 闭合后才可恢复。
5. `VERIFIED_CONTINUITY` 仍必须分别验证平台 receipt、durable log 与 external effect，不能以任一轴替代另两轴。

## 覆盖与确定性验证

- 25 个定向 cases：完整连续性、延迟、NO_EVENT、三轴闭合、解释性丢弃、exporter 故障补偿，以及未解释延迟/丢弃、exporter/query/retention/window/source/单轴/watermark/pagination/attempt/identity/unknown commit 缺口、状态冲突、身份冲突和 receipt-effect 冲突。
- 21 个布尔门执行完整 `2^21 = 2,097,152` 组合，使用流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 同时检查状态分布、七类 evidence-window class 覆盖、三态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产审计窗口、日志/遥测导出、消息队列、查询 API 或外部系统 read-back 的验证。
- 未证明真实系统的 NO_EVENT、QUERY_GAP、RETENTION_EXPIRED、exporter failure、drop counter、platform receipt、durable log 或 external effect 语义。
- 所有布尔门代表“证据是否已获得”，不模拟真实故障时序、平台差异或外部副作用；生产接入必须独立 read-back、按 evidence axis 分开验收，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的状态机门闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
