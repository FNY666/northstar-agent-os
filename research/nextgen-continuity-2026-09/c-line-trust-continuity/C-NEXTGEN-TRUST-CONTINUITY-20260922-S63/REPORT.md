# C 线信任连续性 S63：最终决定的 supersession/reopen/revoke 与 recipient 状态收敛

## 结论（离线合成、推断）

通知最终决定后，旧版本的 supersession、reopen、revoke、recipient 状态、迟到 ack 和重发不能被简单视为成功或失败。只有 decision version、supersession/reopen/revoke 状态、effective window、recipient/read/ack 语义、未确认状态、投递证据保留、retention/export/audit、跨渠道一致性、recipient reconciliation、迟到 ack、stale decision 保护、reissue/dedup 和最终 read-back 全部闭合时，才可判 `RECOVERED`。跨项目身份合并或同一 recipient/version 出现不可调和 active/revoked/delivered/failed 终态冲突判 `REJECT`；版本、撤回、ack、保留、导出、跨渠道、迟到 ack 或最终传播状态未知保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S62 产物。

## 判定门

1. `identity_conflict` 或 `notification_conflict` 任一为真，输出 `REJECT`。
2. decision/supersession/reopen/revoke/effective window、recipient/ack/read/unack、retention/export/audit、cross-channel/reconciliation、late ack/stale decision/reissue/dedup/readback 任一门未闭合，或 propagation state unknown，输出 `UNKNOWN`。
3. 只有旧新决定关系、recipient 状态、迟到事件处理、保留审计和最终收敛全部闭合，才输出 `RECOVERED`。
4. 新决定存在、撤回请求成功、单个 recipient ack 或重发完成本身不能证明旧决定已失效、所有对象已收敛或最终状态已提交；必须版本化逐对象 read-back。
5. `RECOVERED` 仅表示本片夹具中的 supersession/propagation evidence gate 闭合，不代表 external effect、exactly-once、生产连续性或业务提交。

## 覆盖与确定性验证

- 28 个定向 cases：decision version、supersession、reopen、revoke、effective window、recipient/read/ack/unack、投递证据保留、retention/export/audit、跨渠道、reconciliation、迟到 ack、stale decision、reissue/dedup/readback，以及各边界缺口、身份冲突和通知冲突。
- 24 个布尔门执行完整 `2^24 = 16,777,216` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产通知状态机、撤回/重开、recipient store、ack、retention 或多渠道收敛系统的验证。
- 未证明真实系统的版本传播、旧决定失效、迟到 ack、跨渠道一致性、recipient reconciliation、导出审计或重发幂等语义。
- 所有布尔门代表“证据是否已获得”，不模拟真实用户状态、渠道时序或外部效果；生产接入必须按 decision version/recipient 独立 read-back，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
