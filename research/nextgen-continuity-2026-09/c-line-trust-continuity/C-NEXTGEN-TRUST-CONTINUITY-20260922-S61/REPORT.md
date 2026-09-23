# C 线信任连续性 S61：人工决策 provenance、职责分离与 override/appeal/reopen

## 结论（离线合成、推断）

人工审核、批准或 override 的存在不能单独证明最终决定合法、职责分离完成或利益相关者已被通知。只有 decision/reviewer/role/scope、separation of duties、approval evidence、override reason/authorization、dissent/appeal path/owner、reopen condition、decision version/previous digest、effective/expiry time、audit sequence、notification/stakeholder ack 和 final decision read-back 全部闭合时，才可判 `RECOVERED`。跨项目身份合并或同一 decision 出现不可调和人工终态冲突判 `REJECT`；审核者、批准范围、异议/申诉、版本、有效期、审计、通知或最终状态未知保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S60 产物。

## 判定门

1. `identity_conflict` 或 `review_conflict` 任一为真，输出 `REJECT`。
2. decision/reviewer/role/职责分离、approval/override、dissent/appeal/reopen、版本/digest/time/expiry、audit/notification/ack/final read-back 任一门未闭合，或 review state unknown，输出 `UNKNOWN`。
3. 只有决定身份、授权、异议申诉、版本生命周期、通知审计和最终读回全部闭合，才输出 `RECOVERED`。
4. 人工结论、override消息、批准按钮或通知发送本身不能证明范围合法、职责分离、申诉可用或目标状态已生效；必须保留前决策关联和独立读回。
5. `RECOVERED` 仅表示本片夹具中的 human-decision evidence gate 闭合，不代表生产审计、external effect、exactly-once 或业务提交。

## 覆盖与确定性验证

- 29 个定向 cases：decision/reviewer/role、职责分离、approval/override、dissent/appeal/reopen、version/digest/effective/expiry、audit/notification/ack/read-back，以及各边界缺口、身份冲突和人工决策冲突。
- 24 个布尔门执行完整 `2^24 = 16,777,216` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产人工审核、RBAC/职责分离、申诉、override、审计或通知系统的验证。
- 未证明真实系统的审核者身份、审批scope、利益冲突、申诉复核、决策版本、有效期、利益相关者ack或目标状态提交语义。
- 所有布尔门代表“证据是否已获得”，不模拟真实人工行为、时序或外部效果；生产接入必须独立验证review/approval/audit/final state，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
