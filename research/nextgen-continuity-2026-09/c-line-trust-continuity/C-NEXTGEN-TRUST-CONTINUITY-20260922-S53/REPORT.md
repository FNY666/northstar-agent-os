# C 线信任连续性 S53：远程 A2A subagent/session streaming 与持久化边界

## 结论（离线合成、推断）

A2A agent card、认证成功或 streaming task 更新不能单独证明远程 subagent 请求被正确授权、消息属于正确 task/context、跨 invocation 状态已持久化或远端副作用已提交。只有 agent card/endpoint、auth scheme/credential、proxy scope、streaming capability、task/context/message identity、status/artifact update 顺序、session state 与 cross-invocation 绑定、abort/cancel 状态、error/retry、协议兼容性和远端效果 read-back 全部闭合时，才可判 `RECOVERED`。跨 agent/session 身份合并或认证状态冲突判 `REJECT`；agent card、认证、stream、task/context、持久化、取消、错误、重试或远端状态未知保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S52 产物。

## 判定门

1. `identity_conflict` 或 `auth_conflict` 任一为真，输出 `REJECT`。
2. agent card/auth/proxy/streaming、task/context/message/status/artifact、session persistence/cross-invocation、abort/cancel、error/retry、remote read-back 或 version 任一门未闭合，或 remote state unknown，输出 `UNKNOWN`。
3. 只有远程能力、认证、事件关联、持久化、取消/错误和最终读回全部闭合，才输出 `RECOVERED`。
4. agent card、task completed、artifact update、cancel request 或 streaming connection 成功本身不能证明远端已停止、外部效果已提交或下一次 invocation 续接了原状态；必须独立 reconciliation。
5. `RECOVERED` 仅表示本片夹具中的 A2A evidence gate 闭合，不代表 production A2A、exactly-once、external effect 或业务提交。

## 覆盖与确定性验证

- 28 个定向 cases：agent card/auth/proxy/streaming、task/context/message/status/artifact、session persistence、cross-invocation、abort/cancel、error/retry、A2A version 与远端 read-back，以及各边界缺口、身份冲突和认证冲突。
- 23 个布尔门执行完整 `2^23 = 8,388,608` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产 A2A server/client、HTTP streaming、OAuth/Bearer/Basic、session store 或远程 agent 的验证。
- 未证明真实系统的 agent card freshness、认证重试、proxy行为、task/context persistence、artifact/status投递、abort传播、错误/重试、副作用提交或协议兼容性。
- 所有布尔门代表“证据是否已获得”，不模拟真实网络、远端进程或业务效果；生产接入必须独立 read-back task/context/session/effect，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
