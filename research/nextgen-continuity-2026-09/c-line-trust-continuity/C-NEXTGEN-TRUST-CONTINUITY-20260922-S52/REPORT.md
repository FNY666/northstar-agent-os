# C 线信任连续性 S52：hooks、subagents 与工具隔离边界

## 结论（离线合成、推断）

hook stdout、exit code、continue/decision 或 subagent 完成消息不能单独证明 agent loop 的最终状态和工具副作用。只有 hook 事件/作用域/顺序固定、stdout schema 与 exit 语义明确、timeout/continue/decision 可读回、项目 fingerprint/trust 边界闭合、subagent identity/tools/MCP/max_turns/timeout/history/tool isolation/recursion guard/policy/model override 全部绑定，且最终 loop state 可独立读回时，才可判 `RECOVERED`。跨 session 身份合并或同一 tool/loop 不可调和的 hook 控制冲突判 `REJECT`；hook/subagent 声明、事件顺序、超时、递归、隔离、override 或最终状态未知保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S51 产物。

## 判定门

1. `identity_conflict` 或 `hook_conflict` 任一为真，输出 `REJECT`。
2. hook declaration/event/order/stdout/exit/timeout/continue/decision/fingerprint/trust、subagent/tools/MCP/max_turns/timeout/history/isolation/recursion/policy/model/final read-back 任一门未闭合，或 loop effect unknown，输出 `UNKNOWN`。
3. 只有控制结果、隔离边界、递归限制与最终状态全部闭合，才输出 `RECOVERED`。
4. hook exit 0、decision allow、subagent 完成或 stdout JSON 本身不能证明工具副作用、loop 已收敛或远端状态已知；必须独立 read-back。
5. `RECOVERED` 仅表示本片夹具中的 hook/subagent evidence gate 闭合，不代表生产 agent loop、external effect、exactly-once 或业务提交。

## 覆盖与确定性验证

- 28 个定向 cases：hook lifecycle/stdout/exit/timeout/continue/decision/fingerprint/trust、subagent tools/MCP/max turns/timeout/history/isolation/recursion/policy/model override，以及各边界缺口、身份冲突和控制冲突。
- 24 个布尔门执行完整 `2^24 = 16,777,216` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产 hooks、subagents、MCP、policy、session history 或工具隔离实现的验证。
- 未证明真实系统的 hook timeout/exit/decision、项目 fingerprint/trust、subagent递归、history/tool isolation、model/policy override 或外部副作用语义。
- 所有布尔门代表“证据是否已获得”，不模拟真实 agent loop、子进程、网络或工具；生产接入必须独立 read-back hook/subagent/result 状态，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
