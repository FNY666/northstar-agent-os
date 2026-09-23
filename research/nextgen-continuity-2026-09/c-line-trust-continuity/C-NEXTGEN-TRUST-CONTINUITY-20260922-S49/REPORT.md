# C 线信任连续性 S49：headless/JSON/JSONL 输出、Plan Mode 与 cancel/exit 边界

## 结论（离线合成、推断）

headless 输出存在、JSON/JSONL 可解析或进程返回 exit code，不等于本次 run 的最终状态、工具副作用或外部提交已确定。只有运行模式和 identity 明确、事件 schema/framing 闭合、message/tool_use/tool_result/error 与 run/turn/request 绑定、exit code 语义明确、Plan Mode 范围和写入边界固定、approval request/decision 可追溯、cancel signal/state 可观察、stdin/input、stream order、final state read-back 和 external-effect 边界均闭合时，才可判 `RECOVERED`。跨 run 身份合并或同一 run 不可调和的 mode/approval/cancel 终态冲突判 `REJECT`；事件缺失、取消后状态未知、批准缺失、流式 framing/顺序不完整或退出码无法映射保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S48 产物。

## 判定门

1. `identity_conflict` 或 `mode_conflict` 任一为真，输出 `REJECT`。
2. mode/schema/framing、事件绑定、exit code、Plan Mode scope/write boundary、approval、cancel、input/stream、final read-back 或 external-effect 边界任一未闭合，或 final state unknown，输出 `UNKNOWN`。
3. 只有输出事件、批准/取消、计划写入边界和最终状态全部闭合，才输出 `RECOVERED`。
4. exit code、输出结束、cancel request 或 Plan Mode 计划文件本身不能证明远端已停止、动作已批准或外部目标已提交；必须独立 read-back。
5. `RECOVERED` 仅表示本片夹具中的 headless/Plan evidence gate 闭合，不代表 production execution、external effect、exactly-once 或业务提交。

## 覆盖与确定性验证

- 27 个定向 cases：headless JSON/JSONL、Plan Mode、prompt/cancel/exit、stream order、输入绑定、外部效果分离，以及 mode/schema/framing/event/exit/plan/approval/cancel/input/stream/read-back 缺口、身份冲突和模式终态冲突。
- 23 个布尔门执行完整 `2^23 = 8,388,608` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产 headless CLI、JSONL event protocol、Plan Mode、审批/取消或 exit code runtime 的验证。
- 未证明真实系统的事件顺序、stdout/stderr framing、cancel propagation、审批审计、计划写入限制、退出码语义或外部目标状态。
- 所有布尔门代表“证据是否已获得”，不模拟真实进程、网络、工具和外部副作用；生产接入必须保存 run/turn/event identity、独立 read-back，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
