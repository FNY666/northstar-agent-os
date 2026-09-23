# C 线信任连续性 S43：工具调用、权限边界与副作用验收

## 结论（离线合成、推断）

工具声明、policy decision 或命令退出码本身不能证明目标动作安全完成。只有 tool identity/scope 明确、审批要求和批准状态可追溯、sandbox/cwd/path allowlist 闭合、命令参数和输入规范化、输出被完整捕获、side effect 与 postcondition 可独立 read-back、timeout/failure/retry 语义明确、用户可见结果与真实目标状态绑定、skill/tool chain 完整且不存在未知副作用时，才可判 `RECOVERED`。身份冲突或同一请求不可调和的权限决策冲突判 `REJECT`；权限范围未知、审批缺失、路径/参数边界未闭合、失败/超时后的目标状态未知或后置条件缺失保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S42 产物。

## 判定门

1. `identity_conflict` 或 `permission_conflict` 任一为真，输出 `REJECT`。
2. tool declaration/scope、policy、approval、sandbox/cwd/path、arguments/input、output、side effect、postcondition、timeout/failure/retry、user-visible binding、tool chain 任一门未闭合，或存在 `unknown_side_effect`，输出 `UNKNOWN`。
3. 只有权限、执行边界、结果捕获和独立后置条件全部闭合，才输出 `RECOVERED`。
4. shell/file write/skill activation 成功、进程退出码为零或用户看到成功消息本身不能证明外部目标已提交；必须独立 read-back，超时/断流/失败后保持 UNKNOWN，直到对账。
5. `RECOVERED` 仅表示本片夹具中的工具证据门闭合，不代表生产权限系统、外部效果、exactly-once 或业务提交。

## 覆盖与确定性验证

- 27 个定向 cases：tool call、shell sandbox、filesystem write、ask-user approval、skill activation、timeout postcondition，以及 tool/scope/policy/approval/sandbox/cwd/path/arguments/input/output/side-effect/postcondition/timeout/failure/retry/user-result/tool-chain 缺口、身份冲突和权限/副作用冲突。
- 22 个布尔门执行完整 `2^22 = 4,194,304` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产 shell/filesystem/approval/skill/policy/sandbox 实现的验证。
- 未证明真实系统的权限继承、路径解析、命令解释器、超时取消、重试去重、用户审批审计或外部目标提交语义。
- 所有布尔门代表“证据是否已获得”，不模拟真实进程、权限策略或副作用时序；生产接入必须独立 read-back、固定目标边界、保存 tool request/result/postcondition，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
