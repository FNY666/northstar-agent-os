# C 线信任连续性 S46：ACP/IDE session lifecycle 与 context/diff 通知边界

## 结论（离线合成、推断）

ACP/IDE companion 的协议握手、session 创建/加载、prompt、cancel、tool permission、contextUpdate、diff open/close 与 accepted/rejected 通知必须分别关联和验收。只有协议和 initialize 能力协商完成、session/turn/request identity 绑定、newSession/loadSession/prompt/cancel 状态可观察、通知序列完整、tool_call 与 permission 关联、IDE context/diff 状态闭合、stdio transport、session persistence、reconnect 对账、重复通知去重且没有未知远端状态时，才可判 `RECOVERED`。跨 session 身份合并或同一 session 的不可调和生命周期状态冲突判 `REJECT`；取消请求发送、断线、通知缺失、load 未读回或重连状态未知保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S45 产物。

## 判定门

1. `identity_conflict` 或 `lifecycle_conflict` 任一为真，输出 `REJECT`。
2. protocol/initialize、session/turn binding、new/load/prompt/cancel、通知序列、tool permission、context/diff、transport、persistence、reconnect、dedup 任一门未闭合，或 session/远端状态未知，输出 `UNKNOWN`。
3. 只有生命周期、通知顺序、持久化和断线对账全部闭合，才输出 `RECOVERED`。
4. cancel request 不等于远端已停止；loadSession 返回不等于历史完整；IDE accepted/rejected 或 diff close 缺失时不能推断编辑状态，必须保持 UNKNOWN。
5. `RECOVERED` 仅表示本片夹具中的 ACP/IDE evidence gate 闭合，不代表 exactly-once、远端副作用、rollback 或业务提交。

## 覆盖与确定性验证

- 26 个定向 cases：initialize/newSession、prompt/cancel、loadSession、context/diff、tool permission、stdio transport，以及协议/握手/session/prompt/cancel/notification/permission/context/diff/transport/persistence/reconnect/dedup 缺口、身份冲突和生命周期冲突。
- 22 个布尔门执行完整 `2^22 = 4,194,304` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产 ACP、IDE companion、JSON-RPC、session store 或编辑器状态的验证。
- 未证明真实系统的通知投递完整性、cancel 传播、断线重连、session persistence、tool permission 审计、diff 应用或外部文件提交语义。
- 所有布尔门代表“证据是否已获得”，不模拟真实进程、IDE、网络或远端 agent；生产接入必须独立 read-back、绑定 session/turn/request 并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
