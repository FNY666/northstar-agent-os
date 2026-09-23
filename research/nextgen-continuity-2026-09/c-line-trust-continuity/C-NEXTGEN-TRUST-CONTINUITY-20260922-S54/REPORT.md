# C 线信任连续性 S54：多源模型路由、token caching、auto memory 与 git worktrees

## 结论（离线合成、推断）

模型源、token cache、自动记忆或 worktree 状态存在，不等于它们没有跨账户、workspace、session 或分支串线。只有模型来源/优先级/最终 provider read-back、token cache scope/expiry/key/invalidation、auto memory scope/read-write/retention/export、worktree identity/path/branch/dirty state/cleanup 和跨worktree隔离全部闭合时，才可判 `RECOVERED`。跨身份合并或同一请求不可调和的模型路由状态冲突判 `REJECT`；模型来源/路由、缓存复用、memory读写、worktree路径/分支/清理或隔离状态未知保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S53 产物。

## 判定门

1. `identity_conflict` 或 `route_conflict` 任一为真，输出 `REJECT`。
2. model source/precedence/provider、token cache scope/expiry/key/invalidation、memory scope/read-write/retention/export、worktree identity/path/branch/dirty/cleanup/isolation 任一门未闭合，或状态未知，输出 `UNKNOWN`。
3. 只有模型、缓存、memory、worktree 和跨worktree隔离全部闭合，才输出 `RECOVERED`。
4. 模型响应、缓存命中、memory写入或 worktree 命令成功本身不能证明最终归属、未跨边界复用或清理完成；必须独立 read-back。
5. `RECOVERED` 仅表示本片夹具中的 route/cache/memory/worktree evidence gate 闭合，不代表 production isolation、external effect、exactly-once 或业务提交。

## 覆盖与确定性验证

- 27 个定向 cases：model route、token cache、auto memory、retention/export、worktree identity/path/branch/dirty/cleanup/cross-isolation，以及各边界缺口、身份冲突和路由冲突。
- 22 个布尔门执行完整 `2^22 = 4,194,304` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产模型路由、token cache、auto memory 或 git worktree 实现的验证。
- 未证明真实系统的 provider/model precedence、缓存隔离/invalidation、memory注入/保留/导出、worktree路径/HEAD/dirty cleanup 或跨worktree状态共享语义。
- 所有布尔门代表“证据是否已获得”，不模拟真实模型、文件系统、git进程或外部效果；生产接入必须独立 read-back route/cache/memory/worktree，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产隔离或业务提交。
