# C 线信任连续性 S65：最小权限、租约/撤销与 tool/model/data access 隔离

## 结论（离线合成、推断）

权限 grant、工具允许或模型可调用某资源，不能单独证明访问满足最小权限、租约未过期或撤销已传播。只有 principal/resource/action/scope/purpose、least privilege、grant/expiry/renewal/revocation、delegation chain、tool permission、model capability、data class、region/tenant、lease fence、stale writer rejection、runtime access read-back 与 audit 全部闭合时，才可判 `RECOVERED`。跨 tenant/principal 身份合并或同一 grant 不可调和 allow/revoke 终态冲突判 `REJECT`；权限范围、租约、撤销传播、工具/模型能力、数据分类、fence、旧写者或访问 read-back 未知保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S64 产物。

## 判定门

1. `identity_conflict` 或 `permission_conflict` 任一为真，输出 `REJECT`。
2. principal/resource/action/scope/purpose、最小权限、grant/expiry/renewal/revocation、delegation/tool/model/data/region/tenant、lease/fence/stale writer、access read-back/audit 任一门未闭合，或 access state unknown，输出 `UNKNOWN`。
3. 只有授权边界、撤销传播、租约fence和运行时访问读回全部闭合，才输出 `RECOVERED`。
4. policy/allow 成功、token存在、租约续期或工具调用完成本身不能证明旧权限已撤销、scope未扩大或 stale writer 被拒绝；必须独立 read-back。
5. `RECOVERED` 仅表示本片夹具中的 access-control evidence gate 闭合，不代表 external effect、exactly-once、生产安全或业务提交。

## 覆盖与确定性验证

- 29 个定向 cases：principal/resource/action/scope/purpose、least privilege、grant/expiry/renewal/revocation、delegation、tool/model capability、data class/region/tenant、lease/fence/stale writer、access read-back/audit，以及各边界缺口、身份冲突和权限冲突。
- 25 个布尔门执行完整 `2^25 = 33,554,432` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产 IAM/RBAC、工具权限、模型能力、租约、撤销或 fencing 系统的验证。
- 未证明真实系统的最小权限、grant lifecycle、revocation propagation、delegation、data class、region/tenant隔离、stale writer rejection 或访问审计语义。
- 所有布尔门代表“证据是否已获得”，不模拟真实权限缓存、代理或外部效果；生产接入必须独立 read-back grant/use/revoke/lease/fence，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
