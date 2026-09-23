# C 线信任连续性 S32：摘要规范化、算法迁移与分页/保留边界

## 结论（离线合成、推断）

跨系统证据只有在身份域正确、摘要可在明确的 `canonicalization_version` 与 `hash_algorithm` 语义下等价、分页游标链闭合、水位线闭合、保留窗口和 cutoff 边界语义均已证明时，才可判定 `RECOVERED`。算法或规范化版本变化本身不是冲突，也不是等价证明：有可信 dual-digest/映射/重放证明时可恢复；没有证明则保持 `UNKNOWN`。同一规范与算法下的 canonical bytes 摘要冲突必须 `REJECT`；旧 fence token 或身份域冲突同样 `REJECT`。三态互斥、fail-closed。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S31 产物。

## 判定门

1. `identity_conflict`、`digest_conflict`、`fence_conflict` 或无效 `fence_valid` 任一为真，输出 `REJECT`。
2. 身份域缺失、摘要不能证明等价、规范化不完整、算法/规范化迁移没有 attestation、分页链或 cursor 终止边界缺失、水位线未闭合、保留窗口未闭合/已过期、retention cutoff 包含语义未证明，输出 `UNKNOWN`。
3. 只有全部必要门闭合，才输出 `RECOVERED`。
4. `NO_EVENT`、分页成功但未证明终止、恰在 retention cutoff 但 inclusive/exclusive 语义未知，都不能推出未发生，保持 `UNKNOWN`。
5. 算法迁移或规范化迁移只有在同一 canonical bytes 的 dual-digest、版本映射或可复现重放证据闭合时，才可跨版本恢复。

## 覆盖与确定性验证

- 21 个定向 cases：完整窗口、算法迁移、规范化迁移、分页末端、retention cutoff、延迟水位线、算法/规范化缺口、digest 不等价、分页终止缺失、游标跳页、水位线未闭合、retention cutoff 语义未知、过期、身份缺失、NO_EVENT、摘要冲突、身份冲突、旧 fence、canonical bytes 冲突、无迁移证明、多个边界同时未闭合。
- 16 个布尔门执行完整 `2^16 = 65,536` 组合，输出每个状态的计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产协议、哈希实现或数据保留系统的验证。
- 未证明任何真实系统的 canonicalization 规范、哈希碰撞概率、算法迁移兼容性、分页 API 语义、水位线实现、保留策略或 fencing 实现。
- `digest_equivalent` 和边界布尔门代表已获得的外部证据，不模拟真实服务返回；生产接入必须独立 read-back、固定算法/规范版本、验证 cursor 链、watermark 与 retention cutoff，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的规则闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
