# C 线信任连续性 S66：跨系统导出/导入 provenance、脱敏/重签名与权限降级

## 结论（离线合成、推断）

跨系统导出、导入、脱敏或重签名成功不能单独证明内容来源、字段语义、权限范围和最终目标状态保持连续。只有 export/import identity 与 manifest、origin digest、field mapping、transform/redaction policy/authorization、resign scope/authorization、permission downgrade、target scope/recipient、canonicalization/algorithm version、timestamp/lineage order、source attribution 和 final read-back 全部闭合时，才可判 `RECOVERED`。跨项目身份合并或同一 origin 出现不可调和 export/import lineage 冲突判 `REJECT`；导出包、变换、重签名、权限降级、目标范围或最终导入状态未知保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S65 产物。

## 判定门

1. `identity_conflict` 或 `lineage_conflict` 任一为真，输出 `REJECT`。
2. export/import id/manifest、origin/mapping/transform、redaction/resign、permission downgrade、target/recipient scope、版本/时间/顺序、归因和最终读回任一门未闭合，或 transform state unknown，输出 `UNKNOWN`。
3. 只有导出/导入双向映射、变换授权、权限不扩大、版本链和最终状态全部闭合，才输出 `RECOVERED`。
4. 导出成功、脱敏完成、重签名成功或导入完成消息不能证明 origin 未变、目标权限未扩大或最终状态已提交；必须独立 read-back。
5. `RECOVERED` 仅表示本片夹具中的 cross-system provenance evidence gate 闭合，不代表 external effect、exactly-once、生产连续性或业务提交。

## 覆盖与确定性验证

- 30 个定向 cases：export/import id/manifest、origin digest、field mapping、transform、redaction、resign、permission downgrade、target/recipient scope、规范化/算法/时间/lineage、归因与最终读回，以及各边界缺口、身份冲突和 lineage 冲突。
- 25 个布尔门执行完整 `2^25 = 33,554,432` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产导出/导入、脱敏、重签名、权限委托或跨系统 provenance 系统的验证。
- 未证明真实系统的字段映射、变换确定性、重签名授权、权限降级、目标scope、跨平台归因或最终导入提交语义。
- 所有布尔门代表“证据是否已获得”，不模拟真实转换、网络、密钥或外部效果；生产接入必须独立重算 lineage/mapping/scope/read-back，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
