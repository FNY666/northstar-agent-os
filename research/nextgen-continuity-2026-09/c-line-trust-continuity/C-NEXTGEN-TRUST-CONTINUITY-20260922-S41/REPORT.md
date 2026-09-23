# C 线信任连续性 S41：provenance lineage、跨变换导出与证据可追溯性

## 结论（离线合成、推断）

派生证据、导出记录、导入记录、脱敏结果或重签名结果都不能脱离 provenance lineage 单独采信。只有身份域正确、origin 已认证、每条 derivation parent digest 完整绑定、变换已声明且获授权并可确定性重放、export/import mapping 双向闭合、重签名 scope 有效、redaction provenance 完整、canonicalization/algorithm 版本绑定、timestamp chain、actor identity、evidence location 与 lineage order 均闭合且重复派生已去重时，才可判 `RECOVERED`。身份冲突、同一 lineage identity 的不可调和双重陈述或 parent digest 冲突判 `REJECT`；其余 provenance 缺口、未知变换、未授权变换或位置/时间链不完整保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S40 产物。

## 判定门

1. `identity_conflict` 或 `lineage_conflict` 任一为真，输出 `REJECT`。
2. origin、derivation、parent digest、transform、export/import、resign、redaction、canonicalization、algorithm、timestamp、actor、location、order、dedup 任一门未闭合，或 transform 类型未知，输出 `UNKNOWN`。
3. 只有完整 lineage、授权、可重放和双向映射门闭合，才输出 `RECOVERED`。
4. 导出成功、导入成功、脱敏完成或重签名完成本身不能证明源证据、授权范围和变换结果；缺少 parent digest 或 mapping 时保持 `UNKNOWN`。
5. `RECOVERED` 仅表示本片夹具中的 provenance evidence chain 闭合，不代表内容真实性、external effect、exactly-once 或业务提交。

## 覆盖与确定性验证

- 28 个定向 cases：origin/export、确定性变换、授权脱敏、重签名、跨系统 import/export、重复派生，以及 origin/parent/transform/mapping/scope/redaction/canonicalization/algorithm/time/actor/location/order/dedup 缺口、未知变换、身份冲突和 lineage 冲突。
- 21 个布尔门执行完整 `2^21 = 2,097,152` 组合，使用流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产 provenance、签名、导出/导入、脱敏、重签名或审计存储系统的验证。
- 未证明真实系统的 parent digest、transform determinism、mapping、scope、canonicalization/algorithm 版本、timestamp、actor 或 evidence location 语义。
- 所有布尔门代表“证据是否已获得”，不模拟真实转换、跨系统失败、密钥管理或路径重用；生产接入必须保存不可变 lineage、独立验证每步 mapping，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的证据门闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
