# C 线信任连续性 S51：隐私、遥测、条款与配置优先级边界

## 结论（离线合成、推断）

隐私条款存在、telemetry opt-out 已设置或配置文件已修改，不等于当前 runtime 按预期处理数据。只有 auth context、terms/privacy scope、data region、telemetry setting/opt-out、prompt/tool/session/file event 数据分类、redaction、workspace/user/env precedence、runtime read-back、retention、export destination 与 access control 全部绑定并闭合时，才可判 `RECOVERED`。跨账户/项目身份合并或同一 runtime 不可调和的隐私采集状态冲突判 `REJECT`；认证上下文、条款、区域、数据分类、配置优先级、生效状态、保留/导出/访问路径未知保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S50 产物。

## 判定门

1. `identity_conflict` 或 `privacy_conflict` 任一为真，输出 `REJECT`。
2. auth/terms/privacy/region、telemetry/opt-out、数据分类/redaction、配置 precedence/runtime read-back、retention/export/access control 任一门未闭合，或 data path unknown，输出 `UNKNOWN`。
3. 只有适用条款、数据分类、策略生效、导出目的地和访问边界全部闭合，才输出 `RECOVERED`。
4. opt-out 设置、配置文件存在、隐私页面可访问或 exporter 请求成功本身不能证明当前实例行为；必须 runtime read-back 和数据路径对账。
5. `RECOVERED` 仅表示本片夹具中的 privacy/telemetry evidence gate 闭合，不代表生产隐私合规、数据未外泄或业务提交。

## 覆盖与确定性验证

- 28 个定向 cases：terms/privacy/region、telemetry/opt-out、prompt/tool/session/file event 分类、redaction、配置优先级、runtime read-back、retention/export/access control，以及各边界缺口、身份冲突和隐私状态冲突。
- 23 个布尔门执行完整 `2^23 = 8,388,608` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产条款、遥测、隐私、数据区域、配置加载器、retention 或 access control 的验证。
- 未证明真实系统的隐私政策适用性、prompt/tool/session/file event 分类、opt-out传播、workspace/user/env优先级、export destination、数据删除或访问审计语义。
- 所有布尔门代表“证据是否已获得”，不模拟真实采集、网络、供应商或外部效果；生产接入必须独立 read-back runtime/data path/audit，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产合规或业务提交。
