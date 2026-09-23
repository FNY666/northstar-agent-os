# C 线信任连续性 S64：通知内容隐私、同意、数据最小化与访问审计

## 结论（离线合成、推断）

通知已授权发送或渠道成功不等于内容处理合规、recipient 有权接收或数据不会超范围留存/导出。只有 notification classification、recipient authorization/consent、purpose、payload minimization/redaction、channel data policy、region、retention/deletion、export scope/destination、access role/audit、template/locale/decision version、recipient preference、fallback privacy 和 replay safety 全部闭合时，才可判 `RECOVERED`。跨项目隐私合并或同一 recipient/decision 出现不可调和 allow/deny、retained/deleted 状态冲突判 `REJECT`；授权、同意、目的、最小化、区域、保留、导出、访问、模板或重放隐私状态未知保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S63 产物。

## 判定门

1. `identity_conflict` 或 `privacy_conflict` 任一为真，输出 `REJECT`。
2. 分类、recipient授权/consent/purpose、最小化/redaction、渠道/区域、保留/删除、导出/目的地、访问审计、模板/locale/version、偏好/fallback/replay 任一门未闭合，或 privacy state unknown，输出 `UNKNOWN`。
3. 只有内容分类、同意授权、数据最小化、生命周期、访问审计和重放保护全部闭合，才输出 `RECOVERED`。
4. 发送成功、recipient 存在或渠道允许发送本身不能证明内容可被该对象接收、字段最小化或过期数据已删除；必须独立 policy/runtime/read-back。
5. `RECOVERED` 仅表示本片夹具中的 notification privacy evidence gate 闭合，不代表 external effect、exactly-once、生产合规或业务提交。

## 覆盖与确定性验证

- 29 个定向 cases：分类、授权、同意、目的、最小化、redaction、渠道/区域、保留/删除、导出、访问角色/审计、模板/locale/决定版本、偏好/fallback/replay，以及各边界缺口、身份冲突和隐私冲突。
- 24 个布尔门执行完整 `2^24 = 16,777,216` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产通知隐私、consent、数据区域、retention、访问控制或审计系统的验证。
- 未证明真实系统的recipient授权、撤回同意、数据最小化、渠道策略、删除、导出、访问审计、模板版本或重放隐私语义。
- 所有布尔门代表“证据是否已获得”，不模拟真实用户、渠道或数据处理；生产接入必须独立验证policy/runtime/data path，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
