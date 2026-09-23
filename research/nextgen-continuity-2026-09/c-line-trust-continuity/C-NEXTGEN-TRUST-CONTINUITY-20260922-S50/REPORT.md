# C 线信任连续性 S50：认证、配额、计费、隐私与模型路由边界

## 结论（离线合成、推断）

认证成功、模型名存在或请求收到响应，不能单独证明 credential scope、quota、billing identity、privacy/telemetry policy、最终 provider/model 或 retry 费用已经确定。只有认证方式和凭据来源固定、token scope/freshness、quota 范围/余额、billing identity、privacy/telemetry policy、requested/selected model、fallback/routing precedence、provider identity、rate-limit、retry charge、region constraint 与 usage record 全部闭合时，才可判 `RECOVERED`。跨账户/项目身份合并或同一请求不可调和的认证/路由/计费隐私状态冲突判 `REJECT`；credential、配额、计费、隐私、模型选择、fallback、限流、重试费用或 provider 状态未知保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S49 产物。

## 判定门

1. `identity_conflict` 或 `auth_route_conflict` 任一为真，输出 `REJECT`。
2. auth method/credential/scope/freshness、quota/billing、privacy/telemetry、model/fallback/provider、routing precedence、rate-limit/retry/region/usage 任一门未闭合，或 provider state unknown，输出 `UNKNOWN`。
3. 只有认证、配额/账单、隐私、模型路由、重试费用和 usage 对账全部闭合，才输出 `RECOVERED`。
4. API响应、模型名、HTTP成功或 fallback 触发本身不能证明最终 provider/model、计费归属、请求费用、隐私处理或外部效果；必须独立 usage/read-back。
5. `RECOVERED` 仅表示本片夹具中的 auth/quota/routing evidence gate 闭合，不代表生产认证、账单准确性、隐私合规或业务提交。

## 覆盖与确定性验证

- 27 个定向 cases：API key/OAuth/Vertex路径、模型优先级、fallback、quota/billing、privacy/telemetry、限流重试、region/usage，以及认证/凭据/scope/token/quota/billing/privacy/model/provider/routing/retry/region缺口、身份冲突和认证路由冲突。
- 23 个布尔门执行完整 `2^23 = 8,388,608` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产 OAuth/API key/Vertex、quota、billing、privacy、telemetry 或 model router 的验证。
- 未证明真实系统的认证状态、token scope/freshness、配额归属、计费计量、隐私条款、telemetry采集、fallback、retry charge 或 region 语义。
- 所有布尔门代表“证据是否已获得”，不模拟真实 provider、网络、账单或外部效果；生产接入必须独立 read-back usage/provider/model 与账单边界，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产合规或业务提交。
