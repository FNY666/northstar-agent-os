# C 线信任连续性 S44：MCP server/resources 与 web tools 的授权和结果边界

## 结论（离线合成、推断）

MCP server 已连接、tool 返回成功或 web resource 可访问，不等于调用被正确授权、资源未越界、返回内容可归因或远端副作用已知。只有 server 声明并受信、tool/resource allowlist 闭合、include/exclude 语义一致、transport 认证、request context 绑定、argument schema 有效、resource URI/version 绑定、result/error 完整捕获、timeout 与 side-effect class 明确、approval boundary、source attribution、pagination 和 retry 对账均闭合且远端状态不未知时，才可判 `RECOVERED`。身份冲突或不可调和的权限/结果状态冲突判 `REJECT`；server/tool/resource 信任、边界、返回、超时、资源版本或 retry 状态未知保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S43 产物。

## 判定门

1. `identity_conflict` 或 `permission_conflict` 任一为真，输出 `REJECT`。
2. server/tool/resource、include/exclude、transport/context/schema、URI/version、result/error、timeout/side-effect、approval、attribution、pagination、retry 任一门未闭合，或远端状态未知，输出 `UNKNOWN`。
3. 只有授权边界、请求绑定、返回证据和失败/重试对账全部闭合，才输出 `RECOVERED`。
4. MCP tool success、resource URI 存在、HTTP/transport 成功或 web 页面可读取本身不能证明内容来源、完整性、权限范围或外部效果；超时/断流后保持 UNKNOWN，直到独立 read-back/reconciliation。
5. `RECOVERED` 仅表示本片夹具中的 MCP/web evidence gate 闭合，不代表生产 server trust、资源安全、external effect 或 exactly-once。

## 覆盖与确定性验证

- 28 个定向 cases：MCP tool/resource、web tool、allowlist、transport、context、schema、URI/version、result/error、timeout、approval、attribution、pagination、retry，以及各边界缺口、身份冲突、授权冲突和远端结果冲突。
- 22 个布尔门执行完整 `2^22 = 4,194,304` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产 MCP SDK/server、resource backend、web fetch、HTTP transport 或权限系统的验证。
- 未证明真实系统的 server trust、tool/resource allowlist、include/exclude 优先级、transport authentication、URI/version、schema、来源归因、分页、重试、超时或远端副作用语义。
- 所有布尔门代表“证据是否已获得”，不模拟真实网络、服务端执行或资源变更；生产接入必须独立 read-back、记录 request/result/error/URI/version，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
