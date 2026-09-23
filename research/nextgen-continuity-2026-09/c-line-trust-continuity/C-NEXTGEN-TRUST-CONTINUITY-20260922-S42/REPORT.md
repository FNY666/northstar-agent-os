# C 线信任连续性 S42：配置优先级、环境变量与运行时生效边界

## 结论（离线合成、推断）

配置文件存在或环境变量已设置，不等于运行时采用了对应值。只有配置身份和来源明确、schema/type 校验通过、默认值已定义、user/workspace/environment/CLI 各层覆盖均可追溯、优先级顺序已知、最终 effective value 有运行时 read-back、重启和作用域边界闭合、敏感配置脱敏边界闭合、未知键策略明确、版本兼容、来源文件稳定且 runtime snapshot 已认证时，才可判 `RECOVERED`。身份冲突、同一配置身份不可调和的覆盖冲突或最终值冲突判 `REJECT`；来源未读回、优先级未知、重启后状态不明、secret redaction 未闭合、schema/type/version 或 runtime snapshot 不确定保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S41 产物。

## 判定门

1. `identity_conflict` 或 `override_conflict` 任一为真，输出 `REJECT`。
2. source/schema/default、各层 override、precedence、effective read-back、restart/scope、secret redaction、unknown-key、type/version、source stability、runtime snapshot 任一门未闭合，或 effective state unknown，输出 `UNKNOWN`。
3. 只有来源、优先级、运行时读回和生命周期边界全部闭合，才输出 `RECOVERED`。
4. 文件存在、环境变量存在、CLI 参数传入或启动成功本身不能证明运行时采用了该值；必须通过实例级 effective snapshot/read-back 验证。
5. `RECOVERED` 仅表示本片夹具中的配置证据门闭合，不代表生产部署、secret safety 或业务效果。

## 覆盖与确定性验证

- 27 个定向 cases：默认/user/workspace/env/CLI 优先级、重启、schema 兼容、未知键策略、作用域边界，以及来源/schema/default/各层 override/precedence/read-back/restart/scope/redaction/type/version/source/runtime 缺口、身份冲突和覆盖冲突。
- 21 个布尔门执行完整 `2^21 = 2,097,152` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产 CLI、settings、环境变量、容器、IDE 或配置加载器的验证。
- 未证明真实系统的配置优先级、workspace scope、环境变量继承、重启持久化、未知键处理、secret redaction、版本迁移或 runtime snapshot 语义。
- 所有布尔门代表“证据是否已获得”，不模拟真实进程启动、文件竞态或敏感值泄漏；生产接入必须独立 read-back、记录来源和作用域，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
