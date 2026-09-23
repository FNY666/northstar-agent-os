# C 线信任连续性 S47：behavioral eval、integration test 与证据边界

## 结论（离线合成、推断）

behavioral eval 应验证可观察的工具行为和状态，而不是把精确自然语言当成唯一正确性标准；integration test 应明确 fixture、环境和 sandbox 矩阵，并将 blocking errors 与 warnings 分开。只有 test spec/oracle、tool behavior、fixture isolation、environment、no-sandbox/docker/podman 路径、重复运行稳定性、integration boundary、资源基线、failure injection 和 external-effect 边界全部闭合时，才可判 `RECOVERED`。测试身份冲突或同一 case 的不可调和结论冲突判 `REJECT`；规格/oracle缺失、矩阵缺口、重复运行不足/不稳定、fixture泄漏风险或资源/故障证据缺失保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S46 产物。

## 判定门

1. `identity_conflict` 或 `test_conflict` 任一为真，输出 `REJECT`。
2. test spec/oracle、tool behavior、fixture/environment、sandbox矩阵、blocking/warning分离、重复运行、integration boundary、资源基线、failure injection 或 external-effect boundary 任一门未闭合，输出 `UNKNOWN`。
3. 只有测试行为边界、环境矩阵、重复稳定性和集成证据全部闭合，才输出 `RECOVERED`。
4. 单次通过、文本相似、warning数量或某一个 sandbox 路径通过不能证明生产行为、外部提交或所有环境等价。
5. `RECOVERED` 仅表示本片夹具中的 eval/integration evidence gate 闭合，不代表 production readiness、external effect 或业务提交。

## 覆盖与确定性验证

- 26 个定向 cases：behavioral eval、integration sandbox矩阵、blocking/warning、重复运行、失败注入、expected/tool result，以及规格/oracle/fixture/environment/sandbox/路径/重复/integration/resource/failure/external-effect 缺口、身份冲突和测试结论冲突。
- 22 个布尔门执行完整 `2^22 = 4,194,304` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产 behavioral eval、integration test、Docker/Podman/sandbox 或性能基线的验证。
- 未证明真实测试框架的重复门槛、warning/error 语义、fixture隔离、环境等价性、failure injection、资源回归或外部副作用。
- 所有布尔门代表“证据是否已获得”，不模拟真实进程、容器或生产外部效果；生产接入必须保留 suite/case/commit/environment/run identity，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
