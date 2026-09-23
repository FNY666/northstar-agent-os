# C 线信任连续性 S34：因果图、分支合并与有界乱序重放

## 结论（离线合成、推断）

跨系统连续性不能由事件时间排序或单个 receipt 推出。只有身份域正确、parent links 完整、因果图无环且拓扑顺序闭合、分支 merge 有可信证明、分支摘要一致、序列单调、乱序与 bounded replay 窗口闭合、重复投递已证明去重、跨系统关联链完整、source epoch 连续、水位线闭合且 fence 有效时，才可判 `RECOVERED`。父链接缺失、因果顺序不完整、分支合并无证明、乱序/重放窗口未闭合、跨系统链接缺失或查询缺口保持 `UNKNOWN`；身份冲突、causal cycle、分支内容冲突或 stale fence 判 `REJECT`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S33 产物。

## 判定门

1. `identity_conflict`、`fence_conflict`、无效 `fence_valid`、`causal_cycle_conflict` 或 `branch_conflict` 任一为真，输出 `REJECT`。
2. 身份缺失、父链/拓扑/分支/序列/乱序/重放/去重/跨系统/epoch/水位线任一门未闭合，或存在 replay gap，输出 `UNKNOWN`。
3. 只有全部因果与窗口门闭合，才输出 `RECOVERED`。
4. `NO_EVENT`、当前视图无事件但 replay gap 存在、以及延迟事件尚未越过 watermark，不能推断未发生，保持 `UNKNOWN`。
5. 分支合并必须有唯一 merge 边界和可比较的摘要证据；仅仅观察到两个分支或收到一个 merge 消息，不构成连续性证明。

## 覆盖与确定性验证

- 25 个定向 cases：线性因果链、分支 merge、乱序重复、延迟 watermark、跨系统链接、epoch 迁移、父链/拓扑/顺序/分支/序列/窗口/去重/链接/epoch/水位线缺口、NO_EVENT、身份冲突、causal cycle、分支冲突及 stale fence。
- 19 个布尔门执行完整 `2^19 = 524,288` 组合，使用流式计数避免一次性保存组合对象，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产事件图、消息排序、分支合并或跨系统关联协议的验证。
- 未证明真实系统的 causality、拓扑排序、duplicate dedup、replay window、watermark、外部效果或 fencing 实现。
- 所有布尔门代表“证据是否已获得”，不模拟真实服务返回、网络延迟、时钟误差或丢失概率；生产接入必须独立 read-back、固定关联键、校验完整 parent/merge 链，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的证据门闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
