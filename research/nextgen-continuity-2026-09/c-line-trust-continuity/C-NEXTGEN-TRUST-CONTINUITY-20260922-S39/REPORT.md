# C 线信任连续性 S39：跨系统查询完整性、分页/resourceVersion 与 retention/QUERY_GAP

## 结论（离线合成、推断）

查询返回空结果、单页成功或一个 resourceVersion 并不能证明窗口内没有事件。只有 query scope 与时间窗口固定、分页 cursor 链完整且 terminal 已证明、resourceVersion 单调并来自一致快照、watermark 与 retention 边界闭合、NO_EVENT 语义已知、没有 QUERY_GAP、分页 limit 与 filter semantics 明确、跨区域返回完整、重试和重复页已对账时，才可判 `RECOVERED`。身份冲突、同一 query identity/snapshot 对同一事件给出不可调和结果判 `REJECT`；缺页、无终止页、版本回退、快照不一致、保留边界未知/过期或空结果语义未知保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S38 产物。

## 判定门

1. `identity_conflict` 或 `query_conflict` 任一为真，输出 `REJECT`；明确的 retention 契约冲突同样拒绝。
2. query scope/time window、分页 cursor/terminal、resourceVersion、snapshot、watermark、retention、NO_EVENT semantics、gap、pagination limit、filter semantics、cross-region、retry/dedup 任一门未闭合，或 retention 已过期，输出 `UNKNOWN`。
3. 只有完整查询边界、全页链、快照一致性、保留语义和重试对账全部闭合，才输出 `RECOVERED`。
4. `NO_EVENT` 只是查询结果；在 QUERY_GAP、分页缺口、retention expired 或水位未闭合时，不能升级为“事件未发生”。
5. `RECOVERED` 仅表示本片夹具中的 query evidence window 闭合，不代表 API 全量、外部效果或业务不存在。

## 覆盖与确定性验证

- 27 个定向 cases：完整分页、resourceVersion、watermark/NO_EVENT、跨区域、重试、limit，以及 scope/time/cursor/terminal/version/snapshot/watermark/retention/NO_EVENT/gap/filter/region/retry/dedup 缺口、身份冲突、query conflict 和 retention 契约冲突。
- 20 个布尔门执行完整 `2^20 = 1,048,576` 组合，使用流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产 API 分页、Kubernetes resourceVersion、数据库快照、区域查询或 retention 服务的验证。
- 未证明真实系统的 cursor terminal、snapshot consistency、query retry semantics、NO_EVENT/QUERY_GAP 语义、保留期实现或跨区域收敛。
- 所有布尔门代表“证据是否已获得”，不模拟真实服务返回、分页边界竞争或数据删除；生产接入必须独立 read-back、记录 query identity 和 cursor 链，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的证据门闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
