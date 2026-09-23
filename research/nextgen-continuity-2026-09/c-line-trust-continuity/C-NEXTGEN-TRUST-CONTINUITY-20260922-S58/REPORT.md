# C 线信任连续性 S58：research digest 注意力索引、Top-K 检索与引用完整性

## 结论（离线合成、推断）

digest、索引条目或 Top-K 结果存在，不能单独证明检索覆盖了正确语料、排序可复现或结论有可解析引用。只有 document identity/digest、title/topic/claim summary、source link/version/evidence status/freshness、attention score、retrieval scope/Top-K/rank/tie-break、citation anchor/target/version、missing citation 检查、重复文档去重、索引重算和跨平台归一化全部闭合时，才可判 `RECOVERED`。跨项目文档合并或同一 query/version 的不可调和检索结论冲突判 `REJECT`；文档摘要、来源、freshness、排序、Top-K、引用、去重、索引或归一化状态未知保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S57 产物。

## 判定门

1. `identity_conflict` 或 `retrieval_conflict` 任一为真，输出 `REJECT`。
2. document/digest/topic/claim/source/status/freshness/attention/scope/Top-K/rank/tie-break/citation/dedup/index/normalization 任一门未闭合，或 index state unknown，输出 `UNKNOWN`。
3. 只有索引输入、注意力规则、排序稳定性、引用锚点和跨平台归一化全部闭合，才输出 `RECOVERED`。
4. Top-K 结果、文档摘要或 citation URL 存在本身不能证明语料完整、排序可复现或 claim 可追溯；必须解析 target/version 并重算索引。
5. `RECOVERED` 仅表示本片夹具中的 retrieval/evidence index gate 闭合，不代表研究结论正确、external effect、exactly-once 或生产决策。

## 覆盖与确定性验证

- 28 个定向 cases：document/digest/topic/claim/source/status/freshness、attention/scope/Top-K/rank/tie-break、citation anchor/target/version、missing citation、dedup/index recompute、跨平台归一化，以及各边界缺口、身份冲突和检索冲突。
- 24 个布尔门执行完整 `2^24 = 16,777,216` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产研究检索、索引、ranking、citation parser 或跨平台归一化系统的验证。
- 未证明真实系统的 Top-K 语义、注意力评分、rank稳定性、引用版本、missing citation检测、重复文档去重或索引收敛。
- 所有布尔门代表“证据是否已获得”，不模拟真实语料、查询漂移或网页变化；生产接入必须重算索引、解析引用目标并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表结论真实、external effect、exactly-once 或业务提交。
