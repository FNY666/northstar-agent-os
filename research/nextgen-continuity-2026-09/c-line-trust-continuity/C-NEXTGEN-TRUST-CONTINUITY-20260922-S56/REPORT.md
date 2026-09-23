# C 线信任连续性 S56：证据账本、manifest/digest 可追溯性与 canonical/derived 隔离

## 结论（离线合成、推断）

研究账本 entry、manifest、SHA256 或摘要索引存在，不等于研究结论可追溯、canonical 未被派生内容覆盖或计数仍然真实。只有 ledger schema、entry/question/claim/source URL/date/evidence window/status/confidence/caveat 全部绑定，canonical/derived/raw path隔离、raw immutable、digest记录与重算、manifest完整、跨文档引用、文件系统计数和归档索引全部闭合时，才可判 `RECOVERED`。跨项目身份合并或同一 entry 不可调和的 canonical/status/digest 冲突判 `REJECT`；schema、来源、窗口、digest、manifest、计数、归档或 lineage 状态未知保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S55 产物。

## 判定门

1. `identity_conflict` 或 `ledger_conflict` 任一为真，输出 `REJECT`。
2. ledger schema/entry/question/claim/source/window/status/confidence/caveat、canonical/derived/raw、digest/manifest/cross-reference、filesystem count/archive 任一门未闭合，或 lineage unknown，输出 `UNKNOWN`。
3. 只有账本字段、源料不可变性、摘要/manifest、跨引用和归档恢复全部闭合，才输出 `RECOVERED`。
4. digest记录、摘要页面或硬编码计数本身不能证明当前文件未变、账本计数真实或 canonical 未被覆盖；必须从文件系统重算并独立核对。
5. `RECOVERED` 仅表示本片夹具中的 ledger evidence gate 闭合，不代表生产研究可追溯性、external effect、exactly-once 或业务提交。

## 覆盖与确定性验证

- 28 个定向 cases：ledger schema/entry/question/claim/source/date/window/status/confidence/caveat、canonical/derived/raw、digest/manifest/cross-reference/filesystem count/archive，以及各边界缺口、身份冲突和账本冲突。
- 24 个布尔门执行完整 `2^24 = 16,777,216` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产研究账本、文件归档、manifest、digest 或知识库的验证。
- 未证明真实系统的 canonical/derived 生命周期、raw immutability、SHA256管理、跨文档引用、文件系统计数、归档恢复或冲突合并语义。
- 所有布尔门代表“证据是否已获得”，不模拟真实文件变更、归档损坏或多会话写入；生产接入必须独立重算文件/manifest/digest、核对 canonical 和计数，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
