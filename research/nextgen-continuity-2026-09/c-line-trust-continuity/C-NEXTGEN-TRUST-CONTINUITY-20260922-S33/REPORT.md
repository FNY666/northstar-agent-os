# C 线信任连续性 S33：checkpoint、归档恢复与删除链的可证明闭合

## 结论（离线合成、推断）

跨 crash/restart 的连续性不能由单个 checkpoint、snapshot 或 restore 成功消息证明。只有身份域正确、checkpoint 已认证、snapshot digest 可比、增量 segment 链无缺口、compaction manifest 完整、archive restore 有独立 attestation 且 generation 一致、tombstone/segment 链闭合、水位线与 retention 窗口闭合、source epoch 连续并且 fence 有效时，才可判 `RECOVERED`。恢复代际歧义、查询/segment 缺口、未认证的快照或未闭合窗口保持 `UNKNOWN`；身份冲突、同规范 digest 冲突、旧 fence 或不可调和 restore generation 冲突判 `REJECT`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S32 产物。

## 判定门

1. `identity_conflict`、`fence_conflict`、无效 `fence_valid`、`digest_conflict` 或 `restore_generation_conflict` 任一为真，输出 `REJECT`。
2. 身份缺失、checkpoint 未认证、snapshot digest 不可比、delta/compaction/archive/tombstone/segment 链不完整、水位线或 retention 未闭合、epoch 不连续、restore 有歧义或存在 gap，输出 `UNKNOWN`。
3. 只有全部连续性门闭合，才输出 `RECOVERED`。
4. `NO_EVENT`、restore 成功但缺少后续终止边界、tombstone 缺口或 archive 仅有本地结果，不能推断未发生或已连续，保持 `UNKNOWN`。
5. restore generation 与 checkpoint 的一致性必须是可比对的外部证据；版本号或本地进程退出码本身不是 attestation。

## 覆盖与确定性验证

- 25 个定向 cases：checkpoint/delta、archive restore、compaction、tombstone、延迟 watermark、重复 snapshot、未认证 checkpoint、摘要缺失、delta/manifest/restore/tombstone/segment 缺口、水位线/retention/epoch 缺口、restore 歧义、NO_EVENT、身份冲突、旧 fence、摘要冲突及 restore generation 冲突。
- 19 个布尔门执行完整 `2^19 = 524,288` 组合，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产存储、快照、归档、compaction 或恢复协议的验证。
- 未证明任何真实系统的 checkpoint 原子性、snapshot digest 语义、segment ordering、archive 恢复完整性、tombstone 传播、retention、watermark 或 fencing 实现。
- 所有布尔门代表“证据是否已获得”，不模拟真实服务返回、崩溃时序或数据丢失概率；生产接入必须独立 read-back、验证 generation/fence、校验完整链和边界，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的证据门闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
