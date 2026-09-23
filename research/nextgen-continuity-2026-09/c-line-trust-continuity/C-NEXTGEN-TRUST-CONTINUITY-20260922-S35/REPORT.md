# C 线信任连续性 S35：Merkle 证据根、包含/一致性证明与根分叉

## 结论（离线合成、推断）

单独拥有一个 Merkle root、leaf 或签名不能证明跨窗口连续性。只有身份域正确、root 已认证、leaf canonical bytes 固定、inclusion proof 与 consistency proof 均有效、checkpoint/root 链完整且单调、epoch 连续、观察者 quorum 一致且具有独立性、新鲜度窗口闭合、密钥轮换有证明、算法可比较并且没有 query/proof gap 时，才可判 `RECOVERED`。根分叉、同一叶节点路径证明冲突、stale root 越过当前边界或身份冲突判 `REJECT`；证明缺失、观察者不独立、根轮换未认证、算法不可比或新鲜度未闭合保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S34 产物。

## 判定门

1. `identity_conflict`、`fork_conflict`、`proof_conflict` 或 `stale_root_conflict` 任一为真，输出 `REJECT`。
2. 身份缺失、root/leaf/proof/checkpoint/epoch/quorum/freshness/key rotation/algorithm 任一门未闭合，或存在 query/proof gap，输出 `UNKNOWN`。
3. 只有全部证据根、路径、窗口、观察者与 fence 门闭合，才输出 `RECOVERED`。
4. `NO_EVENT`、只看到 root、只看到 leaf、根签名存在但 consistency proof 缺失，不能推断 append-only 连续性，保持 `UNKNOWN`。
5. 根轮换必须有旧新验证密钥的可信 rotation attestation；密钥或算法变化本身不构成连续性证明。

## 覆盖与确定性验证

- 26 个定向 cases：完整包含/一致性证明、root checkpoint 链、密钥轮换、观察者 quorum、延迟新鲜度、重复 proof、root/leaf/proof/checkpoint/sequence/epoch/quorum/独立性/freshness/rotation/algorithm/query 缺口、身份冲突、根分叉、路径冲突及 stale root。
- 19 个布尔门执行完整 `2^19 = 524,288` 组合，使用流式计数避免一次性保存组合对象，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产 Merkle tree、透明日志、证明协议、observer quorum 或密钥轮换系统的验证。
- 未证明任何真实系统的 hash/canonicalization、proof 验证、append-only consistency、根签名、quorum 独立性、freshness watermark 或 fork detection 实现。
- 所有布尔门代表“证据是否已获得”，不模拟真实服务返回、网络延迟、哈希实现或密钥管理；生产接入必须独立 read-back、验证 proof path/root sequence/key rotation，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的证据门闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
