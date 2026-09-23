# C 线信任连续性 S37：时间有效性、时钟不确定性与 nonce/replay

## 结论（离线合成、推断）

时间戳存在不等于时间有效性已证明。只有身份域正确、event/ingest time 均存在、clock skew 上界已认证、时间顺序可在区间语义下确定、not-before 与 expiry 均满足、freshness 窗口闭合、nonce 唯一、replay window 与 sequence/watermark 闭合、最大延迟上界已证明、因果时间一致、当前时点重新验证完成且时间源具有独立性时，才可判 `RECOVERED`。身份冲突、不可调和时间声明或重放/唯一性冲突判 `REJECT`；时间缺失、偏差无界、窗口未闭合、nonce 重复但性质不明或重新验证缺失保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S36 产物。

## 判定门

1. `identity_conflict`、`temporal_conflict` 或 `replay_conflict` 任一为真，输出 `REJECT`。
2. event/ingest time、clock bound、ordering、not-before/expiry、freshness、nonce/replay、sequence/watermark、delay bound、causal time、revalidation 或 time-source independence 任一门未闭合，输出 `UNKNOWN`。
3. 只有全部时间、重放、因果和重新验证门闭合，才输出 `RECOVERED`。
4. `NO_EVENT`、当前窗口没有记录、nonce 重复但无法区分合法重试与重放、或时间源彼此相关，不能推断未发生或安全重放，保持 `UNKNOWN`。
5. `RECOVERED` 仅意味着时间区间和重放证据在夹具中闭合，不意味着外部提交、exactly-once 或生产时钟正确。

## 覆盖与确定性验证

- 26 个定向 cases：完整时间区间、有界偏差、nonce/replay、延迟边界、重新验证、序列一致，以及 event/ingest/clock/not-before/expiry/freshness/nonce/replay/sequence/watermark/delay/causal/revalidation/time-source 缺口、身份冲突、时间冲突、重放冲突和无效时间区间。
- 19 个布尔门执行完整 `2^19 = 524,288` 组合，使用流式计数避免一次性保存组合对象，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产时钟同步、JWT/证书有效期、nonce 存储、replay cache 或 watermark 系统的验证。
- 未证明任何真实系统的 clock uncertainty、timestamp interval、时钟源独立性、重放窗口、延迟界限或重新验证 API 语义。
- 所有布尔门代表“证据是否已获得”，不模拟真实时钟漂移、网络延迟或缓存淘汰；生产接入必须独立 read-back、固定时间区间语义、验证 nonce/sequence/watermark，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的证据门闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
