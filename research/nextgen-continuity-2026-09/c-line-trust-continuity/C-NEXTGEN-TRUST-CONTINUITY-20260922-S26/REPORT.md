# Trust-continuity S26：撤销后的迟到证据与跨观察者 stale view

## 结论边界
本切片是 `synthetic_only=true` 的离线合成研究，`production_verified=false`。所有输入由固定 fixtures 生成，状态机不连接网络、真实服务、SDK 或凭据。`RECOVERED`、`UNKNOWN`、`REJECT` 是互斥且完备的决策状态：安全优先，证据不足不升级。

本切片不能证明生产耐久性、exactly-once、回滚语义、外部效果的真实发生/持久、服务端实现正确性或 production readiness。

## 判定模型
一条候选恢复记录包含：撤销权威状态与可见时间、观察时间、签名时间、epoch、fence、receipt、持久日志、外部效果、观察者视图及事件分类。只有下面所有门同时打开才允许 `RECOVERED`：

1. 撤销状态在权威视图可见，且顺序闭合（签名/receipt 不能在撤销后以未知顺序被接受）。
2. epoch 连续且不回退；fence 连续且无重放窗口。
3. receipt、持久日志、外部效果三类证据均存在、fresh、相互一致。
4. 没有 observer-specific stale view、跨区域撤销传播未知、query gap、retention expiry 或 exporter failure。
5. 分类为 `VERIFIED_CONTINUITY`，而非 `NO_EVENT`、`DELAYED`、`DROPPED`、`EXPORTER_FAILURE`、`QUERY_GAP`、`RETENTION_EXPIRED`、`UNKNOWN`。

确定的 fence replay、epoch rollback、或明确的时间/撤销硬冲突可输出 `REJECT`。迟到 receipt、传播延迟、stale view、重放窗口不确定、证据丢失或 receipt 与外部效果不一致但无法定性为硬冲突，均输出 `UNKNOWN`。

## 场景矩阵

| 场景 | 关键不确定性 | 决策 | 原因 |
|---|---|---|---|
| 撤销前签名、撤销后 receipt 到达 | 顺序未闭合 | UNKNOWN | 迟到不能充当撤销前连续性 |
| fence token 重放且明确 | token 已消费/重复 | REJECT | 硬冲突 |
| fence 重放窗口未知 | 是否重复未知 | UNKNOWN | fail-closed |
| epoch 回退 | 新 epoch 小于已确认 epoch | REJECT | 硬冲突 |
| epoch 连续但跨区撤销尚未传播 | 权威撤销未知 | UNKNOWN | 不升级 |
| observer A fresh、observer B stale | 观察者读到不同视图 | UNKNOWN | 不可形成共享闭合事实 |
| receipt 与外部效果不一致 | 单证据冲突 | UNKNOWN/REJECT | 无法定性则 UNKNOWN；明确不可同时成立则 REJECT |
| receipt、日志、效果均 fresh 且闭合 | 顺序、epoch、fence 全部连续 | RECOVERED | 唯一允许升级路径 |

## 最小反例
最小非恢复反例为 1 个 `late_receipt_after_revocation` 事件加 1 个未闭合门：`observer_stale_view=true`（也可替换为 `external_effect=false`、`ordering_closed=false` 或 `revocation_visible=false`）。事件数量从更长序列收缩到 1 后仍满足 `state != RECOVERED`，说明单一迟到 receipt 无法绕过安全门。

最小硬冲突反例为 1 个 `fence_replay=true` 或 `epoch_rollback=true` 事件，输出 `REJECT`。

## 属性测试
`harness.py` 以固定种子枚举有限状态组合（不是随机外部数据），覆盖关键标签、证据三元组、观察者视图、撤销传播和 epoch/fence 门。性质包括：三态互斥；所有 RECOVERED 样本均满足全部门；任一迟到/未知传播/stale/replay-unknown 不为 RECOVERED；明确回退/重放为 REJECT；确定性输出可重复。报告中的 coverage 是状态转换组合覆盖，不是生产覆盖率。

## 证据与限制
`sources.md` 明确本地合成证据为空外部来源。manifest 的全部 claims 均 `status=inferred` 且 `sources=[]`。本产物不可外推为生产耐久性、exactly-once、回滚、外部效果或上线准备度结论。

## 独立下一切片建议
下一独立切片建议研究“恢复窗口内的 observer quorum 与撤销水位交叉”：仍只用新目录和合成状态，增加可验证的水位单调性、quorum 缺失/分裂、retention 边界及 crash-restart 事件；仍不得把模拟闭合解释为生产 exactly-once 或 durable external effect。
