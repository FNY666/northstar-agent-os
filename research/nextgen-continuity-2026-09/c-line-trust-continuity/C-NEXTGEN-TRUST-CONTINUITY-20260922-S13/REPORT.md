# C 线 S13：offline synthetic evidence-provenance matrix

## 摘要

本独立切片在 `/tmp/C-NEXTGEN-TRUST-CONTINUITY-20260922-S13/` 内构建一个**确定性、离线、纯合成**证据来源矩阵。16 个 fixtures 组合覆盖：来源新鲜度、重复观测、事件顺序错乱、边界时间戳、预算耗尽、冲突、缺失、不可访问。模型严格输出三种互斥状态：`RECOVERED`、`UNKNOWN`、`REJECT`，并逐项保留 provenance 与转换理由。

关键安全性质已由 harness 和本地 validator 检验：

1. `UNKNOWN` 不会因缺失、陈旧、重复、不可访问或预算耗尽而静默升级为 `RECOVERED`。
2. 没有明确的、同一事件版本、跨独立来源、且均为新鲜可访问记录的矛盾终态证据时，不会转为 `REJECT`。
3. `RECOVERED` 只能由至少两个独立来源对同一 `(event_id, seq)` 的新鲜 `RECOVERED` 观测构成。
4. `REJECT` 只能由明确新鲜冲突构成；孤立 REJECT、陈旧 REJECT 或不可访问记录均不足以触发。
5. 新鲜度边界按模型配置闭区间处理：`age <= 3600` 为 fresh，`age = 3601` 为 stale。
6. 事件输入顺序只影响输入索引，不改变按 `(event_id, seq)` 聚合的判定；预算限制则明确标注未消费记录。

## 矩阵结果摘要

| Fixture | 场景 | 结果 | 转换理由（摘要） |
|---|---|---|---|
| S13-01 | 两独立来源、新鲜、一致 | RECOVERED | 同版本至少两条独立可用证据 |
| S13-02 | 单条新鲜观测 | UNKNOWN | 独立 corroboration 不足 |
| S13-03 | 两条一致但陈旧 | UNKNOWN | 无新鲜可用证据 |
| S13-04 | 同源重复 | UNKNOWN | 重复不构成独立来源 |
| S13-05 | 输入逆序、版本一致 | RECOVERED | 规范化聚合后两独立来源一致 |
| S13-06 | age=3600 边界 | RECOVERED | 边界包含在 fresh 窗口 |
| S13-07 | age=3601 边界 | UNKNOWN | 超出 fresh 窗口 |
| S13-08 | 预算恰好覆盖两条 | RECOVERED | 两条证据均被消费 |
| S13-09 | 预算仅覆盖一条 | UNKNOWN | 预算耗尽且证据不足 |
| S13-10 | 新鲜同版本 RECOVERED/REJECT 冲突 | REJECT | 明确独立来源矛盾 |
| S13-11 | 观测缺失 | UNKNOWN | missing |
| S13-12 | 全部不可访问 | UNKNOWN | inaccessible，不可作证据 |
| S13-13 | 两条可访问一致+一条不可访问 | RECOVERED | 可访问独立证据已足够；不可访问仍保留 provenance |
| S13-14 | 两条新鲜 RECOVERED+一条陈旧 REJECT | RECOVERED | 陈旧记录不构成明确矛盾 |
| S13-15 | 单条新鲜 REJECT | UNKNOWN | 孤立 reject 不是明确冲突 |
| S13-16 | 输入逆序的新鲜同版本冲突 | REJECT | 逆序不隐藏明确冲突 |

## Provenance 与模型边界

每个输入记录都保留 `source_id`、`event_id`、`event_time`、`observed_at`、`seq`、原始 `decision`、`accessible`、freshness age、输入索引、是否被预算消费、fresh/usable 标志及 observation role。每个结果保留 `recovery_groups`、`conflict_groups`、预算信息、完整 provenance 和转换理由。

这是模型约定，不是外部事实：独立性以不同的 synthetic `source_id` 近似；freshness 以合成 age 字段判断；事件顺序通过 `(event_id, seq)` 分组处理。模型不推断、也不能证明真实系统的 durable storage、远端状态、exactly-once、rollback、网络可用性、服务一致性或 production readiness。

未访问网络、真实服务、SDK、凭据及任何既有研究或受排除目录。所有交付文件明确 `synthetic_only=true`、`production_verified=false`。manifest 中所有 claims 均为 `inferred` 且无外部 sources，避免将纯模型行为标作 `confirmed`。

## 复现与验证

```sh
cd /tmp/C-NEXTGEN-TRUST-CONTINUITY-20260922-S13
python3 harness.py
python3 validator.py outputs/results.json
python3 manifest_validator.py research-manifest.json
python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py research-manifest.json
sha256sum -c SHA256SUMS
```

## 下一切片建议（不停线）

下一切片建议保持本目录与本切片隔离，针对“证据时间漂移与模型参数敏感性”增加合成测试：观测时钟偏移、相同事件不同 `seq`、重复事件 ID 的去重策略、预算截断位置，以及来源独立性标签误标。仍应坚持三态互斥、完整 provenance、显式转换理由和 `UNKNOWN` 保守性；不得把离线结果外推为生产验证。C 线可在不停止本 S13 复现与审计的前提下继续推进 S14。

synthetic_only=true  
production_verified=false
