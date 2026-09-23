# synthetic_only=true; production_verified=false
# C 线下一独立切片 S12：offline synthetic recovery-window model

## 结论（仅限合成模型）
本切片建立一个离线、确定性的 recovery-window 状态模型，枚举 `journal_write`、`ack_observation`、`replay_application` 与 `reconciliation` 之间的七类 restart/crash 窗口：

- **W0**：journal 之前
- **W1**：journal 之后、ack 之前
- **W2**：ack 之后、replay 之前
- **W3**：replay 进行中
- **W4**：replay 之后、reconciliation 之前
- **W5**：reconciliation 进行中
- **W6**：reconciliation 之后

14 个 fixture 覆盖 evidence `present`、`absent`、`contradictory`，replay budget 0/1/2，并将结果严格分为：

- `RECOVERED`：合成证据完整且 reconciliation 明确 `COMMITTED`；
- `UNKNOWN`：证据缺失、不完整、非确定、或预算耗尽。UNKNOWN 被保留，不能因为“不知道”而 REJECT；
- `REJECT`：证据矛盾，或显式且一致的 `ABORTED`。REJECT 不是 UNKNOWN 的别名。

## 执行结果
运行 `python3 harness.py` 后，结果为：

```text
PASS: case_count=14, summary={"RECOVERED": 4, "REJECT": 3, "UNKNOWN": 7}
```

真实输出写入 `outputs/results.json`，包含每个 fixture 的 outcome、trace、`unknown_preserved`、`replay_used`，且结果级标记均为 `synthetic_only=true`、`production_verified=false`。

本地验证：

```text
python3 validator.py
PASS: local results validator; 14 results; UNKNOWN/REJECT separation verified

python3 manifest_validator.py
PASS: local manifest validator; 6 claims; statuses valid

python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py research-manifest.json
PASS: 6 claims; manifest schema is valid (2026-09-22)
```

## 证据边界与不可证明事项
这是 offline synthetic model，不是线上验证。它**不能证明**：

1. 真实 journal durability、fsync 或崩溃后实际持久性；
2. 远端状态、网络交付、服务端提交状态或 ack 的真实性；
3. exactly-once、幂等性或重复 replay 的安全性；
4. rollback、补偿事务或恢复后业务一致性；
5. 任意生产系统的 production readiness、SLO、容量、性能或安全性。

manifest 中所有 claims 均标为 `inferred`；没有外部一手来源，因而没有 claim 被误标为 `confirmed`。本切片未访问网络、真实服务、凭据、SDK 或既有研究产物。

## 产物
- `REPORT.md`
- `sources.md`
- `research-manifest.json`
- `SHA256SUMS`
- `harness.py`
- `fixtures/cases.json`
- `outputs/results.json`
- `validator.py`
- `manifest_validator.py`

## 下一切片建议（不停线）
建议下一切片 **S13：offline synthetic evidence-provenance matrix**：保持完全离线与 synthetic-only，针对每一条 evidence 增加来源新鲜度、重复观测、顺序错乱、边界时间戳和预算耗尽组合，验证 UNKNOWN 是否在更复杂输入下仍不被静默升级为 RECOVERED，也不被误转为 REJECT；继续不得声称真实 durability、远端状态、exactly-once、rollback 或 production readiness。
