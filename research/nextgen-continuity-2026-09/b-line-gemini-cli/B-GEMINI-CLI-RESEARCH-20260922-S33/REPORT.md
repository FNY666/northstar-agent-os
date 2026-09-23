# S33：跨 epoch 多操作组合矩阵（synthetic-only）

- `synthetic_only=true`；`production_verified=false`。
- 本切片仅使用目录内 22 个合成 fixtures、单 worker harness 与独立 validator；无网络、无真实 Gemini CLI/服务、无凭据。
- 操作集合：`P`、`Q`、`R` 与未声明 `X`。trace 序列确定性 canonical JSON；每个结果保留 epoch 序列、逐 op verdict、reason、blocking_conditions、canonical input SHA-256。

## 规则边界

1. 已知 op 只有在**同一 epoch**同时具备有序 event 与指向该 event 的 ack 时才可能 `accepted`。
2. 新 epoch 首事件若缺失本 epoch 证据、ack 跨 epoch 延迟到达、ack 缺失、reordered/stale/unmatched，均为 `UNKNOWN`，不升级。
3. `X` 即使 event+ack 完整也为 `UNKNOWN`；同 trace 的 P/Q/R 独立判定，不被 X 污染。
4. 同一 op 的跨 epoch重复 payload 不算新证据。
5. 显式撤销记录保持 `UNKNOWN`，不等同 `rejected`；本矩阵仅将显式 `conflict` 记录判为 `rejected`。
6. `UNKNOWN != rejected`。本地结果不证明 durability、远端状态、exactly-once、rollback 或 production readiness。

## 运行与真实输出

在目录内运行：

```text
$ python3 harness.py
PASS: harness deterministic serialization; fixtures=22
PASS: verdicts accepted=18 rejected=1 UNKNOWN=121
PASS: wrote outputs/results.json; result_rows=140

$ python3 validator.py
PASS: schema, hashes, and verdict domain validated
PASS: fixtures=22 verdicts accepted=18 rejected=1 UNKNOWN=121
PASS: required rollover/delayed/missing/unknown/duplicate/revoke invariants validated

$ python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py research-manifest.json
PASS: 5 claims; manifest schema is valid (2026-09-22)

$ sha256sum -c SHA256SUMS
harness.py: OK
fixtures/cases.json: OK
outputs/results.json: OK
validator.py: OK
research-manifest.json: OK
REPORT.md: OK
sources.md: OK
SHA256SUMS: OK
```

以上 verdict 计数为 22 fixtures × 6 个默认/声明 op-epoch slots 的总行数；具体逐条结果见 `outputs/results.json`。

## 结论

本地合成矩阵支持：跨 epoch 证据不能补证；新 epoch 必须使用本 epoch 的完整有序证据；X 整组隔离为 UNKNOWN；重复 payload 不制造新证据；撤销不自动变成 rejected；只有规则内明确 contradiction 才可 rejected。建议下一切片继续增加组合覆盖（例如多 ack、跨 op 引用、epoch 间乱序批次）并保持 synthetic-only；不停线。
