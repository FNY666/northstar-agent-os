# S34 乱序批次组合矩阵（synthetic-only）

## 结论

S34 是完全离线、单 worker、确定性序列化 trace 的合成切片。fixture 矩阵共 24 个案例，覆盖多 ack 一致/冲突、跨 op 引用、跨 epoch 乱序、无法归属 epoch、同 op 同 epoch 重复批次、批次内部分缺失、批次级显式撤销和未声明操作 X。

结果严格使用 `accepted`、`rejected`、`UNKNOWN` 三值：`UNKNOWN` 不等于 `rejected`。本地规则下，单 op 多 ack 全部 accepted 判 accepted；全部 rejected 判 rejected；同一 op 出现 accepted/rejected 冲突时，仅该 op 判 rejected；若该 op 含不可验证、缺失或不可归属证据，则该 op 判 UNKNOWN。其他 op 不因其受影响而传染。

跨 op 文本引用不构成被引用 op 的自身可访问证据：Q 的文本提及 P 的 op_id 时，Q 仍按自身证据判定，P 在无自身证据时保持 UNKNOWN。批次按到达顺序保留，epoch 标签按事件自身规则判定；B2 先到 B1 不自动升级或降级。epoch 不在 1–4 或为空时无法归属，相关 op 为 UNKNOWN。同 op/epoch/batch 的重复批次不产生新证据。显式撤销批次的事件从聚合证据中移除并作为该批次 UNKNOWN；其他批次不受影响。批次内缺失只影响对应 op/事件，不整批传染。

## 可复现运行

在本目录执行：

```sh
python3 harness.py
python3 validator.py
python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py research-manifest.json
sha256sum -c SHA256SUMS
```

本地运行真实输出记录在下方“验证输出”中；`outputs/results.json` 逐结果包含 arrival/epoch 序列、批次 id（及批次列表）、目标 op 判定、全部 op 判定、理由、阻塞条件、重复计数及 canonical 输入 SHA-256。

## 验证输出

```text
PASS: harness deterministic evaluation; fixtures=24; verdicts={'accepted': 10, 'rejected': 6, 'UNKNOWN': 8}
PASS: duplicate_batches_ignored=1; arrival order preserved
PASS: synthetic_only=true; production_verified=false
PASS: validator checked 24 fixtures; verdict domain is exact
PASS: canonical_input_sha256 present and reproducible for every result
PASS: epoch sequence, op verdict, batch id, reason, blockers present
PASS: no UNKNOWN coerced to rejected; duplicate-batch behavior retained
PASS: 3 claims; manifest schema is valid (2026-09-22)
PASS: sha256sum -c SHA256SUMS
```

## 边界与不证明事项

这组测试只验证本地合成规则和确定性序列化，不证明 durability、远端状态、exactly-once、rollback 或 production readiness；不访问真实 Gemini CLI/服务、网络、凭据或任何生产/事故/既有研究目录。所有产物显式声明 `synthetic_only=true`、`production_verified=false`。

## 下一步

建议下一切片继续保持离线、单 worker 和三值严格性，增加独立的规则交叉实现/性质测试（尤其是撤销与不可归属事件的局部性），然后再考虑受控的非生产集成；不要停线或把本切片外推为生产保证。
