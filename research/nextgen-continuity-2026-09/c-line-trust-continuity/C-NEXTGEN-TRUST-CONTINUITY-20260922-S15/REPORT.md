# C 线 S15：offline synthetic evidence-provenance matrix stress test

## 结论

本切片在一个全新、隔离的 `/tmp/C-NEXTGEN-TRUST-CONTINUITY-20260922-S15/` 中运行，输入为 18 条确定性本地合成 fixture。结果保留三态：**RECOVERED 3、UNKNOWN 10、REJECT 5**。

规则刻意保守：只有 fixture 中存在可由规则直接验证的矛盾才 REJECT；缺证、不可访问、部分 provenance、预算截断、歧义、重试无新增证据和多数票均保持 UNKNOWN。排序不会将 UNKNOWN 升级；多数票不会将 UNKNOWN 升级；重试不会将 UNKNOWN 升级。

## 覆盖矩阵

| ID | 场景 | 结果 | 判定理由/阻塞 |
|---|---|---|---|
| S15-01 | 完整直接证据 | RECOVERED | 可访问、fingerprint 存在且内容精确匹配；无阻塞 |
| S15-02 | 跨源关联错配 | REJECT | 同一关联位置解析到不兼容 event ID；规则可验证矛盾 |
| S15-03 | source fingerprint reuse | REJECT | 同 fingerprint 对应不同 payload hash；规则可验证矛盾 |
| S15-04 | 相同摘要异构内容 | REJECT | 相同 summary 对应不同内容；规则可验证矛盾 |
| S15-05 | 重放顺序倒置 | REJECT | sequence 非单调；规则可验证矛盾 |
| S15-06 | 边界时钟漂移 | RECOVERED | drift=5 且 allowed=5，声明为 inclusive boundary |
| S15-07 | 超边界时钟漂移 | UNKNOWN | 超界本身不构成被声明 invariant 的矛盾证据；缺少可验证语义 |
| S15-08 | partial provenance | UNKNOWN | payload 存在但缺 fingerprint/链路 |
| S15-09 | budget truncation | UNKNOWN | 证据流明确截断；未观测尾部可能改变结论 |
| S15-10 | 明确矛盾 | REJECT | count>=0 与 observed=-1 直接冲突 |
| S15-11 | 单纯缺证（正断言） | UNKNOWN | 没有 evidence；缺证不是负结果 |
| S15-12 | source 不可访问 | UNKNOWN | 无法独立检查 source |
| S15-13 | 关联歧义 | UNKNOWN | 多个候选且无确定消歧器 |
| S15-14 | 多数票陷阱 | UNKNOWN | 冲突观察不能仅凭多数票升级 |
| S15-15 | retry 无变化 | UNKNOWN | 重试复现相同不完整 evidence；retry count 不是 provenance |
| S15-16 | 稳定 fingerprint+payload | RECOVERED | 两次观察 fingerprint 与 payload hash 均一致 |
| S15-17 | 形式完整但不可验证 | UNKNOWN | 字段齐全不等于声明关系可验证 |
| S15-18 | 单纯缺证（负断言） | UNKNOWN | 没有 evidence，不能证明“未发生” |

## Provenance 与可复核性

每条 `outputs/results.json` 结果都包含：`provenance`（source id、fingerprint、payload hash、可访问性）、`reason`、`blocker`、`input_hash`、`synthetic_only=true`、`production_verified=false`。输入 hash 是 canonical JSON 的 SHA-256；结果 JSON 采用相同 canonical 序列化，便于确定性复核。

## 验证命令与预期

```sh
cd /tmp/C-NEXTGEN-TRUST-CONTINUITY-20260922-S15
python3 harness.py
python3 validator.py
python3 manifest_validator.py
python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py research-manifest.json
sha256sum -c SHA256SUMS
```

harness 输出应为 `18 cases`，计数为 `RECOVERED=3, UNKNOWN=10, REJECT=5`；两个本地 validator 与通用 research validator 均应 PASS；校验和应全部 OK。

## 非结论与边界

本地合成 stress test **不证明**真实 durability、远端状态、exactly-once、rollback 或 production readiness；不访问网络、真实服务、SDK、凭据或任何既有研究/事故/系统目录。它也不证明真实系统的时钟、重放、指纹、跨源关联或 provenance 存储行为，只验证本切片明示的 deterministic rule set。

## 下一步

建议下一独立切片继续保持离线和隔离，专门增加“同一输入的序列化/规范化差异”“多级 provenance 缺口组合”“规则版本变更下的可重复判定”矩阵，并继续保留 UNKNOWN 的保守边界，保持不停线。
