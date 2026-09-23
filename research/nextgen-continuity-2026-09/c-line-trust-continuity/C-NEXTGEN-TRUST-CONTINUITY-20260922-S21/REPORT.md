# S21 偏序因果（happens-before）判定矩阵

## 范围与结论

本切片是**全程本地合成**的确定性 DAG/偏序判定实验：事件节点、happens-before 边与查询序对均来自 `fixtures/cases.json`，不访问网络、真实服务、SDK、凭据或既有研究产物。标记：`synthetic_only=true`，`production_verified=false`。

对查询“事件 X 是否先于事件 Y”（严格的 X ≺ Y），实现只输出互斥三态：

- **RECOVERED**：存在从 X 到 Y 的可验证路径；仅在查询恰有直接边时标记 `direct_edge`，否则标记 `transitive_order`。传递可达不冒充直接边。
- **UNKNOWN**：X/Y 不可达（包括并发、缺失边、图规模变大但证据不变、节点缺失），也不反向推定顺序；双向都不可达明确表示“无已验证因果”，不是 REJECT。
- **REJECT**：可验证结构性矛盾，包括有向环、边两端记录不一致；只有 fixture 显式声明“图必须全序”且可验证违反时，全序不一致才 REJECT。单纯声明全序而没有该不变量时为 UNKNOWN。

重复边去重后不产生新证据。查询节点缺失或边引用不存在节点不会因其余图合法而 RECOVERED。严格顺序不可自反，因此 X=X 为 UNKNOWN。

## 覆盖与运行结果

24 个确定性 fixtures：

- RECOVERED 7（direct_edge 3；transitive_order 4）
- UNKNOWN 12（含并发/不可比、缺失边、节点缺失、重复边不升级、非强制全序声明、规模升级不升级证据）
- REJECT 5（因果环、边损坏、显式全序不变量违反）

运行方式（目录内）：

```text
python3 harness.py
python3 harness.py
cmp -s outputs/results.json /tmp/s21-first.json
python3 validator.py
python3 manifest_validator.py
python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py research-manifest.json
sha256sum -c SHA256SUMS
```

`results.json` 每条结果保留：节点清单、边清单、查询序对、三态、直接/传递子类、推理路径（或空路径）、反向路径（或空路径）、理由、阻塞条件、重复边忽略数、canonical 输入 SHA-256。

## 边界与非主张

本切片**不证明**真实因果日志系统、durability、exactly-once、rollback 或 production readiness；不证明生产数据质量、时间戳正确性、分布式时钟语义或服务端行为。偏序中“不可比”只代表本图没有已验证的 happens-before 路径。建议下一独立切片：在完全隔离目录中研究“带版本/快照边界的 DAG 输入完整性与增量重放”，仍不得回读本切片或任何既有研究产物；不停止主线。

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
