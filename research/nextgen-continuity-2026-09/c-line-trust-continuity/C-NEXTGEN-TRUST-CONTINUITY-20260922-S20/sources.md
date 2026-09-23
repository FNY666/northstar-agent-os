# S20 sources

本切片仅使用本地合成 fixtures 与本地执行规则；无网络、无外部资料、无真实时钟/NTP、无 SDK、无凭据。

| source_id | kind | location | use |
|---|---|---|---|
| S20-local-fixtures | synthetic-local | `fixtures/cases.json` | 20 条确定性 wall-clock/seq 场景输入 |
| S20-local-harness | synthetic-local | `harness.py` | 保守三态判定、canonical SHA-256 与输出生成 |
| S20-local-validators | synthetic-local | `validator.py`, `manifest_validator.py` | 本地结构、预期结果、哈希和 manifest 约束校验 |

上述条目不是外部来源；所有 manifest claims 均为 `inferred`，不表示生产验证或现实系统事实。
