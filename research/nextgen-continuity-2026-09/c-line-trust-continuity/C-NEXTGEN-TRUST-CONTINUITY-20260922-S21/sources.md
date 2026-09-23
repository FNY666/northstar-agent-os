# Sources

本切片为全程本地合成；没有网络检索、外部来源、真实服务、SDK、凭据或既有研究材料。所有结论均为 `inferred`，依据仅为本目录内的确定性 fixtures、harness 与 validators。

- Input: `fixtures/cases.json`（本地合成事件节点/边/查询）
- Computation: `harness.py`（确定性可达性、环、完整性与声明不变量判定）
- Checks: `validator.py`、`manifest_validator.py`、通用 manifest validator

`sources` 在 `research-manifest.json` 的每项 claim 中为空数组，避免虚构外部证据。
