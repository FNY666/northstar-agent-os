# Sources

本切片为 synthetic-only 离线研究；没有网络来源、远端来源或生产来源。

- `fixtures/cases.json`：本目录内人工构造的 24 个合成输入案例；仅用于规则覆盖，不是外部证据。
- `harness.py`：本目录内确定性本地评估器。
- `validator.py`：本目录内独立结构/语义验证器。
- `/var/minis/skills/evidence-first-research/scripts/validate_research.py`：本机通用 manifest schema validator，仅作为本地工具使用。

所有 claims 在 `research-manifest.json` 中标记为 `status: inferred`，因为它们是本地规则与合成 fixture 的推导，不是外部事实或生产验证。
