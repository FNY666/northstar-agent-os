# S22 本地合成证据来源

无外部来源。全部证据均由本目录的合成 fixture 与本地 harness 产生：
- `fixtures/cases.json`：24 个离线合成场景及预期状态。
- `harness.py`：确定性 DAG 重放与证据门禁执行器。
- `outputs/results.json`：本地执行结果；不代表任何生产观测。
- `validator.py`、`manifest_validator.py`：本地结构与 provenance 验证。

因此本文件不含 URL、外部引用或真实服务数据。
