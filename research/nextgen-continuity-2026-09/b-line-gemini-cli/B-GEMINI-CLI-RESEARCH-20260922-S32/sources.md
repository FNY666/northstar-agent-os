# Sources

本切片为 synthetic-only 离线研究，无外部来源、无网络访问、无真实 Gemini CLI/服务调用。

- `fixtures/cases.json`: 本地生成的 22 个输入 fixture（primary local artifact; 2026-09-22; synthetic evidence and support).
- `harness.py`: 本地确定性单 worker 分类器（primary local artifact; 2026-09-22; executable support).
- `validator.py`: 本地 tri-state 与隔离不变量验证器（primary local artifact; 2026-09-22; executable support).

所有 manifest claims 均标记 `inferred`；没有 `confirmed` 外部事实。