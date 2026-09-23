# S35 sources

本切片仅使用本地 synthetic fixtures 与本目录内独立实现；无网络来源、无外部证据、无真实 Gemini CLI/服务调用。

- `fixtures/cases.json`: 24 个确定性合成输入。
- `impl_a.py`: 独立本地实现 A。
- `impl_b.py`: 独立本地实现 B。
- `harness.py`: 双实现单次运行与 canonical SHA-256 记录。
- `validator.py`: 局部性、不可归属、交叉一致性、保守三态和复跑字节一致性断言。
- `/var/minis/skills/evidence-first-research/scripts/validate_research.py`: 通用 manifest schema 校验器（仅本地执行）。

所有结论状态为 `inferred`，因为它们是由本地合成输入和本地代码运行推导出的性质测试结果；不外推到远端或生产系统。
