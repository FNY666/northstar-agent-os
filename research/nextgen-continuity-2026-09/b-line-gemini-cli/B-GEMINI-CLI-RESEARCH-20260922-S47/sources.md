# S47 sources

访问日期：2026-09-22；完整官方 URL；只读公开一手资料。

| ID | 官方 URL | 证据窗口 | 等级 | 不能证明 |
|---|---|---|---|---|
| S47-1 | https://github.com/google-gemini/gemini-cli/blob/main/docs/behavioral-evals.md | behavioral eval 目标、EDK inventory/validate/report、规则严重性、3 次 deflake、工具行为断言 | verified | 生产效果、exactly-once、所有模型/部署覆盖 |
| S47-2 | https://github.com/google-gemini/gemini-cli/blob/main/docs/integration-tests.md | bundle 前置、显式集成测试入口、5 次 deflake、sandbox 矩阵、memory/perf baseline、诊断 | verified | 生产等价、外部副作用提交、断连后的状态 |
| S47-3 | https://github.com/google-gemini/gemini-cli/commit/d5b3e3accb26000d273abf16e0f1dd83aa5428a9 | 研究所用官方仓库固定提交与时间上下文 | verified | 当前部署版本实际运行状态 |

`verified`=材料直接明确；`inferred`=由材料边界推导；`unknown`=材料未给出保证。
