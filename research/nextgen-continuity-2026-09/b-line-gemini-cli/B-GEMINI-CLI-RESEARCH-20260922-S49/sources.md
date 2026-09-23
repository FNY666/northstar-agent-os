# S49 sources

访问日期：2026-09-22；公开一手官方来源。

| ID | 完整官方 URL | 证据窗口 | 等级 | 不能证明 |
|---|---|---|---|---|
| S49-1 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/headless.md | JSON/JSONL 输出、事件类型、退出码 | verified | 外部提交、exactly-once、生产效果 |
| S49-2 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/plan-mode.md | 只读工具限制、审批、取消、policy 覆盖、hooks | verified | 执行成功、完整审计、回滚 |
| S49-3 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/model-steering.md | experimental/default-off、实时 steering、重新评估计划 | verified | 取消、fencing、外部状态 |
| S49-4 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/tutorials/plan-mode-steering.md | 实际使用流程：研究中 steering、批准后实施 | verified | 全部部署行为、生产效果 |
