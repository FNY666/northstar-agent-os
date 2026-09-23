# B-S38 官方来源清单

访问日期：2026-09-22（Asia/Shanghai）。所有来源均为 Google Gemini CLI 官方 GitHub 仓库或 raw 文件。

| ID | 官方 URL | raw URL | 证据窗口 | 能支持 | 不能证明 |
|---|---|---|---|---|---|
| S38-S1 | https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/index.md | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/hooks/index.md | `index.md` lines 3–21, 34–50, 52–90, 92–162 | Hooks 同步执行、事件、JSON 通道、退出码、matcher、配置优先级 | 不证明实际运行、耗时、顺序、重试、外部效果 |
| S38-S2 | https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/reference.md | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/hooks/reference.md | `reference.md` lines 1–75, 92–139, 143–239, 243–288 | 各事件输入/输出、decision、deny/block、retry、advisory 与 Notification 边界 | 不证明 hook 已加载、能撤销已发请求、完整审计或隔离 |
| S38-S3 | https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/best-practices.md | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/hooks/best-practices.md | `best-practices.md` lines 107–232, 397–450 | stdout/stderr 调试、退出码测试建议、官方 threat model 与任意代码执行风险 | 不能证明建议实施或阻止攻击 |
| S38-S4 | https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/policy-engine.md | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/reference/policy-engine.md | `policy-engine.md` lines 39–123, 125–202, 220–280 | rule 条件/decision/priority、allow/deny/ask_user、headless 行为、tier/approval mode、Workspace 警告 | 不证明策略加载、实际阻断、目标提交、回滚或生产安全 |
| S38-S5 | https://github.com/google-gemini/gemini-cli/issues/18186 | 同 issue 页面 | 由 policy-engine.md lines 127–131 链接；访问日期 2026-09-22 | 官方文档所引用的 Workspace policy 缺陷追踪入口存在 | 不把 issue 本身当作运行验证；不证明修复状态 |

## 证据等级与访问

- S38-S1 至 S38-S4：primary；原始 raw URL HTTP 200，仓库快照 commit `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`（提交时间 2026-09-21T20:36:40Z）。
- `verified` 仅表示官方文字直接陈述；`inferred` 表示从文档控制边界作的谨慎推导；`unknown` 表示本切片没有运行态或外部目标证据。
- 未使用私有账号、凭据、第三方资料、真实服务或受保护目录。
