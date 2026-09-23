# B-S39 官方来源清单

访问日期：2026-09-22（Asia/Shanghai）。来源为 Google Gemini CLI 官方 GitHub 仓库及 raw 文件；本地快照 commit：`d5b3e3accb26000d273abf16e0f1dd83aa5428a9`，提交时间 `2026-09-21T20:36:40Z`。raw URL 均在本切片访问时 HTTP 200。

| ID | 官方 URL | raw URL | 证据窗口 | 证据等级 | 能支持 | 不能证明 |
|---|---|---|---|---|---|---|
| S39-S1 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/session-management.md | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/session-management.md | lines 3–22, 24–97, 99–104, 105–186, 188–208 | primary / verified | session 自动保存、resume、浏览、删除、retention、limits、worktree 建议 | 不证明运行成功、跨机恢复、外部状态或审计完整性 |
| S39-S2 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/checkpointing.md | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/checkpointing.md | lines 1–35, 37–58, 60–95 | primary / verified | 文件修改前 checkpoint、Git snapshot/conversation history、restore | 不证明第三方副作用回滚、远程状态回滚或 exactly-once |
| S39-S3 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/headless.md | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/headless.md | lines 1–45 | primary / verified | headless structured output、JSON/JSONL、事件、退出码 | 不证明业务提交、外部效果或完整日志 |
| S39-S4 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/sandbox.md | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/sandbox.md | lines 20–80, 81–265, 267–337, 361–468 | primary / verified | sandbox 后端、配置优先级、工具级隔离、扩权机制和 workspace 边界 | 不证明特定配置隔离充分、宿主/网络/凭据安全、生产安全 |

## 访问与证据纪律

`verified` 只代表官方文字直接写出；`inferred` 是从文档边界作的保守推导；`unknown` 表示本切片没有运行态或外部目标证据。未使用第三方资料、凭据、私有账号或真实服务。
