# S52 sources

访问日期：2026-09-22；公开一手官方来源。

| ID | 完整官方 URL | 证据窗口 | 等级 | 不能证明 |
|---|---|---|---|---|
| S52-1 | https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/index.md | hook 同步生命周期、事件、JSON/exit code、timeout、fingerprint、enable/disable | verified | 外部副作用、完整审计、exactly-once |
| S52-2 | https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/reference.md | 输入输出 schema、BeforeTool/AfterTool、decision/continue、并行/顺序 | verified | hook 前后外部状态、崩溃前效果 |
| S52-3 | https://github.com/google-gemini/gemini-cli/blob/main/docs/core/subagents.md | agent 定义、tools/mcpServers、turn/time limits、隔离、递归保护、专属 policy | verified | 远端状态、取消、回滚、生产效果 |
| S52-4 | https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/best-practices.md | hook security、project-level trust 与最小权限实践 | verified | 实际项目安全、完全审计 |

`verified`=官方材料直接明确；`inferred`=由材料边界推导；`unknown`=没有统一保证。
