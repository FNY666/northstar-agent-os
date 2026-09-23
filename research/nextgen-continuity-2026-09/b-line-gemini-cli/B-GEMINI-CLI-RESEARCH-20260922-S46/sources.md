# S46 sources

访问日期：2026-09-22。仅使用 Google Gemini CLI 官方 GitHub 仓库/文档，公开、只读。

| ID | 完整官方 URL | 证据窗口 | 等级 | 不能证明 |
|---|---|---|---|---|
| S46-1 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/acp-mode.md | ACP stdio JSON-RPC、initialize/newSession/loadSession/prompt/cancel、filesystem proxy、debugging/telemetry | verified | 外部副作用提交、exactly-once、取消后的远端状态 |
| S46-2 | https://github.com/google-gemini/gemini-cli/blob/main/docs/ide-integration/ide-companion-spec.md | MCP-over-HTTP、port-file、contextUpdate、diff open/close、accepted/rejected 通知、生命周期 | verified | 编辑器持久提交、完整投递、业务效果 |
| S46-3 | https://github.com/google-gemini/gemini-cli/blob/main/docs/ide-integration/index.md | VS Code companion、启停、diff approval、ACP、sandbox、断连排障 | verified | 自动恢复、回滚、重连去重 |
| S46-4 | https://github.com/google-gemini/gemini-cli/tree/main/packages/cli/src/acp | session manager、session execution、workspace/permission boundary、streaming、resume tests | verified | README/测试描述不等于生产运行证明 |

结论标签：verified 表示官方材料明确写出；inferred 仅表示由材料边界推导；unknown 表示材料没有给出保证。断连、取消或超时后的外部状态须保持 UNKNOWN，除非独立 read-back/reconcile 证明。
