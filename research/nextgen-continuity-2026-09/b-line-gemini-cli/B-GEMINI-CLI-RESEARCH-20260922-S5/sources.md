# S5 官方一手来源

固定基线：`https://github.com/google-gemini/gemini-cli/tree/d5b3e3accb26000d273abf16e0f1dd83aa5428a9`

| ID | Exact URL | 等级 | 直接支持 |
|---|---|---|---|
| S5-1 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/core/geminiChat.ts | A | tool response durable ID、linear history、completed tool call recording、stream retry、dangling response close |
| S5-2 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/core/geminiChat.test.ts | A | resumed dangling response 修复、stream error/cancel history 结构、retry 后 history 无文本重复 |
| S5-3 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/tools/mcp-client.test.ts | A | MCP annotations 完整保留，包括 idempotentHint；未测执行去重 |
| S5-4 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/utils/checkpointUtils.ts | A | checkpoint commitHash/history/clientHistory/toolCall/messageId 数据结构与 snapshot 失败处理 |
| S5-5 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/cli/checkpointing.md | B | restore 的官方语义：恢复项目/对话并重新提出原 tool call |
| S5-6 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/integration-tests/resume_repro.test.ts | A | session resume regression 路径 |
| S5-7 | https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/integration-tests/context-fidelity.test.ts | A | resume context fidelity 路径 |

检索结论：没有把二手材料或 issue 讨论当作证据；S5 unknown 仅表示上述固定官方基线未证明。
