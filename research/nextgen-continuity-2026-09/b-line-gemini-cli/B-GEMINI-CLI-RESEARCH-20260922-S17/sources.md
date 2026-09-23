# S17 官方来源清单

1. https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/checkpointing.md — 官方文档；checkpoint snapshot、conversation history、tool call、`/restore` 行为；证据等级 A/primary。
2. https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/checkpointing.md — 同一官方文档 raw 内容；证据等级 A/primary。
3. https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/session-management.md — 官方文档；自动保存、session history、resume、retention；证据等级 A/primary。
4. https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/session-management.md — 同一官方文档 raw 内容；证据等级 A/primary。
5. https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/utils/checkpointUtils.ts — 官方源码；checkpoint payload、client history、tool call、commit hash、恢复数据结构；证据等级 A/primary。
6. https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/utils/checkpointUtils.ts — 同一官方源码 raw 内容；证据等级 A/primary。
7. https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/utils/historyHardening.ts — 官方源码；sentinel/synthetic history repair、tool pairing、ordering、signature；证据等级 A/primary。
8. https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/utils/historyHardening.ts — 同一官方源码 raw 内容；证据等级 A/primary。
9. https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/telemetry.md — 官方文档；OTel local/GCP/OTLP 配置、事件与 session/tool 观测范围；证据等级 A/primary。
10. https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/telemetry.md — 同一官方文档 raw 内容；证据等级 A/primary。
11. https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/telemetry/file-exporters.ts — 官方源码；append JSON、`forceFlush`、`shutdown`；证据等级 A/primary。
12. https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/telemetry/file-exporters.ts — 同一官方源码 raw 内容；证据等级 A/primary。
13. https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md — 官方文档；MCP discovery/execution/response/connection timeout 与 OAuth retry；证据等级 A/primary。
14. https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/tools/mcp-server.md — 同一官方文档 raw 内容；证据等级 A/primary。
15. https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/tools/mcp-client.ts — 官方源码入口（仅官方公开路径核验）；MCP client discovery/connection；证据等级 A/primary。
16. https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/policy/policy-engine.ts — 官方源码入口；policy engine 范围线索，不足以证明 re-approval/audit replay；证据等级 B/primary。
17. https://github.com/google-gemini/gemini-cli/tree/main/packages/core/src/policy — 官方源码/测试目录；policy integrity/persistence/confirmation 线索；证据等级 B/primary。
18. https://api.github.com/repos/google-gemini/gemini-cli/git/trees/main?recursive=1 — GitHub 官方 API；用于限定公开路径清单，未下载全仓库；证据等级 B/primary。
