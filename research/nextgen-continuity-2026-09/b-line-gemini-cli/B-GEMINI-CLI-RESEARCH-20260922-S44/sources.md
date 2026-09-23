# S44 sources — official only

| ID | Complete official URL | Access date | Evidence window | Level | Supports | Does not prove |
|---|---|---|---|---|---|---|
| S44-1 | https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md | 2026-09-22 | `What is an MCP server`; `Core integration architecture`; `Transport mechanisms`; `Global MCP settings`; `Configuration properties`; `Environment variable expansion`; `Security and environment sanitization`; `Working with MCP resources` | verified | MCP discovery/execution architecture, transports, allow/exclude, trust, timeout, env expansion/redaction, resources | safety of a third-party server, external commit, exactly-once, post-timeout status |
| S44-2 | https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-resources.md | 2026-09-22 | MCP resource tool reference | verified | documented resource interaction surface | freshness/completeness/authorization or business effect |
| S44-3 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/tutorials/mcp-setup.md | 2026-09-22 | setup, credentials, restart/reload instructions | verified | documented setup/reload workflow | successful remote execution, durable credential safety, effect confirmation |
| S44-4 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/tutorials/web-tools.md | 2026-09-22 | official web-tool setup/usage page | verified | documented web-tool surface where applicable | remote result correctness or side-effect completion |
| S44-5 | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/tools/mcp-server.md | 2026-09-22 | HTTP 200, 41,902 bytes at access time | verified | raw-source availability/cross-check | semantic production validation |

All URLs are public first-party Google Gemini CLI documentation/repository URLs. Snapshot commit: `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`.
