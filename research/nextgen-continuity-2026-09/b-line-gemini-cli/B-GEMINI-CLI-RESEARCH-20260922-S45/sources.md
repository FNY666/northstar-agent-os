# S45 sources — official first-party only

| ID | Complete official URL | Access date | Evidence window | Level | Supports | Cannot prove |
|---|---|---|---|---|---|---|
| S45-1 | https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md | 2026-09-22 | MCP architecture; discovery/execution; transports; settings; trust; timeout; environment sanitization; resources | verified | documented integration/configuration behavior | third-party safety, target commit, exactly-once, post-timeout state |
| S45-2 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/tutorials/mcp-setup.md | 2026-09-22 | MCP setup, credentials, restart/reload operations | verified | documented setup and reload workflow | credential safety, remote success, external-effect confirmation |
| S45-3 | https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-resources.md | 2026-09-22 | MCP resource interaction reference | verified | documented list/read/resource injection surface | resource freshness, completeness, authorization, business effect |
| S45-4 | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/tools/mcp-server.md | 2026-09-22 | HTTP 200; 41,902 bytes at access time | verified | raw official source cross-check | semantic/runtime production validation |
| S45-5 | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/tutorials/mcp-setup.md | 2026-09-22 | HTTP 200; 3,254 bytes at access time | verified | raw official setup source cross-check | production outcome |
| S45-6 | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/tools/mcp-resources.md | 2026-09-22 | HTTP 200; 1,781 bytes at access time | verified | raw official resource source cross-check | freshness/completeness/effect |

Snapshot reference: public repository `https://github.com/google-gemini/gemini-cli`, commit `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`.
