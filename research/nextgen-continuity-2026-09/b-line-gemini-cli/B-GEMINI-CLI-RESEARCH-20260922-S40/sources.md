# B-S40 官方来源清单

访问日期：2026-09-22（Asia/Shanghai）。

| ID | 官方 URL | raw URL | 证据窗口 | 等级 | 能支持 | 不能证明 |
|---|---|---|---|---|---|---|
| S40-S1 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/telemetry.md | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/telemetry.md | lines 33–48, 154–225, 272–400, 480–551 | primary | Telemetry 配置、导出目标、事件字段 | flush/完整性/不可篡改/外部效果 |
| S40-S2 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/acp-mode.md | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/acp-mode.md | lines 40–70, 78–94, 101–125 | primary | ACP session/prompt/cancel/session mode 与 MCP 集成 | cancel 的外部撤销、生产行为 |
| S40-S3 | https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/tools/mcp-server.md | lines 26–55, 90–188, 190–248, 610–625 | primary | MCP discovery、timeout、过滤器、环境变量脱敏/override、连接状态 | server 可信、重试/重连/exactly-once、工具效果 |
| S40-S4 | https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-resources.md | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/tools/mcp-resources.md | lines 1–42 | primary | MCP resource list/read 的接口边界 | 内容真实性、授权、外部提交 |

verified 仅指官方原文直接陈述；inferred/unknown 均在 REPORT.md 标注。