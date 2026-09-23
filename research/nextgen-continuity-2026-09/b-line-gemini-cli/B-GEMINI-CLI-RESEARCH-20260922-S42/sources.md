# B-S42 官方来源矩阵

访问日期：2026-09-22（Asia/Shanghai）。

| ID | 完整官方 URL | 证据窗口 | 等级 | 能证明 | 不能证明 |
|---|---|---|---|---|---|
| S42-1 | https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md | lines 1–68, 1867–1961, 2424–2490 | verified / primary | 四层配置、环境变量引用、安全设置、MCP trust/filter/precedence | 运行时完整执行效果、故障恢复、生产启用 |
| S42-2 | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/reference/configuration.md | lines 1–68, 1867–1961, 2424–2490 | verified / primary | 同上，原始 Markdown | 同上 |
| S42-3 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/settings.md | lines 1–18, 142–155 | verified / primary | `/settings`、user/workspace 文件、优先级、安全开关 | 配置安全性与完整性 |
| S42-4 | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/settings.md | lines 1–18, 142–155 | verified / primary | 同上 | 同上 |
| S42-5 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/trusted-folders.md | lines 1–6, 25–45 | verified / primary | Trusted Folders 用途、信任目录/父目录关系 | 所有攻击路径都被阻断、外部效果 |
| S42-6 | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/trusted-folders.md | lines 1–6, 25–45 | verified / primary | 同上，原始 Markdown | 同上 |

`verified` 是文档机制事实，不是部署验收；`inferred` 与 `unknown` 见 REPORT.md。