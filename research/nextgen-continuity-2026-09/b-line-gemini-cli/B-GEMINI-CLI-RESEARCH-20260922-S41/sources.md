# B-S41 官方来源矩阵

访问日期：2026-09-22（Asia/Shanghai）。所有来源为 Gemini CLI 官方仓库/官方文档；raw URL 返回 HTTP 200。证据窗口按官方仓库快照行号记录。

| ID | 完整官方 URL | 证据窗口 | 状态/等级 | 直接支持 | 不能证明 |
|---|---|---|---|---|---|
| S41-1 | https://github.com/google-gemini/gemini-cli/blob/main/docs/extensions/releasing.md | lines 1–10, 32–69, 162–215 | verified / primary | Git/GitHub Release 分发、`--ref`、Latest/pre-release、迁移与更新检测 | 下载原子性、供应链安全、回滚、exactly-once |
| S41-2 | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/extensions/releasing.md | lines 1–10, 32–69, 162–215 | verified / primary | 同上，原始 Markdown 可复核 | 同上 |
| S41-3 | https://github.com/google-gemini/gemini-cli/blob/main/docs/extensions/writing-extensions.md | lines 16–24, 52–73, 131–169, 263–304 | verified / primary | 扩展能力、manifest、设置提示、敏感设置、默认环境变量清洗、Skill | 第三方代码可信、MCP 外部效果、完整权限安全 |
| S41-4 | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/extensions/writing-extensions.md | lines 16–24, 52–73, 131–169, 263–304 | verified / primary | 同上，原始 Markdown 可复核 | 同上 |
| S41-5 | https://github.com/google-gemini/gemini-cli/blob/main/docs/extensions/index.md | lines 1–5, 36–60 | verified / primary | 扩展用途、交互式 `/extensions` 管理、安装入口 | 验证强度、运行时安全、更新成功 |
| S41-6 | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/extensions/index.md | lines 1–5, 36–60 | verified / primary | 同上，原始 Markdown 可复核 | 同上 |

官方来源内容可信度与结论正确性分离：文档直接陈述属于 verified；对可靠性、安全性、外部副作用的扩展性结论均保留 inferred 或 unknown。