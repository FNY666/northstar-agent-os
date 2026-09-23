# S50 sources

访问日期：2026-09-22；公开一手官方来源。

| ID | 完整官方 URL | 证据窗口 | 等级 | 不能证明 |
|---|---|---|---|---|
| S50-1 | https://github.com/google-gemini/gemini-cli/blob/main/docs/get-started/authentication.mdx | Google/API key/Vertex AI 认证、headless 凭据、敏感凭据警告 | verified | 认证后所有授权、外部提交 |
| S50-2 | https://github.com/google-gemini/gemini-cli/blob/main/docs/resources/quota-and-pricing.md | 配额、价格、按日/分钟限制、`/stats model` | verified | 最终账单、请求是否已接受 |
| S50-3 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/model-routing.md | 失败 fallback、用户同意、silent policy、model precedence | verified | exactly-once、原请求未执行 |
| S50-4 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/model.md | `/model`/`--model`、Auto/Manual、sub-agent 非继承边界 | verified | 运行时所有实际模型、外部效果 |
