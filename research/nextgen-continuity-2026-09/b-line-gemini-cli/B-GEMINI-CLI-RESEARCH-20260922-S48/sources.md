# S48 sources

访问日期：2026-09-22；公开一手官方来源。

| ID | 完整官方 URL | 证据窗口 | 等级 | 不能证明 |
|---|---|---|---|---|
| S48-1 | https://github.com/google-gemini/gemini-cli/blob/main/SECURITY.md | 漏洞报告入口与响应承诺 | verified | 修复完成、运行安全 |
| S48-2 | https://github.com/google-gemini/gemini-cli/blob/main/docs/admin/enterprise-controls.md | strict mode、Extensions、MCP allow/deny/required、approval 与 trust 边界 | verified | 所有进程实际遵循、外部效果 |
| S48-3 | https://github.com/google-gemini/gemini-cli/blob/main/.github/workflows/verify-release.yml | 显式版本、permissions、release verification action、secret 使用 | verified | 每次发布成功、制品完整、生产部署 |
| S48-4 | https://github.com/google-gemini/gemini-cli/blob/main/.github/workflows/release-rollback.yml | origin/destination/tag 输入、npm/GitHub release 删除/重标、rollback tag、失败处理 | verified | 运行时/数据库/业务副作用回滚、全局收敛 |
