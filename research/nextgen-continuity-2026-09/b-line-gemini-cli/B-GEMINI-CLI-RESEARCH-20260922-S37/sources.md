# S37 官方来源清单

访问日期统一为 **2026-09-22**（Asia/Shanghai）。来源均为 Google Gemini CLI 官方 GitHub 仓库/官方 raw 文件；直接证据窗口见 REPORT.md，以下 URL 可追溯核验。

| ID | 官方 URL | raw URL | 发布者/层级 | 证据窗口 | 能支持 | 不能证明 |
|---|---|---|---|---|---|---|
| S37-S1 | https://github.com/google-gemini/gemini-cli/blob/main/docs/extensions/reference.md | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/extensions/reference.md | Google Gemini CLI；primary | `reference.md` lines 1–34, 36–80, 178–227, 240–280, 346–360；仓库 commit `d5b3e3accb26000d273abf16e0f1dd83aa5428a9` | Extension 管理命令、安装复制/更新、scope、环境变量过滤、skills/hooks/policies 集成、policy allow/yolo 忽略、命令冲突优先级 | 不证明当前运行时成功、第三方安全、源码完整性、回滚、审计、生产效果 |
| S37-S2 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/skills.md | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/skills.md | Google Gemini CLI；primary | `skills.md` lines 1–76, 81–127 | Skills 发现→激活→同意→目录访问生命周期；四层发现优先级；管理命令与 scope | 不证明弹窗不可配置、沙箱/网络隔离、具体版本命令成功、激活后的即时撤销 |
| S37-S3 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/using-agent-skills.md | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/using-agent-skills.md | Google Gemini CLI；primary | `using-agent-skills.md` lines 7–20, 38–80 | Skills 层级、安装/链接/卸载、默认 user scope、安装与激活同意、安全风险说明 | 不证明第三方 skill 可信、权限细粒度、真实环境隔离或运行时审计 |
| S37-S4 | https://github.com/google-gemini/gemini-cli/blob/main/docs/extensions/best-practices.md | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/extensions/best-practices.md | Google Gemini CLI；primary normative guidance | `extensions-best-practices.md` lines 58–108 | 最小权限、excludeTools、MCP 输入验证、敏感设置 `sensitive: true` 的官方设计建议 | 不证明建议已实施、阻止所有攻击、密钥/依赖/供应链安全或生产合规 |
| S37-S5 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/skills-best-practices.md | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/skills-best-practices.md | Google Gemini CLI；primary normative guidance | `skills-best-practices.md` lines 1–77 | Skill description 触发、渐进披露、资源组织、review 第三方 SKILL.md/scripts、限制 scope | 不证明技能作者/脚本可信、效果、隔离或安全审计 |

## 访问与证据等级

- 上述 GitHub 页面及 raw 文件在研究时可访问；raw 核验返回 HTTP 200。仓库本地快照为官方仓库 URL 的只读 clone，HEAD `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`，提交时间 `2026-09-21T20:36:40Z`。
- `verified` 表示“官方原文确实直接写出该规则/建议”；不是对用户机器运行态或生产效果的验证。
- `inferred` 仅用于由官方文档边界推导的风险含义（例如：同名覆盖不等于内容可信）；这些不应被表述为官方对所有环境的保证。
- `unknown` 表示本切片未验证，尤其包括安装实际成功、运行时撤销、沙箱、审计、回滚、exactly-once、外部副作用与生产连续性。
