# B-S37 Official — Gemini CLI Extensions / Agent Skills 生命周期与安全边界

- **研究日期**：2026-09-22（Asia/Shanghai）；官方页面/原始仓库以访问时内容为准。
- **问题**：Gemini CLI 官方资料对 Extensions 与 Agent Skills 的安装、更新、禁用、发现、激活、权限、环境变量和策略安全边界作了哪些可核验规定？这些资料不能证明什么？
- **范围**：仅 Google Gemini CLI 官方 GitHub 仓库文档与其 raw 原文；仓库快照 commit `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`（2026-09-21T20:36:40Z）。未安装、未运行 Gemini CLI 或任何扩展/技能，未访问私有资源、凭据、真实服务。

## 结论

1. **Extension 安装是复制而非持续镜像**：官方 reference 明确安装可接受 GitHub URL 或本地路径；安装时 CLI 创建副本，源端变化要用 `gemini extensions update` 拉取。可指定 branch/tag/commit ref；`--auto-update` 和 `--pre-release` 是显式选项。已安装扩展的管理变更（包括 slash command 更新）要在 CLI 重启后生效。[verified]
2. **Extension 的管理面与 interactive mode 有边界**：`gemini extensions install` 等管理命令不在交互模式支持；交互中 `/extensions list` 可查看已安装扩展。安装/卸载/禁用/启用/更新是终端命令；扩展默认全局启用，也可按 user/workspace scope 禁用或启用。[verified]
3. **Agent Skills 采用渐进披露和显式激活同意**：会话开始发现各层级 skill 的 name/description；任务匹配后调用 `activate_skill`；UI 展示 skill、用途和将获得访问权限的目录，用户批准后才注入 `SKILL.md`/目录访问。[verified]
4. **Skills 的发现优先级是 built-in < extension < user < workspace**；同名 skill 使用更高优先级版本；同层级 `.agents/skills/` alias 优先于 `.gemini/skills/`。[verified]
5. **Extension 的环境变量默认最小化**：敏感环境变量默认不传给扩展或 MCP server；不会继承完整 shell 环境，只允许标准安全变量和 manifest `settings` 中显式声明的 `envVar`。[verified]
6. **Extension policy 不能自行升级为自动批准**：扩展 policy 位于 tier 2，高于默认规则但低于 user/admin；官方明确忽略 extension policy 中的 `allow` 或 `yolo`，防止扩展绕过用户确认自动批准工具调用。[verified]
7. **官方安全指南是设计要求/建议，不是运行时证明**：最小权限、限制强工具、验证 MCP 输入、防止任意代码执行/越权文件访问、敏感设置使用 `sensitive: true` 存入系统 keychain 并在 CLI 输出中混淆，均来自官方 best-practices。[verified as documented guidance; effectiveness in a deployment remains unknown]

## 逐项证据与边界

### C1 — 安装复制、更新与重启生效
- **状态**：verified（文档直接陈述；不是本机运行验证）。
- **证据窗口**：`docs/extensions/reference.md` lines 11–34, 67–80；仓库 commit `d5b3e3a...`；访问/快照日期 2026-09-22。
- **官方 URL**：https://github.com/google-gemini/gemini-cli/blob/main/docs/extensions/reference.md
- **原文 URL**：https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/extensions/reference.md
- **直接支持**：install 接收 GitHub URL/本地路径；安装创建 copy；需 `extensions update` 拉源端变化；支持 ref、auto-update、pre-release、consent；管理操作重启后生效。
- **不能证明**：没有证明某个具体扩展当前可安装、源仓库完整性、更新是否成功、auto-update 的实际时序、重启前后所有状态差异，或任何第三方扩展安全。

### C2 — 安装/卸载/启停/配置的操作边界
- **状态**：verified（文档直接陈述）。
- **证据窗口**：`reference.md` lines 6–14, 36–80；`skills.md` lines 81–127；访问日期 2026-09-22。
- **官方 URL**：https://github.com/google-gemini/gemini-cli/blob/main/docs/extensions/reference.md；https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/skills.md
- **直接支持**：interactive mode 不支持 extension install 等管理命令；`/extensions list` 可查看；extension disable/enable 支持 user/workspace；skills 提供 list/link/disable/enable/reload 和 terminal install/uninstall，scope 默认 user。
- **不能证明**：不能证明命令在当前发布版本、特定 OS、具体权限/网络环境下实际成功；不能证明 disable 对已启动进程中已激活能力的即时撤销语义；不能替代运行时测试。

### C3 — Skills 发现、激活、同意与访问路径
- **状态**：verified（官方 Skills 文档直接陈述）。
- **证据窗口**：`docs/cli/skills.md` lines 15–55, 67–76；`docs/cli/using-agent-skills.md` lines 7–20, 71–80；访问日期 2026-09-22。
- **官方 URL**：https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/skills.md；https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/using-agent-skills.md
- **直接支持**：启动时注入 enabled skill 的 name/description；匹配后 activate_skill；UI 询问并说明目录；批准后才把 SKILL.md 和目录加入上下文/允许访问路径；Skills 可执行 scripts 并访问文件，因此安装和激活都有安全同意层。
- **不能证明**：未证明每次真实版本都一定弹窗、同意提示不可被配置改变、激活后每个脚本都被沙箱隔离、或“目录允许访问”具备细粒度写权限/网络隔离。

### C4 — Discovery tiers 与冲突优先级
- **状态**：verified。
- **证据窗口**：`skills.md` lines 35–55；`using-agent-skills.md` lines 7–20；访问日期 2026-09-22。
- **官方 URL**：https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/skills.md
- **直接支持**：built-in、extension、user、workspace 按低到高；同名 skill 采用高优先级；`.agents/skills/` alias 优于同层级 `.gemini/skills/`。
- **不能证明**：不能从此推出内容安全、作者可信、任意同名覆盖一定符合用户意图，或 workspace skill 自动通过安全审查。

### C5 — Extension 环境变量 allowlist 与秘密处理
- **状态**：verified（reference 的运行设计陈述）。
- **证据窗口**：`reference.md` lines 178–227；访问日期 2026-09-22。
- **官方 URL**：https://github.com/google-gemini/gemini-cli/blob/main/docs/extensions/reference.md
- **直接支持**：敏感环境变量默认过滤；扩展不继承完整 shell 环境；只给标准安全变量与 manifest settings 的 `envVar`；API key/custom host/config path 应先声明。
- **不能证明**：不能证明主机上已有 secret 不会通过文件、命令参数、日志、MCP 返回值或其他通道泄露；也不能证明 `envVar` 声明者可信、keychain ACL 正确，或 MCP server 自身不会外传。

### C6 — Extension policy 的优先级和 fail-closed 边界
- **状态**：verified（reference 直接警告）。
- **证据窗口**：`reference.md` lines 261–280；访问日期 2026-09-22。
- **官方 URL**：https://github.com/google-gemini/gemini-cli/blob/main/docs/extensions/reference.md
- **直接支持**：扩展可贡献 policies；extension tier 2 高于默认、低于 user/admin；扩展 policy 的 allow/yolo 会被忽略，不能自动批准工具调用或绕过确认。
- **不能证明**：不能证明所有危险路径被 policy 捕获，不能证明 user/admin policy 配置正确，不能证明工具自身或 MCP server 没有副作用，也不能证明 policy 形成完整审计记录。

### C7 — Best-practices 的最小权限、输入验证、敏感设置
- **状态**：verified as official guidance；效果/部署达标状态 unknown。
- **证据窗口**：`docs/extensions/best-practices.md` lines 58–108；`docs/cli/skills-best-practices.md` lines 69–77；访问日期 2026-09-22。
- **官方 URL**：https://github.com/google-gemini/gemini-cli/blob/main/docs/extensions/best-practices.md；https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/skills-best-practices.md
- **直接支持**：least privilege；避免不必要 full shell；可用 excludeTools 限制危险命令；MCP server 应验证输入；敏感设置使用 `sensitive: true`，官方称其存于系统 keychain 并在 CLI 输出中混淆；第三方 skill 应审查 SKILL.md/scripts，限制 scope。
- **不能证明**：指南不是独立安全审计、渗透测试、保证书或生产合规证明；不能证明示例配置足以阻止所有命令注入、路径穿越、供应链攻击、keychain compromise 或恶意 skill。

## 覆盖缺口与保留 UNKNOWN

- 未运行 CLI、未安装/激活任何扩展或 skill；所有运行时行为、版本差异、错误路径、权限失败、网络失败均为 unknown。
- 未证明扩展/skill 的源码身份、签名、review、依赖锁定、自动更新回滚、审计日志、exactly-once、崩溃恢复、外部副作用或生产连续性。
- 未把官方文档的 normative guidance 升格为 measured security outcome；未声称任何生产部署通过。

## 资料完整性

随本报告保存了官方仓库快照对应文件：`reference.md`、`extensions-best-practices.md`、`skills.md`、`using-agent-skills.md`、`skills-best-practices.md`。来源 URL、访问日期、证据窗口和不能证明边界均在本报告和 `sources.md` 中列出。
