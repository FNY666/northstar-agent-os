# B-S42 Gemini CLI 官方配置层级、信任文件夹与安全开关

访问日期：2026-09-22（Asia/Shanghai）。官方原文来自 Gemini CLI 仓库，raw URL 均 HTTP 200；仅做公开资料研究。

## 结论

1. **verified / high**：官方定义 system defaults、user、project、system override 四类 settings 文件；project settings 覆盖 user/default，system settings override 其它层。证据：`configuration.md` lines 1–61；`settings.md` lines 7–18。
2. **verified / high**：workspace/project 配置可影响具体项目；官方 Trusted Folders 机制用于控制哪些项目可以使用完整 CLI 能力，并在不信任时阻止加载项目特定配置。证据：`trusted-folders.md` lines 1–6, 25–45。
3. **verified / high**：安全设置包括 tool sandboxing、禁用 YOLO、禁用 Always Allow、永久工具批准、Git extension block、extension regex allowlist、folder trust、环境变量 redaction、context-aware security。证据：`settings.md` lines 142–155；`configuration.md` lines 1867–1961。
4. **verified / high**：项目配置可以引用环境变量语法；system settings 路径可由环境变量覆盖；MCP server 设置含 trust/includeTools/excludeTools 等字段，配置顺序与工具过滤存在明确优先级规则。证据：`configuration.md` lines 63–68, 2424–2477。
5. **verified / high**：官方将“trusted workspace 中低风险工具自动加入 policy”作为可配置行为，并明确 permanent approval/always allow 是独立开关。证据：`settings.md` lines 148–153。
6. **inferred / medium**：配置层级与 Trusted Folder 共同构成“项目配置不可默认等同用户意图”的边界：高优先级 system 配置可以覆盖 project，非信任项目会限制 project-specific config 加载。该组合解释支持配置审查必须记录 effective settings，而不能只读单一文件。
7. **unknown / unverified**：官方文档窗口没有证明恶意 system/user/project 配置在所有执行路径中均被阻断，也没有证明配置加载原子性、并发修改、崩溃恢复、回滚或跨版本兼容。
8. **unknown / unverified**：安全开关的存在与文档化作用不等于实际生产环境已经启用，也不证明 MCP server、扩展、工具调用的外部副作用、审计完整性或 exactly-once。

## 证据边界

文档直接陈述标记 `verified`；组合性工程结论标记 `inferred`；未在窗口中直接证明的可靠性、安全效果和生产状态标记 `unknown/unverified`。本切片未修改配置、未访问真实 CLI 会话、凭据或生产服务。