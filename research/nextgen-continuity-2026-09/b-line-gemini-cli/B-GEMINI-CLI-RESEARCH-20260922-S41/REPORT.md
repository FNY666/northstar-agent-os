# B-S41 Gemini CLI 官方扩展发布、版本更新与环境边界研究

访问日期：2026-09-22（Asia/Shanghai）。研究对象仅为 Gemini CLI 官方仓库文档快照；官方原文通过 GitHub raw HTTP 200 核验。对应仓库快照：`google-gemini/gemini-cli`，commit `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`，HEAD 时间 `2026-09-21T20:36:40Z`。

## 结论摘要

1. **verified / high**：官方支持以 Git 仓库或 GitHub Release 作为扩展分发源；Git 安装可用 `--ref` 固定分支/标签，GitHub Release 通过 Latest release 检测更新，也可用 `--ref` 或 `--pre-release` 选择版本。证据窗口：`releasing.md` lines 5–10, 32–47, 60–69。
2. **verified / high**：Git 源更新检测把 `HEAD` 视为最新版本；GitHub Release 更新检测查询 GitHub API 的最新 release tag，而非 manifest 的 `version` 字段；本地扩展则比较源目录 manifest 与已安装版本。证据窗口：`releasing.md` lines 180–208。
3. **verified / high**：官方要求 GitHub release tag 与 `gemini-extension.json` 的 `version` 保持一致，原因是 CLI 用 tag 检测更新、UI 显示 manifest version；不一致会造成显示与检测语义分裂。证据窗口：`releasing.md` lines 186–193。
4. **verified / high**：扩展可迁移到新仓库：旧仓库 manifest 写 `migratedTo` 与新版本，发布旧仓库更新；CLI 检测到该字段后验证新仓库并自动更新本地安装，但新仓库至少需要有一个 release。证据窗口：`releasing.md` lines 162–177, 214–215。
5. **verified / high**：扩展 manifest 可声明 MCP server、custom commands、system instructions、themes、Agent Skills 等能力；官方建议用 MCP 暴露工具/数据，用 Skill 承载按需激活的复杂工作流，以避免持续占用主上下文。证据窗口：`writing-extensions.md` lines 16–24, 52–73, 263–304。
6. **verified / high**：扩展设置在安装时提示用户输入；敏感设置可标记 `sensitive: true`，并注入 MCP server 进程。默认环境变量经过安全清洗，扩展/MCP server 默认不能访问任意宿主环境变量，只有显式允许的变量可用。证据窗口：`writing-extensions.md` lines 131–169。
7. **inferred / medium**：发布源、tag、manifest version、安装类型元数据共同构成更新判定链；它能降低版本漂移，但不等于供应链真实性、代码安全、release asset 未被替换或运行时行为正确。推断依据为官方对更新检测机制的描述；官方未在这些窗口证明签名、内容寻址、独立审计或运行时证明。
8. **unknown / unverified**：官方文档窗口未证明失败下载、GitHub API 不可用、tag 被重写、release asset 损坏、更新中断、并发更新、回滚、exactly-once 安装或崩溃恢复语义。不能把“自动检查更新”升级为“可靠更新/原子更新”。
9. **unknown / unverified**：官方窗口未证明扩展安装后 MCP 工具的外部副作用、Agent Skill 指令的正确性、插件作者可信度或第三方仓库持续安全。

## 能证明/不能证明

### 能证明
- 官方文档规定的分发方式、`--ref`/Latest/pre-release 入口、更新检测差异。
- manifest `version`、GitHub release tag、`migratedTo` 在官方更新流中的角色。
- 扩展能力组成及敏感设置/环境变量默认清洗的文档化边界。

### 不能证明
- 任何特定第三方扩展安全、无恶意或与 manifest 一致。
- 安装、更新、迁移在网络/磁盘/进程故障时的原子性、幂等性、可回滚性。
- GitHub API、release asset、Git tag 的可用性、完整性或长期保留。
- MCP server、custom command、Skill 的外部副作用已经发生、成功提交或可逆。
- 生产环境已经启用、通过或经过真实服务验证；本切片完全未访问真实 Gemini CLI 会话、凭据或生产系统。

## 证据等级规则

`verified` 仅用于官方文档逐字支持的机制事实；`inferred` 仅用于由多个官方事实推出的工程含义；`unknown/unverified` 表示官方窗口未给出足够证据，不作正向或负向断言。