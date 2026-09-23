# B-S39 官方研究报告：Gemini CLI 会话、Checkpoint、Headless 与 Sandbox 证据边界

**访问日期：2026-09-22（Asia/Shanghai）**  
**研究类型：仅官方/一手公开资料；只读文档证据；非生产验证。**

## 结论摘要

1. **verified（官方直接陈述）**：Gemini CLI 的 session management 会自动保存会话历史；`--resume`/`-r` 可按最近会话、索引或 UUID 恢复；交互界面也提供 `/resume` 浏览和恢复。官方文档还描述了 session retention 默认 30 天、可配置的启用开关、最大年龄和最大数量。
2. **verified**：Checkpointing 是在 AI 对项目文件作修改前创建项目状态快照；`/restore` 可把项目文件恢复到快照状态。官方同时明确 checkpoint 数据包含 Git snapshot 与 conversation history，保存于 `~/.gemini/tmp/<project_hash>/checkpoints` 一类路径。
3. **verified**：Headless 模式输出结构化文本或 JSON；JSONL 流包含 `init` 等事件；官方定义标准退出码。该文档只规定 CLI 输出/退出接口，不证明外部副作用已提交。
4. **verified**：Sandbox 有 flag、环境变量和 settings 配置，并有明确优先级；文档列出 Seatbelt、Docker/Podman、Windows native、gVisor/runsc、LXC/LXD 等机制。工具级 sandbox 可针对单个工具执行；sandbox expansion 可在权限不足时请求额外权限。
5. **inferred**：checkpoint restore 是文件/会话状态恢复机制，不应推断为任意外部副作用回滚。官方文档没有声称它能撤回已发送网络请求、第三方 API 变更、数据库写入或远程服务状态。
6. **inferred**：sandbox 的“当前项目 workspace 默认可访问”与“允许额外路径/网络的扩展权限”说明了访问边界可被配置或扩展；不能将“启用了 sandbox”直接等同于网络、凭据、宿主机或所有工具均隔离。
7. **unknown**：本切片未运行 Gemini CLI，未验证实际 resume/restore、退出码、容器隔离、sandbox expansion 审批、恢复后的外部状态、崩溃恢复、exactly-once、审计完整性或生产连续性。

## 证据窗口与解释

### A. Session management

- `session-management.md` lines 3–22：自动记录会话历史，并按项目关联。
- lines 24–54：`--resume`/`-r` 支持最近会话、索引和完整 session UUID。
- lines 55–97：交互 `/resume` 浏览、预览、搜索、选择，以及命名 chat checkpoints。
- lines 99–104：官方建议使用 Git worktrees 为并行 session 提供独立代码副本，减少碰撞。
- lines 105–146：列出和删除 session。
- lines 152–186：默认保留 30 天，并可配置 enabled/maxAge/maxCount。
- lines 188–208：session limits；交互模式需新建 session，非交互模式会以错误退出。

### B. Checkpointing

- `checkpointing.md` lines 1–6：在 AI 文件修改前创建项目状态 checkpoint，可恢复到 tool 运行前状态。
- lines 8–35：文件修改工具触发 checkpoint；快照包含项目文件状态；`/restore` 恢复文件；checkpoint 数据包括 Git snapshot 和 conversation history。
- lines 37–58：功能启用和 settings 配置。
- lines 60–95：列出、选择并恢复 checkpoint。

### C. Headless output

- `headless.md` lines 1–5：headless 提供无交互终端 UI 的 structured text/JSON。
- lines 11–34：JSON 单对象与 JSONL 事件流，`init` 事件含 session ID/model 等。
- lines 37–45：标准退出码定义。

### D. Sandbox

- `sandbox.md` lines 20–33：sandbox 的总体目标/收益。
- lines 34–80：命令 flag、`GEMINI_SANDBOX` 环境变量、settings 配置及优先级。
- lines 81–265：不同 sandbox 后端及其平台边界。
- lines 267–318：工具级 sandbox 与 sandbox expansion；扩展权限针对特定运行。
- lines 319–337：默认只访问当前 project workspace，额外文件/目录需显式配置。
- lines 361–418：高级 flags、UID/GID 等配置。
- lines 419–468：故障排查和安全注意事项。

## 不能证明的边界

- 文档证据不证明在任何用户机器上功能已安装、配置、加载或成功执行。
- checkpoint/restore 不证明第三方外部效果回滚，也不证明数据库、网络请求、消息队列或远程服务状态被撤回。
- JSON/JSONL 输出与退出码不等于业务 commit、平台完整审计或外部 postcondition。
- sandbox 文档不证明所有 host、network、secret、mount、Docker socket 或自定义镜像配置都安全；具体隔离仍取决于后端和配置。
- session retention 是清理策略描述，不证明恢复数据永久保存、跨机器可用或满足合规留存。

## 范围与状态

本切片只读取官方仓库快照和其公开 raw 文档；未访问真实 Gemini CLI、凭据、私有账号、生产服务或受保护目录。所有“verified”均限于“官方原文直接陈述”；运行态和外部效果均为 unknown。
