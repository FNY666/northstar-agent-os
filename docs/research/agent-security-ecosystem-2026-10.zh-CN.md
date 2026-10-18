# Agent 安全生态调研与 Northstar 覆盖记录

**更新日期：2026-10-17**  
**范围：编程 agent 优先；多模态安全暂缓到编程和攻防闭环稳定之后。**

这是一份滚动的公开资料记录，不声称枚举了“所有 AI”。公开资料分散在厂商文档、开源仓库、问题追踪器、论坛和新闻讨论中；登录后才可见的 Slack、Discord、微信群等内容不在当前可检索范围。搜索结果用于确定攻击面和工程方向，不能替代代码审计或独立产品评测。社区贴文是参与者经验，不当作通用结论。

## 公开资料面

| 来源面 | 代表资料 | 观察到的安全/工程主题 |
|---|---|---|
| 威胁标准 | [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)、[OWASP Agentic Skills Top 10](https://owasp.github.io/www-project-agentic-skills-top-10/)、[AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)、[MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) | agent 权限和高影响动作、skill 的内容/供应链、MCP 工具描述与返回值、凭据与外传边界都需要分别检查；规则扫描只是补充，不能证明 prompt injection 抵抗力。 |
| 厂商编程 agent | [OpenAI Sandbox Agents](https://developers.openai.com/api/docs/guides/agents/sandboxes)、[Codex project configuration](https://developers.openai.com/zh-Hans/docs/config-file/config-basic)、[Anthropic Claude Code security](https://docs.anthropic.com/en/docs/claude-code/security)、[Claude CLI permissions](https://docs.anthropic.com/en/docs/claude-code/cli-usage)、[Cursor Background Agents security](https://docs.cursor.com/background-agent)、[Cursor CLI permissions](https://docs.cursor.com/cli/reference/permissions) | 隔离工作区、权限批准、MCP/工具连接和网络可达性构成一条执行边界；自动运行会放大恶意上下文引发的数据外传风险。不同产品的策略格式不一致，不能假设一个配置检查器适用于全部产品。 |
| 开源运行时 | [LangGraph persistence](https://langchain-ai.github.io/langgraph/concepts/durable_execution/)、[OpenHands SDK workspace](https://github.com/OpenHands/software-agent-sdk/blob/main/openhands-sdk/openhands/sdk/workspace/base.py) | 一类方案以 checkpoint/interrupt 恢复长流程，一类方案把文件和命令放在独立 workspace/sandbox。验证需要绑定 run 的实际状态，而不是只采信 agent 的完成陈述。 |
| 开源仓库与公开问题区 | [OWASP Agentic Skills Top 10 仓库](https://github.com/OWASP/www-project-agentic-skills-top-10)、[OpenHands 文档仓库](https://github.com/OpenHands/docs) | 社区正在形成 skill 安全目录、扫描器集成、MCP 及 workspace 的可复用词汇；工具描述、技能内容、执行环境与权限配置是不同层，单一规则集覆盖不了所有层。 |
| 公开论坛 | [Hacker News：如何测试 agent 验证能力](https://news.ycombinator.com/item?id=49605246)、[Hacker News：agent 生成代码如何测试](https://news.ycombinator.com/item?id=48655020)、[Reddit：面向多个编码 agent 的安全扫描器讨论](https://www.reddit.com/r/ClaudeAI/comments/1qxm0dv/i_built_an_mcp_server_that_scans_claudes_code/) | 讨论集中在测试是否真正验证行为、长会话中的验证退化、MCP/agent 专用扫描需求。它们是线索和个体经历，不是测量结果；需转成可复现的本地探针或明确标成未验证。 |

## 本次落地的产品差距

Northstar 已有源码 SAST、依赖/部署配置检查、MCP 准入扫描、skill 指令审计和可选 coding security gate，但这些能力原先分散在不同命令里。一个仓库可以让 agent 读取的规则文件或 MCP 描述直接改变 agent 行为，因此本次把两类已有审计接入同一个只读工作区扫描：

- 识别 `AGENTS.md`、`CLAUDE.md`、`GEMINI.md`、Cursor/Copilot/Windsurf/Continue/Roo 等规则位置，以及 Northstar/Codex/Claude/Cursor agent 配置文件和已知 skill 目录；对 Codex 完全开放且免审批、Claude 权限提示绕过、Cursor 泛化 shell/文件权限给出专门发现。
- 将现有 `skills audit` 的指令覆盖、隐瞒行为、越权自改、凭据读取、远程脚本、动态执行和不可见 Unicode 规则作为 `SecurityScan` 的 `agent-instruction-scanner` 发现。
- 将现有 MCP admission 规则直接用于 Claude/Cursor/VS Code/Gemini MCP 配置，检查已知恶意或可疑包、未固定包、远程明文 HTTP、凭据转交、硬编码凭据和工具描述注入。
- 扫描报告只给路径、行号、规则、建议和严重级别；不复制匹配到的指令、端点、环境变量名或凭据值。扫描不启动 skill、MCP server、脚本或网络连接。
- 这些规则自然进入既有 `--security-gate` 的基线/新增发现比较，因此仍然由运行宿主判定，agent 无法用自述覆盖门禁。发现只表示需审查，不授予修复或外部操作权限。
- `SecurityProbe` 增加固定的恶意与干净内存样例，覆盖指令注入、环境秘密暴露、Codex/Claude/Cursor 高风险权限配置、MCP 描述注入、未固定包、敏感字段不回显；样例不执行，也不接触用户文件。

## GitHub Actions 的不可信输入流

GitHub 官方文档明确说明，`pull_request_target` 使用基仓库的高信任权限；若再 checkout 并运行 fork PR 的代码，攻击者可借 PR 中的 Makefile、构建脚本或依赖在该权限下执行。另一类常见边界是将 `github.event.pull_request.title`、`body` 等不可信上下文直接插入 `run:` 脚本源。对应参考：[Securely using `pull_request_target`](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)、[Script injections](https://docs.github.com/en/actions/concepts/security/script-injections) 与 [Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)。

Northstar 新增 `CFG008_PULL_REQUEST_TARGET_UNTRUSTED_CHECKOUT`，在 `pull_request_target` 中发现 PR head/ref 或 fork repository checkout，或显式启用 `allow-unsafe-pr-checkout`，且同一 job 后续存在 `run` 步骤时提示；新增 `CFG009_ACTIONS_UNTRUSTED_RUN_EXPRESSION`，检测不可信事件字段直接插入 `run` 块，覆盖 PR head ref 以及 `workflow_run` 的分支名和提交信息。GitHub 也提醒，`workflow_run` 下游工作流下载的上游工件必须视为不可信数据，且通过 `git fetch`、`gh pr checkout` 等方式取回 PR 代码也可能形成同类危险。`CFG010_WORKFLOW_RUN_ARTIFACT_EXECUTION` 会在这类工作流的同一 job 下载工件、随后运行命令时提示；`CFG011_PRIVILEGED_PR_CODE_FETCH` 检查 `pull_request_target`、`workflow_run` 与 `issue_comment` 中的常见 Shell 拉取模式及后续命令；`CFG012_WORKFLOW_RUN_REVISION_EXECUTION` 对 checkout 上游 run SHA/PR head 后在同一 job 执行命令的流程给出中危审查提示，因为 head SHA 也可能来自可信 push；`CFG013_PRIVILEGED_TRIGGER_WRITE_PERMISSION` 对这些特权触发器下显式配置的 workflow/job 级写权限给出中危最小权限提示。CFG013 只标记工作流源码明确写出的权限，不推断仓库或组织默认 token 设置。运行时探针为每条规则核对固定恶意样例，并检查 workflow_run 分支名经环境变量传递、跨 job 分离及只读权限的安全对照；只扫描临时 YAML 文本，不启动 workflow、action 或脚本。

扫描器现在先建立常见 block-style YAML 的 Workflow/Job/Step 行号索引，再在 job 内判定步骤顺序，避免不同 job 的步骤互相拼成一条风险链；探针将“一个 job 下载、另一个 job 只打印摘要”作为负例。这仍不是完整 YAML 解析器。它不解析 flow-style jobs/steps、复合 action、跨 job 数据流、工件路径/来源关联、Shell 变量或远程 action 内部实现。CFG010 的下载后命令顺序是风险线索，不能证明命令实际执行了刚下载的工件；CFG011 也只覆盖显式 `gh pr checkout` 或包含 PR ref 的 `git fetch`/checkout 模式。结果应作为人工审查线索。

静态扫描无法可靠判断自然语言的真实意图、跨文件/远程技能依赖或运行时工具行为，也不能把“未匹配规则”解释为安全。MCP 服务器 package blocklist 是本地知识而非实时漏洞数据库。后续优先级仍是加强编程任务的独立验证和攻防工具的可复现覆盖；不先扩张到图像/音频/视频能力。

## 后续持续检索队列

每轮更新优先追踪可公开检索的官方安全公告、OWASP/标准版本、agent 与 MCP 仓库 release/issue、安全研究披露，以及 HN/Reddit 等公开社区的新攻击链。每条候选变化先记录原始来源、发布日期、影响的运行时边界和可复现证据；未经核验的供应商/社区说法只列为线索。需要登录、邀请或位于私人群聊中的内容不通过猜测补全。
