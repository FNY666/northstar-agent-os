# Northstar Agent OS — 开发者体验（DX）对标分析与改进路线图

> 编制日期：2026-09-08 ｜ 范围：开发者体验（Developer Experience）维度
> 方法：仓库本地实测（代码阅读 + 全部测试运行）+ 公开资料调研（截至 2026-09-07）
> 目标：找出 Northstar 与全球顶级 agent 工具在 DX 上的差距，给出可执行的分阶段改进路线图。
> 说明：本页保留分析基线，同时记录已经落地的批次；代码事实以当前 checkout、测试和后文最新 ledger 为准。

---

> **阅读口径（2026-09-08 当前真值）**：本页保留了早期差距基线与实施 ledger，
> 因而 §0–§8 中的“现状”段落有历史意义，不应覆盖后面的复评。当前 checkout
> 的权威快照是：`make test` **887 项测试，883 项通过、4 项 skip**（runtime 578，
> 其中 4 项因可选 OpenTelemetry 依赖缺失而跳过；其余组件与文档测试全绿）；五个可安装组件仍为
> 对齐的 `0.1.0.dev0`，没有发布 tag。Agent Skills 已支持
> `.northstar/skills` + portable `.agents/skills`、标准 frontmatter、`skills
> check/list` 与 fail-closed 路径校验；runtime 还新增了 bounded checkpoint、
> inspect/diff/rewind/fork 和 mutating-tool workspace receipts；T7 加入
> capability-first approval lease 与可验证 action receipt，本轮又补上 durable-run
> 的 pause/resume、显式 retry/cancel 生命周期与 attempt key 语义；MCP 仍是最小
> stdio 工具客户端，而不是完整的远程 MCP/插件市场。若只想看“现在还差什么”，
> 直接跳到 **§10.17**。

## 0. 执行摘要（TL;DR）

**当前结论：Northstar 已从“库 + 手工拼装”追到可安装、可审计、具备局部可逆执行的 headless harness，但还不是 Claude Code/Codex/Gemini 那样的完整产品。**本地实测 `make test` 为 **887 项测试（883 通过、4 项可选 OTel skip）**（runtime 578），权限门、hooks、预算、只追加 transcript、workspace receipts、checkpoint manifest、capability lease、可验证 action receipt、durable-run 生命周期与离线确定性仍是最强资产。

已经补齐的 DX 基础包括：五个可安装组件、console script、`doctor`/`dry-run`、AGENTS.md 与策略即代码、文件化 subagents、MCP stdio 最小客户端、标准 Agent Skills（含 `skills check/list`）、sessions 读回/NDJSON 审计、Python SDK、脚手架、API 文档和 CI recipe。**这些能力要以当前 checkout 的测试为准；本页后面的早期盘点是历史基线。**

与全球头部工具相比，剩余差距集中在产品外围而不是治理内核：

1. **交互恢复**：已有 resume/list/show/export，以及 checkpoint/inspect/diff/rewind/fork 的 CLI/API；仍没有交互式回放 UI、自动 turn-level checkpoint 策略和跨进程/远端恢复。
2. **可嵌入层**：已有 Python SDK 与结构化事件，没有 TypeScript SDK、长期 app-server 或 approval 协议。
3. **生态深度**：MCP 仍是 stdio 工具发现/调用，没有 HTTP/auth；无 plugins、marketplace、热加载和组织级安装策略。
4. **后台与远程**：durable-run/remote-worker 有内核和协议/运维文档，但没有网络 transport、调度器或真实远端 canary。
5. **发布与隔离**：版本就绪门已在，仍是 `0.1.0.dev0` 未发布；应用层权限不等于 OS/VM sandbox，live Anthropic 与原生 Linux/真实远端验证仍缺。

**路线图红线不变：**接入标准生态不能绕过权限门、hooks、预算、工作区 containment 和审计；Northstar 应把“标准格式可消费 + 默认拒绝 + 可验证结果 + 离线复现”做成面向 CI/企业嵌入的差异化，而不是复制头部产品的 TUI。

---

## 1. 方法：对谁比、比什么

### 1.1 对标对象（为什么是它们）

Northstar 是"运行时组件集合"，不是一个终端产品。因此对标分三层：

| 层 | 对象 | 为什么对标它 |
|---|---|---|
| **直接参照系** | Claude Code / Claude Agent SDK | Northstar 的 hook 事件词汇（PreToolUse、SubagentStop…）、子代理、会话、权限语义都明确以 Claude Code 能力面为模板（见 `components/northstar-agent-runtime/README.md`），是最直接的"能力对表"对象 |
| **同类竞品** | OpenAI Codex CLI + Agents SDK、LangGraph、Cursor、Devin/OpenHands | 覆盖终端代理、编排框架、IDE、全自主平台四种产品形态；其中 LangGraph 与 Northstar 的 durable-run 志向最接近 |
| **横向标准** | Agent Skills（agentskills.io）、MCP、A2A、AGENTS.md | 2025Q4–2026 年形成的跨平台开放标准，是"生态 DX"的裁判；北星 interop 组件已把 OpenBot/Claude Code 等列为未来对接方 |

### 1.2 DX 评估维度

1. 安装与 zero-to-first-run（首次跑通时间）
2. CLI 与终端体验
3. 程序化 API / 包管理（能否 `pip install`、版本、入口点）
4. 配置与项目约定（仓库级上下文文件）
5. 扩展生态（MCP、Skills、Plugins、subagent 文件化）
6. 会话 / 调试 / 可观测（resume、回放、追踪）
7. 测试与确定性（离线测试、mock、replay）
8. 文档与教学（快速开始→教程→API 参考）
9. 版本化与发布工程（tag、changelog、Release）
10. 团队 / CI / 协作面（headless 模式、GitHub Action、review）

评分 1–5，来源为公开资料（第三方评测与官方文档，见 §8）+ 仓库本地实测；分数是便于比较的主观判断，下方每个维度都有文字依据。

---

## 2. Northstar 现状盘点（本地实测证据）

### 2.1 基本盘

| 项 | 实测结果 |
|---|---|
| 组件数 | 6（sidecar / run-contract / host / durable-run / agent-interop / agent-runtime） |
| 测试 | **591 项全部通过**（2026-09-07 本地运行：51+22+24+59+49+3+383；runtime 4 项因未安装 `anthropic` 依赖跳过——CI 中会安装） |
| 文档 | 根 README 160 行 + **11 种语言翻译**（有自动化文档结构测试强制标记与免责声明）；组件 README 共 606 行（最短 31 行 = sidecar，最长 252 行 = runtime） |
| 打包 | **0 个** `pyproject.toml` / `setup.py` / `setup.cfg`；无 `__version__`；无 console entry point |
| 跨组件依赖 | 工作流中靠 `PYTHONPATH=../northstar-run-contract:../northstar-host` 注入（`test.yml`），组件之间没有正式依赖声明 |
| CI | GitHub Actions 3 个 job：基础组件、agent-runtime（装依赖后离线测试）、文档结构测试 |
| 已知缺口（仓库自认） | MCP 未实现；live Anthropic API 未验证；进程组 TERM→KILL 未在真实 Linux 验证；interop 尚未连接任何真实后端（Codex/Claude Code/Hermes/Cursor/OpenBot）；durable-run 非生产调度器（各组件 README） |

### 2.2 已有的 DX 资产（容易被低估的部分）

- **零凭据即可完整体验**：`--provider scripted` 离线跑通全流程，含工具调用、权限、压缩、结果码——Claude Code/Codex 都做不到无 key 演示。
- **结构化输出一流**：JSONL 事件流、每 run 恰好一个 `ResultMessage`、语义化退出码（0–5, 64）——headless 集成的天然基础。
- **hooks 词汇与 Claude Code 对齐**：10 个生命周期事件，开发者从 Claude Code 迁移心智成本低。
- **会话可续**：`--session-dir` + `--resume` + 追加式 JSONL + fsync。
- **追踪有 span 树**：`run → turn → generation|tool|subagent` 带成本属性，OTEL 导出点已在。
- **确定性工程文化**：`tests/` 文档测试强制翻译质量；runtime 自带"不变量验证 harness"（`tools/verify_invariants.py`，回退单个 guard 验证测试能抓住它）。

### 2.3 结构性 DX 短板（本地验证过的事实）

1. **`tools.py` 与 `tools/` 目录同名**：`import tools` 解析为模块，`import tools.verify_invariants` 直接报错 `'tools' is not a package`——这是"随时会踩"的导入地雷，也让自动打包（flat-layout auto-discovery）不可行。
2. **每个组件都是"站在自己目录里跑"**：`python3 -m cli run` 要求 cwd 在组件目录；跨组件示例都依赖 PYTHONPATH 手工拼接；没有任何安装产物。
3. **无配置文件、无项目约定文件**：全部策略靠 CLI flags；workspace 里放一个 AGENTS.md 也不会被读——与 2026 年所有头部工具（CLAUDE.md / AGENTS.md / .cursor/rules）相反。
4. **无 `--version`、无 `doctor`、无配置自查命令**；CLI 报错质量好（错误类分级）但缺少"环境体检"。
5. **文档结构 = README 平铺**：没有 API reference 站点、没有 cookbook/examples 目录、组件 README 最短 31 行；翻译 11 种语言是品牌资产，但内容是"范围声明"而非"使用教学"。
6. **无发布版本**：契约组件叫"versioned Run Request"，但仓库没有任何 tag/版本号/发布渠道。
7. **示例只有 README 内嵌代码块**：无 `examples/` 可执行目录；Quick Start 要求用户手写 `/tmp/demo.json`。

---

## 3. 逐维度对标（顶级做法 vs Northstar 现状）

### 总览矩阵（1–5 分，5 最好）

| 维度 | Claude Code / Agent SDK | Codex CLI + Agents SDK | LangGraph | Cursor | Devin / OpenHands | **Northstar（现状）** |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| 安装与上手 | 5 | 5 | 3 | 5 | 3 | **2** |
| CLI / 终端体验 | 5 | 5 | 3 | 4 | 3 | **3** |
| 程序化 API / 包管理 | 5 | 4 | 5 | 3 | 2 | **1** |
| 配置与项目约定 | 5 | 5 | 3 | 5 | 3 | **1** |
| 扩展生态（MCP/Skills/Plugins） | 5 | 5 | 4 | 4 | 3 | **1** |
| 会话 / 调试 / 可观测 | 4 | 4 | 5 | 3 | 3 | **3** |
| 测试与确定性 | 3 | 3 | 4 | 3 | 3 | **5** |
| 文档与教学 | 5 | 5 | 4 | 4 | 3 | **3** |
| 版本化与发布 | 5 | 5 | 5 | 4 | 3 | **2** |
| 团队 / CI / 协作面 | 4 | 5 | 4 | 4 | 4 | **2** |
| **合计（/50）** | **46** | **46** | **40** | **39** | **30** | **23** |

---

### 3.1 安装与 zero-to-first-run —— Northstar 2/5

**顶级做法**：Codex：`npm install -g @openai/codex` → `codex login` → `codex "任务"`，官方口径"零到第一个任务 5 分钟"[4](https://tosea.ai/blog/openai-codex-complete-guide-2026)；安装渠道覆盖 npm/Homebrew/winget，升级 `@latest`[3](https://blakecrosley.com/guides/codex)。Claude Agent SDK：`pip install` 后数行代码起 loop[15](https://letsdatascience.com/blog/claude-agent-sdk-tutorial)。CrewAI 被评"1–2 天到可用原型"、OpenAI SDK"最简单心智模型"[5](https://o-mega.ai/articles/langgraph-vs-crewai-vs-autogen-top-10-agent-frameworks-2026)。

**Northstar 现状**：需要 `git clone` → 装 Python 依赖 → cd 进组件目录 → 手写 demo JSON → `python3 -m cli run`。没有安装产物、没有 `northstar` 命令、没有可运行示例目录。**"无 key 即可玩"是独有优势，但入口藏得太深**——Quick Start 甚至让用户自己造 `/tmp/demo.json`（虽然 README 给了内容）。

**可借鉴**：① 仓库内置 `examples/demo/`（脚本+JSON 现成可跑）；② 一个 `make demo` 或一行 shell 直达演示；③ 首页 Quick Start 重排为"3 步、0 文件手写"。

### 3.2 CLI / 终端体验 —— Northstar 3/5

**顶级做法**：Claude Code/Codex 是交互式 TUI（斜杠命令、diff 预览、权限确认 UI、`/status` 看额度[3](https://blakecrosley.com/guides/codex)），同时提供 headless 模式（`claude -p`、`codex exec`）供脚本/CI 使用，两套体验共享同一会话状态。

**Northstar 现状**：批处理 CLI 的设计其实很干净——子命令分组（provider/limits/policy/execution/output）、完整帮助、**语义化退出码表**、`--json` 全事件流。缺的是：`--version`、环境自查（doctor）、交互确认模式（permission 提示）和"读回"类子命令（看会话、看追踪）。Northstar 不必自研 TUI（它是组件不是终端产品），但 `doctor` + 输出着色/摘要这类低成本项应补。

### 3.3 程序化 API / 包管理 —— Northstar 1/5（最大单项差距）

**顶级做法**：Claude Agent SDK 官方 Python + TypeScript，`query()` / `ClaudeSDKClient` 双形态，pip/npm 发布[4](https://code.claude.com/docs/en/agent-sdk/overview)；LangGraph v1.x 稳定发布、月下载量 3450 万（第三方口径）[5](https://o-mega.ai/articles/langgraph-vs-crewai-vs-autogen-top-10-agent-frameworks-2026)；Pydantic AI 以"类型安全 + FastAPI 手感"著称[5](https://o-mega.ai/articles/langgraph-vs-crewai-vs-autogen-top-10-agent-frameworks-2026)。

**Northstar 现状**：核心类（`AgentRuntime`、`RuntimeConfig`、`run_collect`）是设计良好的程序化 API，**但没有任何人能 `pip install` 到它**。三个具体障碍（本地验证）：
- 0 个打包文件；
- `tools.py` 模块与 `tools/` 包同名 → flat-layout 打包和 `import tools.verify_invariants` 都会踩坑；
- interop/host 依赖 run-contract，靠 `PYTHONPATH` 注入而非依赖声明。

**可借鉴**：这是 P1 的头号任务——每个组件一个 `pyproject.toml`（stdlib-only 的 run-contract 应最先发布），`northstar-agent-runtime` 提供 console script。

### 3.4 配置与项目约定（仓库级上下文）—— Northstar 1/5

**顶级做法**：2025–2026 年行业收敛为"仓库内声明文件"：Claude Code 读 `CLAUDE.md` + `.claude/settings.json` + skills/subagents 目录[4](https://code.claude.com/docs/en/agent-sdk/overview)；Codex 读 `AGENTS.md` + `config.toml`（profiles、限额）[3](https://blakecrosley.com/guides/codex)；Cursor 用 `.cursor/rules/*.mdc`[1](https://www.themodernblog.com/cursor-ai-agent-review-2026/)。AGENTS.md 已成为跨工具事实标准，团队把约定提交进仓库，全员 agent 行为一致。

**Northstar 现状**：所有策略只能走 CLI flags；没有"仓库内约定文件"，模型看不到项目规范，运维看不到策略归档。**这恰好是 Northstar 治理定位的天然主场**——"策略即代码"（permission mode、deny 列表、预算上限写进仓库文件，且只能收紧不能放宽）比任何竞品都更契合，却完全没做。

### 3.5 扩展生态：MCP / Agent Skills / Plugins —— Northstar 1/5

**这是 2026 年 DX 的最大分水岭，也是北星差距最大处。**

- **MCP**：Claude Agent SDK 原生 MCP 客户端 + 进程内 `@tool` 服务器[5](https://letsdatascience.com/blog/claude-agent-sdk-tutorial)；Codex 支持 MCP 并可作为 MCP server 被 Agents SDK 调用[1](https://blakecrosley.com/guides/codex)；LangGraph 全面接入[5](https://o-mega.ai/articles/langgraph-vs-crewai-vs-autogen-top-10-agent-frameworks-2026)。Northstar：**README 自认 "MCP is not implemented"**。
- **Agent Skills（开放标准）**：Anthropic 2025-10 提出、2025-12-18 发布开放标准（agentskills.io），**截至 2026 年中约 40 个平台采纳**：Claude Code、Codex、Gemini CLI、Cursor、Copilot、VS Code、Goose…[11](https://www.paperclipped.de/en/blog/agent-skills-open-standard-interoperability/)[13](https://agentman.ai/blog/agent-skills-ecosystem-report-2026)。SKILL.md（YAML frontmatter + 渐进式披露：先只载入名称/描述，命中后才载全文）已成通用格式[10](https://www.agensi.io/learn/agent-skills-open-standard)[12](https://strapi.io/blog/what-are-agent-skills-and-how-to-use-them)。社区目录 skills.sh 收录技能以十万计（SkillsMP 口径达百万级，第三方）[13](https://agentman.ai/blog/agent-skills-ecosystem-report-2026)。Northstar：完全不支持——意味着**数十万个现成技能与北星无关**。
- **Subagent 文件化**：Claude Code 的 subagents 是 `.claude/agents/*.md` 文本文件[14](https://www.developersdigest.tech/blog/claude-code-agent-teams-subagents-2026)；Northstar 的 subagent 是 Python 注册表（`agents.py`）——能力更强但门槛更高，两者可以兼容并存（markdown 定义 → 编译进 registry）。
- **Plugins**：Agent SDK 支持打包 skills/agents/hooks/MCP 的插件按本地路径加载[4](https://code.claude.com/docs/en/agent-sdk/overview)。

> 安全注记：北星若接入 skills/MCP，必须让其内容与工具仍走既有权限门与 hooks——技能是"文本+可执行引用"，不是权限提升。这也正是北星可宣传的差异点（"消费开放生态，但由治理内核兜底"）。

### 3.6 会话 / 调试 / 可观测 —— Northstar 3/5（底子好、读回差）

**顶级做法**：LangGraph + LangSmith 是行业标杆：checkpoint、任意节点回放、按节点 token 统计[5](https://o-mega.ai/articles/langgraph-vs-crewai-vs-autogen-top-10-agent-frameworks-2026)；Claude Code 会话可 resume/fork，SDK 会话持久化[2](https://www.totalum.app/blog/claude-agent-sdk-totalum-2026)。

**Northstar 历史基线**：写入侧优秀——append-only JSONL（fsync、0600）、span 树、RunReport、`--resume`；读取侧后来已补上 `sessions show/export`。本段保留为早期差距记录；当前 checkpoint/rewind/fork 与 workspace receipt 的事实以 §10.9 为准。

### 3.7 测试与确定性 —— Northstar 5/5（全行业稀缺优势）

**现状与差距**：LangGraph 靠 LangSmith eval 体系、Claude Code/Codex 的确定性测试都不面向"无 key 离线全流程"；Northstar 的 scripted provider + 383 单测 + 不变量 harness（回退 guard 可被抓）+ 100,000 字中文 prompt 集成测试是**机构级测试纪律**。这一维度北星领先且未被营销。建议：
- 把"确定性回放测试"做成对外文档化能力（给集成商：`cli run` 的 scripted 模式 = 免费 mock server）；
- 增加"黄金文件"式快照测试（给定 scripted 对话，断言事件流不变），作为防回归的公开承诺。

### 3.8 文档与教学 —— Northstar 3/5

**顶级做法**：Claude Code docs 站点（code.claude.com/docs，capability 表 + 分主题指南）[4](https://code.claude.com/docs/en/agent-sdk/overview)；Codex 官方开发者文档 + 社区 guide 极多[3](https://blakecrosley.com/guides/codex)；LangGraph 有课程。**模式：快速开始 → 概念 → 指南 → API 参考，四层结构**。

**Northstar 现状**：单 README 平铺 + 11 语言翻译。质量意识强（文档测试强制免责声明与翻译标记），但：无 API reference（docstring 其实很完整，缺生成/托管）；无 cookbook/examples 目录；最短组件 README 仅 31 行；`docs/superpowers/plans/` 是开发过程文档，不面向用户。11 种语言翻译的维护成本高，建议后续新增内容"英文优先 + 自动翻译预览"，避免翻译成为内容更新的刹车。

### 3.9 版本化与发布 —— Northstar 2/5

**顶级做法**：所有头部项目都有版本号、changelog、发布渠道与升级路径（Codex `npm i -g @openai/codex@latest`[3](https://blakecrosley.com/guides/codex)）；契约类组件尤其吃版本纪律。

**Northstar 现状**：根 CHANGELOG.md 存在，但无 `__version__`、无 tag、无发布渠道；"versioned Run Request" 的 schema 版本与软件发布版本脱节。跨组件演进（比如 run-contract v2）将无法表达"sidecar 1.3 要求 run-contract ≥1.2"这类约束。P1 应建立：每组件 `__version__` + git tag + GitHub Release + CI 打包冒烟测试。

### 3.10 团队 / CI / 协作面 —— Northstar 2/5

**顶级做法**：Claude Code headless（`-p`）用于脚本；Codex `codex exec` 直接进 CI，cloud/IDE/CLI 共享状态[4](https://tosea.ai/blog/openai-codex-complete-guide-2026)；Cursor 后台代理 8 路并行 + Bugbot PR 审查[1](https://www.themodernblog.com/cursor-ai-agent-review-2026/)；Devin 面向 Slack/Linear/API 的异步委托[8](https://www.morphllm.com/comparisons/devin-vs-cursor)；OpenHands 主打自托管 + GitHub Action[2](https://techsy.io/en/blog/background-coding-agents-compared)。

**Northstar 现状**：其实已具备 headless 全部要素（非交互、JSONL、退出码、`--read-only`、`--probe-sidecar`），但没有一个文档化的 CI recipe、没有 GitHub Action、没有"只读审查 agent"示例——把现成能力包装成 `northstar-run-contract` CI 用例（例如：PR 上跑 read-only agent 审查 diff，产出结构化报告）是低成本高展示度的 P1 项。

---

## 4. 洞察：Northstar 应该往哪里站

1. **别做"又一个 LangGraph/Claude Code"**：做图编排、做 TUI、做 IDE 都是红海。Northstar 的稀缺定位是 **"受治理执行层"（governed execution layer）**：自带权限、预算、审计、可恢复的 agent 运行时，可嵌入别人的 agent 栈。
2. **DX 叙事要反转**：北星最强的 DX 卖点不是"像 Claude Code 一样顺滑"，而是 **"确定性 + 可审计 + 可离线测试"**——对团队/企业是刚需，对个人开发者是信任基础。2026 年头部产品都在补治理（permission 系统、审计、企业管控[3](https://blakecrosley.com/guides/codex)），北星是"生而治理"。
3. **生态必须接，但接法要体现内核**：MCP/Skills 是 2026 年的"标准键盘布局"，不接等于让开发者重学打字；但接入方式应是"生态内容一律经过北星权限门与 hooks"，并把这个写成卖点。
4. **诚实声明是品牌资产**：仓库对未验证项（live API、进程组清理、生产就绪性）的免责声明在社区是稀缺品质，路线图不应牺牲它。第三方对 2026 agent 市场的评测也反复把"生产可靠性"与"诚实程度"挂钩[5](https://o-mega.ai/articles/langgraph-vs-crewai-vs-autogen-top-10-agent-frameworks-2026)。

---

## 5. 差距总览（一页版）

| # | 差距 | 现状证据 | 对标做法 | 影响 | 阶段 |
|---|---|---|---|---|---|
| G1 | 不可 pip 安装、无入口命令 | 0 打包文件；PYTHONPATH 拼接；`tools.py`/`tools/` 冲突 | Agent SDK/LangGraph 的 pyproject + console script | 集成方第一道门槛 | P1 |
| G2 | 无版本/发布渠道 | 无 `__version__`、无 tag | Codex `@latest` 渠道 | 无法表达契约演进 | P1 |
| G3 | 无配置/约定文件 | 只有 CLI flags | AGENTS.md、config.toml、settings.json | 团队协作与策略归档 | P2 |
| G4 | 无 MCP/Skills/Plugins | README 自认 MCP 未实现；无 SKILL.md 读取 | 40 平台采纳的开放标准 | 数十万现成技能不可用 | P2/P3 |
| G5 | 会话/追踪无读回 | JSONL 只有写入器 | `sessions` 子命令、checkpoint 回放 | 调试与审计体验 | P1/P2 |
| G6 | 上手路径长 | Quick Start 手写 JSON | 内置 examples + `make demo` | 首次体验流失 | P0 |
| G7 | 无环境自查 | 无 `--version`/doctor | `codex doctor` 类 | 排障成本 | P0 |
| G8 | 文档无 API 参考/教程 | README 平铺，最短 31 行 | docs 四层结构 | 学习与集成效率 | P2/P3 |
| G9 | 无 CI/团队 recipe | 能力齐但无示例 | `codex exec` CI 模式 | 团队采用 | P1 |
| G10 | 优势未叙事化 | scripted provider/383 测试存在但低调 | 确定性=卖点 | 获客与信任 | P0（文档） |

---

## 6. 分阶段路线图

> 每条含：做法 → 对齐对象 → 验证方式。工作量按单人估算。红线：**任何生态内容（skills/MCP/配置文件）不得绕过 `permissions` 门、hooks、预算与事件记录。**

### Phase 0 — 快速赢（约 1–2 周，纯增量、零破坏）

| 项 | 做法 | 验证 |
|---|---|---|
| P0-1 一键离线演示 | 新增 `examples/demo/`（含 demo.json + 两个脚本：scripted 离线演示、anthropic 可选在线演示）；新增根 `Makefile`（`make demo` / `make test`）；README Quick Start 改为 3 步、零手写 JSON | `make demo` 退出码 0；新增 CI job 跑它 |
| P0-2 CLI 基础补全 | `cli --version`（版本单一来源，为 P1 铺路）；`cli doctor`：检查 Python 版本、可选依赖（anthropic/OTel）、workspace 可写、session-dir 可建、sidecar socket 可达（复用 `--probe-sidecar` 逻辑）、权限模式合法性，输出 checklist 与修复提示 | 单测覆盖 doctor 各检查分支 |
| P0-3 `--dry-run` | `cli run --dry-run`：打印解析后的配置（工具集、allow/deny、上限、模式、模型定价）与事件流将如何收尾，不发任何请求——对齐 Codex `/plan` 类"先看后跑"体验，强化治理感 | 单测：dry-run 不调用 provider |
| P0-4 确定性叙事文档 | 在 runtime README 增加 "Deterministic by design" 小节：scripted provider = 免费 mock、黄金事件流、如何用退出码做 CI 断言 | 文档结构测试扩 markers |
| P0-5 组件 README 补齐 | sidecar/run-contract README 从 31/33 行补到与内容匹配（机制细节从根 README 引用，避免重复） | 文档测试（长度断言可选） |

### Phase 1 — 打包、版本与 CLI 工程化（约 2–4 周）

| 项 | 做法 | 验证 |
|---|---|---|
| P1-1 run-contract 首发包 | 零依赖 stdlib-only，最易打包：加 `pyproject.toml`（setuptools，模块级 py-modules 或最小包布局）、`__version__` | `pip install .` 后可在任意目录 import；其 22 测试在"安装态"跑绿 |
| P1-2 runtime 打包改造 | **先解决 `tools.py`↔`tools/` 冲突**（方案 A：`tools/verify_invariants.py` 上移为 `verify_invariants.py`，改动小但动文件路径；方案 B：整体迁入 `northstar_runtime/` 包，最干净但 import 面广——需回归全部 383 测试与 README 命令）。之后 pyproject + console script `northstar-agent run\|tools\|agents` | 383 测试在"安装态 + 源码态"双跑绿；README 命令同步更新 |
| P1-3 依赖正式化 | host/interop 在 pyproject 声明 `northstar-run-contract` 依赖；CI 删除所有 `PYTHONPATH=` 前缀 | 三个组件的 CI job 不再出现 PYTHONPATH |
| P1-4 版本与发布 | 每组件 `__version__`；根 CHANGELOG 拆分条目按组件标注；`git tag v0.x.y` + GitHub Release 模板；CI 增加"打包冒烟测试"（pip install 各组件 → import → `--help`） | Release 产物可安装可运行 |
| P1-5 会话读回 | runtime 新增 `cli sessions list/show/export`：把 append-only JSONL 渲染为可读轨迹（事件→结果）、过滤错误 run、导出 CSV/JSON 审计摘要（保留 redact 选项语义） | 单测 + 对既有 fixture 会话文件验证 |
| P1-6 CI/团队 recipe | 新增 `examples/ci-readonly-review/`：GitHub Action 示例——PR 触发 `northstar-agent run --read-only --workspace .`（scripted 或真实 provider）产出结构化审查报告；文档化退出码映射 | 示例在 CI 中实际运行 |

### Phase 2 — 生态对接：约定文件 + Skills + MCP（约 4–8 周）

| 项 | 做法 | 验证 |
|---|---|---|
| P2-1 项目约定文件（AGENTS.md） | runtime 在 workspace 发现并注入 `AGENTS.md`（或 `--context-file` 显式指定）进 system prompt，与 provider 无关；文档化位置优先级 | 单测：注入只发生在允许路径内；不读取 workspace 外文件 |
| P2-2 策略配置文件 | `.northstar/config.toml`：permission-mode、deny/allow、ceilings、hooks 脚本路径、默认 agent；**优先级 CLI flags > 文件 > 内置**；文件只能收紧不能放宽（防止 CI 里被意外放宽） | 单测：合并规则、收紧性、非法值 fail-closed |
| P2-3 Agent Skills 只读消费 | `--skills-dir`（默认 `.northstar/skills`、`.agents/skills`）发现 SKILL.md：启动只注入 name+description（渐进式披露），调用时载全文/引用文件到子上下文；技能内的任何命令/工具请求仍走既有权限门（写不进 workspace 的技能最多是"知识包"） | 单测：发现、披露、命中加载、权限门拦截；用仓库自带 3 份 plans 文档做夹具原型 |
| P2-4 MCP 客户端（最小） | 自 README 已认领的缺口：先做 stdio JSON-RPC 最小客户端（工具命名 `mcp__server__tool`，默认 deny 直到配置 allow），通过统一 permission 门与 hooks；先出契约文档 + RED 测试，客户端实现放在 P2 末/P3 初 | 对本地一个玩具 MCP server 的集成测试全绿 |
| P2-5 Subagent 文件化桥 | 支持 `.northstar/agents/*.md`（Claude Code 风格 frontmatter：name/description/tools/mode）→ 编译为现有 registry 定义；明确映射到 `max_subagent_depth` 等既有护栏 | 单测：非法 frontmatter 拒绝、护栏生效 |
| P2-6 文档四层化起步 | 每组件 README 增加"概念/指南"链接目标；新增 `examples/` 索引页；API 参考首版用 docstring 生成（mkdocs/pydoc 均可，先本地构建进 CI 检查断链） | CI 文档 job 扩为"结构 + 构建 + 链接" |

### Phase 3 — 平台化与运营化（约 2–3 月，探索性质）

| 项 | 做法 |
|---|---|
| P3-1 策略即代码 + 审计导出 | 策略 schema 化（`northstar-policy.toml`）支持版本修订；事件流审计导出（JSON→NDJSON→SIEM）对接 host/durable-run 原型 |
| P3-2 模板与脚手架 | `northstar new <project>`：生成带 config、agents、hooks、CI recipe 的最小工程——把"治理默认值"烙进模板 |
| P3-3 托管/远程执行评估 | 不自建云：评估把现有 sidecar 模型包装为远程 worker 的对接文档与协议（对 OpenBot 生态的 interop 已有铺垫） |
| P3-4 可观测进阶 | OTEL 导出打通 Jaeger/Grafana 的部署文档 + docker-compose；会话指纹/统计面板（纯本地 HTML 渲染 JSONL，无后端） |

---

## 7. 如果只做三件事（给维护者的优先级建议）

1. **P0-1 一键演示 + P0-2 doctor/--version**：一周内把"首次体验"从 15 分钟手工降到 1 分钟一条命令——所有头部工具都赢在这里。
2. **P1-1/P1-2 打包**：没有 `pip install` 就没有集成方；run-contract（stdlib-only）先行，runtime 紧随。这是"对标顶级工具"的第一性差距。
3. **P2-2 策略配置文件 + P2-3 Skills 只读消费**：用最贴合 Northstar 内核的方式（策略进仓库、生态过权限门）接入 2026 年的开放标准——这是从"库"走向"平台"的转折点。

---

## 8. 参考来源

**官方/权威（2025–2026）**
- Claude Agent SDK 能力总览（hooks/subagents/MCP/permissions/sessions/skills/plugins）：https://code.claude.com/docs/en/agent-sdk/overview
- Agent Skills 开放标准（agentskills.io，2025-12-18 发布，40 平台采纳）：https://strapi.io/blog/what-are-agent-skills-and-how-to-use-them ；采纳全景：https://www.paperclipped.de/en/blog/agent-skills-open-standard-interoperability/ ；生态报告：https://agentman.ai/blog/agent-skills-ecosystem-report-2026
- SKILL.md 格式规范（frontmatter / 渐进式披露 / allowed-tools）：https://www.agensi.io/learn/agent-skills-open-standard

**第三方评测与指南（2026，口径以原文为准）**
- Claude Agent SDK 2026 指南：https://www.totalum.app/blog/claude-agent-sdk-totalum-2026 ；hooks/subagents/MCP 实战：https://www.developersdigest.tech/blog/claude-code-agent-teams-subagents-2026 ；SDK 教程（含事件表）：https://letsdatascience.com/blog/claude-agent-sdk-tutorial
- Codex CLI 2026 指南（安装/AGENTS.md/MCP/成本）：https://blakecrosley.com/guides/codex ；Codex 全景：https://tosea.ai/blog/openai-codex-complete-guide-2026
- 框架横评（LangGraph/CrewAI/OpenAI Agents SDK/ADK/Pydantic AI 等）：https://o-mega.ai/articles/langgraph-vs-crewai-vs-autogen-top-10-agent-frameworks-2026 ；https://www.ayautomate.com/blog/best-multi-agent-frameworks
- Cursor 2026 评测：https://www.themodernblog.com/cursor-ai-agent-review-2026/ ；Cursor vs Devin：https://www.morphllm.com/comparisons/devin-vs-cursor ；后台 agent 横评（含 OpenHands）：https://techsy.io/en/blog/background-coding-agents-compared

---

## 9. 实施进度（changelog of this roadmap）

> 每完成一批实施，在此追加一行，保持路线图与实际仓库同步。早期条目保留其
> 历史分支/提交口径；当前增量在固定的 `arena/01a07be4-northstar-agent-os`
> 分支上推进，分支提交不等同于正式发布。

### 2026-09-07 — Phase 0 完成 + Phase 1 核心完成（未提交）

- **P0-1** 一键离线演示：`examples/demo/` + 根 `Makefile`（`make demo` / `make test`）。
- **P0-2** `cli --version`（版本单一来源 `_version.py`）+ `cli doctor`（环境自检，零副作用，失败退出 1）。
- **P0-3** `cli run --dry-run`：打印解析配置与定价，不构造 provider、不发请求。
- **P1-1/P1-2** `northstar-run-contract` 与 `northstar-agent-runtime` 打包：
  - 消除 `tools.py`↔`tools/` 同名冲突（并入 `tools/__init__.py`，`tools.verify_invariants` 可导入）；
  - 两个 `pyproject.toml`（`0.1.0.dev0`；runtime 无硬依赖，SDK 为 extras：`[anthropic]`/`[tracing]`/`[full]`）；
  - runtime console script `northstar-agent-runtime`；新增 `test_module_layout.py` 锁定布局与版本一致。
- **P1-3** 其余组件打包 + 依赖正式化：
  - `northstar-host`（依赖 run-contract）、`northstar-durable-run` 与 `northstar-agent-interop`（依赖 run-contract + host）各有 `pyproject.toml`；
  - 测试文件自带 sibling-path 引导，全仓 CI 与 Makefile 已删除所有 `PYTHONPATH=` 前缀；
  - CI 按依赖链 pip 安装 + 每组件 packaging smoke；全新 venv 链式安装 5 个包验证通过。
- **P1-4（部分）** CONTRIBUTING 增加发布流程（依赖图顺序、tag、不可变 Release）。
- **P1-5** `cli sessions list/show [--json]`：会话读回（只读、损坏即报错）。
- **P1-6** `examples/ci-readonly-review/`：只读治理审查的 CI recipe（脚本 + GitHub Actions 模板 + 退出码契约）。

### 2026-09-07（同批追加）— P2-1 + P2-2 完成（CLI 范围，未提交→随批提交）

- **P2-1** 项目约定注入：`AGENTS.md`（或策略文件 `project_context`、或 `--context-file`）自动注入 system prompt（清晰分隔、64K 截断标记）；发现严格限制在 workspace 根内——指向外部的符号链接拒绝而非跟随；`--no-project-context` 关闭。
- **P2-2** `.northstar/config.toml` 策略文件：模式仅 `default`/`plan`（acceptEdits/bypassPermissions 只能是 CLI 逐次决定）、`allow_tools` 拒绝、上限只能下调（取 CLI/文件较低者）、deny/read_only 为不可被 `--allow-tool` 复活的硬地板、未知键/未知工具/未知 agent/损坏 TOML/放宽值 = 配置错误退出 64（永不静默忽略）；`--no-policy-file` 一次性跳过。CLI 显式非默认模式 > 文件 > 内置。
- 可见性：`doctor` 与 `--dry-run` 输出 `policy_file=` / `project_context=` 生效行；demo workspace 附带 `AGENTS.md` 示例。

测试规模：本地 runtime **446 项全绿**（+33 策略/上下文测试，含 4 项 SDK 跳过）；guard harness 5 RED 基线绿；全仓 `make test` 654 项。

### 2026-09-07（同批追加）— P2-3 + P2-5 完成

- **P2-3 Agent Skills 只读消费**（`.northstar/skills/*/SKILL.md`）：渐进式披露——启动仅注入 name+description 列表，全文由模型经既有沙箱 `Read` 工具按需读取；技能=知识包（非执行/权限通道）；严格限定 workspace 内解析（含文件级符号链接拒绝）；`--no-skills` 关闭。
- **P2-5 subagent 文件化桥**（`.northstar/agents/*.md`）：frontmatter（name/description/tools/read_only/permission_mode 仅 default|plan/上限不高于内置/model/allow_delegation/require_verdict）+ markdown 正文 → 编译为 `AgentDefinition` 进注册表：`--agent` 可用、可经 `Task` 委托、`cli agents --workspace` 列出；不得遮蔽内置 agent；未知键/未知工具/放宽值/解析失败/符号链接逃逸 = 配置错误 64；`--no-workspace-agents` 关闭。
- 新增共享严格 frontmatter 解析器（`frontmatter.py`，零依赖，重复/畸形/未知内容 fail-closed）。
- 可见性：`doctor` 与 `--dry-run` 增加 `workspace_agents=` / `skills=` 行；demo workspace 附带 1 个 repository agent + 1 个 skill。

测试规模：runtime **470 项全绿**（+24，frontmatter/skills/agent_files/CLI 集成，含 4 项 SDK 跳过）。

### 2026-09-07（同批追加）— P2-4 完成（最小 MCP stdio 客户端）

- `--mcp-server NAME=COMMAND...`（可重复）连接 MCP stdio 服务器：子进程 JSON-RPC 2.0；握手（initialize → initialized → tools/list）带每请求截止（`--mcp-timeout-ms` 默认 15s）；超时/停止应答 → 进程组 TERM→KILL；客户端行/调用字节上限兜底。
- 治理：远端工具注册为 `mcp__<server>__<tool>`、`kind="other"` 默认可变更 → `default` 权限模式下未 `--allow-tool` 即拒绝；策略文件可前瞻 deny `mcp__*` 名（同 CodexReadOnly）；全部调用仍过权限门与 hooks——MCP 只是工具传输，不是策略后门。
- Fail-closed：不可达服务器/坏 NAME=/超量工具或 schema/与 `--agent` 组合（agent 运行工具子集固定）= 配置错误 64；`--dry-run` 与 `doctor` 只列出服务器不拉起进程。
- 离线验证：`tests/fixtures/mcp_echo_server.py`（纯 stdlib fixture：echo/fail/silent/slow 模式）覆盖握手、调用、超时、错误结果、进程组清理。
- 局限（README 同步改写原"MCP 未实现"声明）：仅工具发现与调用、协议 2024-11-05、无 sampling/roots/reconnect、未接真实厂商服务器。

测试规模：runtime **488 项全绿**（+18，含 4 项 SDK 跳过）。

### 2026-09-07（同批追加）— P2-6 完成（文档四层化起步）

- **每组件 README 链接目标**：六个组件 README 开头统一新增 `## Concepts, guides and API reference` 小节，指向概念页、指南页与各自的 API 页——快速开始（README）→ 概念 → 指南 → API 参考，不再平铺单文件。
- **概念页**（`docs/concepts/`）：`governance.md`（权限门是护城河：四层不变式 + MCP 等传输一律穿门）、`audit-trail.md`（会话 JSONL/事件存储与校验/契约收据三面审计）、`handoff-and-contracts.md`（run contract、host 握手、sidecar 委派、interop 边界四处信任跨越）。
- **指南页**（`docs/guides/`）：`governed-run-cookbook.md`（dry-run → 收紧 → skills/agents/MCP/审计的端到端 CLI 食谱）、`packaging-and-ci.md`（make test/guard/CI 三 job/doc 工具链与消费者要点）。
- **API 参考首版 docstring 生成**：`tests/docbuild.py`（纯 stdlib `ast`，不 import 被文档化模块、离线可构建）生成并入库 `docs/api/<component>.md` 六页共 43 模块；`build` 重生成、`verify` 字节级新鲜度 + 全仓 markdown 内链断链检查（零豁免）。
- **`examples/README.md` 索引页**：覆盖全部示例（demo/ci-readonly-review）并给"从哪开始"决策点；结构测试要求每个含 README 的示例目录都必须出现在索引里。
- **CI 文档 job = 结构 + 构建 + 链接**（`test.yml`）：结构单测 + 专属 `python3 tests/docbuild.py verify` 步骤，全程零第三方依赖。
- 生成/校验闭环：README 或 docstring 变更导致 API 页过期 = CI 失败，须 `docbuild.py build` 后提交。

测试规模：全仓 **701 项全绿**（repository documentation 3→8，runtime 488 及其余组件不变）。

### 2026-09-07（同批追加）— P3-1a 完成（事件流审计导出 JSON→NDJSON→SIEM）

- **规范单一来源**：`northstar-run-contract/audit.py` 定义审计 feed 信封 `audit.ndjson/1`（`schema_version/component/event/ts/level/payload` 必填 + `seq/session_id/run_id/actor_id` 可选），严格校验、未知信封字段一律拒绝——扩展信封 = schema 修订，不允许静默漂移；带 `now_rfc3339`/epoch 转换与 `iter_ndjson`（坏行点名报错，绝不静默丢记录）。
- **Runtime 桥**（`audit_export.py` + `cli sessions export <id> --session-dir DIR`）：JSONL 转录回放为 NDJSON 输出到 stdout；denial、失败 tool_result（content 块 `is_error`）、`error_*` result → `"level":"error"`；`ts` 沿用原记录时间戳从不重打。runtime 保持零依赖设计，信封在本地镜像（规范表在概念页，测试双方钉同一版本串）。
- **Durable-run 桥**（`durable_audit.py`）：EventStore 事件映射进 feed，事件身份（event_id/task_id/run_id/step_id/trace_id/payload_digest）保留在 payload；failed/denied/error 状态升为 error 级；支持 ms 级 occurred_at。
- **Host 桥**（`durable_audit.py`）：仅导出**已验证**的授权 grant 为 `authorization_grant` 记录（actor/run/workspace/capabilities/policy_revision/expires_at）；被篡改 token 停留在校验错误，永远不会变成审计记录。
- **SIEM 对接文档**：`docs/concepts/audit-trail.md` 新增"规范信封表 + 三端接入点 + fluent-bit/rsyslog 转发要点（按 component 打标、ts 索引、schema_version 作演进路由键）"；P3-1 拆两批：本批审计导出，P3-1b 策略 schema 化（`northstar-policy.toml` 版本修订）待续。
- 文档接线：py-modules/CI compile 行补 4 个新模块、docbuild MANIFEST +4 → API 页 43→47 模块、README（runtime sessions 段/durable/host/run-contract）与新模块行。

测试规模：全仓 **736 项全绿**（run-contract 34、host 28、durable 65、runtime 501、root docs 8，sidecar/interop 不变）。

---

## 10. 复评：对标全球顶级 agent 工具还剩多远（2026-09-07，追加于 P3-1a 之后）

> 本节是 §0–§8 正文的**增量复评**：外部口径补到 2026 年 9 月初，Northstar 一侧以仓库实测为准（全仓 736 项测试全绿、guard harness 5/5、demo→`sessions export` 真实链路冒烟、docs 47 模块 API 页 0 断链、五组件同 venv 安装导入通过）。头部各列沿用 §3 口径并注明持续进化，本轮只重评 Northstar 列。

### 10.1 外部格局速览：2026 下半年头部工具在卷什么

**Claude Code（2.1.x，2026-09 初）**：插件体系成型（bundled plugins 14 个：code-review/security-guidance/feature-dev…，含 marketplace 与 `source: 'settings'` 内联声明）；`/skills` 热重载 + skill frontmatter 支持 `agent`/`context: fork`/effort 覆盖；任务管理（2.1.16）、后台 agents（2.0.60）、Agent Teams 多代理协作（实验）、Desktop 应用与 remote sessions；`--permission-prompts none`（无头自动拒绝）、managedMcpServers/managed settings（企业下发）、MCP `login/logout` 与 alwaysLoad、stream-json 嵌套 subagent 转发。**一句话：交互面 + 生态市场 + 企业治理三线并进。**

**OpenAI Codex（2026-08-19 "Codex as a platform"）**：明确 app/CLI/IDE 只是同一开源 harness 的三个 surface，把**可嵌入层**开放为 `codex exec`（一次性、结构化输出、无会话）、Codex SDK（start/resume/stream）与 app-server（threads/turns/approval 全协议）；另有 Automations 定时后台任务、cloud sandbox（网络隔离微VM、PR 直出）、approval 三级（Suggest/Auto Edit/Full Auto）。**一句话：竞争焦点从"终端工具"移到"可嵌入 harness + 后台任务平台"。**

**生态与其余**：Gemini CLI 并入 Antigravity 路线（Skills/Hooks/Subagents/Extensions 以插件形式迁移），其功能面（checkpointing、rewind、remote subagents、gVisor sandbox、plan mode、model routing）成为横评参照；Meta Muse Code 入局（默认 seatbelt/bubblewrap 沙箱）；Agent Skills 开放标准扩到 40+ 平台（VS Code/Copilot/Snowflake…），社区 skills 71,000+，触达 5,000 万开发者——同时第三方审计称 **99% 社区 SKILL.md 带"技能坏味道"、36% 带安全缺陷** → "技能供应链校验"是新空白。MCP 深化到服务器登录/托管/市场层面。

### 10.2 上一轮差距清单（G1–G10）落地状态

| # | 差距 | 状态（2026-09-07） |
|---|---|---|
| G1 | 不可安装、无入口 | ✅ 六组件 pyproject + console script；`make install` 五组件同 venv 验证 |
| G2 | 无版本/发布渠道 | 🟡 版本对齐测试 + Release CI 管道就绪；**未发布**（0.1.0.dev0，发布须过就绪门）；未上 pip index |
| G3 | 无配置/约定文件 | ✅ AGENTS.md、`.northstar/config.toml`、agents/skills 文件、context-file；🟡 策略 schema 版本化（P3-1b）未做 |
| G4 | 无 MCP/Skills/Plugins | 🟡 MCP stdio 最小客户端（默认 deny、穿权限门）；SKILL.md 只读渐进披露；**无 plugins/市场、无 HTTP/SSE+auth** |
| G5 | 会话/追踪无读回 | ✅ `sessions list/show/export`（export 即 audit.ndjson/1）+ OTEL + resume；🟡 无 rewind/checkpoint 可视化 |
| G6 | 上手路径长 | ✅ `make demo` 一条命令 + examples 索引 |
| G7 | 无环境自查 | ✅ `--version`、`doctor`、`--dry-run` 全配置预览 |
| G8 | 文档无 API 参考 | ✅ 四层文档 + docstring API 页 47 模块 + CI 结构/构建/链接 |
| G9 | 无 CI/团队 recipe | 🟡 demo + ci-readonly-review 模板 + headless `--json` + 语义退出码；**无官方 GitHub Action/后台任务** |
| G10 | 优势未叙事化 | ✅ 文档强调确定性内核；🟡 对外叙事仍缺"治理即卖点"的独立页 |

### 10.3 十维复评：Northstar 23 → 36（/50）

| 维度 | Northstar（原） | Northstar（复评） | 一句依据 |
|---|:-:|:-:|---|
| 安装与上手 | 2 | **3** | 可 pip 安装 + demo/doctor 一条命令；差官方 index 发布与"账号即用" |
| CLI / 终端体验 | 3 | **4** | headless、dry-run、语义退出码 0–5/64、json 事件流一流；无交互 TUI/rewind/tasks |
| 程序化 API / 包管理 | 1 | **3** | `sdk.run()/stream_run()` + 事件 dict 词表 + resume + 示例；无 TS 面、无 exec/app-server 协议 |
| 配置与项目约定 | 1 | **4** | AGENTS.md/config/agents/skills/context-file 齐全；差策略 schema 版本化与托管下发 |
| 扩展生态（MCP/Skills/Plugins） | 1 | **3** | 三类都占位且默认 deny/只读（安全侧反而领先）；差 plugins/市场、MCP HTTP+auth、技能脚本执行 |
| 会话 / 调试 / 可观测 | 3 | **4** | 读回 + 审计导出 + resume 齐全；差 rewind/checkpoint 与交互式回放 |
| 测试与确定性 | 5 | **5** | 736 项、guard 红绿 harness、离线 scripted provider——头部普遍 3 分档，仍是最稀缺资产 |
| 文档与教学 | 3 | **4** | 四层 + 生成 API + examples 索引 + 11 语言；差课程/playground 型教学 |
| 版本化与发布 | 2 | **3** | 版本单一源 + 对齐测试 + 就绪门 Release CI；未发出版本（按纪律等"最完美"） |
| 团队 / CI / 协作面 | 2 | **3** | CI 模板 + headless + 审计 feed 天然 CI 友好；差官方 Action/review 后台 |
| **合计（/50）** | **23** | **36** | 头部（Claude Code/Codex）2026-09 口径仍 ≥46 且持续外扩 |

### 10.4 新增横向战场六维（2026 年新出现的竞争面，1–5）

| 维度 | 头部代表 | Northstar | 说明 |
|---|:---:|:---:|---|
| N1 可嵌入 harness（SDK/exec/app-server） | Codex platform、Claude Agent SDK（py/ts） | **2** | 内核（AgentRuntime/events/resume/hooks）在，未产品化为 SDK 面 |
| N2 后台/并行/任务化 | Codex Automations、CC background agents/task mgmt | **2** | durable-run 内核（event_store/action_gateway/verifier）超前，无 CLI/调度/云端面 |
| N3 远程/多端 | CC remote sessions/Desktop、Codex cloud、Gemini remote subagents | **1** | 目前只有 sidecar 单向委派 |
| N4 生态市场接入 | CC plugin marketplace、skills 71k+、.mcp.json | **2** | 格式兼容可读；无市场/安装器/索引 |
| N5 安全治理纵深 | CC managed settings/enterprise、Codex sandbox 网络隔离、Muse 默认沙箱 | **3** | 权限门/hooks/只读/审计 feed 治理叙事强；无 OS 级沙箱与技能供应链校验（36% 缺陷率=空白机会） |
| N6 模型层能力 | model routing/steering、多模型 fallback | **3** | providers 抽象 + 记账 + 确定性 scripted；仅两个后端 |
| **合计（/30）** | ≈24 | **13** | 新战场是当前差距的主要来源 |

### 10.5 还差多远：排序与最短路径（批次粒度估算，主观）

| # | 差距 | 对齐谁 | 内容 | 批次 |
|---|---|---|---|---|
| T1 | SDK/可嵌入面 | Codex exec/SDK、Claude Agent SDK | ✅ 已完成（2026-09-07）：`sdk.py`（RunOptions/run/stream_run/RunReport）+ `events.py` 公共事件词表 + examples/sdk 示例；TS 面与稳定 API 承诺待续 | — |
| T2 | 发布工程 | `@latest`/Release 渠道 | 🟡 管道已完成并留作待命；**按发布纪律撤回 v0.1.0**（未发布、dev0、须过就绪门）；余：pip index 上架 | — |
| T3 | 交互最小集 | CC `/rewind`+tasks、Gemini checkpointing | checkpoint/restore 子命令 + `sessions` 可视化回放 | 1–2 |
| T4 | 生态纵深 | CC plugins/marketplace、MCP login | `.mcp.json`/HTTP+auth、skills `check`（供应链校验器，直接回应 99%/36% 审计）、技能脚本沙箱或写明取舍 | 1–2 |
| T5 | 后台/远程化 | Codex Automations、CC remote | durable-run 之上做任务调度 CLI 面 + P3-3 远程 worker 协议评估 | 2–3 |
| T6 | 治理叙事页 | — | "确定性 + 治理默认值"独立页/演示（评审/CI 场景） | 0.5 |

其中 **T2+T1 是把 34 → ~40 的最短路径**（与 §7"只做三件事"呼应：打包已完成，接下来是"包得住 → 嵌得进 → 发得出去"）；T3 增黏性，T4 是差异化杠杆（别的工具都缺的技能安全校验），T5 承接 P3-2/3/4 地图。

### 10.6 结论

- **内核侧差距已经基本收平甚至反超**（测试与确定性 5/5、治理不绕行的架构、审计导出）——这部分不再是对标短板。
- **外围产品化差距仍然显著**：十维口径 23→34（头部 46 并继续外扩）；把 2026 新战场六维算进来，缺口主要落在"可嵌入 SDK 面、发布工程、交互面、后台/远程、市场接入"——全部在 P3 剩余批次 + 上述 T 清单的可执行范围内，按既有批次节奏约 8–11 个小批可把十维推到 40+ 并在新战场完成占位。
- **一句话**：已经从"差一个时代"（库 + 手工拼装）追到"差外围成型"（内核领先、外壳未打磨）；下一个里程碑不是再补内核，而是**把治理内核包装成别人能 embed、能发布、能在 CI 里直接用的产品面**。

### 10.7 本节增补参考来源（2026-06 ~ 2026-09）

- Claude Code changelog（2026-04~09，mcp login/alwaysLoad/effort frontmatter/热重载）：https://code.claude.com/docs/en/changelog
- Claude Code release notes 2.1.219–2.1.260（managed settings/permission-prompts none/嵌套 subagent 转发）：https://updatify.io/releases/claude-code
- Claude Code 能力时间线与插件清单/沙箱边界（第三方调查）：https://agent-safehouse.dev/docs/agent-investigations/claude-code
- Codex as a Platform — Open Agent Harness（2026-08-19：exec/SDK/app-server）：https://explainx.ai/blog/codex-as-a-platform-open-agent-harness-august-2026
- Codex 2026 功能面（cloud sandbox/automations/approval 三级/AGENTS.md）：https://deepstation.ai/blog/what-is-openai-codex-the-guide-to-ai-powered-coding-2026 、https://digitalstrategy-ai.com/2026/04/14/exploring-openai-codex-features/
- Gemini CLI 官方功能表（checkpointing/rewind/remote subagents/sandboxing/plan mode）：https://geminicli.com/docs/ ；Gemini CLI → Antigravity 迁移：https://codeant.ai/blogs/claude-code-cli-vs-codex-cli-vs-gemini-cli-best-ai-cli-tool-for-developers-in-2026
- 2026-08 横评（Claude Code vs Codex vs Gemini CLI，Muse Code 入局、SWE-bench 口径）：https://codersera.com/blog/gemini-cli-vs-claude-code-2026/
- Agent Skills 生态：40+ 平台/71,000+ skills/5,000 万开发者：https://atlan.com/know/ai-agent/ai-agent-skills/what-are-agent-skills/ 、https://enkrateialucca.github.io/lucas-landing-page/blog/2026/01/30/why-agent-skills-are-the-future-of-agents/ ；技能仓库横评（99% smell、36% 安全缺陷为第三方审计口径）：https://rywalker.com/research/agentic-skills-frameworks

### 2026-09-07（同批追加）— T2 完成（发布工程：v0.1.0 发布渠道打通）

- 五组件版本统一 **0.1.0**（此前均为 0.1.0.dev0）：pyproject + runtime `_version.py` 同步；`test_cli` 硬编码断言更新；MCP 握手 `clientInfo.version` 改引 `_version.__version__`（消灭第三处字符串）；组件 README/pyproject 的 "unreleased/next tagged release" 注释改写为发布口径。
- 新增 repo 级测试 `tests/test_release.py`（3 项）：每个组件版本须为纯 `major.minor.patch`、五组件同版、runtime `_version.py` == pyproject——未来升版漂移会红。
- 新增 `.github/workflows/release.yml`：推 `v*` tag 触发，五组件 `pip wheel` 出 wheel 并 `gh release create` 挂附件；幂等（已存在则只校验不动）。
- 新增 `docs/guides/releasing-and-versioning.md`（版本规则/切版步骤/手动兜底/安装/版本策略），packaging-and-ci 指南交叉引用；CHANGELOG 顶部加 0.1.0 发布段。
- 发布物：tag `v0.1.0` + GitHub Release（含五组件 wheel 资产）。

测试规模：全仓 **739 项全绿**（736 + test_release 3）。

### 2026-09-07（同批追加）— T1 完成（SDK/可嵌入面：sdk.py + events.py + examples/sdk）

- **`events.py` 公共事件词表**：`event_to_dict`（`--json` 同构的事件 dict 形状）+ 结果 `EXIT_CODES` 从 `cli.py` 提升为单源模块，CLI 与 SDK 共用（cli 改为 import，输出不变）。
- **`sdk.py` Python API**：`RunOptions`（权限模式/allow-deny/read_only/上限/halt_on_denial/session_dir/subagent/自定义 provider）+ `run(options)->RunReport`（subtype、exit_code、session_id、turns、cost、denials、完整事件表）+ `stream_run`（逐事件 dict，尾部 result）+ `resume`（同 CLI 的续写同一 session 语义）；workspace agents 文件注册与 CLI 对齐；`read_only` 按工具 kind 推导；scripted 默认 → 完全离线确定性。
- **示例** `examples/sdk/`：一次运行展示 Read 放行 + 未授权 Write 在权限门被拒（`python3 examples/sdk/run_sdk_demo.py`），examples 索引与"从哪开始"更新。
- 深配置（policy 文件/AGENTS.md/skills/MCP）刻意留在 CLI——SDK 是稳定嵌入契约（README 新增 "Embedding in Python (sdk)" 小节说明边界）。
- 接线：py-modules + events/sdk、CI compile 行、docbuild MANIFEST +2 → API 页 49 模块、runtime README 布局表。

测试规模：runtime **515 项全绿**（+14：sdk 14 项），全仓 739 → 753。

### 2026-09-07（同批修正）— 发布纪律：撤回过早的 v0.1.0，改为"最完美才发"就绪门

- **撤销发布**：删除 GitHub Release v0.1.0 与远端/本地 tag v0.1.0（此前为演示 Release CI 而打）；五组件版本与 `_version.py` 全部回到对齐的 **0.1.0.dev0**（未发布态），README 版本注记同步回 unreleased。
- **就绪门固化**（防止再犯"发太快"）：
  - `tests/test_release.py`：版本须为 `major.minor.patch[.devN]`、五组件同版、`_version.py` 对齐，且**未发布态必须带 .dev 后缀**（工作树不得伪装成已发布）；
  - `.github/workflows/release.yml` 新增 **Readiness gate 步骤**：dev 后缀版本直接拒发、tag 必须等于对齐版本（`v<version>`）、文档构建须新鲜——三条任一不满足即 fail，不建 Release；
  - `docs/guides/releasing-and-versioning.md` 重写：发布就绪清单（全量测试/guard/示例/wheel 冒烟/版本对齐/CHANGELOG/API 面审查/发布说明），全部绿才允许去掉 .dev 打 tag；发布后回到下一 dev 版本。
- 版本化/发布维度分回调至 3（管道就绪但无发布），合计 36/50；CHANGELOG 0.1.0 段改标 "candidate, NOT yet released"。

> 教训记录：管道本身要提前就位，但**打 tag 发布是产品决定，不是演示 CI 的手段**；此后只由就绪门放行。

### 2026-09-07（同批追加）— P3-1b 完成（策略即代码：schema 版本化 + 修订号）

- **规范身份**（run-contract `policy.py`）：`northstar.policy.v1` + revision 规则（非空、≤128、无空白与斜杠——审计关联键）；runtime 本地镜像常量（零依赖），两侧测试钉同一串（沿用 audit 模式）。
- **runtime `.northstar/config.toml`**：可选 `schema_version`（缺省 v1）+ 可选 `revision`；不支持的未来 schema 直接 fail-closed（报支持列表）——v2 文件永远不会被按 v1 语义读；`PolicyFile` 携带二者并进 `as_dict`；`--dry-run` 输出 `schema=… revision=…`。
- **host 策略即代码**：`host_policy.load_host_policy` 读 `northstar-policy.toml`（`schema_version` 可选缺省 v1、`revision` 必填、`[actors]` 表）→ `HostPolicy`；未知键/未来 schema/坏 revision/不可解析 actor 均在装载期拒绝（fail-closed）。文件 `revision` 即 `authorize_run()` 嵌入 grant、审计 feed 导出为 `policy_revision` 的那个值——"决策 → 策略修订"端到端可溯。
- 文档：runtime README config 示例加两键、host README 新增 "Policy as code" 小节、governance 概念页记录版本化策略面；API 页 49→51 模块（policy、host_policy）。
- 版本仍为对齐 `0.1.0.dev0` **未发布**（守就绪门）。

测试规模：全仓 **777 项全绿**（run-contract 41、host 37、runtime 522、durable 65、interop 49、sidecar 51、repo docs 12）。

### 2026-09-07（同批追加）— P3-2 完成（模板与脚手架：`northstar new`）

- **`northstar-agent-runtime new <dir>`**（`scaffold.py`）生成最小治理工程，"治理默认值"直接烙进模板：
  - `.northstar/config.toml`：`northstar.policy.v1` + 日期 revision，**`agent = "reviewer"` 为默认**——新工程默认每次运行都是只读 reviewer，要放开须显式选择；
  - `.northstar/agents/reviewer.md`：只读 plan-mode reviewer（tools 均为只读集，经 agent_files 校验）；
  - `AGENTS.md`：项目指令模板（自动注入）；
  - `.northstar/hooks/README.md`：hooks 以代码注册（`AgentRuntime(hooks=…)`）、工作区文件永不静默获得代码执行——示例按 hooks.py 真实 API（HookInput.tool_name/tool_input、HookResult.deny）核对过；
  - `.github/workflows/northstar-review.yml`：受治理的 CI review recipe 模板（安装源与 API key 留 TODO）；
  - `README.md`：文件表 + 三条上手命令。
- **自洽性由 runtime 自身校验背书**：模板 config 能过 `load_policy_file`（schema v1/revision/reviewer 已知）、reviewer agent 能注册且只读、`doctor` 绿、`--dry-run` 报策略身份、scripted run 以 reviewer 身份跑通；非空目录拒绝、`--force` 只覆写模板不删文件。
- 接线：runtime README "Creating a governed project" 小节 + 布局行、py-modules/CI compile/docbuild MANIFEST（51→52 模块）、CHANGELOG ninth batch。
- 版本仍为对齐 `0.1.0.dev0` **未发布**（守就绪门）。

测试规模：runtime **536 项全绿**（+14：test_scaffold），全仓 777 → 791。

### 2026-09-07（同批追加）— P3-3 完成（托管/远程执行评估）

- **协议图 + 决策记录**（`docs/concepts/northstar-remote-worker.md`）：远程 worker = sidecar 的**传输变体**而非新治理面——同一 run contract、host 签名短期 grant、opaque workspace、有界且版本钉死的进程、事件/审计、可验证结构化收据；六条传输属性从本地路径继承。传输选型：sidecar-socket-over-SSH（单私有 worker 最低成本）/ durable-run runner+容器（托管 fleets）/ interop-OpenBot（战略）/ 自建 HTTP 服务（否）。**零构建零部署**。
- **可复现评估器**（interop `remote_worker.py`）：36 条静态判据覆盖 6 域，每条对准仓库内真实符号；4 条 ops 缺口为明示 `MISSING` 探针（= T5 工作项：网络传输、身份签发与密钥轮换、真实端到端 canary、部署/监控指南）。**当前 89/100**：contracts/host/durable-run/interop/audit 五域 100%、ops 33%。`python3 -m remote_worker --score` 可进 CI，判据即代码不会漂移；评估器质量本身有测试（内核判据保持绿、MISSING 探针保持红直至刻意移出）。
- **中文评估**（`docs/dx-remote-worker-assessment.zh-CN.md`）：TL;DR/资产清单/协议映射/选型/分数与证据/下一步（T5）。
- 编写中抓到的坑：判据初稿 5 处对准了不存在的符号（validate_run_receipt/Verifier/顶层 acquire/audit 版本串正则/超时参数名）→ 逐一核真实符号修正，**数字由代码说了算，文档跟随实算**（初稿写 ~69，实测 89）。
- 接线：interop README 新增 P3-3 小节、CI compile 行、docbuild MANIFEST（52→53 模块）、CHANGELOG tenth batch。
- 版本仍为对齐 `0.1.0.dev0` **未发布**（守就绪门）。

测试规模：interop **54 项全绿**（+5：test_remote_worker），全仓 791 → 796。

### 2026-09-07（同批追加）— P3-4 完成（可观测进阶）

- **概念页**（`docs/concepts/observability.md`）：双平面读回——实时 OTEL span vs 离线 transcript/audit；span 词汇表逐条对照 `loop.py` 真实属性（`session.id`、`usage.*`、`cost.usd`、`tool.denied` 等）；**ambient seam 明说**（runtime 从不配置 exporter，裸跑不导出，`--trace` 只打印树）；"何时用哪一面"表。
- **本地追踪栈示例**（`examples/observability/`）：compose 双服务（Jaeger all-in-one 收 OTLP/HTTP `:4318` + Grafana 预置 core Jaeger 数据源；不插 collector——部署是 T5 缺口）+ `otel_bootstrap.py`（CLI 的 provider 接线样板：`OTLPSpanExporter`+`BatchSpanProcessor`，端点可环境变量覆盖，缺依赖给指引码 3）。
- **离线会话面板**（`examples/session-panel/`）：单文件零外联 HTML（无任何网络引用），拖放渲染 session transcript 或 `audit.ndjson/1` 导出——类型计数/会话/成本/拒绝统计、errors-only 过滤、时间线逐条展开原始 JSON、FNV-1a64 本地指纹（诚实标注非密码学）。`sample-session.jsonl` 为真实 transcript（含 Write 被拒路径），仅掩蔽绝对 workspace 路径且 README 注明。
- **中文评估**（`docs/dx-observability.zh-CN.md`）；示例索引两行；CHANGELOG eleventh batch。
- 诚实边界（写进文档与测试）：CI/沙箱无 Docker，compose 仅静态校验、tag 落笔时钉；无 otel 依赖故 bootstrap 仅语法级验证；面板 JS 有 node 则 `--check`、无则跳过。**组件行为零改动**。
- 路线图 P3-4 行 ✅；版本仍对齐 `0.1.0.dev0` 未发布。

测试规模：仓库文档 12 → **28**（+16：observability 示例 + 面板套件）；全仓 796 → **812 全绿**（runtime 536 含 skip 4 不变）。

### 2026-09-07（同批追加）— T5 完成（remote-worker ops 实质化，docs phase）

- **supersede 说明**：P3-3 完成块记录的 89/100、ops 33%、四项缺口为本批之前的真值；T5 之后 living 口径为 **94/100（34/36）**、ops **67%（4/6）**、剩余两项实现项——见概念页/评估页/README 现文。
- **交付（纯文档+测试，无传输代码、无真实主机触碰）**：
  - `docs/concepts/northstar-remote-transport.md` — 传输 spec：Profile A = 复用 systemd sidecar socket 走 SSH forward（runtime 零改动、无远程命令执行）；Profile B = 容器 fleets 复用 DurableRunner/EventStore/LeaseManager/verifier；词汇表只引真实工件；失败分类复用契约 fallback 状态；T5b 清单定义"done"。
  - `docs/concepts/northstar-remote-identity.md` — 身份/轮换 story：签发（enrollment secret vs run-scoped binding、policy_revision 钉死）与轮换（双密钥宽限、expiry 兜底、revision 紧急开关），全部挂真实符号；明说无 PKI、无吊销表。
  - `docs/guides/remote-worker-operations.md` — 部署/监控操作指南：Recipe A 步骤 + 轮换演练、Recipe B 明示未建、三路真实监控信号表（audit feed / OTEL spans / trace_metrics）、告警阈值、事件 runbook、首次验证清单、诚实尾注。
  - `examples/remote-canary/` — 操作者执行的通道 canary：ssh 可达 → socket forward → 确定性探针（server 在 spawn 前拒绝，无需模型/key），`NS_REAL=1` 可选真实 codex run；探针在 CI 对真实 `sidecar_socket.serve` 回路验证；整脚本需真实主机、按设计永不进 CI。
- **计分器如实重算**：两条"文档性质"缺口（story、guide）翻转为仓库权威工件检查（状态 marker 本身被 repo 测试钉死，空壳文件翻不了分）；两条实现项缺口保持 MISSING 并写明翻转条件（Profile A helper 存在 + 真实主机 canary 通过）。
- 测试：仓库文档 28 → **43**；全仓 812 → **827 全绿**；docbuild md 48→56。版本仍对齐 `0.1.0.dev0` 未发布。

### 2026-09-07（同批追加）— T4 完成（Agent Skills 标准兼容 + 供应链检查入口）

- **标准兼容**：runtime 的 `skills.py` 现在同时发现历史 `.northstar/skills/`
  与跨工具 `.agents/skills/`，严格校验 Agent Skills 规范的 `name`（≤64、
  小写 kebab-case、不得首尾/连续连字符、必须匹配目录名）和 `description`
  （≤1024），并接受 `license`、`compatibility`、`metadata`、`allowed-tools`
  等标准字段；`metadata` 支持字符串键值映射，兼容性/UTF-8/重复名称错误均
  fail-closed。规范依据：[Agent Skills specification](https://agentskills.io/specification)。
- **安全边界**：技能仍然只是文本知识包。`allowed-tools` 只作为声明展示，绝不
  变成 Northstar 的审批；技能包内脚本、references、assets 从不由 loader 执行，
  包内及工作区外的 symlink 被拒绝，技能根目录受 `--skills-dir` 的 workspace
  containment 约束，最多加载 40 个包。
- **产品入口**：新增 `skills check --workspace .`（人读/`--json` 两种输出）和
  `skills list`；两者都与真实 run 共享同一个 discovery/validation path，避免
  “check 通过但 run 失败”。`doctor`、`run --dry-run`、普通 `run` 也支持
  `.agents/skills` 和重复的 `--skills-dir PATH`。
- **测试与接线**：新增标准字段、frontmatter map/folded string、跨根重复名、
  resource symlink、CLI JSON 错误和“绝不执行脚本”断言；runtime **536 → 544**，
  `make test` 当前实测 **838 项**（4 项可选 OTel 测试在未安装 extra 时跳过）。

### 10.8 当前快照：与全球顶级工具的真实差距（以本 checkout 为准）

下面是给维护者的决策表，不把“已有规范/文档”误写成“已上线产品”。头部工具
的共同基线是：交互式终端/IDE surface、项目记忆文件、Skills/MCP/插件生态、
checkpoint/rewind、headless/SDK、后台任务和企业级策略下发。Northstar 的优势
是可审计、默认拒绝、确定性离线测试；差距主要仍在产品 surface，而不是权限内核。

| 能力面 | Northstar 当前事实 | Claude Code / Codex / Gemini 参照 | 下一步判断 |
|---|---|---|---|
| Zero-to-first-run | `make demo`、`pip install .`、`doctor`、`dry-run`；无公共 index/登录 | 官方安装器、账号/模型即用、交互式首跑 | 发布 wheel，保留零 key demo |
| 嵌入面 | Python `sdk.run/stream_run`、结构化事件、resume；无 TypeScript/app-server | Codex exec/SDK/app-server、Claude SDK 多语言 | 优先稳定协议/版本化 SDK，不先做 TUI |
| 交互与恢复 | sessions list/show/export；bounded checkpoint manifest、inspect/diff、强制 rewind/restore、fork；mutating tool 有 workspace_change receipt | checkpoint、rewind、后台任务、任务队列 | T3b：turn-level 自动策略、交互回放 UI、跨进程/远端 checkpoint lineage |
| 生态格式 | MCP stdio 工具发现/调用；Agent Skills 标准元数据 + `skills check/list`；无 plugins/marketplace、无 MCP HTTP/auth | MCP 多传输/登录、Skills 热加载、插件/marketplace | T4b：HTTP/auth 与插件清单必须先有信任/版本/撤销故事 |
| 供应链 | 目录/字段/路径/symlink fail-closed；不执行脚本、不做恶意内容判断 | 插件市场/组织策略/托管配置 | 把 validator 接入 CI；内容审查与签名不能伪装成已完成 |
| 后台/远程 | durable-run 与 remote-worker spec/ops 文档；无网络 transport/调度器/真实远端 canary | Codex cloud/Automations、Claude remote/background | T5：先 transport helper + 真实主机 canary，再谈 hosted control plane |
| OS 级隔离 | runtime sandbox + sidecar read-only/Unix 权限；host candidate 非 sandbox | Codex sandbox/gVisor/VM 等产品能力 | 不把应用层权限当 OS 隔离，继续保留红线 |

**建议的下一轮优先级：**

1. **T3 小步**：为现有 append-only transcript 增加 checkpoint 元数据和只读回放，
   先不宣称自动文件回滚；这能补上 Gemini/Claude/Codex 最可见的恢复体验，同时
   不破坏 Northstar 的审计不可变性。
2. **T4b 治理化生态**：把 `skills check` 接入消费者 CI recipe；若做插件/MCP
   HTTP，先设计来源、版本、权限、撤销和审计字段，禁止“安装即执行”。
3. **T2 发布**：0.1.0.dev0 的就绪门仍然正确；不要为了追赶头部工具伪造已发布
   版本。先完成全量 wheel 安装态、文档、原生 Linux 和真实 Anthropic/远端验证。

**结论：** Northstar 已经不是“没有生态”的库，而是一个有治理边界的 headless
harness。与头部产品仍差一个产品层：交互恢复、后台/远程、公共发布、TypeScript
和插件市场。当前最有辨识度的路线不是复制 Claude Code 的 TUI，而是把“标准生态
可消费 + 默认拒绝 + 可验证 audit feed + 离线可复现”做成 CI/企业嵌入的第一选择。

### 10.9 当前实现复核：T6 可逆执行内核（2026-09-07）

本节 supersede §10.8 中关于“无 checkpoint/rewind”的旧文字。它只描述当前
checkout 已实现的本地能力，不把 durable-run 原型、文档设想或竞品宣传当作
Northstar 已上线能力。

- **Manifest**：`components/northstar-agent-runtime/checkpoints.py` 以
  `northstar.checkpoint.v1` 保存 bounded regular-file snapshot。manifest 记录
  `session_id`、`session_index`、workspace、timestamp、label、parent checkpoint、
  每个文件的相对路径/SHA-256/大小/权限模式和确定性 workspace digest。
- **安全边界**：默认上限为 10,000 文件、单文件 8 MiB、总计 64 MiB；不遍历
  `.git`、`__pycache__`、`node_modules`、`.venv`，不跟随 symlink；manifest、重复
  路径、digest、checkpoint tree 和 restore 目标出现异常时 fail-closed。恢复不重放
  setuid/setgid 位。
- **动作 receipt**：`loop.py` 在已通过权限门、实际执行的 mutating tool 前后，
  对 `path`/`paths` 形状的目标记录 `workspace_change` session record，包含
  before/after 的 exists/kind/hash/bytes/mode；receipt 是元数据，不把文件正文塞进
  transcript。权限拒绝的工具不会伪造“已执行” receipt。
- **控制面**：`sessions checkpoint` 创建快照；`sessions inspect`/`checkpoints`
  列出链；`sessions diff` 只读比较 added/modified/deleted；`sessions rewind`（或
  `restore`）必须 `--force`，默认不删除新增文件，并先创建 `before-rewind:*`
  safety checkpoint；`sessions fork` 只向不存在的目标目录原子 materialise，生成
  child 初始 checkpoint 与 `fork.json` lineage。
- **验证**：runtime 新增 checkpoint API/CLI 测试和 mutating receipt 测试；T6
  完成时的快照为 `make test` **855 项**（runtime 561，4 项可选 OTel 测试 skip）。
  T7 的当前统计见 §10.10；文档 API 生成器已纳入 `checkpoints` 模块，离线 session
  panel 的 record vocabulary 也已同步 `workspace_change`。

诚实边界仍然重要：这是本地 bounded snapshot，不是 copy-on-write、数据库事务、
VM/OS sandbox 或远端 worker fork；自定义 mutating tool 若没有在 payload 中声明
路径，receipt 只能记录动作而不能声称捕获了所有文件；manifest 目前未签名。T6
本身没有跨进程调度、后台任务或 TypeScript/app-server 协议；T7 的 approval lease
与 action receipt 边界见 §10.10。

**下一步优先级调整：**

1. 将 checkpoint 选择策略提升为 runtime 的 `Run / Turn / Action / Checkpoint /
   Artifact / Receipt` 合同：可配置 turn boundary、崩溃恢复和 checkpoint retention，
   但不让自动化绕过 force/approval。
2. 为 mutating tool 引入声明式影响集（或工具返回的 artifact manifest），让 receipt
   覆盖不止 `path`/`paths` 的自定义工具，并为 receipt/manifest 增加可信 host
   receipt 绑定。
3. 在上述合同稳定后再做 TypeScript SDK、双向 app-server、后台 task queue 和远端
   worker transport；不先复制一个只服务于 TUI 的状态层。

### 10.10 当前实现复核：T7 capability-first approval lease / receipt（2026-09-07）

本节记录在 T6 之上的真实垂直切片；它不是把 durable-run 原型描述成已托管的平台。

- **Lease**：`components/northstar-agent-runtime/receipts.py` 定义
  `northstar.approval-lease.v1`，以精确 `session_id`、已解析 workspace、能力名、
  `issued_at`/`expires_at` 和 `max_uses`/`uses` 约束授权。`ApprovalLeaseLedger.consume`
  在消费点校验 scope、过期和次数，并按 expiry/lease id 确定性选取；没有通配符。
- **Permission integration**：`permissions.py` 保留 `disallowed_tools` 和 plan mode 的
  hard boundary；匹配 lease 在传统 `can_use_tool` callback 之前消费。callback 可以返回
  `{allowed: true, lease: {...}}`，runtime 会 fail-closed 校验并登记；旧的 bool callback
  仍兼容但不获得 lease 复用语义。
- **Receipt**：每个 attempted tool call 产生 `ActionReceipt`（包括 denied/failed），
  记录 capability、canonical input/output digest、可用的 workspace pre/post metadata
  digest、消费的 `lease_id` 和显式 status。传入 host secret 后用 HMAC-SHA256 签名，
  `verify()` 可验证序列化后的 receipt；`to_contract_receipt()` 投影到已有
  `northstar.receipt.v1` status/postcondition shape。
- **Host/SDK**：`northstar-host.authorization.issue_approval_lease` 从已验证的
  `northstar.authorization.v1` grant 生成 bounded lease，并只允许缩窄 capability/expiry；
  SDK `RunOptions` 可传 lease、receipt secret 和 clock。签名 receipt 以现有 session
  `informational` record 的 `subtype=action_receipt` 保存，不记录 secret。
- **边界**：lease 是 runtime 内的 bounded approval cache，不替代 durable-run
  `ActionGateway` 的 argument digest、resource binding、idempotency 或 high-risk approval；
  receipt 证明 runtime 规范化并观察到的结果，不是远端 attestation。没有 secret 时 receipt
  可检查但不可验证；自定义工具未声明影响集时仍不能声称完整可逆。
- **验证**：T7 完成时 `make test` 为 868 项测试、864 项通过、4 项可选 OTel skip；
  runtime 为 572 项。`python3 tests/docbuild.py build && verify` 与 `git diff --check`
  均通过。

T7 仍是 Unreleased；没有创建 tag、GitHub Release，也没有发布到 PyPI/npm。

### 10.11 当前实现复核：durable-run 长任务控制面（2026-09-07）

本节记录在 T7 之上的 durable-run 生命周期垂直切片。它扩展的是已有
`EventStore`、lease、checkpoint、replay 和 verifier 边界，不把本地 runner 描述成
后台调度器或云端任务服务。

- **Pause / resume**：`DurableRunner.pause()` 以 `run.waiting` 将运行中的 run
  持久化为 `waiting`；`resume()` 通过新的 `run.started` 回到 `running`。暂停是
  durable scheduling boundary，`execute()` 在显式 resume 前拒绝继续执行，因此不会
  把“暂停”误报成线程/进程中断。
- **显式 retry**：失败 run 先写 `run.retry`（`failed → planned`），每个失败 step
  再写 `step.retry`，事件回放能得到同一状态。重试可以在事件追加中途崩溃后继续，
  不会重复已写入的 retry transition。
- **Attempt identity**：首次执行使用
  `<run_id>:<step_id>:attempt-1`；事件历史中出现 `step.retry` 后才进入下一个
  attempt。崩溃留下 `step.started` 时没有 retry event，恢复继续复用原 key；显式
  retry 则生成新 key，区分“恢复未完成动作”和“真正的新尝试”。
- **Cancel ordering**：取消时先为每个 `running` step 写 `step.cancelled`，再写
  `run.cancelled`；回放不会留下 run 已取消但活动 step 仍是 running 的假状态。已在
  Python action 内执行的函数不被强行 signal interrupt，后续跨进程 cancellation 仍是
  下一层工作。
- **验证与基准**：durable-run 测试覆盖 pause/resume、paused execute guard、retry
  attempt key、crash recovery key reuse、retry/cancel event replay 和 active-step
  cancel ordering；T8 完成时 `make test` 为 **873 项测试、869 项通过、4 项可选 OTel skip**，
  其中 durable-run 70 项，API 文档由 docbuild freshness 检查。

仍未实现：真正的后台 scheduler、跨进程 task queue、进程组隔离与 signal cancellation、
远程 worker transport、数据库/分布式 event store，以及 HTTP/app-server 控制面。下一步
应先稳定 versioned lifecycle/receipt contract，再评估 transport；不因补上本地 pause/retry
就宣称已经具备云端后台执行。

T8 仍是 Unreleased；没有创建 tag、GitHub Release，也没有发布到 PyPI/npm。

### 10.12 当前实现复核：durable-run 本地控制面（2026-09-07）

T9 在 T8 runner API 之上补齐了一个不带调度器的本地操作面：
`northstar-durable-run` CLI 直接复用 `EventStore` 的校验与 replay，不维护第二套状态机。

- `status --events ... --run-id ...` 输出当前派生状态、事件计数和最后一个事件；
  `history` 输出 canonical JSON 事件列表；`audit` 输出现有 audit.ndjson/1 feed。
- `control pause|resume|cancel` 要求显式 `RunContract` JSON、owner identity 和 event
  timestamp。命令只调用已有 `DurableRunner` 生命周期方法，不执行 step action，不创建队列，
  不开启网络端口。
- `retry` 保持 programmatic-only：它必须接收 `StepPlan` action，才能在新的 attempt
  key 上执行并保留 crash recovery 语义。CLI 不提供一个会伪造“已重试”的标记命令。
- 验证：durable-run 现有 **74 项**测试全部通过；本批新增 CLI 的 replay/history/audit、
  control ordering、missing-history fail-closed 和 owner-bound lease fencing 测试。当前
  `make test` 为 **877 项测试、873 项通过、4 项可选 OTel skip**，durable-run 74 项。

T9 仍是 Unreleased；没有创建 tag、GitHub Release，也没有发布到 PyPI/npm。

### 10.13 当前实现复核：durable-run 本地持久化 fencing（2026-09-08）

T10 继续留在本地 kernel 范围内，解决的是同一台机器上多个进程同时读写
EventStore/lease 文件时的序列竞争，而不是提前实现分布式 scheduler。

- EventStore 为事件流创建 `.lock` sidecar：read 使用 shared lock，append 使用
  exclusive lock；idempotency check、sequence check、状态 replay 和 fsync append
  在同一 exclusive critical section 内完成。
- checkpoint 生成也在 exclusive stream lock 内完成，避免“根据旧 sequence 写出
  checkpoint、随后另一个进程追加事件”的窗口。
- LeaseManager 的 acquire/assert/heartbeat/release 使用独立 lease lock sidecar，
  lease 内容仍通过临时文件 + `os.replace` 原子更新。
- 新增 forked-process 并发 idempotent append 测试；当前 durable-run 75 项测试，
  全仓 `make test` 为 **878 项测试、874 项通过、4 项可选 OTel skip**。

边界仍然明确：这是 POSIX 本地 advisory locking，不是跨主机锁服务、数据库事务、
worker claim protocol 或 fencing token；action 进程隔离和远程 transport 仍未实现。

T10 仍是 Unreleased；没有创建 tag、GitHub Release，也没有发布到 PyPI/npm。

### 10.14 当前实现复核：可归因的 durable-run 控制 receipt（2026-09-08）

T11 在 T10 的本地持久化 fencing 之上，为 `control pause|resume|cancel` 输出
一个版本化、可验证的因果投影；它没有引入第二套 lifecycle 状态机。

- 新增 `northstar.durable-control-receipt.v1`：receipt 绑定 `run_id`、
  `actor_id`、`command_id`、操作类型和请求时间，并记录 before/after status
  与 sequence。
- receipt 精确列出本次观察到的新增 event IDs/sequences，并对最终 replay state
  计算 canonical `sha256:` digest；有新增事件是 `applied`，终态重复或等待状态
  无变化是 `noop`。
- CLI 接受可选 `--command-id` 并在 JSON control response 的 `receipt` 字段输出
  contract。receipt ID 仍是每次响应的随机标识；receipt 不是持久化 command ledger，
  也不把自身变成幂等状态源。
- 验证：durable-run **77 项测试全部通过**；全仓 `make test` 为 **880 项测试、
  876 项通过、4 项可选 OTel skip**；API docbuild freshness 与链接检查通过。

T11 仍是 Unreleased；没有创建 tag、GitHub Release，也没有发布到 PyPI/npm。

### 10.15 当前实现复核：离线 durable-run receipt 验证（2026-09-08）

T12 将 T11 的“可验证”从 schema/digest helper 扩展为一个只读验证路径，仍然
不引入 command ledger 或第二套状态机。

- `northstar-durable-run verify-receipt --events ... --receipt ...` 重新解析
  `ControlReceipt`，检查 receipt 引用的 event IDs/sequences 是否精确对应
  EventStore 的历史片段，并检查 before/after status 与 state digest。
- EventStore 新增 `replay_at(run_id, sequence)`，使用现有 authoritative reducer
  回放指定 event prefix。因此 receipt 在后续 `resume`、`cancel` 等事件追加后，
  仍可验证它当时绑定的历史状态，而不是只能验证当前末状态。
- 验证命令只读、fail-closed：receipt JSON、事件引用、状态或 digest 任何一项
  被篡改都会返回 CLI error，不会写事件、checkpoint、lease 或 receipt ledger。
- 验证：durable-run **78 项测试全部通过**；全仓 `make test` 为 **881 项测试、
  877 项通过、4 项可选 OTel skip**；API docbuild freshness 与链接检查通过。

T12 仍是 Unreleased；没有创建 tag、GitHub Release，也没有发布到 PyPI/npm。

### 10.16 当前实现复核：声明式 mutating-tool 影响集（2026-09-08）

T13 承接 T6/T7 对 workspace/action receipt 的诚实边界：只要工具声明了
非标准路径输入，runtime 就能在现有 sandbox 内捕获该影响集；但声明本身不会
赋予工具权限，也不会把隐藏副作用伪装成已观测。

- `ToolSpec.affected_input_keys` 是 bounded、top-level 的 payload key 声明，
  例如 `("output_path",)`；重复、空值和过长 key fail-closed。未声明的内置
  工具保持 `path`/`paths` 兼容行为。
- mutating tool 调用的 workspace pre/post capture 使用声明的 key 解析路径，
  所有路径仍经过同一个 symlink-aware sandbox；`workspace_change` 记录新增
  `impact_source` 与 `impact_input_keys`，便于审计者区分 legacy 与显式覆盖。
- 这不是影响集权限或 artifact manifest：工具仍须通过 permission gate，声明
  只扩大 receipt 的观测范围；隐藏网络、数据库或未声明文件副作用仍不被声称
  已捕获。
- 验证：runtime **574 项测试全部通过**；全仓 `make test` 为 **883 项测试、
  879 项通过、4 项可选 OTel skip**；API docbuild freshness 与链接检查通过。

T13 仍是 Unreleased；没有创建 tag、GitHub Release，也没有发布到 PyPI/npm。

### 10.17 当前实现复核：版本化 artifact manifest（2026-09-08）

T14 为 T13 的影响集声明补上了非路径输出的结构化观察边界：工具可以返回
artifact manifest，runtime 会严格验证并把它纳入 action receipt，但不会把
工具自报内容升级为 host attestation。

- 新增 `northstar.artifact-manifest.v1`，限制 artifact 数量、ID、locator、
  media type、bytes 和 digest；`file`/`directory` locator 必须是规范化的
  workspace-relative path，URI/opaque artifact 使用独立 locator 语义。
- `ToolResult.data["artifact_manifest"]` 经过 schema 校验后进入 `ActionReceipt`
  canonical bytes；签名 receipt 的 contract projection 增加
  `artifacts_observed` postcondition。非法 manifest 会变成失败 tool result，
  不会静默写入审计记录。
- 该 manifest 不是权限声明，不替代 `ToolSpec.affected_input_keys` 的 workspace
  pre/post capture，也不声称捕获工具隐藏的网络、数据库或未声明文件副作用。
- 验证：runtime **578 项测试全部通过**；全仓 `make test` 为 **887 项测试、
  883 项通过、4 项可选 OTel skip**；API docbuild freshness 与链接检查通过。

T14 仍是 Unreleased；没有创建 tag、GitHub Release，也没有发布到 PyPI/npm。
