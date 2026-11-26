# Northstar Agent OS 深度生态雷达（2026-11-25 扩展扫描与落地转化）

> 核验日期：2026-11-25。本文在 [`docs/ecosystem-survey-2026-11-25.zh-CN.md`](../ecosystem-survey-2026-11-25.zh-CN.md) 与 [`research/2026-10-17/00-ecosystem-synthesis.md`](../../research/2026-10-17/00-ecosystem-synthesis.md) 的基础上，扩大搜索覆盖面至 2026 年底主流开源/商业编程 Agent、通用编排框架、互操作协议栈、执行沙箱、安全攻防研究与评测可信度论文、开源安全工具及公开社区/论坛/仓库入口，并将可复现差距直接转化为本轮 Northstar 代码级加固。
>
> 事实边界：以下所有外部事实均基于 2026 年公开网页、官方文档、开源仓库与论文核验；**未加入或读取任何私密 Slack、Discord、微信群或登录后封闭群聊**，公开群聊邀请链接仅证明社区入口可见，不作为功能或安全背书。遵循蓝图 [`docs/next-gen-agent-blueprint.zh-CN.md`](../next-gen-agent-blueprint.zh-CN.md) §10：`来源雷达 → 可复现差距 → 最小设计 → 实现 → 双轨评测 → 裁决`。

---

## 1. 编程 Agent 与 Coding Harness 全景（2026-11）

2026 年编程 Agent 已从单一 IDE 插件演化为“**终端/无头 CLI + IDE ACP 接入 + 隔离工作树/容器 + 技能/MCP 扩展**”四层结构，同时开源生态发生明显洗牌：

| 项目 / 团队 | 许可与语言 | 核心机制与 2026 演进 | 对 Northstar 的启示与边界 |
|---|---|---|---|
| **OpenCode** (`anomalyco/opencode`) | MIT / TypeScript | 终端优先、内置 `build` 与只读 `plan` 双模式、75+ 模型提供方、20+ 语言 LSP、原生 ACP (`opencode acp`) 与 MCP | 印证“只读计划阶段与变更阶段分离”和原生 LSP/ACP 的价值；但默认无内置 OS 沙箱，权限模型不如 Northstar 宿主证据链严格 |
| **Hermes Agent** (`NousResearch/hermes-agent`) | MIT / Python | 2026 年迅速崛起的自学习 Agent：跨会话 `MEMORY.md`、自动生成并迭代技能、多后端沙箱（Local/Docker/SSH/Daytona/Singularity/Modal）、支持将代码任务转交 OpenCode/Claude Code/Codex | 自生成技能与持久记忆若缺少签名、哈希固定与准入审计，极易触发 OWASP ASI04/ASI06 投毒；Northstar 的 SHA-256 固定 `SKILL.md` 与只收紧策略正是必要反制 |
| **OpenHands** (`OpenHands/OpenHands`) | MIT / Python+TS | 自托管多 Agent 控制面、Docker/VM 沙箱、Agent Canvas 通过 ACP 调度 Claude Code / Codex / Gemini CLI / Pi / OpenCode | 印证“平台与推理内核解耦”趋势；Northstar 继续坚持唯一宿主治理内核，不引入第二个平级控制循环 |
| **Goose** (`aaif-goose/goose`) | Apache-2.0 / Rust | Block 捐赠给 Linux Foundation **AAIF**，70+ MCP 扩展、原生 ACP (`goose acp`)、本地优先与对抗审阅模式 | 值得关注其 Rust CLI/MCP 工程形态及 AAIF 治理；但默认宿主机执行，隔离边界须由宿主补齐 |
| **Cline** (`cline/cline`) & **Kilo Code** | Apache-2.0 / MIT | 覆盖 IDE、独立 CLI、SDK 与并行任务板，强调 `Plan` / `Act` 分离与逐步审批；Roo Code 于 2026-05 归档只读，用户迁向 Kilo Code / Cline | 社区分叉与归档速度极快，佐证 Northstar 不应把核心运行循环绑定到任何单一第三方编排外壳 |
| **mini-SWE-agent** (SWE-bench 团队) | MIT / Python | 极简 100 行核心循环 + 可插拔 Docker/Podman/Apptainer/Bubblewrap 环境 | 证明“薄而清晰的执行循环 + 严格隔离环境”比堆叠框架抽象更易审计和评测 |
| **Qwen Code** (`QwenLM/qwen-code`) / **Kimi Code** / **ByteDance DeerFlow** (`bytedance/deer-flow`) | Apache-2.0 / MIT | 中国开源团队在终端编码（Qwen Code / Kimi Code）与长程多步研究/编码工作流（DeerFlow，集成沙箱、记忆、技能与子代理）全面开源发力 | 可作为未来受监督的外部 Provider/Worker 兼容参考，但工具执行与验证回执必须归宿 Northstar 宿主 |
| **Claude Code / Codex CLI / Gemini CLI** | 厂商工具 + SDK | 各自提供结构化事件/JSONL、headless 模式、hooks/审批、Trusted Folders（Gemini CLI）与 ACP 适配 | Gemini CLI 的 Trusted Folders 准入机制与 Claude Code hooks 生命周期直接启发本轮 Northstar 不可信仓库准入 preflight |

---

## 2. 通用编排框架与持久执行层

除已有扫描覆盖的 LangGraph、OpenAI Agents SDK、Google ADK、Microsoft Agent Framework（2026-04 达 1.0，成为 AutoGen 与 Semantic Kernel 的统一继任者）、PydanticAI、CrewAI 外，2026 年生产生态还形成以下关键分支：

- **AWS Strands Agents**（Python / TypeScript，Apache-2.0）：极简模型驱动循环 + 原生 MCP、Interrupts 与 OpenTelemetry 导出。
- **Mastra**（TypeScript，Apache-2.0 核心）：TypeScript 侧最成熟的 Agent + Workflow + 持久快照 + 评估全栈框架。
- **Agno**（Python，Apache-2.0）、**HuggingFace smolagents**（代码即动作 CodeAgent）、**Alibaba AgentScope**、**Stanford DSPy**（程序化提示优化）、**Letta**（持久化长期记忆块）。
- **持久执行引擎**：**Temporal**、**Restate**、**DBOS**、**Inngest** 已被 PydanticAI 等框架直接接入作为故障恢复底座；核心共识是 **transcript ≠ 文件系统/外部副作用恢复**，外部副作用必须具备稳定 `step_id` 与幂等键，缺失终态回执时严禁盲目重放。

**裁决**：上述框架均不进入 Northstar Core；可作为未来外围适配器或 M2/M4 参考，权限、预算、worktree、验证与审计事实来源永远唯一归属 Northstar 内核。

---

## 3. 2026 互操作标准栈的收拢

2026 年多协议混战已明显收拢为清晰的四层标准栈：

| 协议层 | 标准 | 治理方与 2026 状态 | 解决的问题 | 对 Northstar 的边界 |
|---|---|---|---|---|
| **Agent ↔ Tool** | **MCP** (Model Context Protocol) | Linux Foundation **AAIF**，2026-07-28 规范改为无状态（`server/discover` + 每请求自包含 `_meta` + `input_required`） | 工具、资源与提示接入 | Northstar `mcp_client.py` 已实现 2026-07-28 双代协商与 `mcp_elicitation`；下步应做真实公开服务器兼容性与投毒回归测试 |
| **Editor/IDE ↔ Coding Agent** | **ACP** (Agent Client Protocol) | Zed + JetBrains 共建，2026 年达 **Spec 1.0**，JSON-RPC 2.0 over stdio，公共 Registry 收录 40+ Agent 与 19 个客户端（含 Zed、JetBrains、Android Studio） | 任意编辑器托管任意编码 Agent | **高价值 M2/M4 候选**：未来可提供薄 `northstar acp` 适配面，使 Northstar 可在 Zed/JetBrains 中作为受治理编码 Agent 运行，但协议本身不替代宿主授权与证据封存 |
| **Agent ↔ Agent** | **A2A** (Agent2Agent) | 2026-03 发 v1.0（新增签名 Agent Card），2026-08 加入 **AAIF**；原 IBM ACP 已合并入 A2A | 跨组织/跨框架 Agent 发现与任务委派 | 继续延后至 M4；签名 Agent Card 不能等同于 Northstar 任务级缩小授权（attenuated grant） |
| **发现/身份与跨组织消息** | **AGNTCY**（SLIM + OASF）与 **AG-UI / WebMCP** | Linux Foundation（Cisco/Google Cloud/Red Hat 等共建 AGNTCY；CopilotKit 牵头 AG-UI；W3C CG 推进 WebMCP） | 跨组织 SPIFFE 身份/目录与流式 UI 事件 | 作为远程 Worker Profile B 与未来前端观察面板的参考，不提前耦合到单机闭环 |
| **仓库指令与技能格式** | **AGENTS.md** 与 **Agent Skills (`SKILL.md`)** | AAIF 托管 `AGENTS.md`（60,000+ 开源仓库采用）；`SKILL.md` 成为开放格式 | 项目指令与可复用技能包 | **一律按不可信数据对待**；Northstar 已对 `SKILL.md` 做 SHA-256 审计，并在本轮准入 preflight 中显式标注 `AGENTS.md` 权威等级为 `none` |

---

## 4. 执行沙箱与隔离技术全景

2026 年生态形成“**大脑在沙箱外、双手在沙箱内、凭据经外置代理按白名单注入**”的共识：

- **硬件虚拟化 microVM（强隔离默认）**：Firecracker 阵营（E2B、Vercel Sandbox、Blaxel、Fly.io Sprites、Docker Sandboxes 2026-01 microVM 模式），每个沙箱拥有独立 Linux 内核，支持暂停/恢复与快照分叉。
- **用户态内核 / 混合模式**：Modal Sandboxes（默认 gVisor，2026-10 VM 运行时 GA）、Daytona（容器默认 + VM 暂停/分叉）、Cloudflare Sandbox SDK（每容器独立 microVM + Durable Objects）。
- **轻量本机 OS 隔离**：Anthropic 开源 `sandbox-runtime`（macOS Seatbelt / Linux bubblewrap），以及 Linux Landlock / seccomp / capdrop。

**对 Northstar 的现实约束**：沙箱能压缩爆炸半径，但**不能防住拥有合法工具权限时的提示注入**；同时 Northstar 已有 `landlock-loader-evaluation.md` 明确记录嵌套 Python loader 与 Landlock 路径限制的冲突。因此 Northstar 的底线是：**永远如实披露实际隔离能力，绝不把 `process` 回退伪装成 OS 隔离**。

---

## 5. 安全攻防、评测可信度与 2026 前沿研究

本轮扩展检索中最具工程冲击力的四项研究进展：

1. **OWASP Top 10 for Agentic Applications 2026（ASI01–ASI10）与 OWASP Agent Control Standard（2026-09-01）**：
   - `bin/northstar bench` 当前报告 OWASP ASI 覆盖 `7/10`（残余部分项：`ASI04` 供应链、`ASI07` Agent 间通信、`ASI10` 失控 Agent）。
   - OWASP ACS（2026-09）强调生产 Agent 必须具备标准化运行时策略拦截、可观测性与外部可撤销 kill switch——与 Northstar 治理内核方向完全一致。
2. **Google DeepMind CaMeL（IEEE SaTML 2026）与出带防御的审慎评估**：
   - CaMeL 通过特权规划 LLM 与隔离数据 LLM 分离控制流/数据流，并用带能力标签的解释器阻断不可信数据改变程序流（在 AgentDojo 上取得可证明安全性的高完成率，伴随约 7 个百分点效用代价）。
   - 但 2026-06 的 *Adaptive Evaluation of Out-of-Band Defenses* 同样指出，静态基准高分不等于自适应攻击免疫；Northstar 必须坚持**多道防线（准入 + 阶段门 + 权限 + 交付审计 + 独立验证 + 封存）**，不迷信单一防御层。
3. **UC Berkeley BenchJack（2026-05，arXiv:2605.12673）——评测奖励黑客危机**：
   - BenchJack 审计 10 个主流 Agent 基准并提出 8 类漏洞分类（V1 隔离失效、V2 答案随测试下发、V3 对不可信输入执行代码、V4 LLM 裁判提示注入、V5 弱字符串匹配、V6 评测逻辑漏洞、V7 信任 Agent 产物、V8 过度权限）。
   - 最具警示性的 V1 实例：仅凭一个 **9 行 `pytest_runtest_makereport` hook** 将 `report.outcome` 强制改为 `"passed"`，或投放 `sitecustomize.py` / `.pth` 在 Python 解释器启动阶段劫持测试进程，即可在不解决任何任务的情况下在 SWE-bench Verified / Pro / Terminal-Bench 刷出接近 100% 的假通过率！
   - **直接转化为本轮 Northstar 代码加固**：即使宿主通过 `--check-input` 固定了已知测试脚本，恶意补丁仍可能新增 `sitecustomize.py`、`usercustomize.py`、`*.pth` 或带结果篡改 hook 的 `conftest.py`。本轮已在 `audit_delivery_patch()` 中于宿主检查执行**之前**直接拦截此类交付。
4. **2026 评测基准大洗牌与开源安全工具链**：
   - OpenAI 于 2026-02 停止报告 SWE-bench Verified（审计发现高比例题面/测试缺陷与训练污染），生态转向 **SWE-bench Pro**、**Terminal-Bench 4.0**、**OSWorld 2.0**、**τ³-bench**、**MCP-Atlas** 与 **Toolathlon-Verified**。
   - 开源安全/评测基础设施聚焦于：**UK AISI Inspect AI**（`UKGovernmentBEIS/inspect_ai`）、**Snyk Agent Scan**（原 Invariant Labs `mcp-scan`）、**Cisco `mcp-scanner`**（YARA + LLM + AI Defense）、**Promptfoo**（YAML 红队与轨迹断言）、**NVIDIA SkillSpector / garak / NeMo-Guardrails**、**Microsoft PyRIT**、**OPA**、**Semgrep**。

---

## 6. 公开社区、团队仓库、论坛与公开群聊入口地图

以下为本轮核验到的公开协作面（仅记录公开网页、GitHub 仓库/Discussions、官方论坛与公开邀请页，未加入或读取任何私密群聊）：

| 生态板块 | 公开仓库 / 官网 | 公开论坛 / Discussions / 群聊入口页 |
|---|---|---|
| **Northstar Agent OS** | `https://github.com/FNY666/northstar-agent-os` | GitHub Issues / Pull Requests / Security Policy |
| **Linux Foundation AAIF（MCP / A2A / Goose / AGENTS.md / AgentGateway）** | `https://aaif.io/` · `https://github.com/aaif` · `https://github.com/modelcontextprotocol` · `https://github.com/aaif-goose/goose` | MCP GitHub Discussions、A2A 社区页（`a2a-protocol.org/latest/community/`）、AAIF 公开 Discord 邀请页（`aaif.io`） |
| **Agent Client Protocol (ACP)** | `https://github.com/agentclientprotocol` · Zed / JetBrains ACP Registry | GitHub Issues / Registry PRs |
| **主流开源编程 Agent** | `anomalyco/opencode` · `NousResearch/hermes-agent` · `OpenHands/OpenHands` · `cline/cline` · `QwenLM/qwen-code` · `bytedance/deer-flow` | 各仓库 GitHub Discussions/Issues；Nous Research / OpenHands / Cline 公开 Discord 入口页 |
| **通用框架与云厂商** | `langchain-ai/langgraph` · `openai/openai-agents-python` · `google/adk-python` · `microsoft/agent-framework` · `pydantic/pydantic-ai` · `strands-agents/sdk-python` · `mastra-ai/mastra` | LangChain 论坛（`forum.langchain.com`）、OpenAI 社区论坛（Agents SDK / Codex CLI）、Google ADK 邮件组（`groups.google.com/g/adk-community`）、Microsoft Agent Framework Discussions、CrewAI 论坛（`community.crewai.com`）、Pydantic 公开 Slack 加入页 |
| **安全与评测社区** | `UKGovernmentBEIS/inspect_ai` · `promptfoo/promptfoo` · `cisco-ai-defense/mcp-scanner` · `NVIDIA/garak` · `microsoft/PyRIT` · `OWASP/www-project-top-10-for-large-language-model-applications` | OWASP GenAI Security Project 工作组（`genai.owasp.org`）、NIST NCCoE AI Agent 身份与授权项目、arXiv `cs.SE` / `cs.CR` / `cs.AI` |

---

## 7. 吸收 / 延后 / 拒绝裁决与本轮代码级落地

### 7.1 生态能力裁决

| 能力方向 | 裁决 | 理由与触发条件 |
|---|---|---|
| **不可信仓库准入 preflight（无执行扫描 + 零秘钥读取 + 封存回执）** | **本轮立即吸收落地** | 补齐 `research/2026-10-17` 候选 3；吸收 Gemini CLI Trusted Folders 与多 Agent 配置面发现经验 |
| **BenchJack 级测试劫持与跨 Agent 配置投毒交付审计** | **本轮立即吸收落地** | 直接防御 `sitecustomize.py` / `*.pth` / `conftest.py` 伪造通过与 `.mcp.json` / `.claude/settings.json` 持久化投毒（OWASP ASI04/ASI05/ASI06） |
| **SDK 与 CLI 的 `check_inputs` 契约一致性修复** | **本轮立即修复** | 发现 `sdk.run_code()` 漏传 `check_inputs=task.check_inputs` 导致 SDK 路径未固定校验输入 |
| **薄 `northstar acp`（Agent Client Protocol 1.0）只读/受治理适配层** | **排入 M2/M4 评估** | ACP 1.0 已成为 Zed/JetBrains/Android Studio 通用接入面，但需在单机长任务与持久审批闭环稳定后再建 |
| **SWE-bench Pro / Terminal-Bench 4.0 冻结样本增量** | **排入 M2 评测升级** | 顺应 SWE-bench Verified 退场趋势，与现有 24 题离线包与 50 题样本并行演进 |
| **MCP 真实公开服务器窄范围安全互操作测试（配 Snyk/Cisco 规则对照）** | **排入 M2/M3 Labs** | 补齐 OWASP ASI04 实测覆盖，保持默认显式工具授权 |
| **全功能框架替换内核 / 自修改无签名技能 / 默认无沙箱 Full Auto** | **明确拒绝** | 违背蓝图唯一宿主治理内核与“策略只可收紧”不变量 |

### 7.2 本轮已落地的代码级强化

1. **修复 `sdk.run_code()` 校验输入固定缺口**（`components/northstar-agent-runtime/sdk.py`）：
   - 将 `check_inputs=task.check_inputs` 透传至 `CodePhaseMachine`，与 `cli._run_code()` 保持完全一致，并新增端到端防篡改单测。
2. **新增不可信仓库准入 preflight 回执 `admission.json`**（`components/northstar-agent-runtime/code_task.py`、`sdk.py`、`code_resume.py`、`scripts/check-code-run-evidence.py`）：
   - `IsolatedCodeWorkspace.prepare()` 在创建隔离 worktree 后执行纯非执行扫描（仅依赖 Git index 与 `lstat`），分类 `.env*`/密钥、`.mcp.json`、`.claude`/`.codex`/`.gemini`/`.cursor`/`.opencode`/`.goose` 配置、`AGENTS.md`、`.gitmodules`/`.githooks`、`sitecustomize.py`/`*.pth` 等面，绝不读取秘密文件内容（`content_read: false`、`sha256: null`），将 `admission.json` 与 `admission_sha256` 封存进 `manifest.json`，并在独立硬门校验脚本 `check-code-run-evidence.py` 中新增 `admission_contract` 校验与篡改拒绝测试。
3. **新增 BenchJack 测试劫持与跨 Agent 配置投毒交付审计 + 攻防实验室双轨扩展**（`components/northstar-agent-runtime/code_task.py`、`scripts/run-code-security-lab.py`、`tests/test_code_security_lab.py`、`docs/guides/code-security-lab.md`）：
   - `audit_delivery_patch()` 在宿主检查运行**之前**拒绝 `sitecustomize.py` / `usercustomize.py` / `*.pth`（`python_startup_hook`）、在 `conftest.py` 中注入强制通过的 `pytest_runtest_makereport` / `pytest_sessionfinish` hook（`test_runner_hijack`，对正常 `@pytest.fixture` 保持零误报），以及向交付补丁植入 `.mcp.json` / `.claude/settings.json` / `.claude/hooks/*` 等跨 Agent 持久化配置（`agent_config_poisoning`）。
   - 24 题离线基准参考解全量审计 **0 误报**（24/24 通过）。
   - `code-security-lab` 由 7 对扩展为 **9 对**恶意/良性对照用例（新增 `benchjack-startup-hook` 与 `agent-config-poison`），如实区分事前阻断（6/9）、事后审计检测并拒绝（3/3）与良性任务效用（9/9）。
