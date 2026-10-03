# Northstar Agent OS — 对标全球顶级 agent 工具（2026-10 公开资料横向调研）

> 编制日期：2026-10-03 ｜ 范围：**全球头部 agent / 编程智能体公开资料横向对比**（能力面 + 架构安全 + 治理 + 模型 + 基准 + 定价生态）
> 方法：隔离 deep-research 案头调研（官方文档/官方博客优先，多源印证次之，单一第三方标注）；**未做本地实测、未连接任何真实后端**——口径与 09 版"本地实测 + 最小复现"不同，见 [benchmark-top-agents-2026-09.zh-CN.md](benchmark-top-agents-2026-09.zh-CN.md)
> 定位：本报告是分析文档，**未做任何代码改动**。其中一处调研结论经仓库代码核对已勘误（seccomp-BPF 并非"未证实"），见 §9。

---

## 0. 执行摘要

截至 2026 年 10 月，全球 AI 编程智能体市场已从"模型竞赛"转向"**harness（执行框架）竞赛**"：同一模型在不同 harness 下成绩可相差 22 个百分点，任何基准数字都必须绑定"版本 + 日期 + harness + 自报/独立"四要素，否则无意义。

1. **双寡头 + 追赶者**：Claude Code（Opus 5，SWE-bench Verified 自报 96.0%）与 Codex（GPT-5.5，Terminal-Bench 2.0 官方榜 82.2%）在能力上限上互有胜负；Google 以 Antigravity 平台整合战线，罕见引入第三方模型（Claude Sonnet/Opus 4.6、GPT-OSS）。
2. **并购重塑版图**：Windsurf 被 Cognition 收购并更名 **Devin Desktop**；Manus 经历 Meta 收购（约 20 亿美元，2025-12）→ 中国监管要求剥离（2026-04）→ 2026-09 恢复独立运营；Meta 另于 2026-08-05 自行发布终端 agent **Muse Code**。
3. **扩展层已标准化**：MCP（现行规范 2026-07-28）与 Agent Skills（2025-12 开放标准）成为跨厂商"普通话"；但 **MCP 服务器普遍在命令沙箱之外**，是全行业共性风险面。
4. **治理是最大分化带**：商业产品在"评权限门决策"上**集体空白**（无一发布权限门基准分），审计日志普遍只在企业版提供。Northstar 的离线确定性 governance bench + `audit.ndjson/1` 规范 feed 在此维度**代际领先**。
5. **Northstar 定位**：治理维度领先所有商业产品；产品维度（模型生态、IDE、基准成绩、托管云）落后约 1–2 代，版本仍为 `0.1.0.dev0` 未发布。最现实的定位是**高合规场景下商业 agent 的治理侧车/审计与权限内核**，而非正面替代品。

---

## 1. 口径：跟谁比、凭什么说

| 厂商 | 产品 | 形态 | 状态（2026-10） |
|---|---|---|---|
| Anthropic | Claude Code（含 Claude Agent SDK） | 终端 CLI + IDE 插件 + 桌面 App + Web + SDK | 活跃，订阅制核心产品 |
| OpenAI | Codex（含 Codex CLI / 云端 harness / Agents SDK） | CLI + 桌面 App + IDE 扩展 + 云端并行任务 + SDK | 活跃，ChatGPT 订阅捆绑 |
| Google | Antigravity（IDE/CLI/SDK/Managed Agents） | 平台型 | 2.0（I/O 2026），public preview 转企业化 |
| Google | Gemini CLI | 开源 CLI | **2026-06-18 起并入 Antigravity CLI** |
| Google | Jules | 异步云端 agent | GA（2025-08-06），无企业套餐 |
| Google | ADK | 开源框架 | 活跃，Python/Java |
| Cursor | Cursor（IDE + CLI + Cloud Agents） | VS Code fork IDE | 活跃，多模型 |
| Cognition | Devin（含 Devin Desktop，原 Windsurf） | 云端 agent + IDE | Windsurf 已更名 Devin Desktop |
| Manus | Manus（通用云 agent） | 云端 VM agent | 独立运营（收购剥离后） |
| xAI | Grok Build / Grok CLI | 终端 agent | 2025-05-14 发布 |
| Meta | Muse Code | 终端 agent（macOS/Linux） | Beta（2026-08-05） |
| Amazon | Kiro | IDE + CLI + Web + 移动端 | GA，spec-driven |
| Microsoft/GitHub | Copilot（含 coding agent / Agent Mode / SDK/CLI） | IDE + 云端 + SDK | 活跃，多模型 |
| Microsoft | Agent Framework（MAF） | 开源框架 | 1.0 GA（2026-04-03） |
| 开源 | LangGraph / OpenHands / CrewAI | 框架/平台 | 活跃 |

**证据可信度分级**（下文表格沿用）：
= 一级官方来源 ｜ = ≥2 独立来源一致 ｜ = 仅一家第三方来源 ｜ = 厂商自报未经独立验证 ｜ = 未找到公开证据

---

## 2. 双寡头格局与 harness 方法论警示

### 2.1 SWE-bench Verified（500 任务，patch 正确性）

| 模型/系统 | 成绩 | 性质 | 日期/来源 |
|---|---|---|---|
| Claude Opus 5 | 96.0% | 自报 | 2026，idea2app 转述 |
| Claude Opus 4.8 | 88.6% | 第三方转述发布会 | 2026-05-28 |
| Claude Opus 4.7 | 87.6% | 自报 | 2026-05，marktechpost 榜单 |
| Gemini 3.1 Pro | 80.6% | 转述 Google 数据 | 2026，dev.to |
| GPT-5.1-Codex-Max | 77.9% | 自报（最高 reasoning 档） | 2026，dev.to 转述 |
| Claude Opus 4.6 | 75.6% | 第三方（BenchLM，mini-swe-agent-v2） | 2026-10-02 |
| Sonnet 4.5 / GPT-5 | 77.2% / 74.9% | 转述厂商 | 2026-09-01 验证 |
| Antigravity（平台） | 76.2% | 自称转述 | 2026-09，wildrunai |

注：Claude Opus 5.5（2026-09-22）官方基准表**未再公布 SWE-bench Verified**，转向 Terminal-Bench 4.0（66.4%）、OSWorld 2.0（81.8%）、GDPval-AA v2.1（1846 Elo）——SWE-bench 饱和后厂商正迁移到更难的 agentic 基准。

### 2.2 SWE-bench Pro（1,865 任务，更难）

Opus 5：79.2%（自报）；Opus 4.8：69.2%；Opus 4.7：64.3%（Anthropic 对比表）；GPT-5.5：58.6%（自报）；GPT-5.3-Codex：56.8%（2026-02 自报）；Gemini 3.1 Pro：54.2%（Anthropic 对比表）。

### 2.3 Terminal-Bench（终端实战，Harbor 容器化，binary pass@1）

- **TB 2.0 官方榜**（tbench.ai）：Codex CLI + GPT-5.5 **82.2%**；Codex CLI + GPT-5.2 62.9%；Claude Code + Opus 4.6 58.0%；OpenCode + Opus 4.5 51.7%。
- **TB 2.1 榜**（公开 cost 列）：Claude Code + Fable 5 **83.8%**（$553/run）；Codex + GPT-5.5 83.1%（$2,059/run，4 倍成本）；Cursor CLI + Grok 4.5 79.3%（$134/run，top5 最便宜）；设 "Hacks" 列扣作弊分。
- TB 3（更难）：最佳约 43.5%；TB 4.0：Opus 5.5 66.4%（自报）、GPT-6 Astra 57.9%（自报）。

### 2.4 其他基准

- **SWE-Lancer**（Upwork 真实任务）：原始论文（2025-02）Claude 3.5 Sonnet Diamond 集 $208,050 / $500,800；**2026 年无新一轮公开成绩**，已边缘化。
- **OSWorld 2.0**（computer use）：Opus 5.5 81.8%（自报）；GPT-6 Astra 72.6%（自报）；GPT-5.3-Codex 64.7% OSWorld-Verified（2026-02 自报）。
- **DeepSWE v1.1**：GPT-6 Sol 68.8% vs Claude Fable 5 69.9%（转述 OpenAI，成本差 80%）。
- Devin / Jules / Kiro / Grok / Manus：**均无公开标准基准成绩**；Devin 自报 PR 接受率 68.0%（aligned window，口径不明）。

> **方法论警示**：同一模型换 harness 可差 22pp（Opus 4.6 在 TB 2.0 十一次上榜 80.2%→58.0%）；原始 Scale AI 统一 SWE-Agent scaffold 下 GPT-5 仅 23.3%，同一基准在不同 scaffold 下可从 23% 报到 79%。**所有高分都必须标注 harness，否则无意义。**

---

## 3. 版图变化：并购与新玩家

- **Windsurf → Devin Desktop**：Cognition 收购 Windsurf 后更名，Cascade agent 延续，技能兼容 `.claude/skills` 与 `.agents/skills`。
- **Manus 收购→剥离→独立**：Meta 2025-12 以约 20 亿美元收购，2026-04 被中国监管要求剥离，2026-09 Manus 恢复独立运营。
- **Meta 自推 Muse Code**：2026-08-05 发布的终端 agent（macOS/Linux），Beta；亮点是 append-only 本地 event log（含 approval 记录、可断点恢复）；另于 2026-09-28 发布企业平台（无定价/SLA）。
- **Gemini CLI 并入 Antigravity CLI**（2026-06-18），独立时代结束；Antigravity 2.0 走平台路线（IDE+CLI+SDK+Managed Agents）。
- **"免费 land-grab 结束"**：Antigravity 免费档 2026-03 从 250 req/天砍至约 20 req/天，premium 模型改周刷新。

---

## 4. 能力面：扩展层已标准化，执行层仍分化

### 4.1 MCP：事实标准，但服务器在沙箱之外

MCP 规范现行修订版 **2026-07-28**（stateless core；Client ID Metadata Documents 取代 Dynamic Client Registration；Roots/Sampling/Logging 弃用；附安全公告 APS-2026-01）；传输以 **Streamable HTTP** 取代 SSE；2026-09-13 **Skills 扩展**（`io.modelcontextprotocol/skills`，SEP-2640）合入主分支，新增 `skills/list`、`skills/get`，基于 Resources 原语、带 SHA-256 清单。

安全共识：tool descriptions 是不可信输入；2026-01-20 披露的 mcp-server-git 三个 CVE 可经 prompt injection 链至 RCE。Codex 官方文档明确 **MCP 服务器在沙箱之外**——这是全行业共同的风险面。

### 4.2 Skills / 子代理 / Hooks / Plan Mode 已成标配

- **Agent Skills 开放标准**（Anthropic，2025-12）：`SKILL.md` + frontmatter，未调用前仅占约 30–50 tokens；OpenAI（Codex CLI/ChatGPT）、Cursor 已采用，40+ 客户端。Northstar 的 `.northstar/skills/<name>/SKILL.md` 只读包与该格式对齐。
- **Hooks**：Claude Code（PreToolUse/PostToolUse/…/PermissionRequest，确定性脚本）、Cursor（约 18 事件，兼容 Claude Code settings.json hooks）、Cascade（12 事件，**exit 2 = 阻断 fail-closed**）三家最完整；Codex 的 hooks 未暴露到 SDK 表面。Northstar hooks 为 veto-only 事件集 + interpreter allowlist。
- **子代理**：普遍支持；Claude Code 有 Agent Teams（2026-02）与 worktree 隔离；Codex 云端并行任务（50–300 / 5h 窗口）。Northstar 子代理为固定工具子集 + ceilings，且**不可放宽父级拒绝**。
- **Plan Mode**：Claude Code / Codex（云）/ Cursor / Antigravity / Devin（plan-first）/ Jules（plan→审批→执行→PR 强制流程）/ Kiro（spec-driven）/ Muse Code（`/plan` 审批门）全部覆盖；Northstar 尚无产品化 plan mode。

---

## 5. 架构与安全：权限模型 / 沙箱 / 供应链

### 5.1 权限模型

| 产品 | 模型 | 特点 |
|---|---|---|
| Claude Code | **单轴** permissionMode：default/acceptEdits/plan/dontAsk/auto/bypassPermissions + allowedTools/disallowedTools | 沙箱与审批合一；逃生舱 `--dangerously-skip-permissions` |
| Codex | **双轴**：sandbox_mode（read-only/workspace-write/danger-full-access）× approval_policy（on-request/never/granular） | 职责分离；granular 可按类别配置；named permission profiles 支持 deny 路径规则与 `[network.domains]`；逃生舱 `--yolo` |
| Cursor | 三模式：Run Everything / Auto-Run in Sandbox / Ask Every Time | 沙箱命令默认 deny 网络代理 + 团队网络 allowlist |
| Devin | plan-first + approval cards（环境/secret/部署/网络访问，Slack 可批）+ `bypass_approval` API 参数 | 人门在关键动作 |
| Grok CLI | 权限提示展示完整脚本；`--tools` **allowlist**（非 denylist，fail-safe）；sandbox deny-glob | allowlist 语义优于 denylist |
| Copilot | tiered approval（session/workspace/user）；assisted approvals（AI 自动批低风险） | AI 代批是新风险面 |
| Northstar | **default-deny 三层门**：permission gate（kind=exec 默认 DENY，acceptEdits 不覆盖）→ hooks veto → per-call action gates；policy 只能收紧（ceilings 取 min、denials 取 union）；子代理/插件不可放宽父级 | 最严格的默认姿态 |

### 5.2 沙箱机制

| 产品 | 沙箱原语 | 范围说明 |
|---|---|---|
| Claude Code | macOS Seatbelt / Linux bubblewrap | 命令继承沙箱边界 |
| Codex | macOS Seatbelt；Linux/WSL2 **bwrap + seccomp**，Landlock 为兼容回退；Windows 自研沙箱 | Linux 默认 `--ro-bind / /` 整盘只读；workspace-write 下 `.git`/`.agents`/`.codex` 仍只读；MCP 服务器在沙箱外 |
| Jules | 每任务全新 Google Cloud VM | 最强隔离之一，但 prompt injection 外泄风险被披露过 |
| Cursor | IDE 沙箱 + 沙箱命令 default-deny 网络代理；Cloud Agents 隔离 Ubuntu VM | 云强、本地中等 |
| Grok CLI | Landlock/Seatbelt（仅 Linux/macOS）；作用于**整个进程**而非逐命令包装；沙箱不可逆 | 进程级设计独特 |
| Northstar | bwrap 后端（/usr 只读绑定、仅 workspace 可写、unshare net/pid/ipc/uts、--die-with-parent、env scrubbed）优先；缺 bwrap 时**诚实降级**为 process 后端并明示非 OS 隔离 | 诚实标注隔离等级 |

### 5.3 供应链安全

- Codex 官方 cyber 配置拒绝 `**/.env*`、`**/*.pem` 读取（deny-glob 最佳实践）。
- Northstar：无 marketplace、无远程拉取；bundle 只能收紧不能放宽；带 `env` 的 MCP server 在加载时被拒（防插件经 env 侧信道带 secret）；MCP server 默认 mutating-by-default、未命名即 deny——对照组中最彻底的供应链保守姿态。

**小结**：沙箱原语各家趋同（Seatbelt/bwrap/seccomp/VM 四件套），差异在**默认策略的严格度**（Northstar default-deny 最严；Codex 默认整盘可读但可配 deny）与 **MCP 是否在沙箱内**（普遍不在，共性短板）。

---
## 6. 治理专项：评权限门空白、审计与企业版绑定

### 6.1 谁在"评权限门决策"（而非只评模型输出）

| 主体 | 对象 | 形态 | 证据 |
|---|---|---|---|
| **Northstar** `northstar bench` | 自家三层权限门：denial 正确性、注入抵抗、budget 命中率 | **离线、确定性**，JSON 版本化 scorecard | |
| **ActionGuardBench**（独立第三方） | 任意 guardrail/审批系统：判 ALLOW/ASK/BLOCK | 离线基准 | |
| GuardianBench（独立第三方） | action-firewall：FN/FP/refusal | 确定性、无需模型 | |
| Anthropic Auto Mode | Sonnet 分类器评审每个动作 | research preview，**无公开基准分** | |
| OpenAI Codex `auto_review` | 评审 agent 代人工批 | 机制存在，**无公开基准分** | |
| Devin Planning Critic | 第二 agent 评审自动批准的 plan | 评 plan 质量**非权限门**，自报 | |
| 其余所有商业产品 | — | **只评任务完成**（SWE-bench/TB 类） | — |

**结论**：商业产品侧"评权限门"几乎空白；唯一成体系、可离线复跑的是 **Northstar governance bench** 与独立第三方的 ActionGuardBench——这是治理维度的结构性洼地，也是 Northstar 差异化最锋利之处。

### 6.2 谁有审计追踪

- **有（企业版）**：Cursor（仅企业）、Copilot（agent attribution + agent_session.task）、Devin（企业 API 审计端点）、Kiro（prompt logs + activity reports）、Anthropic Enterprise（audit logs + compliance API）。
- **有（本地/产品内）**：Muse Code append-only 本地 event log（含 approval 记录）；Cascade `post_cascade_response_with_transcript` hook；LangGraph checkpoint/time-travel + LangSmith；MAF OpenTelemetry。
- **结构化程度最高**：Northstar `audit.ndjson/1` 规范信封——transcripts、durable events、host grants（actor/run/workspace/policy revision/expiry）统一导出，可直灌 SIEM。商业产品中无同等"审计 feed 规范"公开。

### 6.3 谁是确定性离线可测的

- **是**：Northstar（`make demo`/`northstar bench` 全离线）；ActionGuardBench/GuardianBench；ADK `adk eval`（确定性取决于 judge 模型）。
- **否**：所有商业云 agent（Devin、Manus、Jules、Codex 云、Copilot coding agent）——评测依赖在线模型与云沙箱；Terminal-Bench 虽容器化可复跑，但评的是任务完成而非治理，且成本高昂（单 run $134–$2,059）。

### 6.4 格局总览：三层断裂

(1) 任务基准极度繁荣（SWE-bench/TB/OSWorld 内卷）；(2) 权限门评估无人认领（除 Northstar 与独立第三方）；(3) 审计能力与付费档位强绑定（企业版才有）。**买方启示**：若把"可审计、可离线验证权限决策"列为硬性要求，2026-10 的商业产品无一开箱满足——只有 Northstar（开源、自托管）与自研 guardrail + ActionGuardBench 的组合能覆盖。

---

## 7. 模型支持：自有 vs 多模型

| 产品 | 模型策略 |
|---|---|
| Claude Code | 仅 Anthropic（Opus 5/5.5、Sonnet 5/5.5、Fable 5/5.1、Haiku）；**无多模型路由** |
| Codex | 仅 OpenAI（GPT-5.6 Sol/Terra/Luna、GPT-5.5/5.4、GPT-6 Sol/Luna/Astra）；**无多模型路由** |
| Antigravity | **多模型**：Gemini 3.1 Pro/Flash + Claude Sonnet/Opus 4.6 + GPT-OSS 120B |
| Cursor | **多模型最强**：Claude 5 系、GPT-5.6 系、Gemini 3.1 Pro/3.8 Flash、Muse Spark 1.3、Grok 4.7、自研 Composer 2.5 |
| Devin | 多模型：OpenAI + Claude + Gemini 前沿 + 自研 SWE 1.6（Pro 以上） |
| Copilot | **多模型**：OpenAI/Anthropic/Google 精选 + auto model selection |
| Grok / Muse Code / Jules / Kiro | 仅自家模型（Grok 4.3/4.5/4.7；Muse Spark 1.2；Gemini；Claude Sonnet 3.7/4.0 系） |
| LangGraph / MAF / CrewAI / ADK | 模型无关 |
| Northstar | sidecar 绑定 codex CLI（单模型路径）；interop 适配器可接 Codex/Claude Code/Cursor CLI（默认禁用） |

**小结**：Anthropic 与 OpenAI 坚持单厂商闭环；Cursor、Antigravity、Copilot、Devin 走多模型路线；开源框架天然模型无关。

---

## 8. 定价与生态

> **口径警告**：以下为 2026-09/10 第三方快照（美元/月，税前），价格变动频繁，**决策前请复核官网**。

| 产品 | 入门 | 重度 | 团队/企业 | 计费方式 |
|---|---|---|---|---|
| Claude Code | Pro $20（年付 $17） | Max 5x $100 / 20x $200 | Team $25/席；Enterprise ~$20/席+用量 | 订阅（5h 滚动窗口+周限额） |
| Codex | ChatGPT Plus $20（含） | Pro 5x $100 / 20x $200 | Business $20/席；Codex-only seat 去限流 | token-based 全档 |
| Antigravity | Free ~20 req/天 | AI Pro $19.99 / AI Ultra $100 / Ultra Max $200 | 企业经 Gemini Enterprise Agent Platform | 订阅+credits overage |
| Jules | Free 15 tasks/天 | AI Pro $19.99（100/天）/ Ultra $124.99（300/天） | 无 | 任务数 |
| Cursor | Hobby 免费 | Pro $20 / Pro+ $60 / Ultra $200 | Teams $40/席；Premium $120/席；Enterprise 定制 | 双池（Cursor Models + 第三方 API credits） |
| Devin | Free $0 | Pro $20 / Max $200 | Teams $80 起+$40/席；Enterprise 定制（ACU） | quota + on-demand credits |
| Manus | Free（300 日刷新） | $20（4k credits）/ $40（8k）/ $200（40k，含云电脑） | Team $20/席共享池 | credits |
| Kiro | Free 50 credits | Pro $20 / Pro+ $40 / Pro Max $100 / Power $200 | IAM Identity Center 集中管理 | credits（口径年内多次变更） |
| Copilot | Pro $10 / Pro+ $39 | Max $100 | Business $19/席；Enterprise $39/席 | 订阅 + AI credits |
| Muse Code | — | pay-as-you-go：标准 $1.25/$4.25 per MTok；**Contributor $0.10/$0.20（以训练数据换折扣）** | 企业平台（2026-09-28，无定价） | 按量 |
| 开源框架 | 免费 | 自付模型 token | 自托管 | BYOK |

生态：Claude Code 的 Skills/Plugins 已成为跨厂商兼容的"普通话"（Antigravity、Cursor、Cascade、Grok 均兼容）；IDE 覆盖最广的是 Copilot；Kiro 的"spec 落盘"、Cursor 的"双池计费"、Meta 的"数据换折扣"是差异化定价实验。

---

## 9. Northstar AgentOS 对照点评

对照对象：github.com/fny666/northstar-agent-os（`0.1.0.dev0`，未正式发布）。

### 9.1 领先之处（商业产品无同类公开机制）

1. **离线确定性 governance bench 评权限门**：`northstar bench` 评 denial 正确性、注入抵抗、budget 命中率，JSON 版本化（northstar.governance.bench.v1），`make bench` 与产品入口同一代码路径防漂移。商业产品中无任何同类机制。
2. **NDJSON 审计 feed 规范**：`audit.ndjson/1` 信封统一导出 transcripts、durable events、host authorization grants（含 actor/run/workspace/policy revision/expiry），可直灌 SIEM（fluent-bit/rsyslog），附告警阈值 runbook。商业产品审计多为企业版黑盒功能，无公开 feed 规范。
3. **事件溯源的 durable 执行**：append-only 事件历史 + leases + per-call action gates + 独立 postcondition verifier（"trust the history, not the worker's report"），崩溃可恢复、幂等重放。商业云 agent 的"恢复"多为会话续跑，无事件溯源语义。
4. **默认最严的权限姿态**：permission gate default-deny（kind=exec；acceptEdits 不覆盖）→ hooks veto → per-call gates 三层；policy 只能收紧（ceilings 取 min、denials 取 union）；子代理/插件不可放宽父级；MCP server 默认 mutating-by-default、未命名即 deny、带 `env` 的 server 加载即拒。横向对比：Codex 默认整盘可读、Cursor 三模式需用户选——Northstar 是唯一 default-deny 且不可放宽的设计。
5. **诚实的隔离分级**：bwrap 可用时 OS 隔离，否则诚实降级为 process 后端并在每次执行中明示 `isolation=process`（"不是 OS 隔离"）。商业产品极少如此自我披露。
6. **MCP 客户端加固是真实能力（含 seccomp-BPF）**：调研报告原文称 seccomp-BPF"未证实"，**此为调研员误判，特此勘误**——仓库内 `components/northstar-agent-runtime/tools/seccomp.py` 真实存在（纯 Python classic-BPF 汇编器，无 libseccomp 依赖），配套 `tests/test_seccomp.py`、`tests/test_mcp_seccomp.py`，bwrap 后端经 `bwrap --seccomp` 加载、process 后端经 `python3 -c` prctl wrapper 应用（`--seccomp auto|on|off`，tighten-only），已在 main 分支。连同 env allowlist（`_FIXED_ENV`）、MCP 默认拒绝、拒 `env` 侧信道，构成对照组中最完整的 MCP 客户端纵深防御。

### 9.2 齐平之处

- 沙箱原语（bwrap/namespace/env scrub/seccomp-BPF）与 Codex/Claude Code 同代；
- Skills（SKILL.md 只读包）、subagents（固定工具子集）、hooks（veto-only）与主流扩展模型对齐；
- `AGENTS.md` 项目指令、MCP 客户端（stdio）与生态兼容。

### 9.3 落后之处（客观短板）

1. **无模型生态**：sidecar 绑定 codex CLI（单模型路径）；多模型路由无；interop 适配器默认禁用。
2. **无分发与成熟度**：0.1.0.dev0，无 release tag、无 pip 发布、无 TUI、无托管云；Linux 倾向（bwrap）。
3. **无基准成绩、无生态**：零公开 benchmark、无插件市场、无 IDE 集成；MCP 支持标注 experimental。
4. **能力面窄**：无 plan mode 产品化形态、无 agent teams、无 background tasks 调度（商业产品 2026 年标配）。
5. **定位天花板**：自述"非完整多 agent OS、非生产就绪、非企业身份栈替代"——它更像"治理内核"而非"智能体产品"。

**一句话点评**：Northstar 在"治理"这一无人区是**代际领先**（把权限门变成可离线评分、可审计、可事件溯源的工程对象）；在"智能体产品"维度则**落后约 1–2 个产品世代**。它最现实的定位是：商业 agent 的**治理侧车/审计与权限内核**，而非正面替代品。

---

## 10. 对比矩阵表

### 10.1 能力与架构矩阵

| 产品 | MCP | Skills | 子代理 | Hooks | Plan 模式 | 权限模型 | 沙箱 | 多模型 |
|---|---|---|---|---|---|---|---|---|
| Claude Code | ✅ | ✅（标准制定） | ✅（+Teams） | ✅ | ✅ | 单轴 | Seatbelt/bwrap | ❌ |
| Codex | ✅（沙箱外） | ✅ | ✅ | ⚠️（SDK 未暴露） | ✅（云） | **双轴** | bwrap+seccomp | ❌ |
| Antigravity | ✅ | ✅（跨兼容） | ✅ | ✅ | ✅ | 三模式 | 平台原生 | ✅ |
| Jules | ⚠️白名单 | — | ✅（内部） | — | ✅（强制） | plan 门+VM | 云 VM | ❌ |
| Cursor | ✅ | ✅ | ✅ | ✅（~18 事件） | ✅ | 三模式 | IDE+云VM | ✅（最强） |
| Devin Desktop | ✅ | ✅（跨兼容） | ⚠️（无命名） | ✅（12 事件，exit2 阻断） | ✅ | approval cards | IDE | ✅ |
| Devin | ⚠️有限 | ✅ | ✅ | — | ✅ | approval cards | 云 VM/VPC | ✅ |
| Manus | 未公开 | ✅ | ✅ | — | — | 云 VM | 云 VM | ✅（自称） |
| Grok Build | ✅ | ✅（兼容） | ✅（8 并行） | — | ✅ | allowlist+deny-glob | Landlock/Seatbelt | ❌ |
| Muse Code | 未公开 | ✅（/plan//grill//goal） | ✅（持久） | — | ✅ | 未公开 | 未公开 | ❌ |
| Kiro | ✅ | steering+hooks | ✅（并行） | ✅（agent hooks） | ✅（spec） | autopilot/supervised | IDE | ❌（暂） |
| Copilot | ✅（allowlist preview） | ✅ | ✅ | ❌ | ✅ | tiered+AI 代批 | 分层+云 | ✅ |
| LangGraph | ✅（第一方） | — | ✅（subgraph） | —（图节点） | — | 开发者自定 | 自带 | ✅ |
| MAF | ✅+A2A | — | ✅（Team） | middleware | — | 开发者自定 | Foundry micro-VM | ✅ |
| OpenHands | ✅（OAuth） | — | ✅ | — | — | least-privilege | Docker | ✅ |
| CrewAI | ✅+A2A | ✅（输出方） | ✅（Crew） | — | — | 开发者自定 | 自带 | ✅ |
| Agents SDK | ✅（第一方） | — | ✅（handoff） | guardrails | — | needs_approval | 无 | ❌（OpenAI） |
| ADK | ✅ | — | ✅ | callbacks | — | per-tool 确认 | 无 | ✅ |
| Northstar | ⚠️（experimental，默认 deny） | ✅ | ✅（受限） | ✅（veto-only） | ❌（产品化无） | **default-deny 三层** | bwrap | ❌ |

### 10.2 治理矩阵（专项）

| 产品 | 评权限门决策 | 审计追踪 | 确定性离线测试 |
|---|---|---|---|
| Claude Code | ❌（Auto Mode preview，无基准） | ⚠️（企业版；或 hooks 自建） | ❌ |
| Codex | ❌（auto_review 机制，无基准） | ⚠️（云端；Compliance API 云） | ❌ |
| Antigravity | ❌ | ❌（未公开） | ❌ |
| Jules | ❌（Planning Critic 评 plan） | ❌ | ❌ |
| Cursor | ❌ | ⚠️（仅企业） | ❌ |
| Devin | ❌ | ⚠️（企业 API） | ❌ |
| Manus | ❌ | ❌ | ❌ |
| Grok | ❌ | ❌ | ❌ |
| Muse Code | ❌ | ✅（本地 append-only event log） | ❌ |
| Kiro | ❌ | ⚠️（prompt logs，企业） | ❌ |
| Copilot | ❌ | ⚠️（企业，agent attribution） | ❌ |
| LangGraph | ❌ | ✅（checkpoint/time-travel+LangSmith） | ⚠️（图可单测） |
| MAF | ❌ | ✅（OTel） | ⚠️ |
| OpenHands | ❌（/goal judge 评完成） | ✅（自报全动作日志） | ❌ |
| Agents SDK | ⚠️（guardrails 可自测） | ✅（tracing） | ⚠️ |
| ADK | ❌ | ✅（Cloud Trace） | ⚠️（adk eval） |
| **Northstar** | ✅（governance bench） | ✅（audit.ndjson/1） | ✅ |
| ActionGuardBench（第三方） | ✅（独立基准） | — | ✅ |

---

## 11. 结论

1. **选型按任务分层**：硬核多文件重构/代码质量 → Claude Code；终端/DevOps 长程任务 → Codex；IDE 日常 + 多模型 → Cursor；异步批量 PR → Jules/Codex 云；企业 GitHub 原生 → Copilot；预算敏感/可审计 → 开源（OpenHands/LangGraph）+ 自备模型。没有单一产品在三层全胜。
2. **harness 决定成绩**：基准数字必须带 harness、版本、日期四要素；SWE-bench Verified 已饱和（90%+），前沿转场到 Terminal-Bench 3/4.0 与 OSWorld 2.0。
3. **治理是 2026 年最大的能力洼地**：商业产品在"评权限门"上集体缺席，审计与企业版付费绑定。若合规要求"权限决策可验证"，当前唯一开箱组合是 Northstar（或自研 guardrail + ActionGuardBench）。
4. **标准统一、执行分化**：MCP + Agent Skills 已成为跨厂商"普通话"，但各家在"谁来执行、如何隔离、谁可审计"上深度分化；MCP 服务器在沙箱之外是全行业共性风险。
5. **Northstar 的定位建议**：不建议将其作为智能体产品正面选型；建议评估其作为**高合规场景下商业 agent 的治理侧车**（权限门 + NDJSON 审计 + durable 执行），或其 governance bench 方法论被现有 harness 吸收。

---

## 12. 未能验证 / 待补充

1. **Claude Code MCP 协议版本与传输细节**：官方文档确认支持 MCP，但具体协议版本（2025-06-18 / 2026-07-28）未在已读页面确认。
2. **MCP 规范 2026-07-28 与 Skills 合入（SEP-2640）**：仅单一第三方来源，建议以规范仓库（modelcontextprotocol/spec）复核后再引用。
3. **Manus 收购/剥离时间线**：多源确认"收购→监管剥离→独立"，但交易金额（~$20 亿）与具体月份各源口径有出入。
4. **Kiro 定价口径**：2026 年内多次变更（interactions → credits），各第三方快照数字冲突（225 vs 1,000 credits/Pro），以 kiro.dev 实时页面为准。
5. **Anthropic Auto Mode**：仅见单一第三方指南提及"研究预览"，未见官方文档，存在性与范围待确认。
6. **各厂商基准分**：除标注"官方榜"的 TB 数据外，其余多为厂商自报或第三方转述；Devin/Jules/Kiro/Grok/Manus 均无公开标准基准成绩。
7. ~~**Northstar seccomp-BPF**：调研原文称未证实~~ —— **已勘误**：仓库内 `components/northstar-agent-runtime/tools/seccomp.py`（+ `tests/test_seccomp.py`、`tests/test_mcp_seccomp.py`）真实存在，已在 main 分支，见 §9.1 第 6 条。
8. **Cursor/Devin 等的实时 sandboxes 细节**：部分基于 2026-06 preview 公告，GA 状态未逐一复核。
9. 本报告未做实时浏览器逐项验证定价页（价格变动频繁），定价以 2026-09/10 第三方快照为准，决策前请复核官网。

---

## 13. 来源与可信度

调研执行：2026-10-03，隔离 deep-research 案头调研。原始完整报告（含逐条 URL 与读取时间）见 `~/workspace/research_notes/top-ai-agents-comparison-2026-10-20261003-0804/report.md`。关键来源分组如下：

- **官方文档**：code.claude.com/docs（Claude Code 多表面/统一引擎）；learn.chatgpt.com 引述（Codex CLI v0.155.1 沙箱/审批/permission profiles）；OpenHands 官方通稿（控制平面）；Antigravity 官方博客转载（定价档调整）。
- **基准**：tbench.ai / benchlm.ai（TB 2.0 官方榜、SWE-b-V*）；genztech.blog（Opus 5.5 基准表）；arxiv.org/pdf/2502.12115（SWE-Lancer 论文）；marktechpost.com（2026-05 榜单与 SWE-bench Pro 方法论）。
- **版图/并购**：macrumors.com、newsbytesapp.com（Muse Code 发布）；nocode.mba、simular.ai（Manus 收购剥离时间线）；gald3r-labs（Windsurf→Devin Desktop 更名）。
- **治理专项**：github.com/shuhansun/agent-action-safety-benchmark（ActionGuardBench）；github.com/vadale/project-guardian（GuardianBench）。
- **Northstar 自身**：github.com/fny666/northstar-agent-os 的 README、CHANGELOG、docs/concepts/threat-model.md、northstar-host README（官方文档口径）；**seccomp-BPF 的存在性另经仓库代码直接核对**（`tools/seccomp.py` + 双测试文件，main 分支）。
- **定价**：allaboutcookies.org、flexprice.io（Cursor）；morphllm.com、vibecoding.app（Claude）；dev.to/dmaxdev（Jules）；marktechpost.com（企业 500 席对比）——均为第三方快照，决策前复核官网。
