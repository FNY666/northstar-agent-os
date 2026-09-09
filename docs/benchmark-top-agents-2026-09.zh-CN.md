# Northstar Agent OS — 对标全球顶级 agent 工具（2026-09-08 能力与链路审计）

> 编制日期：2026-09-08 ｜ 范围：**能力面 + 架构链路闭合**（不是 DX；DX 口径见 [dx-benchmark-2026.zh-CN.md](dx-benchmark-2026.zh-CN.md)，其 §10 已把十维从 23 推到 36）
> 方法：本地实测（全仓测试运行 + 两处问题最小复现）+ 外部公开资料（官方规范/文档优先，第三方评测标注）
> 定位：本报告是分析文档，含 3 项可直接开工的 P0 修复建议，但**未做任何代码改动**。

---

## 0. 执行摘要

**内核不必再对标了，外壳要，链路必须补。** 三句话：

1. **机制层已齐平甚至领先**：10 事件 hooks + 三层权限门 + 收紧型仓库策略（`northstar.policy.v1` + 修订号）+ 唯一 `ResultMessage` + 语义退出码 + NDJSON 审计 feed + **1239 项离线确定性测试**（无 key、无网络）。后三项在 Claude Code / Codex / LangGraph 里都**没有一手等价物**——这是真实护城河，不是自我安慰。
2. **但有三个"未闭合"是本次新发现的，且不在既有差距清单里**：(a) Run Contract 的绑定/回执**没有进入唯一真实执行路径**（runtime 自己实现了 sidecar wire 格式，`adapter.to_sidecar_request` 只在自己测试里被调用）；(b) `.northstar/` 治理目录**不在写保护前缀里**，agent 可改写自己的策略文件（已复现）；(c) `durable-run` 的 checkpoint/lease/verifier 与 runtime **未接线**，可恢复执行是"有零件没整机"。
3. **标准代际正在拉开**：MCP 现行规范 **2026-07-28** 已改为无状态（移除 `initialize` 握手与会话）并用 MRTR 承载服务器→客户端交互；Northstar 客户端仍是 stdio + 旧握手。Claude Code 的 hook 面已到 **31 事件 × 5 类 handler 且可在 settings 声明**，Northstar 的 hooks **只能 Python 注册、无法写进 config.toml**——这一条对"策略即代码"的叙事比分数更伤。

**结论**：对标顶级工具，Northstar 输的不是深度是**闭合度与代际**。P0 三项（约 1–2 周）把治理链真正焊在执行路径上；P1 四项（4–8 周）追代际；产品面（TUI/IDE/自建云）明确不做。

> **2026-09-08 更新**：P0 四项（含新增的 F3 前置项）已随第十三批落地，全仓 830 → 890 项测试全绿；F1/F2 已闭合、F3 未动。
> **同日第十四～十八批**：F3（检查点/派生恢复）、P1-2（多模型 + 独立完成判定）、`skills check`（技能供应链门）、**P1-1（MCP 2026-07-28 代际 + elicitation 走审批门）**、**token 级流式（`--stream`，带流-记录一致性校验）**、**durable 统一（会话一写者 + 检查点↔durable 事件双向翻译）**全部落地，全仓 **1239 项全绿**（runtime 942）。下表与 §4/§5 的"待做"标记已按此同步；仍未做：显式重试/退避/降级、OS 级沙箱、sidecar 侧 binding 校验。吸收"顶级优点"的取舍判据与冲突清单见 [next-gen-agent-blueprint.zh-CN.md](next-gen-agent-blueprint.zh-CN.md)。
> **同日第五批（执行边界 P0-7 / F5）**：MCP 子进程从「全量继承父环境」改为白名单；仓库声明起进程另需`--mcp-allow-exec`；`command` 形状与 hooks 同尺（shell / 内联脚本拒，`${VAR}` 展开后判定、wrapper 前缀剥壳）；`system:init` 记 `mcp` 段（argv 摘要、env 键名、`sandboxed:false`）；`--mcp-allow-roots` 报的 root 修成`--workspace`。上表 MCP 行已按此改写。未闭合的一条仍是「服务器子进程不经 OS 沙箱」，理由写在 audit §12.2。
> **2026-09-09 第三轮（执行路径与治理税）**：本轮基线已复测为 **1612 项全绿**（runtime 1294）；**F2 被证实只闭合了一半**——`protected_prefixes` 只拦文件工具，`Shell` 与 MCP 子进程都能改写 `.northstar/` 与 `.git/`（含一条"沙箱内植入、沙箱外 `git` 执行"的复现链），并且中毒之后 `sessions checkpoints` 仍报 `[verified]`，因为摘要只覆盖 transcript。三条新发现（F4/F5/F6）、治理税的毫秒数与修订后的路线见 [execution-boundary-audit-2026-09.zh-CN.md](execution-boundary-audit-2026-09.zh-CN.md)。

---

## 1. 口径：跟谁比、凭什么说

| 层 | 对标对象 | 为什么是它 |
|---|---|---|
| 直接参照系 | **Claude Code / Claude Agent SDK** | hooks 词汇、子代理、权限语义、AGENTS.md↔CLAUDE.md 全部以它为模板，是能力对表的基准 |
| 同类竞品 | **OpenAI Agents SDK v2 + Codex harness** | 2026-04-15 v2 加了原生沙箱、harness/compute 分离、snapshot/rehydrate——与 Northstar 的 sidecar 分权几乎同题 |
| 同类竞品 | **LangGraph（+Temporal）** | durable-run 的直接对手：super-step 检查点、time-travel、interrupt；Temporal 是事件溯源可恢复执行的标尺 |
| 横向参照 | **Gemini CLI / Antigravity、OpenHands** | checkpointing、rewind、gVisor 沙箱、plan mode 的功能清单来源 |
| 标准裁判 | **MCP 2026-07-28、Agent Skills、AGENTS.md、A2A** | 生态兼容性的唯一客观度量 |

**证据可信度分级**（下文表格沿用）：
🟢 = 官方规范/文档｜🟡 = 多源第三方印证｜🔴 = 单一第三方口径（存疑）｜✅ = 本地实测复现

---

## 2. 本地实测基线（2026-09-08）

| 项 | 实测 |
|---|---|
| 测试 | **1239 项全绿**：sidecar 51 + run-contract 41 + host 37 + durable-run 65 + interop 54 + runtime 942（4 skip：未装 `anthropic`）+ 仓库文档 49 ✅ |
| 代码量 | 非测试 Python 15,493 行；测试 12,724 行（≈0.82:1）；Markdown 6,332 行 ✅ |
| 打包 | 6 组件均有 `pyproject.toml`，统一 `0.1.0.dev0`，console script `northstar-agent-runtime`；`make install` 同 venv 通过 ✅ |
| hooks | 10 事件；veto 5 个（`PreToolUse`/`UserPromptSubmit`/`SessionStart`/`PreCompact`/`SubagentStart`）；**handler = Python 可调用对象，无 command/http/mcp_tool 型** ✅ |
| 权限 | 4 模式（`default`/`acceptEdits`/`plan`/`bypassPermissions`）；`disallowed_tools` 连 `bypassPermissions` 也不能覆盖 ✅ |
| 内置工具 | `Read`/`Write`/`Edit`/`LS`/`Grep`/`DescribeTools`（+ 条件 `Task`、`CodexReadOnly`）；**无 shell、无网络工具** ✅ |
| 工具沙箱 | `realpath` 先于包含性检查、写路径保护前缀默认 **仅 `(".git",)`** ✅ |
| MCP | stdio 子进程、`server/discover` 探测 2026-07-28 无状态代际并回落旧 `initialize` 握手、MRTR `input_required` 多轮、elicitation 走审批门（默认全拒）、roots 仅 `--mcp-allow-roots` 且只报`--workspace`、`mcp__<server>__<tool>`、**默认 deny**、单服务器 25 工具上限、无 sampling/prompts、无重连；**第二道闸门（第五批）**：读声明≠起进程（`--mcp-allow-exec`）、`command` 不能是 shell 或内联脚本、子进程环境是白名单（`${VAR}` 要 `--mcp-env` 点名）、init 记 `mcp` 段（argv 摘要 + `sandboxed:false`） ✅ |
| Skills | `.northstar/skills/*/SKILL.md` 只读渐进披露（仅 name+description 入 prompt，上限 40）；**不执行 scripts/**；无供应链校验 ✅ |
| 策略 | `.northstar/config.toml`，13 个允许键（**不含 `hooks`**），收紧型，未知键/放宽值 fail-closed（实测：写 `permission_mode=bypassPermissions` → 拒绝启动）✅ |
| Provider | `anthropic`（`messages.create` / `messages.stream`，prompt cache 已接）+ `openai_compat`（一个适配器覆盖一片模型，SSE 分片重组 + `stream_options` 取 usage）+ `scripted`（确定性分片）；**token 级流式已落地（第十七批）；仍无显式重试/降级策略** |
| 互操作 | 有 attestation / handoff grant / context envelope / typed receipt + `remote_worker.py --score`（自评 94/100），但**未连接任何真实后端** ✅ |

---

## 3. 能力对标矩阵（16 维）

判定列：**领**=领先头部 / **平**=齐平 / **后**=落后 / **隔**=代际差（不是分数差，是规范换了）

| # | 能力面 | Northstar | Claude Code / Agent SDK | OpenAI Agents SDK v2 / Codex | LangGraph / Gemini CLI | 判定 |
|---|---|---|---|---|---|---|
| 1 | 生命周期 hooks | 10 事件，Python-only | **31 事件** + 5 类 handler（command/http/mcp_tool/prompt/agent），settings 声明式 🟢🟡 | run 级 hooks 为主 🟡 | 无同级抽象 | **后** |
| 2 | 权限门与模式 | 4 模式 + 三层门 + 仓库收紧 | 6 模式（含 `dontAsk`、`auto` 分类器）+ managed settings 下发 🟡 | approval 三级（Suggest/AutoEdit/FullAuto）🟡 | 无原生权限门 | **平**（企业下发缺） |
| 3 | OS 级执行沙箱 | **无**（靠 `codex --sandbox read-only` + 路径沙箱）✅ | seatbelt(macOS)/bubblewrap(Linux) 🟡 | 原生 sandbox + 7 家 provider（E2B/Modal/Daytona/Cloudflare/Vercel…）🟢🟡 | gVisor / 容器 | **后**（安全叙事最大空洞） |
| 4 | 工具面宽度 | 6 内置，无 shell/web | Bash/WebFetch/Glob/NotebookEdit 全套 | apply_patch + shell + git_* 🟡 | 全套 | **有意收敛**（可辩护，但需威胁模型自证） |
| 5 | 并行 / 后台 | 串行工具批、无后台任务 | 默认 20 并发子代理 + background + `isolation: worktree` 🟡 | 跨容器并行、子代理路由到隔离沙箱 🟡 | LangGraph 并行节点 | **后** |
| 6 | 模型层 | 2 真实 provider、可流式、无自动降级 | 多模型 + 自动 fallback（`PostModelSwitch`）🟡 | **100+ 模型**（Chat Completions 兼容）🟡 | model routing / plan mode | **后** |
| 7 | 上下文工程 | compaction 安全边界 + AGENTS.md + skills 披露 | Tool Search 延迟工具定义、memory scopes、per-agent cacheTtl 🟡 | compability 内建、MEMORY.md 双层记忆 🟡 | 状态即上下文 | **平** |
| 8 | MCP 客户端 | stdio、2025 代际握手 | 无 per-server 上限 + 远程 OAuth + `streamable-http` 默认 🟢 | MCP 原生进 harness 🟢 | — | **隔**（2026-07-28 已去会话） |
| 9 | Agent Skills | 只读渐进披露，兼容 SKILL.md 格式 | 40+ 平台标准、脚本执行、插件分发 🟡🟢 | 原生 progressive disclosure 🟢 | 采纳中 | **平**（浅但安全） |
| 10 | 会话与续跑 | append-only JSONL + fsync + `resume` + `sessions list/show/export` | /rewind + checkpoints + 会话 fork 🟡 | RunState/session/snapshot 三级 🟡 | **time-travel + fork from checkpoint** | **平**（弱于 LangGraph） |
| 11 | 可观测 | OTEL span 树（run→turn→generation/tool/subagent）+ NDJSON→SIEM + 本地面板 | OTel + `/context` 🟡 | tracing 内建 | **LangSmith 全链路** | **平**（本地一流，无托管 UI） |
| 12 | 确定性与测试 | **1239 项离线测试 + scripted provider + guard 红绿 harness** ✅ | 无"无 key 全流程演示" 🟡 | 无 | 需 mock 自建 | **领** |
| 13 | 治理可归因 | 唯一 ResultMessage + 语义退出码 + 审计 feed + 策略修订号 ✅ | 有 hooks 审计但无 SIEM feed/修订号 | 有审计但无策略即代码 | 无 | **领** |
| 14 | 契约 / 多代理互操作 | 有零件、**不在执行路径上**（见 F1）✅ | Agent Teams（实验）+ MCP 服务器可充当 🟡 | handoffs 内建 🟢 | subgraphs/swarm | **概念领、落地 0** |
| 15 | 独立验证 / eval | durable-run verifier（后置条件 + 工件摘要）+ 确定性 fixture eval ✅ | **无一手 eval** | 无 | 无 | **领**（但是孤岛） |
| 16 | 分发与生态 | `0.1.0.dev0` 未上架、**TS 面已有（`sdk-ts/`，同样未发布）**、无官方 Action ✅ | pip+npm+市场+GitHub App | pip+npm | pip + Platform | **后** |

**小计**：领先 3（#12/#13/#15，全部集中在"确定性 + 治理 + 验证"）、齐平 4、落后/代际 8、有意收敛 1。
**读法**：分数不是重点——**#3/#5/#6/#8 是可被验证的硬缺口，#14/#15 是"已经有但没接上"**。后者性价比远高于前者。

---

## 4. 三个未闭合（本次新发现，代码级）

### F1 — 治理契约没有站在真实执行路径上 ｜ 优先级最高

```
真实路径：runtime.loop → sidecar_client（自建 {request_id,prompt,timeout_ms}）→ socket → sidecar → codex
契约路径：run-contract（binding/receipt）→ adapter.to_sidecar_request → sidecar   ← 仅出现在 run-contract 自己的测试里
```

实测证据 ✅：
- `sidecar_client.py` 的 `REQUEST_FIELDS` 与校验是**第二份实现**，`import` 列表里没有 `contract`/`binding`/`adapter`；
- 全仓 `to_sidecar_request` 引用只出现在 `northstar-run-contract/{adapter.py,tests/*}`；
- `northstar-agent-runtime/*.py` 里**没有任何** `authorization`/`handoff`/`run_contract` 导入；
- sidecar README 显式把责任推给父级：*"The parent runtime must provide identity binding, per-run workspace authorization, cancellation propagation"*，而 runtime 侧未承担 → **责任悬空**。

后果（准确说，不夸大）：执行侧无法证明"我在为哪个被授权、哪一版策略的 run 跑"；审计流里的 run 与 sidecar 日志之间的关联只有一个自拟 `request_id`；两份 wire 校验必然漂移。**这不是可利用漏洞，是治理叙事的自证缺口**——对外讲"契约化、可审计"时，被内行一眼看穿的就是这里。

修法：`sidecar_client` 复用 `adapter.to_sidecar_request` 作为唯一出口（runtime 依赖 `northstar-run-contract`），把 `policy_revision` 与 `run_id` 写入事件流与 `request_id` 派生规则；加一条跨组件 vertical-slice 测试 `runtime → adapter → 真实 socket → sidecar`；把"三份字段校验合一"写成不变量测试（仿 `test_release.py` 的版本对齐做法）。

### F2 — agent 可以改写自己的治理文件（CBSE 类）｜ 已复现

`tools/__init__.py` 的 `protected_prefixes` 默认只有 `(".git",)`，`.northstar/` 不在其中。

复现（✅ 本机 2026-09-08，scripted provider，无需 API key）：

```sh
# workspace 里 .northstar/config.toml 无 deny_tools；run 以 --permission-mode acceptEdits 执行
# 模型第 1 轮：Write → .northstar/config.toml（把 revision 改成 rev-2-evil）
← ok: wrote 63 chars to .northstar/config.toml      # 写入成功，策略文件被改
```

边界（同样实测，避免危言耸听）：
- `default` 模式下 mutation 无审批回调 → 直接被拒；只有 `acceptEdits` / 显式 `--allow-tool Write` 可写；
- 改写**不能**放宽成 `bypassPermissions`：`configuration error: permission_mode must be 'default' or 'plan'` → 下一次运行拒绝启动（fail-closed ✅）。

所以真实风险是**三条，不含提权**：① **持久化策略漂移**——删掉仓库声明的 `deny_tools`/降低的 ceilings，之后所有运行静默继承被改写的策略；② **上下文投毒落盘**——植入/修改 `skills/*/SKILL.md`、`agents/*.md`（这些只读但进 prompt，是间接注入的持久载体）；③ **自我 DoS**——写坏 config 让整个 workspace 拒绝运行。2026 年业界共识正是这条："treat sandbox configuration as immutable, never let an agent modify its own approval policy" 🟡。头部工具靠"策略在 `~/.claude/` + managed settings，不在 agent 可写根里"绕开了这个问题；Northstar 把策略放进 workspace 是优点（可评审、可 git 管），但需要补一道写保护。

修法（1 天，含测试）：`ToolLimits.protected_prefixes` 默认改为 `(".git", ".northstar")`，拒绝信息复用现有"that tree holds repository metadata"句式；逃生门 `--allow-policy-writes`（默认关，且在 `--json` 与审计流里落一条 `policy_writes_allowed` 事件）；补测试：写 `.northstar/config.toml`、`.northstar/agents/x.md`、`.northstar/skills/x/SKILL.md`、以及**指向这些路径的符号链接**均被拒。

> **2026-09-09 复核：这只闭合了文件工具。**`Shell`（含 bwrap 后端）与 MCP 子进程不经过 `ToolSandbox.resolve`，
> 因此同一条不变量在执行路径上是空的，并已复现"沙箱内植入 git alias → 沙箱外执行"。修复分三层
> （bwrap 只读绑定 / process 后端 drift 检测 / 叙事收口），见 [execution-boundary-audit-2026-09.zh-CN.md](execution-boundary-audit-2026-09.zh-CN.md) §3。

### F3 — durable 零件与 runtime 未接线

✅ `loop.py` 里的 `durable` 是 **fsync 级别**的写持久化（`sessions.py:74 durable: bool = True`），不是可恢复执行；`DurableRunner`/`EventStore`/`LeaseManager`/`verifier` 与 runtime **零 import 关系**。

后果：对外说"durable execution"时，对手是 LangGraph 的 super-step checkpoint + time-travel 与 Temporal 的事件溯源重放——Northstar 有同样形状的零件（append-only 历史、检查点、租约、后置条件验证），**但用户拿不到端到端的"崩了再续"**。这也是 2026 年头部共识线："checkpoints are not durable execution" 🟡，以及 harness/compute 分离（OpenAI v2 的核心卖点，Northstar 早就这么分了却没讲）。

修法：不必自建调度器。做**最小闭环**：runtime 的每个 `turn` 边界写一条 `EventStore` 事件（复用 durable-run，可选开关 `--durable-events`），`--resume` 改为"从 event store 的最后检查点恢复对话状态"，`verifier` 在 run 结束后对工件摘要出 `verified|failed|unknown` 并入 `ResultMessage` 附属字段。三处改动都能被现有确定性测试覆盖。

---

## 5. 标准代际核对（这半年变了什么）

| 标准 | Northstar 现状 ✅ | 外部现行口径 | 判定 |
|---|---|---|---|
| **MCP** | stdio + `initialize`/`notifications/initialized`/`tools/list`；无 elicitation/sampling/roots；无 HTTP | **2026-07-28**：去协议级会话与 `Mcp-Session-Id`；**移除 initialize 握手**，版本与能力改由 `_meta` 逐请求携带；服务器→客户端交互改 **MRTR**（`InputRequiredResult` + 客户端带 `inputResponses` 重试）；`Mcp-Method`/`Mcp-Name` 头必选；list 结果要求 `ttlMs`/`cacheScope`；HTTP+SSE 归类 Deprecated 🟢 | **隔**：旧握手仍能对 2025 代服务器工作，但新代服务器逐步去握手；未实现 elicitation = 服务器发起的确认会卡住 |
| **Agent Skills** | 只读消费、上限 40、仅 name+description 入 prompt | 2025-12-18 开放标准，2026-03 已 32+、年中约 40 平台采纳；spec 只约束文件格式（**安装路径各家不同**：`.claude/skills`/`.agents/skills`/`~/.gemini/…`）🟡 | **平**：兼容度反而更好（不依赖目录约定），但缺 `scripts/` 执行与 `allowed-tools` 语义 |
| **项目约定** | `AGENTS.md` + `--context-file` + `.northstar/config.toml`（收紧型） | `AGENTS.md` 已成跨工具事实标准，并被写进 OpenAI harness 原语 🟢 | **平** |
| **A2A / 多代理协议** | 自有 interop 契约（attestation/handoff/receipt），未接真实后端 ✅ | A2A 在 Linux Foundation 路线上演进；头部仍以 MCP + 自家 teams 为主 🟡 | 观察即可，**不建议现在对齐 A2A** |
| **安全基线** | 权限门 + hooks veto + 只读默认 + redaction + 审计 feed | OWASP ASI Top10：ASI02 工具滥用 / ASI03 身份提权 / ASI05 强制硬件级沙箱 / ASI06 记忆投毒 / ASI07 代理间通信签名 / ASI08 熔断回滚 🟡 | **部分对齐**：ASI07 有零件（签名 attestation）✅、ASI08 有 ceilings/veto ✅、ASI05 **缺**、ASI06 由 F2 直接命中 ⚠️ |

---

## 6. 路线（按性价比排序，不按期程）

**红线不变**：任何生态/配置内容都不得绕过权限门、hooks、预算与审计。

### P0 闭合与自证（≈1–2 周，纯增量）
| 项 | 做法 | 验证 |
|---|---|---|
| ✅P0-1 契约上路径 | runtime 依赖 `northstar-run-contract`，`sidecar_client` 唯一出口走 `adapter.to_sidecar_request`；`request_id` 由 `run_id` 派生；`policy_revision` 入 init 事件 | 新 vertical-slice 测试 runtime→adapter→真 socket→sidecar；不变量测试：两份字段校验合一 |
| ✅P0-2 治理文件写保护 | `protected_prefixes` 默认含 `.northstar`；`--allow-policy-writes` 逃生门（默认关 + 入审计） | 4 条拒绝测试（config/agents/skills/符号链接） |
| ✅P0-3 hooks 进配置 | config.toml 增 `hooks`（**仅 command 型**：仓库内相对脚本 + 超时 + 输出上限 + 不搜 PATH），复用 `HookResult` veto 语义，只允许注册到 `VETO_EVENTS` | 收紧性测试：hook 不得放宽；恶意绝对路径/`..`/symlink 脚本被拒 |
| ✅P0-4 漂移可检测 | `doctor` 增加"workspace 磁盘策略 vs git HEAD 策略"diff 检查；审计 feed 落 `policy_revision` | doctor 分支单测 + 文档标记 |

### P1 追代际（4–8 周）
| 项 | 做法 |
|---|---|
| P1-1 MCP 2026-07-28 ✅ 第十六批 | 逐请求 `_meta` 版本/能力携带 + `server/discover` 代际探测（`-32022` 即 modern；其余错误回落 `initialize` 握手）+ MRTR 重试回环；**把 elicitation 映射成一次受治理的权限审批回合**（这是别人没有的角度：MCP 的"问用户"天然对齐 Northstar 的 deny-by-default）。**未做**：`Mcp-Method/Mcp-Name` 与 `ttlMs/cacheScope` 属 HTTP 传输面，stdio 客户端无对应物——原表把两者混进了一行 |
| P1-2 模型层 | ✅ token 级流式（`StreamDelta`，唯一 ResultMessage 不变，且流必须等于记录）+ ✅ 第二 provider（Chat Completions 兼容面，一次覆盖 100+ 模型）；**未做**：显式重试/退避 + 过载降级、定价表外置可覆盖 |
| P1-3 并行/后台 | 同一 tool batch 内并行执行（**每调用独立过权限门 + hooks**，denial 记账顺序确定）；子代理并发上限；`--background` + `jobs list/show` 承接 durable-run |
| P1-4 沙箱自证 | 显式威胁模型页（"我们不承诺 OS 级隔离，承诺的是 X"）+ 可选 `bwrap` 包装（只读 bind + no net + cgroup 限额），CI 在 ubuntu runner 上跑真隔离冒烟 |

### P2 产品面（选做）
- `pip` 上架 + tag/wheel 就绪门（管道已就绪，按"最完美才发"纪律待定）；
- ~~`skills check` 供应链校验器~~ ✅ 第十五批已落地（`skill_audit.py` + `skills.lock` 摘要钉定 + `--require-skill-lock` 拒跑）；
- ~~P1-1 MCP 代际 + elicitation 审批门~~ ✅ 第十六批已落地（见上表）；
- 官方 GitHub Action + **治理基准数字**（denial correctness、注入抵抗、预算命中率）——把"机制领先"变成"可比较的领先"。

### 明确不做
交互式 TUI / IDE 插件；自建云或托管；模型微调；插件市场；浏览器/计算机操作；在 P1-4 之前加 shell 工具。

---

## 7. 一句话

**上一轮对标补的是"能不能用"（DX：安装、CLI、文档、发布），这一轮该补的是"敢不敢信"（链路闭合：契约上路径、治理文件不可自改、可恢复执行成环）。** 内核分数已经不需要再证明，需要证明的是内核之间的接缝——那里现在是三个 `TODO`，而全球顶级工具的竞争点恰好也移到了同一层（harness/compute 分离、可嵌入、可恢复）。方向没错，节奏该换。

---

## 8. 来源与可信度

🟢 官方：MCP 2026-07-28 spec 与 changelog（`modelcontextprotocol.io/specification/2026-07-28/…`、`blog.modelcontextprotocol.io/posts/2026-07-28/`）；Claude Agent SDK hooks 表与 overview（`code.claude.com/docs/en/agent-sdk/hooks`、`/overview`）；OpenAI Agents SDK 2026-04-15 公告（`openai.com/index/the-next-evolution-of-the-agents-sdk/`、community.openai.com/t/1379072）。
🟡 多源印证：OpenAI v2 harness/compute 分离与 7 家沙箱 provider（Help Net Security、idlen.io、junia.ai、agentpatterns.ai、abhs.in）；Claude Code 31 事件与 5 类 handler（ofox.ai、blakecrosley.com）；Codex "as a platform" 2026-08-19（kenhuangus.substack.com）；Agent Skills 40+ 平台（strapi.io、firecrawl.dev、paperclipped.de、rywalker.com）；LangGraph vs Temporal 与 "checkpoints are not durable execution"（cordum.io、aiworkflowlab.dev、reactify-solutions.com、temporal.io/blog/manetu）；沙箱选型 seatbelt/bubblewrap/gVisor/Firecracker（northflank.com、augmentcode.com）；OWASP ASI Top10（dev.to alessandro_pignati）；prompt injection  containment 策略（ecorpit.com、atlan.com）。
🔴 单一口径：技能仓库审计（99%/36%，rywalker.com）——数字未独立复核，仅作机会点论据。
✅ 本地实测：1239 项测试、`--version`、F1/F2 复现与 fail-closed 验证、`remote_worker.py --score`=94/100（自评）。
