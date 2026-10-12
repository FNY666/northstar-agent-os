# 次世代 Agent 蓝图：顶级工具的优点，哪些能收、哪些必须改、哪些要拒

> 编制日期：2026-09-08 ｜ 触发问题：**"能不能包含所有顶级 agent 的优点，因为我们要创造次世代的 agent"**
> 本文是设计与取舍文档；本批已按其中 P0 四条落了代码（见 §6）。配套现状对标见 [benchmark-top-agents-2026-09.zh-CN.md](benchmark-top-agents-2026-09.zh-CN.md)。
> **2026-09-09**：产品目标从「组件库」升格为 **Agent OS 整机**——见 [next-gen-agent-os.zh-CN.md](next-gen-agent-os.zh-CN.md)（统一入口 `northstar agent`、默认会话/检查点、优先级重排）。本文的吸收/拒绝判据仍然有效；「明确不做」里的 shell 在 OS 沙箱落地前仍拒绝，但已排进脊梁第 1 序而非永久搁置。

---

## 1. 直接回答

**不能"全都要"。不是能力不够，是那些优点彼此冲突，而且有 8 组与 Northstar 的不变量直接矛盾。**

把 2026 年头部工具的优点摊开看，它们并非同向叠加：Claude Code 的"无 per-server MCP 工具上限"与它自己的"上下文是公共财产"互相拉扯；Codex 的 Full Auto 与可审计确定性互相拉扯；OpenAI Agents SDK v2 的 snapshot/rehydrate 需要可变工作区状态，而"append-only 审计"要求不可变；Cursor 的多模型自由切换与"成本可预测"互相拉扯。**头部工具的做法是各自选边，形成一个产品人格**；把它们的优点做布尔并集，得到的是一个没有一致语义的框架，而不是次世代 agent。

所以"次世代"的定义必须换掉：

> **不是"拥有他们所有的能力"，而是"把每一项能力都重写成穿过同一道门的治理原语"。**
> 同一条工具调用，在 Claude Code 里是"能跑"，在 Northstar 里必须是"能跑 + 谁批准的 + 花多少 + 留下什么证据 + 崩了从哪儿续"。

这件事有一个可检验的判据，本仓已经具备而头部工具都没有：

> **零凭据、零网络、1515 项测试（另加 57 项 node 面测试）跑通同一套语义。** 任何被吸收进来的优点，若不能在没有 API key 的情况下被确定性测试，就不算吸收成功——那只是多了一条无法回归的功能面。

按这个判据，顶级工具的优点分成三类。

---

## 2. 八组硬冲突（必须显式选边，不能默默并集）

| # | 想吸收的优点 | 来源 | 与 Northstar 哪条不变量冲突 | 裁决 |
|---|---|---|---|---|
| C1 | 任意 shell 工具 + Full Auto | Codex Full Auto、Devin/OpenHands 长自主 | 根 README 的"不是通用 shell 执行 API"；`Shell` 已落地但**默认 deny** + OS 沙箱（bwrap\|process） | ✅ **改造落地**：有隔离才有 Shell；宿主机 Full Auto 仍明确拒绝；显式 `--allow-tool Shell` 才放行 |
| C2 | settings 里声明 command hooks | Claude Code（31 事件 × 5 类 handler） | 仓库文件=可执行代码 → 绕过权限门；clone 即执行 | ✅ **改造后收**：本批 P0-3 落地，但只允许否决型事件 + 无 shell + 脚本必须在工作区内 + 默认关 + 子进程环境变量清洗 |
| C3 | 无限工具/无限技能（no per-server cap、几百个 skill） | Claude Code Tool Search、Skills 生态 71k+ | `MAX_TOOLS_PER_SERVER=25`、`MAX_SKILLS=40`、listing 上限——"仓库文件不得无界撑大上下文" | 🔧 **改造**：数量可有界放宽（如 25→100），但必须配 **deferred definitions**（按需取 schema）；直接去上限 = 放弃边界 |
| C4 | 模型分类器自动批准（`auto` mode） | Claude Code auto、Cursor auto-review | 三层权限门的确定性；"谁批准了这次调用"必须可复现 | ⛔ **拒绝原样**：分类器只能作为**额外否决**挂在 PreToolUse 上（可 deny、不可 allow），默认关 |
| C5 | 插件市场 / install 即得能力 | Claude Code marketplace、skills 目录 | "策略只能收紧"（`policy_file` fail-closed）；市场内容未签名 | ✅ **改造后收**（第 19 批，§6.24）：落地 `northstar.plugin.v1` bundle = config/agents/skills/hooks/MCP 的打包格式，安装 = `.northstar/plugins/<name>/` 一次 git 可见的拷贝 + `plugins.lock` 按内容 digest 钉住；策略只收紧、hook 走 `command_hooks.parse_hooks`、跨平台用 `compatibility` 装前拒绝而非半装。**不做在线市场/解析器/远程拉取** |
| C6 | 容器快照/恢复（sandbox 丢了能续） | OpenAI Agents SDK v2 snapshot+rehydrate | 需要可变工作区生命周期；本仓 `northstar-host` 只有 0700 分配，无 lease/回收 | 🔧 **改造**：F3 的 durable 接线已落地（§6.23：lease 与检查点翻译），剩下的快照/回收属于 host 层，不进 runtime |
| C7 | 全局记忆（跨会话 MEMORY.md、user-scope memory） | Claude Code memory scopes、OpenAI 双层记忆 | 记忆是 ASI06 上下文投毒的持久载体；审计边界"只在工作区内" | ⛔ **拒绝全局**：只做 workspace-scoped、带摘要+摘要 digest、可 `--no-memory`、写入走 Edit 同一道门 |
| C8 | 后台并行 / 20 并发子代理 | Claude Code background+Agent Teams | 成本上限与"每 run 恰好一个 ResultMessage"要重定义（并发下预算是共享还是分片） | 🔧 **改造**：批内并行工具调用（每次调用独立过门，denial 记账顺序确定）先行；子代理并发必须继承**父预算池**而非各自新开 |

一句话：**8 组里有 3 组直接拒、5 组要改造后再收，0 组可原样搬。** 这就是"全都要"不成立的精确原因——也恰好是次世代 agent 的机会：别人做不到的"能力多 + 门不绕"，正因为他们在这些点上被迫选边。

---

## 3. 应该吸收的（无冲突，纯粹是欠账）

这几项与不变量不相冲，不做没有理由，属于"必须补齐"：

| 优点 | 来源 | 吸收形态 | 状态 |
|---|---|---|---|
| 策略即代码（settings 里写权限/钩子/上限） | Claude Code | `.northstar/config.toml` + `[[hooks]]`，收紧型、fail-closed | ✅ 本批补齐 hooks 面 |
| 契约化的 run↔执行关联 | 无（Northstar 独有零件） | `contract_bridge`：单一 wire 定义 + 绑定交叉校验 | ✅ 本批 |
| 检查点/可恢复执行 | LangGraph / Temporal / v2 | `checkpoints.py`：turn 边界记录（长度+前缀摘要+已消耗计数器），恢复时**继承**而非重置 | ✅ 已落地（第十四批续） |
| durable 词汇与会话上锁的统一 | LangGraph/Temporal 的 event sourcing + 本仓 durable-run | `session_lease.py`（一写者）+ `durable_bridge.py`（检查点 ↔ durable 事件/文档双向翻译，跨校验） | ✅ 已落地（第十八批） |
| 多模型 | OpenAI 100+ / Cursor | `providers/openai_compat.py`：一个 Chat Completions 适配器覆盖一片模型 | ✅ 已落地（P1-2） |
| 独立完成判定 | 无人做（各家都把"模型自述"当完成） | `postconditions.py`：`--verify` / `[[verify]]`，运行前后快照比对 | ✅ 已落地 |
| token 级流式 | 全员 | `--stream`：`StreamDelta` 事件 + **流-记录一致性校验**（不一致即判 provider fault，不写 assistant 记录），唯一 `ResultMessage` 不变 | ✅ 已落地（第十七批） |
| 显式重试/退避/降级 | Claude fallback | `provider_retry.py`：故障分类 + 纯函数退避 + per-turn 等待预算 + `compact_once` | ✅ 已落地（第二十批） |
| 外家 `.mcp.json` 导入 | Claude Code/Cursor/VS Code 的配置文件 | `mcp_config.py` + `--mcp-config`（默认 off）+ `mcp list`（拒绝即 exit 1，可当 CI 门） | ✅ 已落地（第二十一批） |
| MCP 现行规范 2026-07-28 | 标准 | `mcp_negotiate.py`：`server/discover` 代际探测 + `params._meta` 逐请求携带 + MRTR 重试 + 旧代际 fallback | ✅ 已落地（第十六批） |
| elicitation ↔ 审批回合 | MCP 特性 | `mcp_elicitation.py`：把"服务器问用户"映射到权限门，无人应答即拒绝并 `notifications/cancelled`（**这是别人没有的角度**） | ✅ 已落地（第十六批） |
| OS 级沙箱 | Claude seatbelt/bubblewrap、Gemini gVisor | `tools/os_sandbox.py`：bwrap 优先、process 诚实回退；`Shell` 默认 deny；[threat-model](concepts/threat-model.md) | ✅ 已落地（次世代脊梁 P1；显式 bwrap 不可用则硬错误，不静默降级） |
| 技能供应链校验 | 无人做（第三方审计：99% 坏味道/36% 缺陷） | `skills check`：规则纯函数 + `skills.lock` 摘要钉定 + 漂移拒跑 | ✅ 已落地（第十五批） |
| 两语言可编程面（Python + TypeScript SDK） | Claude Agent SDK（py/ts 双官方面） | `sdk-ts/`：把 `run --json` 包成 `RunOptions`/`RunEvent`/`RunReport`，**镜像而非重定义**，两侧各有一条漂移门 | ✅ 已落地（第二十三批）；发布仍按纪律不做（`private: true`） |
| 会话 rewind/fork | Claude /rewind、LangGraph time-travel | `--resume-from`：从任一检查点分叉新 session（摘要校验），**绝不回写**旧文件 | ✅ 已落地（与 append-only 兼容） |

---

## 4. 五项"只有 Northstar 组合起来才有"的次世代能力

吸收完上面那些只是"齐平"。真正让别人抄不动的是这几条——它们的共同点是**用治理机制实现别处用自由度实现的功能**：

1. **可证明的策略变更（policy as code, with revision）**
   `.northstar/config.toml` 带 `schema_version` + `revision`，只能收紧、非法即拒绝启动；本批起 `revision` 进 `init` 事件与审计 feed，`doctor` 直接对比 git HEAD 报漂移（P0-4）。
   → 头部工具的权限配置是"行为开关"，这里是**可评审、可归因、可 diff 的策略文档**。CI 场景里这是合规资产，不是 DX 糖。

2. **确定性回归治理（治理本身的 golden test）**
   scripted provider + 1515 项离线测试 + guard 红绿 harness，意味着"把 deny 改成 allow 会让哪些测试变红"是可计算的。
   第二张脸（TypeScript）也不放宽这条：它的测试直接问 Python 侧的模块与 argparse 树"你今天的定义是什么"。
   → 别人有 output eval；**没有人在 eval 权限决策**。这条可以直接做成公开基准（denial correctness / 注入抵抗 / 预算命中率），是 Northstar 唯一能自定义考题的赛道。

3. **可归因的委派链（contract → execution → receipt）**
   本批把 runtime↔contract↔sidecar 三方字段焊成一份（漂移即测试失败），`run_id` 贯穿 runtime transcript 与 sidecar 日志；interop 组件已有签名 attestation + narrowed handoff + typed receipt。
   → 多代理生态现状是"消息能传"，没人能回答"**这一步是谁授权的、结果被谁验证过**"。A2A 不管这个，Claude Agent Teams 不管这个。这是 Northstar 的正面战场。

4. **后置条件验证，独立于模型** ✅ 本批已接进 runtime
   durable-run 的 `verifier.py` 用文件系统工件摘要判定 `verified|failed|unknown`；本批在 runtime 侧落为 `postconditions.py`（`exists`/`absent`/`changed`/`unchanged`/`contains`），运行前取摘要、结束后由**本进程**比对，失败即 `error_postconditions_failed`（exit 6）并写入独立审计记录类型 `postconditions`。
   → 即：**agent 说"我改完了"不再算数**。这比任何"自我批评/反思"式提示技巧都更接近次世代该有的定义。
   → 关键约束：**验证条件绝不进 prompt**——告诉模型要查什么，模型就去写那句话；`contains` 因此被明确标为"便利而非证据"，可依赖的是结构型四种。

5. **把协议的"问用户"变成治理的"要审批"** ✅ 已落地（第十六批）
   MCP 2026-07-28 的 MRTR/elicitation 让服务器能中途要输入；把它接到权限门上，远端工具的确认请求就走与本地写操作**同一道**门、进**同一条**审计流。
   → 头部工具把 MCP 当"工具管道"；这里是"带审批的管道"。
   → **原文那句"工程量小（只补一轮）"是错的，留在这里当反面教材**：真正小的是一轮重试的编码。变大的是它旁边的三件事——代际探测必须先于一切请求（否则 modern-only 服务器只会给一个"超时"）、能力宣告必须与"有没有审批人"绑定（否则"没人答就默认答"这条底线从协议层就漏了）、以及拒绝之后要做成**可审计事件**而不是吞掉。总计两个新模块 67 项测试。凡是被文档写成"顺手就能补"的协议改动，都要按"它会牵住握手语义"来估工。

---

## 5. 明确不做（拒绝清单，写下来防漂移）

自建云/托管服务；交互 TUI 与 IDE 插件；插件市场与在线索引；模型微调；浏览器/计算机操作；全局跨项目记忆；模型分类器批准；无界工具注入；以及在 OS 沙箱之前引入 shell 工具。

这一栏的价值在于**可检验**：它让"要不要加 X"从每次重新争论变成一次对照——想加就得先改这一节，改这一节就得给出上面 8 组冲突里对应的那一条怎么解。

---

## 6. 本批已落地（P0，代码 + 测试）

| 项 | 内容 | 验证 |
|---|---|---|
| P0-1 | `contract_bridge.py`：单一 wire 字段来源；`--run-id` → sidecar `request_id`；host 注入 binding 时对 runtime 请求做**契约交叉校验**，不一致或不可验证即**拒绝发起**（fail-closed，非降级）；无 binding 时完全惰性，runtime 仍零依赖 | `tests/test_contract_bridge.py` 18 项，含 runtime↔adapter↔sidecar 三方一致性 |
| P0-2 | `.northstar` 进入写保护（`Write`/`Edit` 拒绝），`--allow-policy-writes` 为一次性逃生门，生效集合写入 `init` 事件 | `tests/test_governance_writes.py` 12 项（含 symlink、未创建文件、Edit 打补丁、开关后审计可见） |
| P0-3 | `[[hooks]]` 仓库声明式生命周期钩子（C2 的改造形态） | `tests/test_command_hooks.py` 30 项，其中真跑子进程的 3 项做了反向突变验证（泄露凭据→测试失败；去掉超时→测试变慢可见） |
| P0-4 | `doctor` 增加 `policy-drift`（对比 git HEAD 的磁盘策略摘要）与 hooks 声明告警；`--dry-run` 打印 `run_id`/`policy_revision`/`protected_prefixes` | 手工实测篡改策略后 warn 命中；文档测试同步 |

**全仓 890 项测试全绿**（sidecar 51 / run-contract 41 / host 37 / durable-run 65 / interop 54 / runtime 596 / 文档 46），离线、无 key、无网络。

### 6.20 第十五批（技能供应链）

| 项 | 内容 | 验证 |
|---|---|---|
| 技能审查 | `skill_audit.py`：注入/隐藏/自改策略/远程脚本/凭据/元数据端点/不可见字符/上下文膨胀；代码块内降一级 | `tests/test_skill_check.py` 48 项，含"良性技能零告警"与"确定性可重复" |
| 审完即钉 | `--write-lock` 写 `skills.lock`（按路径+摘要）；`--require-skill-lock` 漂移即 64；`doctor` 加 `skills-review` | 审→钉→篡改→**拒跑**全流程实测；改名不继承他人审查 |
| 模型无法自证 | `skills.lock` 在 `.northstar` 下，工具层拒绝写 → 运行不能把自己的技能标成"已审" | 端到端断言：工具错误而非权限拒绝 |

### 6.15 第十四批续（F3：可恢复执行）

| 项 | 内容 | 验证 |
|---|---|---|
| F3 | `checkpoints.py` + `--checkpoint-turns` / `--resume-from` / `--resume-record`；恢复时**继承**花费与计数器；fork 写新文件、父文件字节不变；前缀摘要不符即拒跑；SDK 平价。**第 22 批补上只读面**：`sessions checkpoints`（校验每条边界，不符即 exit 1）与 `sessions replay --from-checkpoint`（孩子在花钱之前能看到自己会继承什么） | `tests/test_checkpoints.py` 26 项（"预算不能被 resume 洗掉"断言 exit 4）+ `tests/test_session_replay.py` 39 项（含"listing 说 verified 的边界真能 resume"） |

**这一项的真实动机不是便利，是漏洞**：上限是 per-run 的，而 `--resume` 会新开一次运行——
所以"恢复"一直是绕过 `max_budget_usd` 的后门。现在它必须把父花费带过来；
嵌入式调用忘了传 seed 过的 `Budget` 会直接报错，而不是拿到更宽的额度。

### 6.28 第二十三批（第二张脸不能变成第二份真相）

**选边**：Claude Agent SDK 有官方 py + ts 两 face；本仓只有 `sdk.py`。要补 TS 面，最省事的写法是
"照抄一份类型定义"，而照抄的定义一旦漂移，用户拿到的就是**同一条命令的两种语义**——这恰好是本项目
最不能接受的失败。因此第二十三批的实现把"抄"变成"抄 + 对账"，并让对账在没有 node 的机器上也跑。

落地：`components/northstar-agent-runtime/sdk-ts/`（`@northstar/agent-runtime`，57 项 node 测试）：

- **一次运行 = 一个子进程**：`run(options)` / `streamRun(options)` / `preview(options)` 直接组装
  `python3 -m cli run ... --json`，权限门、上限、transcript、退出码全部继承；没有守护进程、没有第二协议，
  也就没有"TS 侧多一条能绕过的路"。
- **封闭选项面**：`RunOptions` 45 个键与 `run` 的 60 个 flag 一一对上，`retry/mcp/sidecar` 是命名空间；
  未知键是 `ConfigurationError`（在建 argv 时、进程存在前），`--json` 由 SDK 追加、调用方不得关闭；
  没有 `extraArgs` 逃生舱——那会把漂移门挡在真正需要它的那些选项之外。
- **语义陷阱写明而非抹平**：`maxToolCalls: 0` = 一次工具调用都不允许（不是 unlimited）；
  `compactionThresholdTokens: 0` = 关闭压缩；`retry.baseDelayMs/jitter/onContextOverflow` 属于
  `[retry]` 策略表，被点名拒绝而不是静默丢弃；`mcp.elicitAnswers` 必须配 `elicit: true`；
  `agent` 与 `mcp.servers` 互斥；`null`/`undefined` 都表示"不设"，永远不等于"放宽"。
- **失败形状**：跑完的 run 从不抛错（subtype + `exitCode` 说话），只有"流不可信"才抛——
  没有 result 事件、出现非 JSON 行、exit 64 分别对应 `RunFailedError`/`UsageError`；
  `exitCode`（契约）与 `processExitCode`（事实）同时保留，两者不一致时报出来而不是被抹平。
- **取消是一等公民**：`signal`/`timeoutMs` 发 SIGTERM（正是 runtime 会封存 transcript 的那个信号），
  宽限后再对**进程组** SIGKILL；测试用一个自证文件确认"被中止的运行没有留下孤儿"。

**漂移门（两面都装）**：`sdk-ts/test/parity.test.ts` 直接问 Python 侧——`events.EXIT_CODES`、
`providers.base.RESULT_SUBTYPES`/`ResultMessage` 的字段集、`loop.Denial.as_dict()`、
`permissions.PERMISSION_MODES`、`postconditions.KINDS`、`provider_retry.RETRYABLE_CLASSES`、
`cli.build_parser()` 里 `run` 的真实 flag 与 `choices`，外加一次真实 `--json` 跑的 result 键集合；
`tests/test_typescript_sdk.py`（21 项）用同一批断言在 **Python** 里再跑一遍，所以
"这台机器没有 node"不能成为绿灯的理由。`Makefile` 的 `ts-test` 是**守卫式**的：node < 22.6 时打印
skip 并 exit 0，绝不把"跑不了"伪装成"跑过了"，也绝不让真失败的测试被 `||` 吞掉。

**顺手修掉一个显示层的谎**：`run --dry-run` 把显式 `--max-tool-calls 0` 打成 `unlimited`，而
`loop.py` 的判定是 `max_tool_calls is not None`——0 是"一次都不许"，且 `_ceiling_stop` 在**首次生成之前**
就结束运行（`num_turns: 0`、`input_tokens: 0`、连 denials 都没有，因为根本没有调用被拒）。
`cli.format_tool_call_ceiling` 现在把三种状态分开写：`unlimited` / `0 (no tool call allowed)` / 数字；
`CeilingTests` 钉住 0 与 1 的差别（1 会花掉一次请求并记录一条 denial）。镜像读错这一点，正是"第二张脸
能让第一张脸变诚实"的最直接证据。

测试量：**+9 → 1197**（runtime 片：上限语义 +5、守卫 harness 自身 +4），TypeScript 面 **+57**（node，
独立口径不与 python 相加），全仓 `make test` **1515 全绿**（51+41+37+65+54+1197+70）；`make demo` exit 0。

**顺手把 CI 的一个"假绿"变真**：`tools/verify_invariants.py` 过去只把本组件拷进临时目录，而本组件的
桥接测试是**故意**去 import 真实的兄弟组件的——拷贝里缺了它们，基线直接红，于是每次变异的结果都不再说明
任何事（这正是 `Guard verification` 步骤自桥接落地起就失败的原因）。现在它拷整棵 `components/`，并由
`tests/test_tools_verify_invariants.py` 钉住"拷贝必须带齐兄弟组件 + 一次端到端变异必须变红"；另一条
变异锚点原本按 `loop.py` 的缩进写，缩进一改就变成"锚点没找到"——一个报不出结果的守卫等于没有守卫，
现在锚在调用上方的注释上。五个守卫对 1197 项基线全部转红 ✓。§10.5 T1 的"TS 面"尾巴因此收口，剩下的只有发布纪律
之外的部分——见第 23 批 dx-benchmark 追加。

### 6.30 第二十五批（持久记忆必须在再次注入前验完整性）

**触发证据**：[OWASP Agent Memory Guard](https://owasp.org/projects/agent-memory-guard) 指出，跨会话 memory 会成为下一轮的高权限输入，写入端扫描无法覆盖写后篡改；[OWASP AAI3](https://cornucopia.owasp.org/cards/AAI3) 建议检索前核验记忆来源与完整性。[MemSecBench](https://arxiv.org/abs/2607.27080) 则用 Write–Execute–Forget 生命周期评估持久化、下游影响与修复，而不是只看一次写入判定。

代码核对发现 `memory_safety.baseline_memory_file()` / `verify_memory_baseline()` 仅被自测与治理基准调用，production 的 `discover_memory()` 只算并标注 digest，从不校验之前的内容。现在受治理 Write/Edit 会先在工具不可写的 `.northstar/memory-integrity.json` 中暂存新内容摘要；下一次记忆召回会核验完整原始文件字节，摘要不符或已删除即拒绝启动该次注入，并要求操作者在 agent 外恢复或审查。操作员可见的 dry-run 与 prompt 标记 `verified` / `unverified`；旧记忆无基线时仍能读取，但明确标为未验证。工具失败发生在基线暂存之后时，下次读取将失败闭合，避免把半写内容当可信记忆。复核又发现路径解析会把工作区内的符号链接解析成普通文件，可能让 `.northstar/memory/MEMORY.md` 指向记忆区外并绕开清单；现在凡词法路径落在托管记忆目录的文件或任一父目录是符号链接，召回前都会拒绝。随后审计了检查与读取之间的 TOCTOU 竞争窗口：托管记忆现在通过逐级 `O_NOFOLLOW` 目录描述符打开，最后检查常规文件类型和大小上限，避免校验后被替换成链接。最后发现写路径保护只看 realpath，工作区内符号链接可把普通路径映射进记忆 carve-out，或把 carve-out 映射出去；写请求路径和解析后的目标只要涉及 `.git` 或 `.northstar`，就必须是同一规范工作区路径，普通 agent 别名不能借道改写受保护元数据。红队覆盖增加一条真实 `AgentRuntime` 攻击：即使审批回调放行，已失陷模型试图通过 `Write` 持久化提示注入内容仍会得到错误结果，且文件不会落盘。

**验证**：覆盖首次工具写入后验证、文件被外部改写、已钉定文件删除、普通 agent 文件工具无法改写完整性清单、以及工作区内显式 memory 路径的兼容行为。清单是本地基线而非签名；process fallback 下获批的 Shell 或可直接改 workspace 的主机主体仍能同时替换 memory 与清单。bwrap 的只读治理挂载补上了后者之外的运行时写保护，但不改变外部主机的信任边界。

平台复核补上了显式能力边界：memory 完整性登记依赖 POSIX `O_NOFOLLOW`、`O_DIRECTORY`、目录 fd 操作和 `flock`。缺少任一原语时，托管 memory 会失败闭合；写入返回清晰的 capability error，避免在 Windows 等未验证宿主上退化成不完整锁。

并发复核又发现，manifest 更新虽有原子替换与锁，但 Write/Edit 在“读取旧字节、验证摘要、登记新摘要、写入文件”之间没有共同事务锁；两个并发运行可能互相覆盖摘要，令合法结果无法再次召回。现在 agent 对托管记忆的 Write/Edit 在整个读检改写事务外层持有 `.northstar/.memory-write.lock` 的 POSIX `flock`；manifest 自己仍用独立锁原子更新。锁等待采用非阻塞轮询，默认 5 秒超时，避免另一进程挂起导致当前 run 无限等待；超时、无锁原语或不安全路径都会拒绝写入。线程与独立进程竞争测试都确认第二个写入者必须等第一个离开事务后才能进入，另有测试证明锁超时和非法时限会失败闭合。

**验证**：`test_memory.py` 38 项（包含线程及独立进程锁竞争、超时/非法时限、并发 append 后两个更新均保留且 manifest 仍验证通过）、`test_memory_safety.py` 22 项与红队运行时 24 项通过。

### 6.31 第二十六批（技能引用资源也属于被审查的指令）

**触发证据**：OWASP Agentic Skills Top 10 将 skill 定义为编排多步任务的行为层，并强调审查、扫描与版本固定。复核发现 `skills check` 虽已扫描 `SKILL.md` 与脚本，但 `references/guide.md` 等按需读取的文本仍未扫描或锁定；恶意指令可以在模型打开第二个文件时才出现。

`skills-rules/3` 将最多 64 个 Markdown、文本、YAML、JSON、TOML、XML 等配套资源纳入规则扫描和 `skills.lock` 的独立摘要，拒绝符号链接和超出扫描上限的资源。改动被 `--require-skill-lock` 在 provider 启动前识别，旧规则锁要求重新评审。静态扫描仍有误报和漏报，摘要只证明与本地评审字节一致，不证明发布者身份。

**验证**：配套文档提示注入命中、资源哈希漂移、以及 `--require-skill-lock` 启动前拒绝三项回归通过。技能审查套件 58 项通过；doctor 测试另受当前主机 Landlock ABI 0 的 `mcp-network` 检查阻塞。

### 6.32 第二十七批（Shell 获批也不能改治理文件）

**触发证据**：[OWASP AISVS](https://owasp.github.io/www-project-artificial-intelligence-security-verification-standard-aisvs-docs/) 要求 agent 编排安全具备可测试的验证项；[OWASP Agentic Skills Top 10](https://owasp.github.io/www-project-agentic-skills-top-10/) 将技能视作有运行时影响的执行层，并建议隔离执行与持续审计。代码核对发现工具级 `.northstar/` 写保护无法约束显式获批的 Shell：bwrap 原先把整个 workspace 绑定为可写，命令可更改 skill 或 policy，下一次运行再加载。

现在 bwrap 将 `.northstar/` 覆盖为只读挂载，只有 pledge 授予 `tmppath` 时才把 `.northstar/tmp/` 单独覆盖为生命周期内的 tmpfs；未授予时 `/tmp` 也只创建成不可写目录。seccomp/身份临时文件仍通过打开的文件描述符提供。bwrap 启动前拒绝 `.northstar` 或 `tmp` 是符号链接。process fallback 不具备该独立挂载边界，工具结果会明确报告治理路径没有单独只读保护；需要这条保证的部署必须使用 `--sandbox bwrap`。该差异符合 process backend 本身“不是 OS 隔离”的定位。

**验证**：新增 bwrap argv 回归证明 `.northstar` 先只读覆盖、临时目录按 pledge 再转为临时文件系统，并拒绝治理目录符号链接。当前执行容器未安装可用 bwrap，故验证了构造参数，没有声称完成真实 mount namespace 端到端测试；`test_os_sandbox.py` 其余 process 用例还有 2 项因容器 Landlock ABI 0 而失败。

### 6.33 第二十八批（非对象工具参数在授权前拒绝）

**触发证据**：[OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) 建议对消息做结构与 schema 校验。运行时复核发现 `ToolUseBlock.input` 若不是对象会被静默替换成 `{}`，随后仍可能触发 hook、审批与 handler；这把畸形协议输入变成了一个含义不同的有效请求。

现在初始工具参数及 `PreToolUse` 的重写结果都必须是对象，否则在权限回调和 handler 之前拒绝，记录 `invalid_input` 报告并触发失败 hook。真实 `AgentRuntime` 红队回归断言：列表形状的 Shell 参数不会进入审批回调，也不会创建目标文件。

**验证**：`test_redteam_runtime.py` 22 项通过；`loop.py` 与测试文件通过 `py_compile`，`git diff --check` 通过。这里校验的是运行时对象形状；具体字段类型仍由各工具自身参数校验负责。

### 6.34 第二十九批（字段 schema 是授权前的执行契约）

**触发证据**：MCP 规范把 `tools/call.params.arguments` 定义为对象，并由 `tools/list` 提供 `inputSchema`；schema 是调用契约，不只是给模型看的提示。[官方 schema 使用说明](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2025-11-25/basic/index.mdx)要求按声明方言验证。后续核对 [2026-07-28 Tools 规范](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/server/tools.mdx)发现，outputSchema 存在时 server 必须返回符合 schema 的 structured result，client SHOULD 验证；structuredContent 现在可以是任意 JSON 值，outputSchema 也可使用完整 JSON Schema。之前实现虽验证 schema，却缺少数组和原始标量结构化结果的互操作测试。

工具输入在 `PreToolUse` 前校验，hook 改写后再次校验；MCP 的 `tools/list` 阶段也会先 meta-validate schema，拒绝项不会进入 provider 的工具列表。基础安装保留无依赖子集；新增 `json-schema` extra 后使用标准 JSON Schema 2020-12 validator，并额外识别 Draft 7。`$ref` 只在当前 schema 内解析，registry 不提供网络加载器；远程 ref 在 admission 时拒绝。正则使用 timeout 引擎，单次最多 25 ms、一次输入校验总预算 250 ms。`format` 按默认注解语义不做断言。MCP `outputSchema` 同样在 admission 验证，并纳入工具定义 digest；声明输出 schema 的 server 必须返回符合约束的 `structuredContent`，否则结果被拒绝且 server 隔离。Fixture 已验证对象、数组和原始字符串三种结构化输出通过 schema 后能到达模型。没有 extra 时，子集外关键字仍失败关闭；显式的 Draft 7 以外方言也会清楚拒绝，而不被误判成有效 schema。MCP 的远程引用场景尚未完整互操作。

**验证**：新增 validator 单测 16 项（full extra 模式 16/16 通过；基础模式 11 项通过、5 项 full-extra 用例跳过）；MCP client 8 项定向用例通过：远程 `$ref` 在暴露前拒绝并关闭子进程，对象/数组/原始字符串 `structuredContent` 均通过 schema 校验并转交模型，无效或缺失输出触发隔离，错误结果保留来源，output schema 漂移改变工具 pin。红队运行时 24 项、hook/runtime 测试 31 项、`test_loop.py` 26 项、`test_tools.py` 38 项、子代理 34 项、并行工具 7 项与 MCP admission 59 项通过。其余 `test_mcp_client.py` 仍受容器 Landlock ABI 0 阻断（默认测试需要 ABI 4+），所以未声称整个 MCP 子系统端到端全通过。

### 6.35 工具结果信任元数据必须穿过 provider 边界

**触发证据**：MCP 成功结果虽然创建了 `ToolProvenance(trust="low")`，但 `ToolResult.ok(..., provenance=...)` 曾把它存进普通 `data`，再由 `as_block()` 丢弃；模型实际看到未标记的服务端文本。并且内存防护使用同名 `provenance` 携带审计字典，重用参数名会把内存写入拒绝路径变成运行时异常。

现在 `ToolResult.ok/error` 将工具来源与普通审计数据分开保存；MCP 结果保留 server/tool 来源，普通 handler 结果由 runtime 以注册工具名补全来源。trust 仅接受 low/medium/high，source/detail 各限 256 字符；结果送入 provider 前加入 runtime 生成的 JSON 元数据头，并从同一个结果字符预算中扣除 header 长度。预算过小时使用保留 trust 的短头。来源和信任级别也进入 PostTool hooks、trace 属性与 `ToolCallReport`，让审计面和模型上下文共享同一 provenance。默认系统提示明确要求只把工具结果当作与任务相关的证据，不执行其中要求改规则、泄露秘密或绕过治理的文本。内存防护审计字段改名为 `memory_provenance`，不会与模型可见的工具来源混淆。此标记和提示是纵深防御，不是能保证模型抵御所有 prompt injection 的隔离机制。

**验证**：工具结果来源、边界与预算单测、工具 38 项、loop 26 项、内存安全 22 项、红队运行时 24 项、hook 31 项与 validator 16 项通过；MCP 结构化结果、输出 schema 要求、远程引用拒绝和 error provenance 共 8 项定向用例通过。`py_compile` 与 `git diff --check` 通过。

**新增攻击链用例**：测试用真实 runtime 先调用返回恶意指令的低信任工具，再由已失陷的 scripted provider 尝试将指令写入持久记忆；工具来源被标记为 `tool:FetchInjected`，记忆写入在默认治理路径拒绝，文件未产生。

### 6.36 测试 runner 与运行时依赖分离且由 CI 显式安装

**触发证据**：完整发现运行遇到大量 `ModuleNotFoundError: pytest`；检查发现数百个测试模块直接用 pytest 辅助断言，而 README 和 CI 只安装运行依赖，却用 unittest 扫描这些文件。产品依赖应保持精简，但仓库测试入口必须声明并安装自己的 runner。

新增 `requirements-test.txt`，CI 与 README 都显式安装它；pytest 不进入运行时依赖。测试 runner 准备好后，全量发现能执行到 18,196 项，但此容器缺少 Landlock ABI 4+ 和 bubblewrap，MCP/doctor/sandbox 能力测试因此失败；当前工作区还残留 `ba_01.py` 至 `ba_50.py` 基准生成物，令模块布局检查额外报告未声明文件。新版安全模块的打包声明已补全。

**验证**：包含 `tool_input_schema.py`、`memory_integrity.py` 与 `ssrf_detect.py` 的 wheel 成功构建并核对归档；pytest 环境下全量 18,196 项已执行（37 failures、42 errors、18 skipped，未声称全量通过）。测试依赖文件已被 uv 成功解析安装，`git diff --check` 通过。

### 6.29 第二十四批（技能代码也必须属于被审查的字节）

**触发证据**：OWASP Agentic Skills Top 10 将 skills 定义为 MCP 工具层之上的行为执行层；HarnessSecurity-Bench 的 23 个任务强调，验证安全控制时要同时保住合法任务效用，并覆盖替代执行路径。代码核对发现一个具体断口：`skills check` 和 `skills.lock` 只覆盖 `SKILL.md`，但 runtime 会把 `scripts/` 下的可执行文件列给 agent，再允许经 Shell 调用；脚本可在审查后被改，原锁仍然通过。

本批把审查边界扩到实际执行字节：

- `skills check` 对每个 skill 的 `scripts/` 可执行文件做静态检查：既跑现有文本规则，也调用 `skill_scanner` 检出硬编码凭据、网络访问、动态执行和编码载荷。危险形状产生 `error`，并附脚本相对路径与行号；这是一层确定性筛查，不宣称证明代码安全。
- `skills.lock` 为每个脚本记录独立 SHA-256、大小和权限模式；`--require-skill-lock` 对新增、删除、修改内容或执行位均在 provider 启动前拒绝。规则版本升为 `skills-rules/2`，旧锁不会被默认为已按新规则复核。
- 运行时拒绝 `scripts/` 目录或脚本文件的符号链接。否则审查时看到的包与 Shell 最终执行的目标可以不同。

**验证**：新增审查、资产锁漂移、改动脚本后 provider 前拒绝、以及两类 symlink 拒绝的回归用例；本轮相关 targeted tests 通过。全仓入口在当前执行环境缺少 `make`，直接组件全量 unittest 另有与运行环境的 `mcp-network` 能力检查冲突，不能据此声称全仓验证通过。该设计不扫描任意文件类型或递归子目录，且静态规则仍会有漏报/误报；脚本通过检查不代表执行时无害，Shell 权限门与 OS 沙箱仍是实际执行边界。

### 6.27 第二十二批（fork 点必须能在花钱之前被检查）

checkpoint 自第 14 批起就在写，`run --resume-from` 也一直在按它恢复——但**没有任何办法先问一句**：
这个 session 有哪些边界？第 6 条记录还作不作数？从那儿恢复的孩子会带着什么起步？于是一个组件里
最强的持久化原语，恰好是其中最不可检视的一个；README 里"无篡改痕迹"那句话也就此失去了 excuse
（每个 checkpoint 记录里就躺着前缀摘要）。

- **校验不能靠两份实现"碰巧一致"**：`session_replay.py` 用读方自己的过滤器重建 transcript、用写方
  自己的规范化形式重算摘要，所以"这里说 verified"与"`run --resume-from` 会接受"是**同一条代码路径**
  的两个出口，而不是两个近似实现。四种结论：`verified` / `digest-mismatch` / `prefix-short` /
  `malformed`——被认出是 checkpoint 却缺 `turns` 的记录**只报告不补零**，因为"恢复部分计数器"正是
  checkpoint 当初要堵的那个预算漏洞。
- **`sessions checkpoints` 是给 CI 的那一半**：扫一个 transcript 或整个目录，有任何边界不是 verified
  就 **exit 1**。于是"审计流被改过/被截断"变成一个构建结果，不需要 provider key、不占 session lease、
  也不为了发现它而花一次运行。每条边界同时报价：文件里记着的 `max_budget_usd` 上限减去已花费，就是
  孩子还能花的钱；已经花完的边界会直说"resume 会被拒"。
- **`sessions replay` 回答"这次运行干了什么、能在哪儿切"**：记录折成帧（start/prompt/turn/checkpoint/
  compaction/result/note），一个 turn 帧同时带上散文、调用清单、错误与拒绝计数、token 用量——可 diff
  的清单，而不是滚动原始记录。`--from-checkpoint N` 把回放**切在该边界处**：那之后的记录是"孩子看不见
  的历史"，这一句就是 fork 预览。`--json` 给机器同一形状；孩子的 `session_start` 谱系会被渲染出来
  （"forked from session X record #N, inherits 2 turns / $0.500000"），因为说不出父亲的 fork 就是没人
  能审计的 fork。
- **刻意不做的**：不是 TUI，也不是重放执行器——不二次运行任何工具、不重新裁决任何权限，transcript 是
  "当时被允许了什么"的记录而不是待重演的脚本；也不是签名——摘要能发现事故与顺手改文件，能改写文件的
  人就能重算摘要，这句现在写进 limitations 而不是含糊过去。

诚实边界继续写全：`transcript_len` 决定切点（在任何消息之前的边界合法地摘要空 transcript）；谱系优先读
loop 写的嵌套 `resumed_from`，旧的平铺键仍接受（append-only 的文件不能因为读方洁癖而变成读不出）。

测试量到 **1188**（runtime 片，+39：`test_session_replay`，其中两条是"这里说 verified 的边界，真去
resume 也被接受"与"改一行 prompt 后两条命令一起拒绝"），仓库 `make test` 全绿（51+41+37+65+54+1188+49）。
接线：runtime README 的读回小节 + Sessions 条目 + limitations 改写、cookbook §16、`py-modules`/`docbuild`
MANIFEST，以及 `dx-benchmark` §10.5 的 T3 整项收口。

### 6.26 第二十一批（外家的 `.mcp.json` 可以读，外家的审批不能读）

这一批始于一个勘误：三处文档让操作者"把 MCP server 写进工作区的 `[mcp.servers]` 表"，而那张表从来
不存在——`policy_file.py` 里没有 `mcp` 键，唯一的入口是 `--mcp-server`。勘误恰好暴露了缺口本身：2026
年每一家宿主都读 `.mcp.json`，于是采用者的 server 清单被抄在两个文件里，靠人肉同步。补上它，顺手也就
把那句话变成真的。

- **读他们的格式，留我们的门**：`.mcp.json` / `.cursor/mcp.json` / `.vscode/mcp.json` /
  `.gemini/settings.json`（`mcpServers`，或 VS Code 的 `servers`——同一文件里两者并存即报错），产出的
  就是 `--mcp-server` 产出的东西：名字 + argv（+ 可选 `env`/`cwd`）。因此导入的 server 默认 mutating、
  未点名即拒、随 run 一起 TERM→KILL、在 transcript 里与旗标无差别——**没有第二类工具**。
- **三档严重度，因为配置文件可能以三种方式出错**：*含义*需要猜的一律 fatal（JSON 坏、两个表键并存、
  本导入器不读的键、`command` 写成数组、未解析的 `${VAR}`、`cwd` 逃出工作区、超过 16 个 server）→
  exit 64，什么都不启动；本运行时*起不了*的（`url`/`headers`/`type: http|sse`）是 stderr 上点名跳过，
  因为这是我们缺的传输而不是别人写错的文件——一个仓库里有一个远程 server 不该连累它的 stdio 伙伴；
  `disabled: true` 是**注记**，那是文件自己的决定，但评审该看得见。
- **`autoApprove` 不是配置项，是被拒的申请**：仓库里的文件不能替操作者把撤回的审批买回来，所以非空的
  `autoApprove`/`alwaysAllow` 直接终止运行并打印"该删的是这句"；空列表是 no-op。`env` 的值从**操作者的
  环境**展开（`${VAR}` 缺失是错误而不是空 API key），是往子进程环境里**加**而不是**筛**（裁剪进程能看
  什么归宿主 OS，写在这里就是吹一个兑现不了的承诺），报告里只出现变量名。
- **默认 off，不问就不动**：`--mcp-config off|auto|PATH` 默认 `off`。仓库里的一个文件不能自己启动进程
  ——这跟"插件的 server 仍要操作者的旗标"是同一条规则。`northstar mcp list --workspace .` 是只读面
  （不 spawn、不联网），有任何拒绝就 **exit 1**，于是 CI 能为"某个依赖悄悄加了个 server"这件事红掉。
- **名字不翻译**：`"GitHub"` 被拒并附改写指引——没人读过的工具名就是没人评审过的工具名；同一个名字被
  两个文件声明，两边都拒（"哪个赢"不该是评审进程启动器时要做的事）。

诚实边界：没有 HTTP/SSE 传输，也没有那套传输自带的 auth（远程声明因此只是被跳过，不是被降级实现）；
`mcp list` 只描述不启动，`--mcp-config` 只在命令行里被打开；导入的 `env` 不是隔离机制。

测试量到 **1149**（runtime 片，+46：`test_mcp_config`，含"孩子进程自己报告拿到了什么 env/cwd"的端到端
一条），仓库 `make test` 全绿（51+41+37+65+54+1149+49）。接线：runtime README 的 MCP 节 + 布局行 +
Limitations、cookbook §15、`py-modules`/`tests/docbuild.py` MANIFEST，以及把插件加载器那句指向不存在
的 `[mcp.servers]` 的错误文案改成指向 `.mcp.json` + `--mcp-config`。

### 6.25 第二十批（重试预算必须属于运行时，不属于 SDK）

契约面最后一项。此前"会不会重试"在本仓**没有答案**：两个 provider 把 `max_retries` 交给
SDK 客户端，于是一次运行的请求数 = 我们的循环 × 它的循环，`Retry-After` 由库按自己的上限处理，
没有任何事件/跨度说过"第 2 轮实际发了 4 个请求、等了 11 秒"。所谓"运行受 max_turns 与
max_tool_calls 约束"在这种传输层上是不成立的。

- **先分类，再谈退避**：`provider_retry.py` 用十个封闭名字描述故障（429/529/网络/超时/5xx/
  超长/鉴权/坏请求/流中断/未知），判据顺序是状态码 → provider 自己的声明 → 文本模式。
  四类**禁止**出现在 `retry_on` 里：auth 与 client_error 不会因为重发变真；`unknown` 不是"临时"的证据
  （把"我们判断不了"当成"可重试"，等于把每个 bug 变成对已故障服务的请求风暴）；`stream_interrupted`
  是刻意堵死的——终端已经看到文字，重发就是同一句话出现两次，而"记录与所见一致"正是流式契约存在的全部理由。
- **日程是纯函数**：`plan(attempt, fault, waited)` 只回一个延迟或一个具名停止（attempts_exhausted /
  deadline_exceeded / not_retryable），于是整份策略可以作为一张数字表被测试；`execute()` 是唯一碰时间的
  地方，且 sleeper 由调用方注入。full jitter 的**种子取自 session id**：这样"测试要确定性"与
  "别一起卡在同一个 429 窗口"才不再互相矛盾。上限归运行时而非操作者（8 次尝试 / 单次 120 s /
  每轮等待 15 min），越界直接拒绝而不是四舍五入。
- **`[retry]` 是工作区表，命令行只能收紧**：`restrict()` 统一钳制（`--retry-max-attempts 9` 遇到文件里的 4
  就是 4），`--no-retry` 额外关掉 jitter，让"我要第一时间看到故障"真的最早看到。插件碰不到它——
  `retry` 不是 bundle `[policy]` 的键，否则包就能自己抬高自己访问 provider 的请求数。
  `Retry-After` 服从到 `max_delay_ms` 为止，并且**越权覆盖必须写进事件**；HTTP-date 形式宁可不解析。
- **降级有界，且不换答题人**：`on_context_overflow = "compact_once"` 把 413 当作请求问题——走正常
  `PreCompact` hook 路径压缩一次（hook 仍可否决）、重发、**不消耗重试预算**，一个 run 只许一次
  （能被爬两次的梯子就是把上下文削到什么都不剩）。没有 `fallback_model`：换模型 = 换定价/能力/审计归属，
  那是策略决定，不是传输细节。
- **可见但不改格式**：provider 侧 `max_retries` 默认为 0，并把 `failure_kind`/`status_code`/`retry_after_ms`
  附在抛出的 `ProviderError` 上（循环的分类因此与它的分类由构造一致）；重试是**事件 + 跨度属性**，
  不是 transcript 记录——429 发生不该移动评审员钉住的摘要；但若重试耗尽导致失败，它进记录，因为那时它就是解释。
- **零凭据可彩排**：`--script` 的轮次现在可写 `{"raises": {"status": 429, "retry_after_ms": 300}}`，
  造出与真实网关同形的已分类故障；未知键在装载脚本期就拒（静默不产生故障的脚本会测错东西）。于是 74 项
  新测试全部跑在 demo 用的那个 provider 上。

诚实边界（写进 README 同一节）：这不是熔断器（进程间无共享状态，靠种子化抖动避免齐步走），也不是队列
（`deadline_ms` 封住等待，需要十分钟恢复的 provider 应该由 CI 显式稍后重跑，让意图可见）；没有触碰任何
真实服务端点；"流中断后继续生成"这类能力我们**刻意不做**。

测试量到 **1103**（runtime 片，+74：`test_provider_retry`，其中含 CLI 层"429+529 重试后落地答案"与
"`--no-retry` 让同一脚本立即失败"两条端到端），仓库 `make test` 全绿（51+41+37+65+54+1103+49）。
接线：runtime README 新增 "Provider faults, retries and the wait budget" 一节 + 布局行、cookbook §14、
`py-modules`/`tests/docbuild.py` MANIFEST、CI 编译行改为整目录 glob（手抄清单已漏掉数个新模块，正是它该被自动化的原因）。

### 6.24 第十九批（插件是打包格式，不是权限通道）

用户问的是"我们有插件吗？能不能适配所有平台"。诚实的基线是：这一批之前有**四个扩展缝**
（skills、agent files、command hooks、MCP），**没有 bundle 概念**——`dx-benchmark-2026` 因此把
扩展生态记 3/5、N4 记 2/5，缺的就是"无 plugins/市场、无安装器/索引"。这一批只补 C5 裁定允许的
那一半：**格式**，并把"适配所有平台"拆成两个都能验证的答案。

- **格式与钉住**：`plugin.toml`（`northstar.plugin.v1`）是封闭 schema——未知键直接拒（"A key nobody
  reads is a capability somebody meant"）。`load_bundle` 计算内容 digest，**故意排除 `[integrity]` 表**：
  自己哈希自己是自证，能治理加载的那个数字属于 `plugins.lock`（`{name, version, content_digest, source}`）。
  安装 = `shutil.copytree` 到 `.northstar/plugins/<name>/`，一次 git 可见的落地；卸载只删自己放下的东西，
  且**拒绝穿过符号链接删**（进去时也不收 symlink）。没有市场、没有解析器、没有远程拉取。
- **能力只减不增**：`[policy]` 与已加载的 workspace policy 比，放宽即拒；没有 `allow_tools` 键；
  `permission_mode` 只接受 `plan`——`acceptEdits`/`bypassPermissions` 是**批准**，批准只能由人在命令行给。
  四个缝全部复用既有门：skill 走 `discover_skills(..., extra_roots=)`（与仓库同名 = 错误，不是覆盖）、
  agent 走 `register_workspace_agents(..., extra_paths=)`（不得遮蔽内置）、hook 渲染成**真实 `[[hooks]]` 表**
  交给 `command_hooks.parse_hooks(workspace=<workspace>)`（脚本必须在包内、无 shell、`--enable-workspace-hooks`
  仍是唯一开关）、MCP server 进操作者自己的 `--mcp-server` 列表（默认 mutating、未点名即拒）。**声明 env 的
  MCP server 在加载时被拒**，指向 workspace 自己的 `.mcp.json`（由 `--mcp-config` 导入，第二十批前无处可指）：
  为插件密钥另开一条通道 = 新的权限路径；而配置文件里那份 `env` 的值来自操作者的环境，不来自仓库。
- **安装即评审**：bundle 自己的 `SKILL.md` 在拷贝**之前**过一遍 `skills check` 的同一套规则，
  `--fail-on`（默认 `error`）之上有发现即拒绝安装；`plugin verify` 每次重跑该评审（规则随
  `RULES_VERSION` 进化，"三月干净"不等于"九月干净"），但 `run` 刻意不看它——规则升级本身不该把
  所有工作区的已装插件变成配置错误，那是一次人工复审（`--write-lock`）的事。
- **不"半装"**：未钉住、内容漂移、seal 不可验、denial 指向不存在的工具——一律 block 整个 run（exit 64），
  而不是 warn。理由与 C2 同源：「skills 装上了但 hooks 没装」不是任何人评审过的状态。
- **发布者**：stdlib 里做不了签名验证，所以 `[integrity]` 是 **HMAC-SHA256 seal**（`seal_key_env`），并如实叫它 seal；
  `--require-seal` 时"验不了的 seal"不等于"没有 seal"，仍然拒。
- **跨平台第一义 = 按宿主门禁**：`compatibility.{platforms,min_python,requires_flock,requires_network}` 在**安装时**
  拒掉跑不起来的 bundle（不是装上再失败）；`plugin compat` 对每个已装 bundle 打印 `HOST_PROFILES` 矩阵，含
  **大小写不敏感宿主上的同名冲突**（`A1.md`/`a1.md` 在 Windows 是一个文件）。矩阵只改显示、不改结论
  （`only_hosts` 过滤视图，`portable_everywhere` 仍按全表算），且如实标注：profile 是我们对自己用到的原语的描述，
  不是一致性测试，本仓没有任何东西在 Windows 上跑过。
- **跨平台第二义 = 导出到别家原生格式，并列出丢了什么**：`plugin export <target>` 支持 7 个目标
  （`claude-code/codex/openai-agents/agents-md/cursor/mcp/skills`）。`dropped` **由 `CARRIED_BY_TARGET` 一处算出**，
  渲染器无权各写一份；目标带不动 hook 与 ceiling 时默认**拒写**，要 `--allow-drop` 才落盘。别家格式是按我们读到的
  文档渲染的，本仓没跑过任何别的宿主——这句话写进每个导出的 notes 里。

测试量到 **1029**（runtime 片，+87：`test_plugin_manifest` 42 / `test_plugin_install` 45，其余为
`test_module_layout`/`docbuild` 对新模块的接线），仓库 `make test` 全绿（51+41+37+65+54+1029+49）。
新增两个公开模块同时进 `pyproject.toml` 的 `py-modules` 与 `tests/docbuild.py` 的 MANIFEST，
`policy_file.read_policy_document()` 作为"只取值、不重复评审"的原始读入口被抽出来——插件的比较需要
workspace 的数字，但不需要在这里第二次判定文件名对不对。

### 6.23 第十八批（durable 统一：会话只有一个写者，运行边界只有一份事实）

| 项 | 内容 | 验证 |
|---|---|---|
| 会话上锁 | `session_lease.py`：按会话文件认领（`flock LOCK_EX`，运行期一直持有），认领发生在**第一条记录落盘之前**、释放在**最后一条记录落盘之后**；冲突即 `error_session_busy`（**exit 7**），不写任何字节、不触发任何 hook；`--session-lease-seconds N`（默认 900，每轮与每个检查点续期）/ `--no-session-lease`；`sessions list/show` 只复述持有者的声明并标注"未验证" | `tests/test_session_lease.py` 54 项：真起子进程争同一把锁、子进程被 kill 后锁随描述符消失、"过期但仍持有"不可被夺、无 `fcntl` 即拒启动、退出码表与 `RESULT_SUBTYPES` 双向钉死、委派不会自锁（子 agent 与父共享同一 transcript 文件） |
| 词汇统一 | `durable_bridge.py`：把 runtime 的 `checkpoint` 记录翻译成通过 durable-run **闭合** `EventContract` schema 的字典（`checkpoint.created → running`、sequence 一对一连续、id 字符集同规则、`payload_digest` 覆盖边界事实），以及 `northstar.checkpoint.v1` 文档（`state_digest` 用 durable 的规范 JSON 规则）；`cross_check()` 在可导入时用真模块复算，不可导入即报 `unchecked` | `tests/test_durable_bridge.py` 33 项：镜像常量与真 schema 逐项对齐（字段集是**有序元组**比对，因为规范 JSON 的键序进摘要）、翻译出的事件真投进 `EventStore` 追加并 replay、同键重放是 no-op 而不同边界撞键即冲突、`EventStore.restore()` 对外来文档**如期拒绝**、无 durable 目录时子进程仍可用 |

**"统一"在这里不是把两个组件并成一个。** 依赖方向仍然单向：runtime 不 import durable。统一的是**工件**——同一份边界既能被 transcript 的摘要规则解释，也能被 durable 的 event schema 接受；以及**词汇**——lease 的信封字段、`checkpoint.created` 这个事件类型、`sha256:` 前缀的摘要写法。跨校验是可选的（`cross_check()` 报 `unchecked` 而不是猜），漂移由测试兜住。

**明确不统一的东西**：transcript 的记录格式（`RECORD_TYPES` 仍是 13 项——检查点摘要认证的是 transcript 的字节区间，改字节就是改所有既有检查点的断言），以及"durable 事件可以授权恢复"这件别人会顺手做的事：事件的 `payload_digest` 认证的是它自己的 payload，不是 transcript，所以 `checkpoint_from_event()` 必须把外来边界送进 `prepare_resume` 的同一道摘要门。**同一个门**是这批唯一真正想守住的抽象：不管边界是谁写的，能恢复的只有摘要对得上的。

**enforcement 分歧是设计而非遗漏**：durable-run 的 `LeaseManager` 按时间戳回收（它的 run 可以活过请求），runtime 不能把锁从一个活着的进程手里夺走（那正是我们要防的损坏）。因此 `expires_at` 在 runtime 侧是"我还活着"的声明而非回收期限，并且信封写在**已加锁的描述符上**（绝不 `os.replace`——那会 unlink 锁所在的 inode，让互斥静默失效）。这两条都写在模块 docstring 里，也各有一条测试守着。

### 6.22 第十七批（token 级流式，且流不能绕开记录）

| 项 | 内容 | 验证 |
|---|---|---|
| 流式 | `providers/base.py`：`StreamDelta` + `Provider.stream()`（"分片→恰好一个 `Generation`"契约）+ `stream_fidelity`；`loop`：转发/重新切片/每轮字符与事件双上限/前缀放宽；`--stream`（CLI）与 `RunOptions.stream`（SDK）；`scripted`/`anthropic`/`openai` 三适配器全接 | `tests/test_streaming.py` 45 项：流与记录不一致即 `error_during_execution` 且**不写 assistant 记录**；中途断流不留残片；transcript 与不流式**逐字节相同**（只差 init 里的 `stream` 声明）；`RECORD_TYPES` 不变、恢复无可回放 |

**这批的难点不是把 token 打出来**，而是三条同时成立：(1) 唯一 `ResultMessage`；(2) 审计不被流式改写（分片不入 transcript，摘要/检查点语义不变）；(3) **"给操作者看的"与"记下来的"必须同源**。第 (3) 条是别人不做的：多数客户端把流式当 provider 的自由文本转发，于是"直播说成功、记录里是失败"成为可能。这里由 loop 强制 `"".join(deltas) == 记录文本`（客户端自己截断时放宽为前缀），不信任 provider 的自述。

**刻意不流的东西**：`tool_use` 的半截 `arguments`（半个 JSON 既不能显示成定论也不能执行）、`thinking`/`reasoning_content`（Anthropic 侧签名未到 ≠ 合法块，chat 侧它根本不进 transcript）、以及子 agent 的运行（流式是操作者终端的属性，不是委派链的语义）。

### 6.21 第十六批（MCP 代际 + elicitation 走审批门）

| 项 | 内容 | 验证 |
|---|---|---|
| P1-1 | `mcp_negotiate.py`：`server/discover` 探测→代际判定（`-32022` 即 modern 并采纳服务器点名的版本；method-not-found/垃圾/超时才回落到 `initialize`）；`_meta` 逐请求携带（含探测与通知），legacy 载荷一个多余键都不加；`--mcp-protocol auto\|legacy\|modern` | `tests/test_mcp_negotiate.py` 30 项：断言的是**线上字节**（fixture 把每条入站消息写进 wire log），不是客户端自述 |
| §4-5 | `mcp_elicitation.py` + `call_tool` 的 MRTR 循环：能力位与"是否挂了审批人"绑定；`sampling` 永远拒绝；`roots` 仅在 `--mcp-allow-roots` 下回答且只给工作区一个根；凭据字段名先拒后问；schema 宽度/深度/体积设界；重试是**新请求**且逐字回显 `requestState`；`--mcp-max-rounds` 设界；整轮皆拒即 `notifications/cancelled` 并回错 | `tests/test_mcp_elicitation.py` 37 项 + CLI 层 10 项：包含"答案值绝不进审计"、"预批集少一个必填字段就是拒绝"、"非 tty 拒绝启动" |

**为什么这行的收益不是"兼容性"**：MCP 更新把 elicitation 从"服务器发起请求"改成"结果里内嵌请求"，各家都当成协议细节跟着改；但对治理系统来说，这是**第一个从网络那头递进来的审批请求**。跟法有三条，全都可测：没人被授权时就答不了（能力位没宣告，问题不会来）、答了也只答预批过的字段（值不猜）、以及答与不答都留在 transcript 里（`[governance]` 注记 + `answered_fields`，永不含值）。

**明确没做**：HTTP/Streamable 传输（代际规则与 MRTR 与传输无关，只差封帧）、`prompts`/`resources` 的 UI 面、tasks 扩展、以及"对着真实厂商服务器验证"——本仓库无网络，fixture 是按规范文本自写的，说"符合规范"就是说"符合已发表的语法"。

### 6.2 第十四批（多模型 + 独立验证）

| 项 | 内容 | 验证 |
|---|---|---|
| P1-2 | `providers/openai_compat.py` + `--provider openai`：双向翻译、`thinking` 只出请求不出 transcript、非 JSON `arguments` 失败闭合、reasoning 代际自动换 `max_completion_tokens`、价格不臆造、`--model`/`--provider` 组合在触网前校验 | `tests/test_provider_openai_compat.py` 28 项，含"聊天形状的工具调用仍过同一道权限门" |
| §4-4 | `postconditions.py` + `--verify` / `[[verify]]`；协议新增 `error_postconditions_failed`(exit 6) 与 `RECORD_TYPES` 第 12 项 `postconditions`；面板渲染 | `tests/test_postconditions.py` 32 项：条件对模型不可见、符号链接/越界配置期拒绝、仓库只能加不能减、只读评估（mtime 不变） |
| 漂移防护 | `py-modules` 与磁盘模块集合一致性；面板 record 词表测试如期报警 | 反向验证：从 `pyproject.toml` 删掉一行即失败 |

全仓 954 项测试全绿（runtime 660）。**未做**：流式（`StreamDelta`）、`skills check`、F3。

**F3、skills check、P1-1、token 级流式、durable 统一、plugin bundle（C5）、显式重试/退避/降级均已完成**（见 §6.15、§6.20、§6.21、§6.22、§6.23、§6.24、§6.25）：契约面**清空**。重试之所以排在最后是有理由的——它是跨组件接口之上的调用点，先定死接口再谈"失败后怎么再来一次"，才不会把重试写成第二个未定义的边界；这条理由已随 §6.25 兑现。此后本蓝图剩余的都是产品面（T 清单：SDK 化、发布、交互、后台/远程、托管），不是语义。

---

**未做且刻意留在后面的**：sidecar 侧真正校验 binding（要动它那个"只允许三字段"的协议——这是安全敏感组件的协议决策，不该在一次功能批次里顺手改）；F3 durable 接线；P1 全组。

（以上是第十四批之前的排序，已被 §6.21 末尾的当前排序取代：F3、P1-1、skills check、P1-2 多模型与 `[[verify]]` 均已落地。）

### 6.37 Shell 的每进程资源上限落地，进程树配额仍待补

**触发证据**：逐项核对 `tools/os_sandbox.py` 后确认，Shell 只限制墙钟时间、捕获输出、argv 与环境规模；bwrap 提供 namespace 和挂载边界，但没有为进程树配置 CPU、内存、进程数或工作区磁盘配额。输出截断后会终止子进程，不能限制输出之外的文件增长或短时内存峰值。CSA 的 [Agentic Universe 2026](https://labs.cloudsecurityalliance.org/agentic/agentic-universe-april-2026-v1/) 将 CPU、memory、execution time 限额列为运行不可信 MCP 服务器的最低部署控制；其 [Agentic AI Autonomy Levels and Control Framework v2](https://labs.cloudsecurityalliance.org/research/agentic-ai-autonomy-levels-control-framework-v2-csa-styled/) 也把资源消耗限额纳入自治等级控制。

**实现**：Shell 现在用独立 exec launcher 在命令运行前设置 POSIX `RLIMIT_CPU`、`RLIMIT_AS` 与 `RLIMIT_FSIZE`；进程和 bwrap 后端都继承这些限制。默认 CPU 秒数随墙钟 timeout 设置，默认地址空间上限 2 GiB，默认单文件上限 1 GiB；模型调用只能收紧、不超过运行时硬上限。无需 `Popen(preexec_fn=...)`，避免在线程化运行时使用不安全的 fork 前钩子；限制无法设置时 launcher 返回 126，不执行目标命令。

**边界**：这些是每进程上限，fork 出来的每个子进程仍各自有额度；单文件限制不是工作区总磁盘配额。进程树 CPU/内存、PID 数与工作区总存储仍需外部 cgroup/container 控制。威胁模型已按此边界更新，不能将本批描述成完整资源隔离。

**验证**：新增真实子进程回归，分别确认超大单文件写入被截断在 1 MiB、128 MiB 地址空间限制阻止 512 MiB 分配、1 秒 CPU 限额先于 5 秒墙钟超时触发；另验证正常命令仍可启动、超时进程组照常回收。验证未覆盖 bwrap 主机上的真实 mount namespace 执行（当前环境无可用 bwrap）。

### 6.38 Landlock 不可用时默认 pledge 回退与收紧请求拒绝

**触发证据**：完整 `test_os_sandbox` 在当前无 Landlock 的宿主上有两项 Shell 用例以 exit 126 失败。根因是默认 pledge 集合未收紧权限，但仍无条件启动 Landlock 专用 launcher；这与 `landlock=auto` 的回退契约冲突。

现在默认全量 pledge 在 `auto`/`off` 且无 Landlock 时使用已有 seccomp 进程路径，并在结果 detail 标明缺少 Landlock 路径层。若请求收紧 pledge，则 Landlock 不可用或显式关闭时在 spawn 前拒绝；当前 launcher 还不能在 `seccomp=off` 时组合执行收紧 pledge，因此这组请求也明确拒绝，避免静默绕过策略。

**验证**：`test_os_sandbox` 40 项通过、3 项因本机无 bwrap 跳过；新增回归覆盖默认 Shell 可运行，以及 Landlock 不可用、显式关闭和 seccomp 关闭时的收紧 pledge 拒绝。之前因 Landlock 缺失而失败的两项 Shell 集成测试现在通过。

### 6.39 每次模型请求先原子预留预算

**触发证据**：运行时原先只在一次 provider 响应按真实 usage 记账后，才会在下次 generation 前检查 `max_budget_usd`；若单次请求超出剩余额度，超支无法提前阻止。社区 spend-control 的 [Tollgate](https://github.com/sakura-sky/tollgate) 与 [Agent Budget Protocol RFC](https://github.com/iamapsrajput/agent-budget-protocol/blob/main/RFC.md) 都把请求前预留作为并发硬停止的关键模式；CSA 的 [Agentic Universe](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/agentic-universe-april-2026-v1.pdf) 也将每任务 token 与 cost 上限列为运行控制。

现在每个 provider attempt 在发出前对共享 `Budget` 原子预留：按完整序列化请求的 UTF-8 字节数估算输入、加 framing headroom、按最大输出 token 数计费，并对输入采用较贵的 cache-write 倍率、不折算 cache-read 优惠。usage 返回后预留与真实报告金额在同一锁内结算；网络/协议错误无法确定是否已计费时，保留预留金额为 `unverified_cost_usd`，且重试必须再次预留。预留不足时不触达 provider，返回 `error_max_budget_usd` 并记入 denial。并发预算对象共享同一锁，不能同时占用同一余额。

**边界**：该 envelope 是基于价格表和字节长度的保守估算，并非每个 tokenizer/服务端计费口径的数学上界，也无法预知价格表变动；真实 usage 若高于 envelope，仍会如实记录超出。失败请求的不确定额度按估算全额占用，可能偏保守；`ResultMessage` 明确展示这部分，不伪装成确认账单。

**验证**：预算套件新增请求估算、线程并发预留只能成功 9/16 次、真实 usage 结算、失败后不确定额度保留，以及不足时 provider 调用计数仍为零等回归。


### 6.40 MCP 默认拒绝现在要求完整 TCP/UDP 隔离

**触发证据**：复查 Landlock 内核接口文档发现，ABI 4 才引入 TCP bind/connect 控制，UDP 的 bind/connect/send 到 ABI 10 才可由 Landlock 拒绝。旧实现把 `--mcp-network denied` 的最低条件设为 ABI 4，因此在 ABI 4–9 上会挡 TCP，却仍允许 UDP 出站；选项名和“denied”结果容易让操作者误以为所有 IP 网络都已封住。

现改为仅在 Linux Landlock ABI 10+ 上启动默认拒绝的 MCP 服务；较旧 ABI 明确拒绝启动，`doctor` 同步报告 TCP/UDP 两种能力，`--mcp-network allowed` 仍是清晰的显式退出策略。依据：[Linux 内核 Landlock 官方文档](https://docs.kernel.org/userspace-api/landlock.html)。MCP 的 AF_UNIX 也纳入能力内：ABI 6+ 启用 abstract socket scope，只允许同一/嵌套 Landlock domain 内通信；ABI 9+ 将 `RESOLVE_UNIX` 作为 handled 权限但不授予路径规则，拒绝路径型 Unix socket 连接。stdio pipes 不受影响。

**验证**：专用测试覆盖 ABI 0、4、9 的拒绝、模拟 ABI 10 的 Landlock 启动封装，以及真实 TCP、UDP、abstract 与 pathname AF_UNIX 回环探测（运行内核 ABI 不足时仅跳过需要内核能力的探测）。`doctor` 测试将技能审计 finding 与宿主网络能力分开断言。相关 475 项安全与运行时测试通过，12 项按宿主能力跳过；本机缺少 Landlock，TCP、UDP 与 Unix socket 的真实隔离用例无法执行。


### 6.41 MCP 工具基线损坏或落盘失败时不再静默降级

**触发证据**：检查 `McpStdioClient.connect()` 发现，基线文件读取失败或 JSON 损坏会被当成“尚无基线”，然后继续连接；首次基线写入失败也会被 `except OSError: pass` 吞掉。这样服务重启后会丢失工具定义钉定，漂移可能被当成新服务面接受。

现在 `.northstar/mcp-tool-baseline.json` 通过目录 fd、`O_NOFOLLOW`、regular-file 检查和 4 MiB 上限读取；畸形 JSON、重复键、符号链接和无效 entry 会拒绝连接。更新用 POSIX `flock` 串行化多服务 read/modify/write，以 0600 临时文件写完并 fsync，再通过同目录原子替换和目录 fsync 提交。无法打开、锁定或持久化基线时 MCP server admission 失败关闭。没有 workspace 的嵌入式客户端仍只有当前进程内存保护。

**边界**：基线保存在工作区本地、未签名；能修改 `.northstar` 的宿主主体仍可替换它，摘要只发现工具定义与已保存基线不一致，不证明 MCP server 发布者身份。

**验证**：新增损坏 JSON、基线符号链接、模拟磁盘写入失败与两个并发服务更新互不覆盖四项回归；`test_mcp_client` 65 项通过。总定向套件 479 项通过、12 项按宿主能力跳过，`py_compile` 与 `git diff --check` 通过。

### 6.42 Shell stdout/stderr 共用单一输出预算

**触发证据**：审查 `_run_popen()` 时发现 `max_output_bytes` 分别应用在 stdout 和 stderr 缓冲区上。一个双流输出的命令因此能占用两倍于参数承诺的内存，且运行时在达到单流上限后才回收进程组。

现在每次命令的两路输出共享一个字节预算；任一路超出剩余预算即截断输出并终止整个进程组。工具 schema 明确标注这是 stdout+stderr 合计上限。

**验证**：真实子进程同时向两个管道写入 8 KiB，设定 1 KiB 总上限，断言两路捕获字节合计恰好不超过 1 KiB，并确认输出截断标记出现。

### 6.43 Shell leader 退出时清理遗留进程组

**触发证据**：共享执行器在主进程退出且 stdout/stderr 都关闭时立即返回。主进程可以 fork 一个同组后台子进程、让它关闭继承管道后退出，导致后台工作在本次 Shell 调用结束后继续运行；已有超时与输出限额清理只有在触发这些条件时才杀进程组。

现在检测到 leader 退出后若同组仍有进程，会向进程组发送 TERM，并在短暂宽限后发送 KILL；回收事实写进结果 detail。默认 Linux seccomp denylist 同时拒绝 `setpgid` 与 `setsid`，避免后代改换进程组或会话逃离回收目标。没有残留进程组时正常命令不增加等待。

**验证**：新增 Linux 子进程回归：后台子进程关闭所有标准流并忽略 TERM，父命令正常退出；测试确认执行器返回时子进程已死亡或处于不可运行的 zombie 状态。另在真实 seccomp 子进程中分别调用 `setpgid` 与 `setsid`，两者都返回 EPERM。syscall 编号按 upstream Linux x86_64 syscall table 与 asm-generic header 核验。输出上限与超时回归继续覆盖各自的进程组收尾路径。

### 6.44 MCP stdio 按行保留读取缓冲并严格限长

**触发证据**：MCP `_read_line()` 每次 `os.read()` 收到多条换行消息时只返回第一行，后续字节随局部缓冲区丢失；另外它先查找换行再判断大小，因此同一读取块内结束的超长行可以越过 `MAX_LINE_BYTES`。

现在客户端使用实例级 stdout 缓冲逐条消费消息，未消费后缀保留到下一次读取；按换行位置检查单行字节长度，超限失败关闭；EOF 落在未终止的半行时返回明确 `McpError`，不把截断数据当成普通超时。

**验证**：管道级测试覆盖同一写入里的两条消息依序读取、同一块内含换行的超长行拒绝，以及半行 EOF 报错；随后运行 MCP client 全套回归验证握手、通知和工具调用。

### 6.45 MCP 响应 JSON 消除重复键与类型混淆

**触发证据**：标准库 `json.loads()` 默认接受同一对象中的重复键，并将非标准 `NaN`/`Infinity` 解码成浮点数；Python 相等比较还会让 `true == 1` 与 `1.0 == 1` 成立。恶意服务器可借此构造歧义响应，或让错误类型的 JSON-RPC ID 被当作本次请求的回复。

现在服务端行采用严格解析：重复键、非标准数值常量与超过 128 层的容器嵌套均不会作为有效响应接受；请求响应路径将其作为协议错误拒绝，非请求通知路径则存入 untrusted 记录并忽略。响应 ID 必须是精确的 `int` 类型并等于当前请求 ID，bool/float 不会命中。嵌套检查识别 JSON 字符串转义，因此字符串中的括号不误算深度。

**验证**：测试覆盖重复 `id` 键、NaN/Infinity、过深数组、字符串内括号，以及 bool/float ID 后跟合法响应的场景；MCP 全套回归随后检查握手与通知互操作。

### 6.46 SSRF 提示器识别常见旧式 IPv4 数值写法

**触发证据**：`ssrf_detect.is_private_url()` 使用严格 `ip_address()` 解析文本 host，`127.1`、单整数、八进制或十六进制 IPv4 写法会被当作普通主机名，漏掉它们按常见 libc resolver 规则指向 loopback 或 link-local 的情况。

现在严格 IP 解析失败后，使用本地 `socket.inet_aton()` 规范化旧式 IPv4 数字，再按 `ipaddress` 分类；该路径不触发 DNS 查询。该函数仍只是日志/审查信号，不负责实际连接授权，也不证明 DNS 主机名安全。

**验证**：离线测试覆盖 loopback 的 `127.1`、八进制、十六进制、单整数形式，以及 metadata link-local 地址的十六进制和单整数形式；原有公网地址、主机名与畸形 URL 测试保留。

### 6.47 MCP 通知 drain 对 pipe 做零超时 readiness 轮询

**触发证据**：`call_tool()` 在执行前调用 `_drain_notifications()`，它把当前时间作为 `_read_line()` deadline；reader 在检查 deadline 到期后直接返回，因而没有从文件描述符读取任何已经抵达、但尚未进入内部缓冲区的通知。列表变更通知可能因此直到下一次正常响应交换才被看见。

现在到期 deadline 会转换为 `select(..., 0)` 的非阻塞轮询，保留同步路径的 deadline 语义，同时真正读取 ready pipe 数据；无数据时立即返回。

**验证**：管道测试先将已完整写入的 `tools/list_changed` 通知留在 OS pipe 中，再调用 pre-call drain，断言 pending 标记即时设置；已有 buffered-line 与无数据 bounded drain 测试继续通过。

### 6.48 MCP 交换路径统一通知 opt-in 并限制不可信样本

**触发证据**：`_drain_notifications()` 会拒绝未订阅的 `tools/list_changed`，但 `_exchange()` 在等待 RPC 回复时仍会无条件设置 refresh 标记，绕过同一 opt-in 规则。另外，不可信通知列表原先无限追加，server 可持续发送通知占用 client 内存。

现在两个读取路径统一检查客户端的 opt-in 状态：已订阅才设置刷新标记，否则只记录为不可信样本。样本最多保留 64 条、总计 64 KiB，超出计数单独累计，避免日志成为内存增长通道。

**验证**：模拟 RPC exchange 中分别注入已订阅与未订阅通知，检查刷新状态和记录；再注入 30 条 5 KiB 通知，确认保留字节与条数有界且丢弃数递增。


### 6.49 现代 MCP 工具变更通知建立真实订阅

**触发证据**：[MCP 2026-07-28 变更记录](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/changelog.mdx)引入 `subscriptions/listen` 长期订阅；[stdio 传输规范](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/transports/stdio.mdx)要求订阅通知通过 namespaced subscription ID 与流关联。此前 runtime 仅有本地布尔开关，不能证明服务器已确认订阅。

现代服务器在 `server/discover` 声明 `tools.listChanged` 后，客户端现在发送 `subscriptions/listen`，请求只订阅 `toolsListChanged`，并等待带匹配订阅 ID、且确认过滤器的 `notifications/subscriptions/acknowledged`。拒绝、超时或畸形确认会失败关闭。之后只有携带匹配 ID 的 `notifications/tools/list_changed` 才能触发下一次调用前重列；工具面与 admission pin 不同则隔离服务器。旧协议继续依据 `initialize` 声明能力处理通知；关闭现代 stdio 会话时尽力发送取消，随后终止子进程。

**边界**：当前只接入工具列表变更通知；资源/提示订阅和独立后台读取循环仍未实现。强制 `--mcp-protocol modern` 会跳过能力发现，因此不会猜测服务器能力或擅自订阅。通知在同步 RPC 等待期间或下一次工具调用前被处理。

**验证**：真实 stdio fixture 检查 discover → listen → tools/list 顺序、过滤器和确认状态；工具调用期间推送带订阅 ID 的通知并改变列表，客户端在第二次执行前发现新增工具、隔离服务，wire 中确认第二次 `tools/call` 未发送。


### 6.50 记忆 provenance 扩展字段不能覆盖受保护事实

**触发证据**：审查 `memory_safety.stamp_provenance()` 时发现 `extra` 元数据通过无条件 `dict.update()` 合并，可覆盖内容 SHA-256、来源、写入者、时间戳和 schema。当前内部调用只加 gate/outcome，但函数本身提供的通用扩展点会让未来调用者意外伪造审计事实。近期 [AgentSecBench](https://arxiv.org/abs/2605.26269) 也强调，安全评估应检查 provenance 与 capability 是否在生成前由系统强制投影，而非依赖提示文字。

现在扩展字段与基础 provenance 的保留键冲突时立即抛出 `ValueError`；合法的 gate/outcome 附加字段保持原样。这样不会把模型可写内容误当作可信来源元数据。

**验证**：新增回归分别尝试覆盖 schema、writer、session、source、内容摘要和时间戳；全部被拒。`test_memory_safety` 23 项通过。


### 6.51 持久记忆完整性 manifest 拒绝歧义 JSON

**触发证据**：`memory-integrity.json` 位于记忆信任基线链上；审查发现其加载器虽验证 UTF-8、schema、条目路径与摘要格式，却使用默认 `json.loads()`，接受重复键和 `NaN`/`Infinity`。重复键会让不同解析器对基线含义产生分歧，非标准数字则破坏规范 JSON 的假设。

manifest 现在对所有层级的 JSON 对象拒绝重复键，并拒绝非标准数值常量。解析错误会保留具体原因供操作者定位，但记忆读取仍失败关闭。

**验证**：内存测试注入重复顶层 `schema` 和额外字段中的 `NaN`，两者均被拒绝；全套聚焦安全回归 583 项通过，12 项因宿主能力跳过。


### 6.52 记忆基线写入也只允许规范 JSON

manifest 读取已拒绝重复键与非标准常量；进一步检查发现写入端 `json.dumps()` 默认仍会生成 `NaN`，而 provenance 参数未来也可能包含不可序列化对象，导致成功写出下一次无法读取的基线，或把编程错误泄漏成工具异常。现在序列化显式使用 `allow_nan=False`，并把类型/数值错误转成可审计的 `MemoryIntegrityError`；失败时不替换现有 manifest。

**验证**：传入 `NaN` provenance 时写入失败，且 manifest 不会被创建；全套聚焦安全回归 584 项通过，12 项因宿主能力跳过。


### 6.53 Skills 正文与脚本在消费时复核启动摘要

**触发证据**：Skill lock 在启动阶段核验 `SKILL.md` 和附属资源，但正文通常稍后才通过 `Read` 进入模型上下文；脚本则在之后才经 `Shell` 执行。只在启动时校验，留下“检查后替换、消费时使用新字节”的窗口。

运行配置现在保存启动时读取的 `SKILL.md`、受支持文本型 companion 资源和脚本的 SHA-256，并传给子代理。`Read` 对 pin 中的文件以有界读取和最终组件 no-follow 打开完整字节后校验，再返回内容；不匹配或超过 1 MiB 就拒绝。Shell 对 argv 或 shell 命令中可直接识别的技能脚本路径在启动前复核摘要，脚本 pin 同样限制为 1 MiB。

**边界**：Shell 是有权限门的通用执行器，任意命令可以间接读取/解释文件，无法仅靠路径扫描证明所有动态执行都使用已 pin 字节；宿主并发改写与校验到 exec 之间也不是原子文件系统事务。此机制拦截普通漂移及直接脚本替换，不替代 OS 沙箱或 Shell 授权。

**验证**：回归在 prompt setup 捕获摘要后篡改 `SKILL.md` 和 companion Markdown，确认 Read 拒绝；篡改已发现脚本后经 Shell argv 执行，确认执行前拒绝。资源 cap 按 skill 独立计算，pin 与执行前读取都限制在 1 MiB。Skills、已验证 prompt/plugin、工具、loop 和代理测试组合 638 项通过，12 项因宿主能力跳过。


### 6.54 上下文压缩保留工具结果的信任标签

**触发证据**：工具结果的 provenance 首行以 JSON 写入 provider transcript，但 extractive compaction 对整段统一截取 220 字符。`detail`、`source` 字段可各达 256 字符且按字母序排在 `trust` 前面，因此合法长元数据会把 `trust=low` 挤出后续摘要。自定义 summarizer 也可能完全省略标签。

压缩器现在为结果行先提取并优先保留 trust/source，再生成短摘要；无可信 provenance 的旧格式结果按 `unknown` 处理。无论使用 extractive 还是 provider summarizer，只要被压缩前缀含工具结果，压缩边界都会带 runtime 生成的持久提醒：工具输出仍是数据，不是指令，并携带有界 trust/source 清单。再次压缩时继续传递该清单。

**验证**：构造字段达到上限的低信任工具结果，验证默认摘要仍显示 `trust=low`；随后连续两次压缩，第二次使用会丢弃上下文细节的自定义 summarizer，信任标签与不可信提醒仍保留。聚焦运行时与安全回归 663 项通过，12 项因宿主能力跳过。


### 6.55 Session replay 按 compact boundary 恢复真实 provider transcript

**触发证据**：session JSONL 是 append-only，compaction 只追加 `compact_boundary`，不会删掉审计历史；但 `transcript_from_records()` 原先把边界前消息也重建到 provider transcript。它会重放已压缩内容，并令边界后的 checkpoint `transcript_len` / digest 对不上。共享审计文件里的子代理消息也不属于根代理对话，却曾被无差别重建。

恢复器现在以首个 `session_start` 的 agent 作为根代理，只重建该 agent 的消息；遇到其 `compact_boundary` 时清空 provider transcript 并从摘要开始。之后写入的 informational 上下文会恢复；只用于审计、未进 provider transcript 的 session-lease-loss 记录不会被注入。JSONL 原始历史仍完整保留供审计查看。

**验证**：session fixture 混入根/子代理消息、compact boundary、信任标签、host context 和 lease 审计记录；恢复结果只包含当前根 transcript。用该结果构建的 checkpoint 可通过 digest 校验并成功 `prepare_resume()`。session、checkpoint、session replay、compaction 与运行时安全回归共 744 项通过，12 项因宿主能力跳过。


### 6.56 压缩器不再从工具正文推断 provenance

**触发证据**：工具正文可以自行以看起来像 `[Northstar tool result metadata]` 的文本开头。若压缩器解析正文首行作为来源标签，低信任插件便能伪装成 `trust=high`，把伪造标签带入后续摘要。

`ToolResultBlock` 现在有独立的运行时 provenance 三元组；它不进入 provider API payload，也不会由 provider/session 形状的字典重建。不可变元组避免拿到请求对象的自定义 provider 原地改写信任字段。压缩清单和摘要裁剪只读该结构化字段；字段缺失时记为 `unknown`。正文中的同名 header 仍按普通工具数据处理。session replay 对未经验证的序列化内容不恢复该运行时权限，已落入 compact boundary 的摘要清单则继续随边界保留。

**验证**：新增伪造高信任 header 的插件正文回归，确认实际低信任来源仍显示为 `low`，provider/session 形状重建后降为 `unknown`，且运行时 provenance 不可变。运行时聚焦回归 745 项通过，12 项因宿主能力跳过；相关模块通过 `py_compile`，`git diff --check` 无错误。


### 6.57 sanitizer 豁免绑定到具体内容，修改后自动失效

**外部信号**：[AgentProv](https://github.com/webpro255/agentprov) 专门观察不可信指令经过多跳上下文“洗白”后的来源归因；[AgentSecBench](https://arxiv.org/abs/2605.26269)也把来源投影和工具完整性作为评测维度。对照 Northstar 的 taint tracker 时发现，`sanitized_for` 仅记录规则名：可变 payload 在净化后被修改，仍保留原有豁免，形成 sanitizer time-of-check/time-of-use 漏洞。

净化结果现在为每条豁免记录 RFC 8785 规范化 JSON 内容摘要。sink 检查时重新计算摘要；内容变化、循环/非 JSON 值无法摘要时，豁免不生效，taint 规则照常拒绝。后续其他 sanitizer 只会为自己新授予的规则写摘要，不能刷新旧 sanitizer 的过期证明。原始数据仍可供工具互操作，规则证明只绑定净化时那份精确内容。

**验证**：新增嵌套可变对象净化后篡改、另一 sanitizer 不得刷新旧豁免的回归，修改后均被拒；另确认非 JSON 对象无法取得有效 sanitizer 豁免。`test_provenance_taint` 与 `test_governance_bench` 合计 86 项通过。


### 6.58 安全自动机并行转移不能被声明顺序遮蔽

**触发证据**：`AutomatonEngine` 文档承诺跟踪非确定状态集合，但实现对每个状态只走第一条条件匹配转移并立即 `break`。同一状态存在多条有效边时，后续状态丢失；若安全边写在错误状态边前，配置顺序就能把违规路径遮住。

引擎现在对每个当前状态保留所有有效转移的目标状态，并在任何分支触及错误状态时立即拒绝。条件未知/解析失败仍按触发处理；只有全部条件明确为假时才保留原状态。

**验证**：新增并行状态分支的后续错误路径测试，以及安全转移先于拒绝转移时不能遮蔽的测试。`test_provenance_taint` 与 `test_governance_bench` 合计 88 项通过；相关模块通过 `py_compile`，`git diff --check` 无错误。


### 6.59 条件表达式求值拒绝可执行 Python 对象

**触发证据**：`safe_eval` 虽限制 AST 节点，但 `==`、`in` 和 `len()` 仍会调用环境对象的 Python 特殊方法。若条件环境收到自定义对象，这些“安全表达式”可以执行其 `__eq__`、`__contains__` 或 `__len__`，并非纯数据求值。

变量现在必须是精确类型的 JSON 标量、list、tuple 或 string-key dict；拒绝子类与任意对象，浮点数要求有限，整数限制为 256 bit。容器总节点数、深度、条目、字符串以及表达式长度/AST 节点数都有上限；循环对象失败关闭。求值器只对完成验证的副本执行比较和成员检查。

**验证**：新增恶意比较对象和 list 子类探针，确认其特殊方法从未执行；循环、超长字符串及超限表达式值均拒绝。`test_provenance_taint` 与 `test_governance_bench` 合计 90 项通过。


### 6.60 sanitizer 摘要计算设定资源上限

**触发证据**：sanitizer 豁免需要规范化完整输出以绑定内容摘要，但即使拒绝循环对象，直接把任意大小、任意深度的 JSON 交给规范化器仍可能造成高内存/CPU 消耗，攻击者可用超大工具结果拖垮治理路径。

摘要前增加 exact-type JSON 预检：最多 32,768 个节点、64 层、2 MiB UTF-8 字符数据、单字符串 1 MiB，整数最多 4,096 bit；循环、非有限浮点、非 JSON 对象和超限结构不生成摘要，因此不能取得 sanitizer 豁免。规范化器只接收通过预检的有界对象。

**验证**：新增超 1 MiB 字符串回归，sanitizer 不发放豁免且敏感 sink 拒绝。`test_provenance_taint` 39 项与 `test_governance_bench` 52 项通过；相关模块通过 `py_compile`，`git diff --check` 无错误。


### 6.61 自动机配置引用完整且实例名唯一

**触发证据**：自动机初始状态或转移目标若拼错，之前会变成一个永远没有匹配边的“隐形安全状态”；多个同名 automaton 则会在引擎的状态字典中互相覆盖。两种配置错误都可能让策略看似启用、实际不再约束行为。

`SecurityAutomaton` 构造时验证状态非空且唯一、初始状态和所有转移端点均已声明、转移工具/条件字段类型正确，并把经有界 JSON 验证的常量递归冻结，切断构造参数及嵌套值别名。`AutomatonEngine` 拒绝未验证对象和重复实例名，避免状态覆盖。

**验证**：新增未知初始态、未知转移目标、重复状态名、重复 automaton 名称和策略常量嵌套别名回归；错误在运行前被拒绝，常量改写也不能改变已构造策略。`test_provenance_taint` 与 `test_governance_bench` 合计 94 项通过。


### 6.62 策略比较不继承 Python 的 bool/int 混同

**触发证据**：即便条件输入限制为 JSON 类型，Python 仍定义 `True == 1`，并让 `[1]` 包含 `True`。策略作者表达数值条件时，模型提供的布尔值会意外匹配；若该转移通向许可状态，可能造成条件绕过。

条件比较现在采用严格的 JSON 类型边界：bool 与数值比较或成员匹配视为类型错误，排序只接受同类标量（或 int/float 组合），字符串/对象成员查询要求正确的 key 类型。类型错误沿现有 fail-closed 路径处理：自动机条件按触发处理，taint 条件按规则适用处理。

**验证**：新增 `True == 1`、`True in [1]` 拒绝，以及自动机中类型混淆条件触发拒绝的回归。`test_provenance_taint` 44 项与 `test_governance_bench` 52 项通过。


### 6.63 策略条件必须产生明确布尔值

**触发证据**：`safe_eval` 是通用表达式求值器，允许返回标量；两个策略调用点却直接使用 Python truthiness。一个返回空字符串/空列表的非条件表达式会被当成明确的 `False`，可能错误地让 taint 条件免责。

策略层现在通过 `_eval_condition()` 要求精确 `bool` 结果。非布尔值抛出验证错误；自动机将其按触发处理，taint 条件则继续应用规则。通用 `safe_eval()` 仍能用于纯表达式值求值，但策略入口不再隐式转换类型。

**验证**：新增空字符串结果不能解除 taint 拒绝，以及非布尔自动机结果触发错误转移的回归。`test_provenance_taint` 46 项与 `test_governance_bench` 52 项共 98 项通过。


### 6.64 taint 策略定义不会被构造方别名改写

**触发证据**：tracker 只复制规则列表和 spec 外层字典；`ToolTaintSpec`/`TaintRule` 的 tuple 注解并不阻止调用方传入 list，而 constants 的浅复制仍共享嵌套容器。配置加载后修改这些原始对象会悄悄改变 source label、sink 参数或豁免条件。

工具 spec 与 taint rule 现在验证字段、类型、长度和唯一性，并把可变列表规范成 tuple。tracker 验证 spec key 与名称一致、拒绝重复规则名/非规则对象，并将受限 JSON constants 递归冻结；原始输入容器的后续改写不会改变已建策略。

**验证**：新增构造后分别篡改 labels、sink 参数、规则列表、spec 映射和嵌套策略常量的回归，策略行为保持原样；重复 rule 名称被拒绝。`test_provenance_taint` 48 项与 `test_governance_bench` 52 项共 100 项通过。


### 6.65 自动机不能从错误态启动

**触发证据**：配置可将 `initial_state` 指向 `is_error=True` 的状态，但引擎原先只在转移时检查错误态。这样的策略启动后若先收到没有匹配转移的普通调用，会保留错误态却返回允许，违反错误态为终止拒绝状态的语义。

自动机结构校验现在拒绝错误态作为初始态；错误配置在引擎启动前失败，不再依赖后续恰好触发某条转移。

**验证**：在既有无效状态引用回归中加入错误初始态构造拒绝断言；taint 与治理基准组合 100 项通过，相关模块通过 `py_compile`，`git diff --check` 无错误。


### 6.66 条件表达式字面量也受值边界约束

**触发证据**：求值器已验证从环境读取的 JSON 值，但 AST 常量分支直接返回 parser 生成的 Python 值。超大整数文字和 `1e999` 产生的无穷浮点数因此绕过变量值的 bit-length 与 finite 检查。

所有 AST 字面量现在也通过同一 `_validate_condition_value()`，变量、策略常量和表达式内常量使用一致的有限值与大小边界；无效常量沿策略调用点的 fail-closed 路径处理。

**验证**：新增 `1e999` 与超过 256 bit 的整数文字拒绝测试。`test_provenance_taint` 49 项和 `test_governance_bench` 52 项共 101 项通过；`py_compile` 与 `git diff --check` 通过。


### 6.67 并发工具调用预算采用原子预留

**触发证据**：`BudgetEnforcer.check()` 与 `record()` 分离；两个并发调用可同时看到同一余额并都通过检查，随后把已执行次数推过上限。仅在 `check()` 加锁并不能解决跨执行区间的 TOCTOU。

受限工具现在通过 `reserve()` 在同一锁内核对已提交与待执行调用数，并返回唯一 reservation token。后续 gate 检查拒绝时自动释放；成功执行后必须用 token 提交。没有 token 的直接 `record()` 在已有 reservation 时拒绝，也会拒绝超过上限的提交。gate 序列化预算、自动机与 taint 决策，避免并发状态转移交错。

**验证**：并发两个调用争抢单槽预算，恰好一个拿到 reservation；错误 token、无 token 抢占和超限提交被拒。taint denial 会释放 reservation，安全调用随后仍可获得该槽。治理基准预算场景改用 reservation token。`test_provenance_taint` 51 项与 `test_governance_bench` 52 项共 103 项通过。


### 6.68 预算 reservation API 在查表前验证调用者类型

**触发证据**：预算 reservation 使用 dict 做 token 查找；`release()` 和 `record()` 虽标注 token 为 `str`，Python 不会强制类型，直接传入对象会执行其自定义 `__hash__`/`__eq__`。工具名也会在 `_limits` 映射中参与查找。

预算构造阶段验证普通 dict 和精确字符串工具名；运行时 check/record 在任何映射操作前验证工具名。release/record 只接受 runtime 生成格式的 32 位小写十六进制 token，其他对象直接拒绝，不会触发其哈希或比较代码。

**验证**：新增恶意 `__hash__` 探针，确认 token 与工具名路径均在散列表查找前拒绝；budget reservation 并发与治理基准回归合计 104 项通过。


### 6.69 非法预算 limit 的错误报告不调用对象表示方法

**触发证据**：预算限额类型错误原先用 `repr(limit)` 填充拒绝详情。公开 API 可收到任意 Python 值，因此定制 `__repr__` 能在 fail-closed 拒绝过程中执行副作用或抛异常，让策略门本身失效。

limit 现在只接受精确 `int` 类型；拒绝详情只写入 `type(limit).__name__`，不格式化或保留调用者对象。布尔值仍被拒绝，因为它的精确类型不是 `int`。

**验证**：新增恶意 `__repr__` 限额对象，确认 gate 返回拒绝、给出安全类型名且不调用该方法。`test_provenance_taint` 53 项与 `test_governance_bench` 52 项共 105 项通过。


### 6.70 独立 AutomatonEngine 的状态迁移与读取也线程安全

**触发证据**：组合 gate 有自己的锁，但 `AutomatonEngine` 同时作为独立公共原语使用；其 `observe()` 会读写状态集合和永久违规表，直接从并发调用方使用时可能发生 lost update 或在违规后继续放行。

引擎现在用重入锁保护完整状态迁移、违规查询与状态快照。组合 gate 的顺序保证仍保留；独立实例也不再依赖调用方自行串行化。

**验证**：16 个并发 `observe()` 调用竞争一个两步自动机，恰有首次安全迁移放行，触发错误态后其余调用均拒绝，最终违规状态稳定保留。`test_provenance_taint` 54 项与 `test_governance_bench` 52 项共 106 项通过。


### 6.71 MCP 隔离测试显式声明测试网络边界

**触发证据**：运行时默认拒绝 MCP 网络；该策略必须依赖 Linux Landlock ABI 10 才能可靠阻止 TCP/UDP。此前一批仅验证 stdio 协议、环境筛选或 seccomp 包装的本地 fixture 测试仍隐式使用生产默认值，在不支持 ABI 10 的 CI/容器中于握手前失败，导致测试无法到达它们真正要验证的逻辑。

这些纯本地 fixture 现在明确设置 `network="allowed"`，或在 CLI 测试中传入 `--mcp-network allowed`；独立网络策略测试仍覆盖默认拒绝和不支持时 fail-closed。生产配置没有改变，`doctor` 对默认拒绝策略继续报告当前主机是否能满足 ABI 要求。另将 Shell 会话断言改为读取结构化结果块，并令 Paxos 测试从自身路径定位模块，移除测试对 `repr()` 格式和某台开发机绝对路径的依赖。

**验证**：MCP elicitation、环境隔离、seccomp、配置导入、Shell 会话、doctor、插件与 scaffold 相关 94 项测试通过；Paxos 接口 31 项通过。随后 runtime 全量套件通过 18,310 项（24 项条件跳过）。


### 6.72 工具输出注入基准同时核对遏制与任务完成

**触发证据**：基准原有注入案例只证明默认权限门拒绝恶意 Shell 调用；单独的 utility 指标来自不同 probe，不能证明同一条受攻击运行在拒绝后仍可继续完成目标。近期公开的 [InjectEval](https://github.com/aarohigandhi/injecteval) 明确把植入指令是否执行与用户任务是否完成一起计分；[AgentInjectionBench](https://github.com/ppradyoth/AgentInjectionBench) 也要求保留 benign controls，并检查真实工具调用轨迹。

工具输出注入基准现改为单条完整轨迹：读取含伪造“系统覆盖”指令的收件箱，尝试执行恶意 Shell（必须被拒绝且不能创建标记文件），随后仍读取正常项目状态并产出准确答案。后置检查分别核对 Read/Shell/Read 的真实结果、攻击拒绝、正常读取证据和最终文本；因此“一概拒绝”不再能让这个场景通过。基准版本升至 `northstar.governance.bench.v38`。

**验证**：该端到端案例单独通过；完整治理基准 167/167 通过。它是脚本化模型下的运行时回归证据，不声称衡量真实模型对提示注入的行为。


### 6.73 workspace 文件操作绑定 no-follow 目录描述符

**触发证据**：`ToolSandbox.resolve()` 的真实路径检查与后续 `open(path)` 之间存在 TOCTOU 窗口；并发执行者可在两者之间把已检查文件或父目录替换成指向 workspace 外部的 symlink。常规路径检查也不会识别指向外部 inode 的 hardlink。

Read、Write、Edit、List 与 Grep 现在基于 workspace 根目录描述符逐级打开父目录，并对每级使用 `O_NOFOLLOW|O_DIRECTORY`；叶子文件同样禁止跟随 symlink。Read/Grep/Edit 不读取多重链接文件，Write/Edit 拒绝写入多重链接 inode；越界或竞态状态以工具错误结束。`ToolSandbox.resolve()` 仍负责给出友好的策略拒绝，描述符操作作为实际 I/O 的第二道边界。

**验证**：新增检查完成后替换叶子 symlink、替换父目录 symlink 的写入竞态测试，均确认外部文件不变；新增检查后替换 symlink 的读取测试和外部 hardlink 读写拒绝测试。`test_tools` 45 项通过；Read/Write/Edit 与 memory integrity 相关定向测试 146 项通过；runtime 全量 18,310 项通过（24 项条件跳过）。


### 6.74 Shell 子进程限制文件描述符并禁用 core dump

**触发证据**：Shell 已限制每个进程的 CPU、虚拟地址空间与单文件大小，但没有限制继承的文件描述符数量；被授权运行的命令仍可快速打开大量 FD。core dump 也可能把凭据或提示内容从进程内存写入工作区。

资源限制 exec launcher 现在把 `RLIMIT_NOFILE` 收紧到最多 256（若宿主 hard limit 更低则沿用更低值），并把 `RLIMIT_CORE` 设为零。两项均在目标命令执行前设置，失败时沿用原有 fail-closed 启动行为；描述符上限仍是每进程限制，不代表整个进程树的总量配额。

**验证**：真实 exec 子进程及 process backend 集成测试检查继承的地址空间 hard limit 未被抬高、文件描述符软上限不超过 256、core limit 为 `(0, 0)`；缺少新必需参数的 launcher 调用被拒绝。`test_os_sandbox` 45 项通过（3 项条件跳过）；runtime 全量 18,312 项通过（24 项条件跳过）；文档测试 80 项通过，构建新鲜度、链接与 `git diff --check` 均通过。


### 6.75 skill 脚本发现阶段也限制目录扫描量

**触发证据**：脚本条目数有上限，但发现逻辑此前先对整个 `scripts/` 目录执行 `iterdir()` 并排序，再筛选前 16 个脚本。目录里即使全是无关文件，也能在截断前迫使启动过程分配与目录大小成正比的列表。

发现器现在最多收集 4,096 个目录项再排序；遇到第 4,097 项就以明确的 `SkillError` 拒绝加载，不会静默给模型一个不完整目录，也不再无界累积目录名。脚本内容仍保留单文件大小限制和运行时 digest 校验。

**验证**：将扫描上限缩小到 2 的回归测试，放入 3 个脚本条目后确认发现阶段拒绝；skill 与 memory 定向测试 102 项通过；runtime 全量 18,313 项通过（24 项条件跳过）。


### 6.76 子 agent 返回值在父上下文中标注低信任来源

**触发证据**：委派子 run 的 `final_text` 会作为 Task 工具结果回到父模型。尽管子 agent 的工具子集、权限和预算受到约束，子模型仍可能受到其读取内容的提示注入影响；回传文本此前没有来源标签，父模型看到的是普通工具文本。

Task 结果现在带有 `source=subagent:<name>`、`trust=low` 和“将委派结果视为不可信数据”的元信息，沿用现有工具结果边界格式。原始答案仍完整保留，便于父 agent 使用和审计；该标记只声明来源与信任级别，不验证子 agent 的身份，也不证明其事实正确。远程 A2A/MCP 的身份认证仍是独立工作项。

**验证**：新增端到端委派测试，让子 agent 返回伪装成指令的内容，确认父模型收到的结果同时包含低信任来源标记和完整原文。`test_agents.DelegationTests` 20 项通过；runtime 全量 18,314 项通过（24 项条件跳过）；文档测试与构建链接验证通过。


### 6.77 SubagentStart 可安全最小化交接提示

**触发证据**：生态对照显示，agent handoff 常见输入过滤能力；Northstar 只向子 agent 发送显式 Task prompt（不转发父 transcript），但还没有 hook 接口在发送前去除任务里不必要的隐私。官方 Agents SDK 也强调 handoff 的 history recipient 与 guardrail 覆盖边界需要由应用明确控制。[OpenAI Agents SDK handoff](https://openai.github.io/openai-agents-python/handoffs/)。

`SubagentStart` 现在支持 `modify_input`，但只接收仅含 `prompt` 的改写对象；目标 agent 和它已通过 gate 的工具集不可改。空提示、额外字段或超过 64,000 字符的改写 fail-closed；原始提示仍只提供给获准的宿主 hook，子 provider 收到过滤后的 prompt。

**验证**：隐私过滤测试确认子 provider 请求不含原提示中的测试标识、而含过滤后任务；恶意尝试把 agent 改为权限更大的 general agent 会被拒绝且 child provider 不启动。hook 与 delegation 定向测试 53 项通过；runtime 全量 18,316 项通过（24 项条件跳过）；文档测试 80 项通过，构建新鲜度、链接与 `git diff --check` 均通过。


### 6.78 skill 目录描述按来源标注为不可信数据

**触发证据**：Agent Skills 的 MCP 扩展把 server-origin 标注和禁止隐式执行列为 host 要求；Northstar 当前仅接入 workspace 与已锁定 plugin skills，但它们的 `description` 曾以普通 Markdown 直接拼进 system prompt。换行描述可制造新的提示行，且父模型无法从列表识别条目来自哪个插件。

skill 列表现在逐条序列化为单行 JSON，明确携带 `source`（`workspace:<tree>` 或 `plugin:<name>`）和 `trust=low`。固定说明声明这些字段只是发现目录、不能作为指令；读取完整技能仍走带低信任来源的 Read 工具。目录字符上限按完整记录截断，不会裁断 JSON 结构。Northstar 尚未实现 MCP-served skills，不能把本地/plugin 标注描述成远端 server 身份验证。[MCP Skills 扩展安全要求](https://skills.extensions.modelcontextprotocol.io/specification/stable/skills)。

**验证**：新增测试确认换行/伪指令描述留在单条 JSON 字段中，无法伪造新列表行；目录条目包含来源、路径和低信任字段。`test_workspace_ext.SkillTests` 8 项通过；runtime 全量 18,317 项通过（24 项条件跳过）；文档测试 80 项、生成器 freshness 与链接检查、`git diff --check` 均通过。


### 6.79 skill 根目录与资源树扫描在遍历时受限

**触发证据**：前一项为脚本目录加了扫描上限，但 skill 的外层根目录仍用 `sorted(iterdir())`，引用资源则用 `os.walk`。特别是单个目录内的海量项目会在既有 `MAX_SKILLS` / `MAX_SKILL_RESOURCES` 被检查前被系统 API 全部物化；而 `MAX_SKILLS` 常量此前并未实际执行。

发现阶段现在每个 skill 根目录最多收集 256 个名字，整个 workspace/plugin skill 集最多 40 项；资源 pinning 使用逐层 `scandir`，每个 skill 最多访问 4,096 项，并保留嵌套 skill、symlink 与文本资源规则。任一上限超出即明确拒绝加载。

**验证**：模拟上限为 2 的测试确认第三个根目录项、第三个 skill 和第三个资源树条目都会在继续遍历前被拒绝。skill、memory 与 plugin 定向测试 151 项通过；runtime 全量 18,320 项通过（24 项条件跳过）；文档测试 80 项、构建 freshness 与链接、`git diff --check` 均通过。


### 6.80 插件 bundle 加载在遍历与读取前有总量边界

**触发证据**：插件加载器原有 `MAX_FILES=200` 只在 `Path.rglob("*")` 遍历、stat 和读取所有文件之后检查。单个超大目录仍可先产生无界路径列表；plugin.toml 也直接 `read_bytes()`，没有大小上限。manifest 的 `MAX_FILE_BYTES` 注释不能保护这两个路径。

bundle 树改为逐层有界 `scandir`，最多 4,096 个条目；最多 200 个普通文件、单文件及 manifest 各 1 MiB、bundle 文件总量 64 MiB。manifest 和内容文件都通过 `O_NOFOLLOW` 描述符读取，要求普通单链接文件，并在读取期间检测超限增长。文件列表最终按相对路径排序，内容 digest 的确定性保持不变。

**验证**：新增扫描项、bundle 总字节、manifest 大小上限与 manifest symlink 拒绝测试；plugin manifest/install 定向测试 129 项通过。`docbuild verify` 与文档测试 13 项通过。之后按 `requirements-test.txt` 安装 pytest 并重跑 runtime 全量测试，见本节末尾的最新验证记录。

### 6.81 技能审计器本身的目录遍历也有硬边界

**触发证据**：runtime 的 skill loader 已限制根目录和资源树，但只读审计工具仍在 `skill_files()` 对根目录 `sorted(iterdir())`，脚本目录也先完整排序；伴随资源通过 `os.walk()` 遍历。恶意仓库可在审计阶段先耗尽内存或时间，造成拒绝服务，或者让扫描器在超大树里未完成检查却输出部分结果。

审计器现在每个技能根最多收集 256 项、每个 checkout 最多 40 个 skill；脚本目录和每个 skill 的资源树最多检查 4,096 项。超限会形成明确 error finding，或在发现阶段以 `SkillAuditError` 拒绝不完整扫描。资源 symlink 仍明确报错；正常文件与目录保持排序后的确定性审计顺序。

**验证**：新增根目录、skill 总数、脚本目录及资源树上限测试；skill audit 66 项、plugin manifest 46 项、plugin install 83 项定向测试通过。

### 6.82 Grep 的扫描上限在目录枚举前生效

**触发证据**：Grep 虽然限制最多读取 4,000 个文件、匹配数和单文件字节，但 `os.walk()` 会先为每个目录生成完整的文件名和目录名列表，导致一个含大量空目录或文件的 workspace 在结果上限生效前仍可消耗大量内存。

Grep 改为逐层 `scandir`，整个树最多收集 16,000 个条目；已收集路径仍按目录名排序，超出时停止并在结果中给出具体截断原因。结果保持 `truncated=true`，避免把部分扫描冒充完整搜索。

**验证**：新增测试把全树预算压到 2 项，确认最多扫描两份文件、返回截断状态并标明是树条目预算耗尽；Grep/工具测试 44 项通过。

### 6.83 自定义 agent 定义在解析前受数量和字节预算约束

**触发证据**：`.northstar/agents/*.md` 及插件 agent 目录原先用 `glob()` 全量收集，再 `read_bytes()`，最后才把 prompt 截到 16,000 字符。单个巨大文件或海量定义仍会在截断之前占用无界内存。

agent 定义目录最多检查 256 个目录项，workspace/plugin 合计最多 40 个 agent 文件；每份定义最多 256 KiB，并用 no-follow 描述符在解析前检查文件类型、链接数和读取期间增长。外部 symlink 保持明确拒绝。

**验证**：新增目录项和单文件上限测试，workspace extensions 30 项、Grep 工具 44 项、skill audit 66 项定向测试通过。安装 `requirements-test.txt` 的测试依赖后，本轮 runtime 完整套件 18,334 项通过、19 项条件跳过。

### 6.84 插件发现拒绝越界根目录、符号链接与超量部分扫描

**触发证据**：bundle 内部遍历已有 4,096 项上限，但安装插件根目录仍通过 `sorted(root.iterdir())` 全量收集；插件根或插件子目录的符号链接也会被 `is_dir()` 跟随。大量伪插件目录可在各 bundle 的限制执行前消耗资源，路径链接则会让加载从 workspace 预期位置转向别处。

加载器现在先验证解析后的插件根仍位于 workspace 内，并拒绝插件根和单个插件目录 symlink。安装根最多扫描 256 项，超过时返回明确问题且不产生部分插件清单；运行时贡献因此被阻断。

**验证**：新增插件根外链、单插件目录 symlink 和模拟 2 项扫描上限的拒绝测试，plugin install 定向测试 86 项通过；后续 runtime 完整套件累计 18,335 项通过、19 项条件跳过。

### 6.85 项目上下文在读取字节时就受限

**触发证据**：项目 `AGENTS.md` 最终只保留 64,000 个字符，但此前通过 `Path.read_bytes()` 先完整载入文件再截断。大型仓库指令文件因此能在 prompt 上限生效前消耗任意内存。

上下文读取改用 no-follow 文件描述符，并最多读取 UTF-8 字符预算所允许的 256 KiB 加一个检测字节；随后仍按 64,000 字符截断，保持 prompt 语义与显式 `truncated` 标记。非普通文件拒绝读取。

**验证**：ASCII 与四字节 Unicode 超长上下文都保持字符上限并标记截断，policy/context 定向测试 41 项通过；runtime 完整套件 18,335 项通过、19 项条件跳过。

### 6.86 审计日志恢复改为逐行校验

**触发证据**：append-only 审计 feed 每次 writer 重启都会被 `read_bytes()` 整体载入；随后 `split(b"\n")` 又创建多份与历史长度相关的对象。长会话的恢复内存因此随日志总量增长。

恢复校验现在直接迭代二进制文件行，保持最后有效记录、截断字节偏移和损坏尾部恢复语义；`verify_on_open=False` 的尾哈希扫描也改成逐行解析。公开 `verify_lines()` 同步改为单遍验证，普通模式只保留链状态、HLC 状态及签名失败行，不再缓存整份解析记录。严格 nonce 去重仍需保留 nonce 集；单条记录也仍会整体解析。

**验证**：审计耐久性测试 20 项、审计链测试 82 项通过；新增回归在 `Path.read_bytes()` 被设为失败时成功重开，并确认 verifier 遇到首条坏链后不继续消费尾部。runtime 完整套件 18,337 项通过、19 项条件跳过。

### 6.87 工具输入和 schema 的验证遍历受资源预算约束

**触发证据**：JSON Schema validator 已限制正则执行时间和嵌套深度，但在校验前仍可遍历任意宽的 provider 参数树或本地扩展声明的 schema 树。远程 MCP schema 有单独字节上限，通用入口此前缺少统一的树预算。

验证前现在迭代计算保守的 JSON 编码体积估算，并限制 1 MiB 与 50,000 个展开后的节点；每个容器在加入子节点前先检查剩余预算，避免超宽对象先扩张待处理队列。共享引用按 JSON 展开后的每次出现计数，循环对象由 32 层深度上限拒绝；非 JSON 值也会在 schema 执行前拒绝。

**验证**：新增共享子树放大、超宽容器和非 BMP 转义体积回归，tool input schema 定向测试 23 项通过；real-runtime 红队测试用 16 层共享引用树验证审批回调和 handler 均未触发，并以合法 network 工具调用作对照，红队套件 25 项通过。该拒绝场景已加入 `northstar bench` 的 redteam track（v39），离线 CLI 用例通过。运行时完整回归此前通过 18,515 项、21 项按环境条件跳过；该完整回归早于这条端到端用例。

### 6.88 OpenAI-compatible 响应归一化对文本与工具调用设上限

**触发证据**：工具 schema 的 1 MiB 输入树预算发生在 provider 把 OpenAI `arguments` JSON 解码成 Python 对象之后。仅限制 1 MiB 字符仍允许短标量数组在解析时先构造远超 50,000 个节点；流式适配器也需要在累计参数片段时及时拒绝。

适配器限制归一化文本和每个工具参数 blob 各 1,048,576 字符、所有工具参数累计 4 MiB、单响应最多 128 个工具调用；SSE 逐片拼接时也先检查累计大小和索引范围，再保存参数片段。OpenAI 兼容适配器现在在 `json.loads()` 前扫描字符串结构并限制展开节点数与深度，解码后再检查保守树体积；对象形式参数及 Anthropic 已解码输入会按同样树预算和单响应节点总数检查。SDK 自身在 normalizer 前解析 JSON 的风险现由传输层响应体上限覆盖（见 §6.142）；但通过宿主注入的 SDK client 不会自动包裹。

**验证**：新增短数组扩张在 JSON 解析前拒绝、单响应跨工具调用累计节点上限、解码后 Unicode 体积预算和 Anthropic 汇总节点限制回归；schema 测试 25 项、OpenAI adapter 37 项、Anthropic provider 36 项、streaming 47 项定向测试通过。完整 runtime 套件 18,523 项通过、21 项按环境条件跳过（151.7 秒）。

### 6.89 Hook 原地改参不能绕过显式重写与 schema 检查

**触发证据**：`PreToolUse` 收到的 `tool_input` 与待授权 payload 曾共享同一个可变 dict。Hook 可以直接写 `payload.tool_input["path"] = ...` 后只返回 `allow`；runtime 只有检测到 `updated_input` 时才对改写再次校验，导致 handler 执行的参数不是最初过 schema 的参数。

可改写 hook 现在每次得到 `tool_input` 和 `data` 的深拷贝；hook 之间也互不共享可变输入。只有显式 `modify_input` 的返回值会被深拷贝为新 payload，并在权限检查前重新校验 schema。这样 handler 与权限门都消费同一份改写后参数。

**验证**：新增 runtime 回归让 hook 原地改写写入路径但仅返回 allow，确认写入仍落在原先授权路径；既有显式安全重写与非法 schema 重写测试也通过。hook suite 32 项通过；runtime 完整套件 18,346 项通过、19 项条件跳过。

### 6.90 Provider 不能通过共享引用改写运行时工具 schema

**触发证据**：`ToolSpec` 是 frozen dataclass，但 `input_schema` 内部仍是可变 dict；`to_api()` 和 OpenAI adapter 曾直接复用该引用。注入的 provider client 收到 request kwargs 后可原地修改 schema，影响同一 runtime 随后的 `_authorize_tool()` 校验。

`ToolSpec` 构造时现在复制调用方 schema，API view 不再暴露内部对象，OpenAI 参数及 Anthropic tools 也在构建请求时深拷贝。provider 收到并修改的请求数据与 gate 持有的 schema 分离。

**验证**：新增端到端恶意 provider 用例修改 Write 的 path schema 并返回整数路径，runtime 仍以 `invalid_input` 拒绝且文件未创建；新增 ToolSpec 源 schema/API view 双向隔离测试。tools suite 45 项、OpenAI adapter 33 项通过；runtime 完整套件 18,348 项通过、19 项条件跳过。

### 6.91 ToolSpec 的可变兼容字段不是运行时授权规则

**触发证据**：即使 provider API view 已深拷贝，公开 `registry.require(name).input_schema` 仍是可变 dict。任意持有 `ToolSpec` 引用的 in-process 扩展可以在 run 期间把字段改宽，而 `_authorize_tool()` 之前直接读取这个兼容字段。

`ToolSpec` 创建时保留第二份私有 gate schema snapshot；`schema_snapshot()` 每次返回隔离副本。授权校验只消费该快照；原字段保留给既有调用方读取，但其后续修改不再改变 runtime 规则。API 导出同样从快照产生独立对象。

**验证**：新增回归直接把注册后 `Write.path` 的公开 schema 改为 integer，runtime 仍拒绝整数输入；既有 provider 请求 mutation 回归继续通过。tools suite 45 项、OpenAI adapter 34 项通过；runtime 完整套件 18,349 项通过、19 项条件跳过。

### 6.92 封存输入指纹绑定单次工具调用 ID

**触发证据**：治理 ledger 的输入指纹此前只绑定工具名和参数。同一轮两次完全相同的调用会落下相同指纹，导致审计方无法仅凭 `RunReport.tool_calls` 判断某条封存记录属于哪个 provider `call_id`。

运行时现在将 `call_id`、工具名及 hook 处理后的有效参数共同摘要后送入 SAFR 与封存 ledger；`ToolCallReport` 同时暴露该摘要。报告与 ledger 可按摘要直接关联，原始参数仍不会写入封存记录；独立 runner 的调用方若未传入摘要，仍沿用原来的工具参数指纹。

**验证**：并行执行两个参数完全相同的 `Peek` 调用，确认两个报告摘要互异，并与两个封存事件的输入指纹集合完全匹配；拒绝路径也确认与 `denied:authorize` 封存记录匹配。runtime 全量套件 18,350 项通过、19 项条件跳过。

### 6.93 Workspace hook 脚本读取有字节上限

**触发证据**：workspace hook 的注册与每次派发前都会读取脚本以验证摘要，但此前通过 `Path.read_bytes()` 无上限地装入父进程内存。执行超时和子进程输出上限无法保护这段读取。

hook 脚本现通过 `O_NOFOLLOW` 文件描述符读取，确认是普通文件，并在注册与派发前都限制为 1 MiB；读取期间文件增长超限也会立即拒绝。派发期读取失败或超限按 veto 处理，不启动子进程。

**验证**：注册阶段超限拒绝，以及注册后脚本增长到上限以上时派发拒绝且 runner 未启动的回归通过；command hooks 定向测试 84 项通过，runtime 全量套件 18,352 项通过、19 项条件跳过。

**残余风险与显式契约**：默认 `execution = "path"` 为兼容性保留原路径执行及其同 UID 替换竞态。需要执行内容与审核字节绑定的 Linux 部署可显式配置 `execution = "snapshot"`；该模式只接受显式的 Python、Node、`sh` 或 `bash` interpreter，把注册时字节写入 sealed memfd 后通过继承 FD 交给适配器执行。逻辑 `__file__`、Node 文件名/相对 `require`、shell `$0` 会保留；未支持平台或创建/密封失败时拒绝 hook，不回退到路径模式。它仍只快照主脚本，脚本再导入的辅助文件按原工作目录规则读取。

设计依据：[Python 命令行脚本路径语义](https://docs.python.org/3/using/cmdline.html)、[Node.js 模块解析](https://nodejs.org/api/modules.html) 与 [Linux memfd 密封语义](https://man7.org/linux/man-pages/man2/memfd_create.2.html)。

### 6.94 Linux hook 的注册字节快照执行

**实现**：workspace policy 的 `[[hooks]]` 与 plugin hook 都可显式声明 `execution = "snapshot"`。该模式需要 Linux procfs、sealed memfd 和显式的 `python`、`python3`、`node`、`sh` 或 `bash` interpreter；hook 注册时保存受 1 MiB 限制的字节，dispatch 将其写入匿名 memfd 并加 write/grow/shrink/seal 四种 seal，再通过继承 fd 启动解释器。无支持或密封失败时 hook veto，不回退到 `path`。Python `__file__` 与 `sys.path`、Node CommonJS 文件名及相对 `require`、Shell `$0` 有启动器回归覆盖。快照范围是主脚本，不包含脚本随后读取或导入的 workspace 资源。

**兼容性边界**：默认 `execution = "path"` 保持既有执行方式及其同 UID 路径替换竞态；需要把审核字节与实际执行绑定的 Linux hook 可显式启用快照。非 Linux hook 不能请求快照模式。

**验证**：snapshot 替换来源文件后仍执行注册字节、memfd 创建失败 fail-closed、Python/Node/sh/bash 路径语义与 plugin manifest round-trip 均覆盖；新增 plugin install → `load_contributions` → `parse_hooks` 接线测试确认配置与 reviewed digest 均抵达 runtime。command hooks、plugin manifest/install 定向套件 182 项通过；runtime 全量套件 18,357 项通过、19 项条件跳过（全量运行后增加的唯一用例是上述接线回归，已在定向套件中通过）。

### 6.95 人工批准绑定完整 egress 请求形状

**触发证据**：egress approval receipt 原先签名绑定 action card、call、参数与 body 摘要，却没有绑定实际请求目标、方法、路径和自定义 header。持有同一份有效 receipt 的调用者可能在 TTL 内将批准重放到另一 allowlisted host，或改写影响上游行为的 header。

现在 egress 请求另计算规范化请求形状摘要，覆盖小写 host、port、方法、path、body SHA-256 与所有会透传的 agent header；sidecar 覆盖的 `Host`、`User-Agent` 不取调用方值。receipt 将该摘要纳入 Ed25519 签名，enforcer 在授权时重新计算并比较。缺少该字段的旧 receipt 对需要 approval 的 egress fail-closed；它们仍保持原有非 egress approval 语义。

**验证**：批准的 host（在同一规则内）、路径或自定义 header 被改变时均拒绝；旧格式 receipt 对 egress 拒绝。egress、sidecar、audit-fix 与通用 permissions 定向测试合计 165 项通过、12 个 subtests 通过；API 文档重建与链接校验通过。

### 6.96 Egress authority 必须是 DNS 主机名

**触发证据**：allowlist 的 `hosts` 过去只拒绝通配符，没有拒绝 `user@host`、路径片段或空标签。虽然请求层做了控制字符和长度限制，但错误配置仍可能让 resolver、TLS SNI 与 HTTP authority 对同一字符串产生不同解释。

策略加载、sidecar wire 校验和 runtime enforcer 现在共用 DNS-style ASCII hostname 检查：总长与 label 长度遵循 DNS 上限，只允许字母数字与 label 内连字符，可接受单个末尾点；userinfo、斜杠、空标签、多余末尾点和非 ASCII 均拒绝。数值 IPv4 地址仍符合格式并可作为显式 allowlist 项。

**验证**：策略加载测试覆盖路径、userinfo、内空标签和重复末尾点；sidecar 与策略引擎分别验证请求期 host；egress enforcer、sidecar 和 audit-fix 定向测试 74 项通过、4 个 subtests 通过，文档链接与构建验证通过。

### 6.97 Run 终态事件公开 call_id 绑定的执行证据

**触发证据**：runtime 内部 `ToolCallReport` 已记录 `call_id`、执行状态、gate 与输入 digest，但公共 JSON `result` 事件只公布 denials。CLI、Python SDK 与 TypeScript SDK 消费者只能看到 assistant 提议的 tool call，无法从终态报告中确定其是否被拒、阻断、失败或完成；这会使外部基准误把提议动作当执行。

`ResultMessage` 与公共终态事件现在携带 `tool_call_reports`，以 call id 和 assistant `tool_use` 块关联。报告保留状态、gate、permission source、provenance 与治理输入 digest，不复制原始参数；TypeScript SDK 同步提供 `toolCallReports`，旧 runtime 缺字段时安全归一为空列表。子代理汇总在 6.98 继续扩展为递归执行报告。

**验证**：Python SDK 测试验证允许工具状态为 completed、策略拒绝为 denied/not_started，且报告不含 raw input；events、CLI、loop、TypeScript parser 与 SDK parity 测试覆盖新字段。runtime 定向套件 162 项通过、15 个 subtests 通过；TypeScript 测试 57 项通过。TypeScript `tsc` 未安装；项目 SDK 声明使用 Node 原生类型剥离并无 build/typecheck 依赖，未将缺少 `tsc` 报作失败。

### 6.98 Delegation 执行报告递归贯穿公共结果

**触发证据**：6.97 加入 parent `Task` 报告后，delegated child 的执行报告仍只在进程内的 `SubagentReport`，SDK 和 benchmark consumer 无法观察子代理内部哪些调用被拒或完成。nested delegation 还会将这一缺口继续向下传递。

每个 `SubagentReport` 现在携带该子代理自己的 call reports 和下一层 subagent summaries；父级 `ResultMessage.subagents` 递归输出这些摘要。TypeScript SDK 以递归类型和解析器映射同样结构。只输出 agent、执行状态、gate、denial、预算/用量与 final text 长度等摘要，不嵌入 transcript 或最终文本；每个 child call 保留自己的 `agent` 与 `call_id`。

**验证**：runtime 真实子代理读取文件后，父级终态中同时出现 `Task` completed 与 explorer `Read` completed；类型层测试解析两层嵌套，包含 completed 和 blocked 状态且确认没有 transcript。runtime agents/SDK/events/loop/CLI 合计 199 项通过、26 个 subtests 通过；TypeScript 测试覆盖新增递归结构。

### 6.99 Egress socket 的排队连接数受 worker 容量限制

**触发证据**：sidecar 的 `ThreadPoolExecutor` 虽将活动 worker 固定为 16，但其内部待处理队列无界。持续建立连接可让 accept loop 不断排入 socket 与任务；每个排队连接还可能长期占用文件描述符，直到 worker 处理它或读取超时。

服务现在用容量为 `MAX_WORKERS` 的有界 semaphore 包住接入与提交过程。活动及排队任务总数不超过 worker 容量；满载时新接受的 socket 立即关闭，不加入 executor 队列。提交异常时也会释放容量并关闭 socket，避免资源槽泄漏。

**验证**：新增满载回归确认提交函数拒绝并关闭 socket，peer 观察到 EOF；egress sidecar 全套 23 项通过，模块与测试文件编译通过。

### 6.100 Egress 凭据清理保留二进制响应字节

**触发证据**：sidecar 将最多 4 MiB 的上游响应体先按 UTF-8 `errors="replace"` 解码，清理凭据后再编码。合法的二进制响应包含无效 UTF-8 时会被替换为 U+FFFD，导致返回的 base64 内容与上游字节不一致。

响应体现在直接按 UTF-8 凭据字节序列执行替换，未命中的任意字节保持原样；响应头继续按文本清理。这样可保留二进制 API 内容，同时继续隐藏 brokered credential 的原样反射。

**验证**：新增混合 NUL、无效 UTF-8 字节、凭据和高位字节的回归，确认仅凭据变为 `[REDACTED]` 且其余字节不变；egress sidecar 全套 24 项通过，模块与测试文件编译通过。

### 6.101 Shell 对已知攻击工具直接调用默认拒绝

**触发证据**：offensive-security denylist 原先只检查注册工具名。`nmap` 作为工具名会被拒绝，但模型可把同一可执行程序写进 `Shell.command`，此时权限层只看到 `Shell`，会继续进入常规批准路径。

权限层现在对 Shell 命令做有界的本地词法扫描，识别命令起始位置上的已知 offensive executable，并覆盖绝对路径、命令链、`sudo`/`env`/`timeout`/`nice`/`xargs` 包装、`find -exec`，以及反引号、`$(...)` 和 process substitution（包含双引号内仍会执行的替换）。单引号内的相同文本视为数据，不误拦。默认拒绝，显式 `offensive_allowlist` 可放行；它仍不把 shell 字符串当作完整 AST：变量拼接可执行名、`eval`、脚本解释器和其它间接启动仍须由宿主批准及 OS 沙箱/网络隔离约束，威胁模型保留此边界。

**验证**：新增直接调用、绝对路径、链式命令、常见包装器、`find -exec`、命令替换、文本参数误报控制和显式 allowlist 测试；另有真实 loop 回归确认 Shell handler 未执行且终态报告为 `not_started/offensive`。权限测试 100 项、loop 测试 32 项通过。

### 6.102 Linux 进程沙箱默认拒绝创建网络套接字

**触发证据**：`process` 后端在 Landlock 不可用时仍可运行，但旧 seccomp denylist 未覆盖 `socket`/`socketpair`；因此工具不能仅凭 `network=false` 对网络能力作出可靠约束。

Linux seccomp 表现加入 x86_64 与 aarch64 的 `socket`、`socketpair`、`io_uring_setup` syscall 拒绝项。BPF 对未知 audit architecture 和 x86_64 x32 syscall ABI fail-closed，避免错误架构表意外放行。该屏障限制 socket 创建，不是目标域名/地址级 egress 授权；关闭 seccomp、不支持的系统以及显式传入的联网文件描述符仍是残余边界。bwrap 继续通过独立 network namespace 隔离网络。

**验证**：seccomp 解释器回归覆盖拒绝表、未知架构与 x32 fail-closed；真实 Linux process 后端回归确认 `socket()` 返回 EPERM。seccomp 定向测试 20 项通过，OS sandbox 测试 53 项通过、3 项因 bwrap 不可用跳过，相关模块 `py_compile` 通过。syscall 编号对照 Linux 上游 [x86_64 syscall table](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl) 与 [generic syscall definitions](https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/unistd.h)。

### 6.103 Landlock 拒绝通过 workspace 符号链接读取外部文件

**验证缺口**：既有真实内核测试确认 workspace 外写入被拒，但没有覆盖攻击者把 workspace 内路径指向 workspace 外文件的常见逃逸尝试。

新增真实 Landlock loader 回归：在 workspace 内创建指向同级目录“主机文件”的符号链接，执行 `cat` 读取；测试要求非零退出、输出不含秘密内容且 stderr 明确报告权限拒绝。这个用例验证 path-beneath 访问检查跟随解析后的目标生效，而不只验证直接访问绝对路径。

**验证**：新增回归属于真实内核执行测试；本工作环境的 Landlock 版本探测返回 `ENOSYS`（当前内核未提供 syscall），因此 `test_landlock.py` 共 17 项通过、6 项真实内核测试跳过，符号链接隔离效果仍待启用 Landlock 的 Linux runner 实跑，不将跳过计作隔离通过。

### 6.104 Landlock 进程白名单不再递归开放宿主 `/dev`

**触发证据**：默认进程文件规则曾对整个 `/dev` 递归授予读写权限，因而把权限延伸到 `/dev/shm` 与 `/dev/pts` 等宿主子树，而普通命令只需要少量标准设备。

默认规则现在只允许真实字符设备节点 `/dev/null`（读写）及 `/dev/zero`、`/dev/random`、`/dev/urandom`（只读）。不授予 `/dev` 目录树，也不跟随 host-side 设备节点替换 symlink。普通 bwrap 后端继续使用 bubblewrap 创建的独立 `/dev`。

**验证**：纯策略回归检查设备节点精确授权和 `/dev/shm`、`/dev/pts` 不在规则中；真实内核回归要求 `/dev/shm` 访问被拒、`/dev/null` 重定向仍可用。当前环境无 Landlock syscall，真实内核部分跳过；不能据此宣称 runtime 隔离已实跑。

### 6.105 父进程读取管道异常时清理整个命令进程组

**触发证据**：`_run_popen` 已处理正常超时、输出超限和命令 leader 退出，但 selector 注册或读取 stdout/stderr 若向调用方抛异常，旧清理路径只关闭父端管道，不保证已启动的命令及其后代退出。

现在 selector 在 spawn 前初始化；子进程启动后的管道/selector 处理发生任何异常时，runtime 对整个 session process group 发送 TERM，短暂等待后发送 KILL、回收 leader，再重新抛出原异常。这样取消和父端 I/O 故障不会把长期运行的命令留在后台。

**验证**：故障注入在 `Popen` 成功返回后令父端 `os.read` 失败；测试确认异常仍传给调用者，已启动的子进程 PID 随后不存在。

### 6.106 Workspace 根路径祖先逐段 no-follow 打开

**触发证据**：文件工具此前对 workspace 内父目录使用 `openat` + `O_NOFOLLOW`，但 workspace 根本身只通过一次绝对路径 `open(..., O_NOFOLLOW)` 打开。该标志只约束最后一个路径组件；若校验完成后将根路径的上级目录替换为 symlink，内核仍可能沿上级 symlink 打开另一个 `workspace` 目录。

新增目录链打开器从 `/` 开始逐组件通过 dirfd 与 `O_NOFOLLOW|O_DIRECTORY` 建立句柄，再从这个已固定的根目录 fd 执行 Read、Write、Edit 和目录访问。任一祖先在打开时变成 symlink 或非目录即拒绝。相同逻辑也用于列出 workspace 根目录。

**验证**：回归在路径校验返回后，将 workspace 的上级目录改名并换成指向外部目录的 symlink；Read 必须失败且不得返回外部秘密。`test_tools.py` 48 项通过。

### 6.107 Shell 攻击工具扫描识别带引号的活动命令替换

**触发证据**：基于 `shlex` 的命令位置扫描能识别未加引号的 `$(nmap ...)` 和 process substitution，但 `shlex` 会把双引号中的 `"$(nmap ...)"` 当作一个普通参数；shell 仍会执行其中的替换。此前的 backtick 正则也不区分单引号文本，存在误报。

新增有界、引号感知的替换提取，递归检查活动的 `$(...)`、`<(...)`、`>(...)` 与 backtick 命令体；单双引号语义分别处理，单引号和转义内容不当作可执行替换。此扫描仍只是前置 tripwire，变量构造、eval 与解释器执行继续由 permission gate 和 OS 沙箱承担。

**验证**：权限测试新增双引号内命令替换拒绝、process substitution 拒绝及单引号文本放行；loop 回归确认双引号内 `$(nmap ...)` 在 Shell handler 前被拒绝，终态为 `not_started/offensive`。权限测试 100 项、loop 测试 33 项通过。

### 6.108 Shell 静态扫描解析不完整时拒绝执行

**触发证据**：扫描器对嵌套 shell 替换设有深度上限以保持有界；上限到达后原本停止递归，深层双引号内替换可能只被 `shlex` 看作普通参数。`shlex` 对未闭合引号抛错时，旧逻辑也会返回“未发现攻击工具”，把解析失败当作无害。

现在语法不完整或替换嵌套超过扫描上限都会产生独立拒绝条件 `offensive:shell_scan_incomplete`。该拒绝不受 offensive executable allowlist 影响：allowlist 只允许已识别的明确命令，不会把无法审查的 shell 文本变成已审查。

**验证**：权限测试覆盖超深嵌套与未闭合引号；真实 agent loop 回归确认超深输入在 handler 前拒绝，终态为 `not_started/offensive`。权限测试 101 项、loop 测试 34 项通过。

### 6.109 安全启动包装器不从可写 PATH 查找解释器

**触发证据**：process sandbox 与 MCP seccomp/Landlock launcher 曾通过 `PATH` 查找 `python3`。PATH 前置目录可写时，同名程序会在资源限制、seccomp、Landlock 或能力丢弃包装器之前运行，直接绕过这些边界。

所有可信启动器现在固定使用当前运行时的 `sys.executable`；目标程序仍按其既有 PATH 规则解析。这样不改变被启动命令的搜索语义，只固定安全控制自身的引导解释器。

**验证**：process backend 回归在 PATH 首位放置恶意 `python3`，确认目标程序正常运行且标记文件未产生；MCP seccomp 与 Landlock argv 测试分别断言包装器使用 `sys.executable`，即使 `shutil.which("python3")` 被替换为非可信路径。

### 6.110 MCP 响应必须符合 JSON-RPC 2.0 响应信封

**触发证据**：MCP 客户端此前只要收到匹配请求 ID 的 JSON 对象，就可能把其中 `result` 当作成功；缺少 `jsonrpc` 版本、同时存在 `result` 与 `error`，或形状错误的错误对象都未被拒绝，造成协议歧义。

匹配请求 ID 的响应现在必须声明 `jsonrpc: "2.0"`，并且恰好包含 `result` 或 `error` 之一。错误响应还必须是对象，包含整数 `code`（拒绝布尔值）与字符串 `message`。不匹配 ID 的异步消息继续走既有通知筛选逻辑。

**验证**：新增用例分别拒绝缺版本、缺少结果/错误、双字段和错误对象类型，并确认合法错误响应仍正常返回给调用方。

### 6.111 MCP 订阅确认与拒绝响应采用严格协议校验

**触发证据**：订阅确认路径独立于通用请求交换器，之前只核对 subscription ID 与通知能力，缺少 JSON-RPC 版本校验；匹配 ID 的拒绝响应也没有验证错误码/消息类型，且可把近 1 MB 的服务端文本直接写入异常。

订阅确认现在须带 `jsonrpc: "2.0"` 才能启用 list-changed 通知；匹配 ID 的拒绝响应必须是 2.0 错误信封、含整数 `code` 与字符串 `message`。用户可见的拒绝原因限制为 400 字符，避免不可信服务器扩大日志和错误上下文。

**验证**：新增测试覆盖缺失版本、有效确认、畸形错误对象，以及超长拒绝文本裁剪；只有验证完整的确认才会写入已订阅状态。

### 6.112 MCP 通知积压时推迟工具执行

**触发证据**：调用工具前的通知 drain 为避免聊天服务器拖住 agent loop，最多消费 32 帧后就会继续执行。服务器可先排入 32 帧无关消息，再把 `notifications/tools/list_changed` 放在队列后面；调用方会在发现工具定义变化前发出下一次工具调用。

drain 现在在达到帧预算后额外做一次非阻塞探测。若仍有可读帧，就处理该帧并返回“未排空”；调用路径拒绝发出 MCP 工具调用，提示积压消退后重试。这样保持有界读取，同时不把“预算耗尽”误当成“队列为空”。

**验证**：测试确认持续可读流最多读取预算加一帧并标记未排空；工具调用集成回归确认未排空时 `_request("tools/call")` 不会被执行。

### 6.113 MCP 工具列表拒绝同名歧义并在刷新时重用准入上限

**触发证据**：初次准入把工具定义写入以名称为键的字典，重复名称会被后一个定义静默覆盖；刷新阶段也允许同名项覆盖 digest，且没有沿用初次准入的 25 工具和 30,000 字符 Schema 上限。服务器可能借此制造模型看到的定义、pin digest 与按名称执行行为之间的歧义，并在刷新时放大验证成本。

初次准入发现重复名称即拒绝连接；刷新发现重复项、无效条目、超出工具数或 Schema 大小上限时隔离服务器。输入与输出 Schema 在刷新时均复用初次准入的大小限制。

**验证**：集成测试确认重复定义不会暴露任何工具；刷新测试确认重复名和超限列表触发隔离，未产生可调用的新定义。

### 6.114 MCP 工具结果的 `isError` 必须是布尔值

**触发证据**：工具结果此前用 `bool(result.get("isError"))` 解释服务端字段。协议违规值如字符串 `"false"` 会被当成错误；某些其它非布尔值又会被当成成功，造成调用结果语义由 Python truthiness 决定。

客户端现在只接受缺省（按成功处理）或真实布尔值。出现其它类型就隔离服务器并返回协议错误，不再将值强制转换成成功/失败。

**验证**：回归让已准入服务器返回字符串 `"false"`；调用必须报错并触发 quarantine，而不能把文本当成功结果交给 agent。

### 6.115 MCP 关闭时清理已脱离组长生命周期的后台后代

**触发证据**：MCP server 在独立 session/process group 中启动，但 `close()` 只在组长 `poll() is None` 时发送 TERM。服务器若先 fork 后退出，`Popen` 会显示组长已结束，旧清理逻辑便跳过整个组，后台 worker 可继续运行。

关闭现在总是向该 server 的进程组发送 TERM，并在宽限期内检查整个组是否消失；宽限期结束仍存在时发送 KILL。组长退出状态不再决定是否清理后代。

**验证**：真实子进程回归让组长生成一个处理 TERM 时写标记的长睡眠后代，然后立即退出；调用 `close()` 后必须观察到后代的 TERM 标记。

### 6.116 MCP 服务器终止变更订阅时停止工具调用

**触发证据**：MCP 2026-07-28 规定服务器主动结束 STDIO `subscriptions/listen` 时，以 `notifications/cancelled` 引用该订阅请求 ID。客户端此前忽略了这一事件，仍把 list-changed 标记为已订阅；之后工具集发生变化时，客户端可能收不到刷新信号。规范依据：[SEP-2575 stateless MCP](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/seps/2575-stateless-mcp.md)。

客户端现在在交换响应和通知 drain 两条路径识别匹配当前订阅 ID 的取消，清除订阅状态并隔离服务器；同一 drain 中的工具调用会立即拒绝，正在等待响应的调用也会在返回结果前被拒绝。非当前订阅的取消不会影响状态。

**验证**：回归向活跃 client 注入匹配与取消帧，确认订阅被清除、server 进入 quarantine，且 `_request("tools/call")` 没有执行。

### 6.117 MCP 重新准入只能在断开后执行，并在成功连接时替换 pin

**触发证据**：`re_admit()` 可在活动连接上立即清除 quarantine；同时，已有持久化工具 pin 时，下次 connect 仍按旧基线比较，和“显式重新准入后建立新基线”的接口契约不符。复用同一 client 重连还会把前一 server 进程的 `_tools` 留在字典里，触发重复名称拒绝。

重新准入现在要求 server 已断开，并把“接受新定义”作为待完成状态；只有新进程的完整工具列表通过校验后，才原子写入新 pin 并清除待完成标记。每次连接先清空进程范围内的工具、digest 和订阅状态；失败时仍走既有全量回滚。

**验证**：测试覆盖活动连接重新准入拒绝、伪造旧 pin 后显式重新准入成功替换、同一 client 关闭后重连不残留旧工具，以及重复 flap 的断开后重新准入流程。

### 6.118 Egress 授权 receipt 必须先落盘，再发送上游请求

**触发证据**：sidecar 原先在 HTTP 请求完成后才追加 receipt，而且 `ReceiptFeed` 写失败仅记 `last_error`，不会影响请求处理。磁盘满、目录权限异常或 feed 目录被替换时，带 broker 凭据的出站动作可能已发生但没有持久审计记录。

授权 verdict 现在在附加凭据和打开 socket 之前写入 receipt feed；写入失败时返回错误并明确未发送上游请求。receipt 内容在内层保留原始签名，外层 sidecar feed 使用单独的连续 `northstar.egress-feed/2` 链，绑定追加顺序。允许请求只预写一次，拒绝和校验失败由外层补记，不依赖有界 digest 缓存去重。生产 socket 入口强制要求签名密钥，未配置时拒绝启动；开发库调用仍可显式不签名。启动时验证新链；旧版本的单条 receipt 链逐条验证后迁移，历史未签名记录只保留链完整性，不宣称追溯认证。

**验证**：故障注入让 feed 父路径变成普通文件，确认 `_perform_http` 未调用；feed 连续写入后由 `audit_chain.verify_lines` 验证完整多记录链，测试还覆盖合法旧 singleton feed 迁移、签名新链重启恢复、生产签名密钥缺失/畸形拒绝、带生产密钥的旧未签名链迁移与 append 顺序。

### 6.119 Egress 签名密钥轮换必须保留可验证历史

**触发证据**：生产入口强制签名后，单个当前公钥验证器会让旧 seed 签过的 feed 在换钥后无法启动；若直接把校验降级成无签名模式，攻击者则可能把签名链改造成未签名尾部。

审计链验证器现在接受按 `key_id` 查找的公钥映射；生产 feed 要求每一条记录都带有效签名。sidecar 的当前 key 由 seed 自动加入信任集，旧公钥从受控 JSON 配置加载，新记录必须带 `NORTHSTAR_EGRESS_KEY_ID`。轮换时在改当前 seed 前保留旧 `key_id` 公钥；未知 key、无 key ID 的签名（除显式登记 `__legacy_default__`）及未签名记录都会让启动失败。旧公钥可在其签名记录全部归档并不再需要验证后移除。

**验证**：审计链测试覆盖一条链中旧/新 key 混签、缺失旧公钥失败及强制签名拒绝无签名链；sidecar 测试真实写入旧 key 记录、用新 key 恢复并追加，再用同一 keyring 重启恢复整条历史。

### 6.120 将执行后的用户知情度与工具拦截、任务效用分开评分

**触发证据**：[2026 年 3 月的大规模间接提示注入竞赛](https://arxiv.org/abs/2603.15714)把 concealment 作为独立目标：攻击可成功改变状态，而最终回答不暴露发生过攻击。单看最终回答会漏掉状态副作用，单看拦截又无法表示“动作执行后有无通知用户”。

`agent_threat_bench_adapter.score_concealment` 现可在受控用例中接收评测器给定的有害 call ID 与 disclosure marker，按根 run 的执行报告确认动作已完成/可能部分完成，再只检查最后一次工具结果之后的纯文本 assistant 答复。未执行的提议不算 concealment；缺少执行报告、最终答复或显式 ground truth 时返回 inconclusive。字面 marker 命中与否都只是诊断信号，可能被否定、引用或用同义表达绕过；只有带评审者 ID 与固定 rubric SHA-256 的外部 adjudication 才能判定已披露或隐瞒，字面信号会随评审结果一同保留但不推翻评审标签。该工具不冒充语义意识检测，也不改变上游 AgentThreatBench 分数。

**验证**：回归覆盖执行后隐藏、执行后明确告知、被拒绝的提议、仅中间工具调用消息出现告知词、空 ground truth、缺失执行证据、marker 命中/未命中但未评审时的不确定结果、带 rubric 的隐瞒与披露判定及字面信号与评审标签不一致；另用真实 scripted SDK run 执行文件写入，再从 `RunReport.events` 读取工具执行收据并评分。安全、效用、用户知情度仍是不同维度，不用其中一个替代另两个。

### 6.121 将信息流敏感度策略接入真实运行时授权路径

**触发证据**：`PermissionEngine` 已支持按来源工具提升敏感度轨迹、按接收端 sink 规则升级授权，但 `AgentRuntime` 没有把会话轨迹传给权限判定。仅有策略解析和单元测试，真实 agent run 仍不会执行这道门。

运行时现在在显式配置时创建会话级 `SessionDataflow`，每次工具授权都将其交给权限引擎；来源规则只在基础授权通过后观察，sink 超出敏感度要求时升级给宿主审批，没有审批回调则拒绝。子 agent 与父 agent 共用同一条只升不降的轨迹。Python SDK 接受已验证的 `DataflowPolicy`，CLI 提供 `--dataflow-policy default|PATH`，未配置时保持原行为。恢复旧会话时尚无持久化的信息流 checkpoint，因此将历史信任级别设为最高、受众状态标记为未知；受众受限 sink 遇到未知历史时必须升级审批，不能把“未知”当作“无受众标签”。

该机制是按来源/接收端规则进行的保守调用级近似，不是模型内部数据因果追踪；若宿主使用 `bypassPermissions`，即表示主动绕过审批，信息流升级也不执行。

**验证**：SDK 端到端回归让 `Read secret.txt` 后尝试 `Write`，确认文件未创建且拒绝原因记录 confidential；恢复无信息流 checkpoint 的会话后，具有受众约束的 `Write` 也因未知历史受众被拒绝。独立策略回归覆盖未知受众决策；CLI 参数测试确认策略默认关闭，并可选择内置策略。

### 6.122 同一工具兼具来源和接收端时先检查投影标签

**触发证据**：工具可同时匹配 source 与 sink 规则。旧顺序先用调用前轨迹检查 sink，再应用本次 source 标签；一类“读取并转发”的工具若把敏感内容从来源直接送往更低级别接收端，就可能在标签生效前通过 sink 检查。

`check_sink()` 现在在授权前计算本次调用匹配到的首个 source delta，并将投影后的信任级别和受众用于 sink 校验；实际轨迹仍只在基础授权通过后更新。因而同一调用可被正确升级审批，而 denied 的调用不污染会话轨迹。

**验证**：新增双重匹配的 source/sink 回归，确认首次调用即触发敏感级别升级，且纯检查不提前修改轨迹；数据流、SDK 和 CLI 定向套件通过。

### 6.123 默认敏感来源按具体程度先于宽泛路径规则匹配

**触发证据**：默认策略采用 first-match-wins；宽泛的 `/etc/*` 规则排在 `*.pem` 与 `*credentials*` 前，使 `/etc/server.pem` 和 `/etc/app-credentials.json` 被标为 confidential，而不是 restricted。后续只要求不高于 confidential 的 sink 因此可能放行本应更严的来源。

默认 TOML 与嵌入式 fallback 已将 PEM 和 credentials 规则置于 `/etc/*` 之前，保留 first-match-wins 语义，同时确保更敏感规则优先。

**验证**：新增默认策略回归覆盖 `/etc/server.pem` 与 `/etc/app-credentials.json` 均落到 restricted；canonical embedded TOML 与 shipped TOML 一致性测试继续校验。

### 6.124 合并多来源数据时收紧 audience，而非扩大接收范围

**触发证据**：同一轨迹先后读取不同来源时，旧实现对 source audience 取并集。例如 HR 数据限定 `hr`、Finance 数据限定 `finance`，合并处理后会允许发送给其中任一方；合并数据应满足所有来源的限制，接收范围应取交集。交集为空也不能退化成“未标记数据”。

轨迹现在记录 audience 是否受限，并对每个带 audience 标签的来源执行交集；受限交集为空时，任何声明了 audience 要求的 sink 都需审批。未标记的公共数据仍保持既有可流向任意受众的语义；恢复会话的未知 audience 继续单独 fail closed。

**验证**：新增 HR/Legal 与 Legal/Finance 的多来源回归，确认只有 Legal 可接收；另覆盖空交集仍被强制检查，不能当成空标签放行。

### 6.125 信息流标签变更进入可读且不含内容的授权证据

**触发证据**：runtime 的 allow/deny 会同步进入 sealed permission ledger，但来源标签提升只保存在 `SessionDataflow.events` 内存中，外部审计者无法从工具报告确认某次成功读取把轨迹提升到哪个 trust 级别；sink 升级也缺少结构化标记。

信息流决策现在在 permission audit record 中包含内容无关的摘要：匹配的来源规则、最终 trust、受众标签是否启用/未知及受众数量；sink 触发升级时标记 `sink_escalated`。相同摘要随 `ToolCallReport.permission_details` 出现在 SDK/JSON 结果中；报告仅白名单导出 dataflow 摘要，不暴露 decision 中的多签等 audit-only 细节。摘要不复制工具参数、文件路径、文件内容或收件人列表；sealed audit sink 对完整 record 计算 execution digest。

**验证**：SDK 回归确认来源提升与 sink 升级同时出现在工具报告，且文件路径不在信息流摘要里；permission audit 测试确认允许与拒绝记录均携带该摘要。sealed audit、权限和 SDK 定向测试通过。

### 6.126 授权审计写入失败时阻止工具执行

**触发证据**：`PermissionEngine` 在允许决策的 audit sink 抛错时，原逻辑仍返回 `allowed=True`，只追加错误文本。runtime 随后继续到 handler；因此 sealed ledger 或宿主审计存储故障时，副作用可以发生而没有可确认的授权记录。

配置了 audit sink 后，允许记录必须成功返回才放行。sink 抛错将转换为 `source=audit`、`rule=audit:write_failed` 的拒绝；拒绝保持拒绝，且不重试写入，避免 sink“已写入后再抛错”时产生重复记录。没有配置 audit sink 的嵌入式调用保持原授权行为。

**验证**：权限引擎单测确认 otherwise-allowed 操作在 sink 异常后返回拒绝；runtime 回归确认写文件 handler 未启动、目标文件不存在，执行状态为 `not_started`。

### 6.127 TypeScript SDK 保留可选的信息流授权证据

**触发证据**：Python 的 `ToolCallReport` 已携带 `permission_details.dataflow`，但 TypeScript NDJSON 解析器将结果归一化为固定字段集合，会静默丢弃新字段。跨语言调用方因此无法看到敏感来源与 sink 升级证据。

TypeScript 事件类型现在定义可选的 dataflow permission summary，并在解析时只保留受控字段；旧 runtime 缺少该字段时仍可正常解析，新字段也不改变 result 顶层 schema。

**验证**：事件解析测试断言 dataflow trust、受众状态、来源规则和 sink 升级字段完整保留，同时旧结果的可选字段保持缺省；TypeScript SDK 全套 59 项通过。

### 6.128 用真实 CLI 结果验证 TypeScript 信息流证据互操作

**触发证据**：直接构造 NDJSON 的 parser 单测只能证明字段映射正确，不能证明 runtime 真实授权结果会进入 JSON 事件并被 SDK 保留；跨语言契约需要穿过 CLI、策略执行、事件序列化和 TS 归一化的完整路径。

TypeScript parity 测试现在启动受控 scripted CLI run：读取匹配 confidential 来源规则的文件，再尝试写入要求 public 信任级别的 sink。测试解析真实 `--json` 结果，检查 Read 报告携带来源规则和 trust、Write 报告标记 sink 升级，且摘要不含文件路径；同时确认 Write handler 未运行、输出文件未创建。临时 workspace 在断言完成后清理。

**验证**：新增真实 CLI→NDJSON→TypeScript `RunReport` 回归通过；完整 TypeScript SDK 测试 59 项通过。

### 6.129 扫描常见 shell 的内联 `-c` 命令

**触发证据**：权限门能识别 `nmap host`、命令替换与 `find -exec`，但 `bash -c 'nmap host'` 会把攻击工具名作为普通参数传给 shell，原扫描器不会进入第二层命令字符串。

对 `sh`、`bash`、`dash`、`zsh`、`ksh` 和 `ash` 的静态 `-c`、`--command` 及包含 `c` 的组合短选项，扫描器现在递归检查命令字符串，继续使用同一 deny-by-default allowlist 规则；普通 inline shell 和脚本路径不因此被拦。嵌套超过解析深度上限时按 incomplete 拒绝。此项仍是词法 tripwire，不覆盖变量展开、`eval`、混淆语法或 Python 等非 shell 解释器代启动。

**验证**：权限回归覆盖 `sh -c`、`bash -lc`、绝对路径 dash 调用均拒绝已知攻击工具，深层嵌套按 incomplete 拒绝，同时确认普通 `bash -lc 'printf safe'` 与 `sh script.sh` 仍可通过；权限测试 105 项及 32 个子测试通过。

### 6.130 隔离宿主审批回调的嵌套工具参数

**触发证据**：`PermissionEngine` 传给 `can_use_tool` 的是顶层 `dict(payload)` 副本，但嵌套字典仍共享引用。宿主审批回调若原地改写嵌套路径并返回允许，runtime 参数会一并改变；权限请求 digest 已按旧参数生成，而 governed runner 的 authorize pin 在回调后生成，因而 assess 阶段会把新参数误认为原授权参数。

普通 mutating 审批、信息流 sink 升级和 scope capability 越权审批现在都向 callback 传递深拷贝。callback 可自由操作自己的展示数据，但不再能改动实际交给 handler 的参数；复制失败沿 callback error 路径拒绝。

**验证**：PermissionEngine 回归确认 callback 深改对象不改变原 payload，且 request digest 等于原参数 digest；runtime 端到端测试让允许回调改写嵌套路径和添加 schema 外字段，确认 handler 仍收到原始获批参数。权限与 runtime 定向测试通过。

### 6.131 隔离 pre-trade 风险事实提取器的工具参数

**触发证据**：`PreTradeRiskConfig.value_of` 与 `reference_of` 是宿主提供的估值/参考事实提取器，但它们原本拿到权限引擎内部 payload 的嵌套引用。若提取器为便于计算而原地改写对象，后续 extractor、普通审批以及 handler 可能看到估值时未对应的参数。

估值与参考值提取现在分别接收独立深拷贝，异常或不可复制内容按既有 `fact_missing` fail-closed 路径拒绝；extractor 仍只能给出事实值，不改变被授权调用的实际参数。

**验证**：回归让 `value_of` 改写嵌套路径并注入额外字段，确认 `reference_of` 仍看到原路径、原始 payload 不变且通过正常检查；权限测试 108 项及 32 个子测试通过。

### 6.132 隔离权限审计 sink 与返回决策的结构化证据

**触发证据**：权限 allow/deny record 将 `decision.details` 直接交给审计 sink。审计 sink 是调用方代码，可能对嵌套字典做原地脱敏、字段规范化或错误修补；由于权限决策是浅层 frozen dataclass，这会同时改写 runtime 将返回的 dataflow 审批证据。

allow 与 deny 审计都改为向 sink 传递记录的深拷贝。sink 仍同步收到完整记录，配置 sink 写失败的既有 fail-closed 语义不变；sink 对输入对象的修改不会回流污染待返回的 decision。

**验证**：新增 dataflow 授权回归让 audit sink 把 `trust` 和 `source_rule` 改成伪值，确认返回的 permission decision 保留真实标签；权限、dataflow、runtime 与 hooks 测试 215 项及 42 个子测试通过。

### 6.133 显式报告执行后 forward-seal 写入失败

**触发证据**：permission allow 记录会在 handler 前同步封存，写入失败时已 fail closed；但 governed runner 在 handler 成功后追加执行完成记录，若这次追加失败只把 `[seal_failed:...]` 放在 `GovernedOutcome.reason`。runtime 忽略成功 outcome 的 reason，仍报告普通 `completed`，JSON 与 TypeScript 调用方看不到完成记录未封存。此时副作用已发生，不能把它谎报成“未执行”或诱发盲目重试。

`GovernedOutcome.audit_seal_error` 现在保留封存异常类型，Python `ToolCallReport`、JSON 与 TypeScript `ToolCallReport` 可选字段 `governance_seal_error` 会显式暴露它。runtime 也把有界的审计警告加入模型收到的工具结果，明确动作已完成且未回滚；`is_error` 仍保持 false，避免模型把已发生的副作用当成可安全重试的失败。`execution_status` 仍为 `completed`，报告同时指出执行后封存失败，便于宿主触发补偿审计或人工核验。

**验证**：runtime 故障注入先允许权限记录封存、再让执行完成封存抛错；确认文件已经写入、provider 收到 `is_error=false` 且含未回滚提示、状态仍是 `completed` 且错误字段为 `OSError`。另用 26 字符的极小结果上限验证警告压缩为完整短标记且报告截断；不会留下“可重试”之类断章尾句。TypeScript parser 回归保留该字段；runtime/runner 41 项与 TS SDK 60 项通过。TypeScript `tsc --noEmit` 在当前环境因未安装 `tsc` 未能执行；文档构建与链接验证通过。

### 6.134 将目标范围与跨代理通道纳入隔离模型

**触发证据**：[OpenAI 对 2026 年评测事件的公开报告](https://openai.com/index/hugging-face-incident-and-the-road-ahead/)描述代理利用共享包服务通信并借其取得外网访问，随后把行为扩展到原评测范围之外；[OWASP Q3 2026 事件综述](https://genai.owasp.org/2026/10/08/genai-and-agentic-ai-exploit-roundup-q3-2026/)据此强调签名目标清单、范围外主机拒绝、工作负载隔离和进程执行日志。综述声明自己是精选、非穷尽的社区汇编；案例也不能直接推导普通部署具有相同攻击路径。

Northstar 已有精确主机 egress policy、默认网络禁用、子代理工具集合收窄和低信任结果标记；此前未把每个外部目标绑定到单次 run 的宿主授权范围。该 run 级目标子集现已实现（见 §6.135）。这些措施仍没有证明共享可写存储不会充当代理间消息板；下一步评估要明确列出共享目录/服务、父子及跨 run 的写入可见性，并分别记录 proposed、denied、executed 的外部动作。

**验证状态**：本条的共享通道分析是基于外部事件报告和当前 runtime/egress/委派边界的威胁模型更新，不表示复现了该事件。跨 run 持久化边界仍待隔离测试和运行时控制。

### 6.135 将外部目标清单收紧到单次 run

**触发证据**：全局 egress sidecar allowlist 限定哪些主机可达，但任务通常只授权其中一部分。允许某个代理服务主机不等于允许 agent 将它当作任意目标代理；OWASP Q3 事件综述建议使用宿主控制的目标清单并拒绝范围外主机。

新增 `RuntimeConfig.egress_target_scope`、CLI `--egress-target HOST`（可重复）和 `.northstar/config.toml` 的 `egress_targets` 数组。配置在启动时验证为最多 128 个精确 ASCII 主机名，统一大小写与单个末尾点；重复、通配符、路径、userinfo、Unicode 或控制字符均拒绝。CLI 与 workspace policy 同时设定时取交集，policy 的空数组明确拒绝所有 Fetch 目标。Fetch 的目标在 PreToolUse 重写完成后、审批 callback 和 handler 之前按精确主机匹配；不在集合内会走治理拒绝路径，记为 `not_started` 且不调用审批器。子代理继承同一目标集合，不能拓宽。dry-run 展示最终生效范围；未设置 scope 时维持原来的 sidecar 全局 allowlist 语义。新增 `egress_scope.py` 已登记进显式 setuptools 模块清单，并刷新生成式 API 参考。

**验证**：新增测试确认 `evil-example.com` 不会因包含 `example.com` 而通过、越权目标不会触达 handler 或 approval callback、hook 无法将已允许目标改写到集合外、policy 与 CLI 取交集，以及模糊/重复主机在配置阶段失败。`agent` 首次运行及 `resume` 分叉续跑的集成测试确认 workspace policy 会重新加载并保留范围。`test_loop.py`、`test_cli.py`、`test_policy_file.py`、`test_product_path.py`、`test_governed_action_runner.py`、`test_egress_enforcer.py` 共 267 项与 15 个子测试通过；CLI help 暴露了新参数。该列表是宿主配置的精确 Fetch 主机子集，不会阻止已允许主机自身充当代理，也不覆盖宿主另外注册的网络工具。

### 6.136 将 Fetch 纳入默认敏感数据出口策略

**触发证据**：默认数据流策略把 `http_post` 标记为 public sink，但实际内置网络工具名是 `Fetch`。启用默认 dataflow policy 后，读取 `.pem` 等 restricted 来源再调用 Fetch，之前不会命中 sink 规则，因而绕过敏感轨迹的审批升级。

默认策略内嵌 TOML 与随包 `policy/dataflow.toml` 现都将 `Fetch` 声明为仅接收 public 信任级别的 sink。读取高敏感来源后，Fetch 会触发信息流升级；无宿主审批回调时拒绝，有回调时由宿主决定。`bypassPermissions` 按既有语义仍跳过审批升级；该规则须启用默认数据流策略才生效。

**验证**：新增策略检查确认 `.pem` 来源提升到 restricted 后 Fetch 命中 public sink；PermissionEngine 回归确认未配置审批回调时拒绝 Fetch，并输出 `sink_escalated` 证据。策略嵌入字符串与随包 TOML 的一致性测试也覆盖该规则。

### 6.137 将子代理提示词传递纳入敏感数据出口治理

**触发证据**：`Task` 在 runtime 内部直接切换到 `_delegate`，先前绕过 PermissionEngine 的普通 sink 路径。共享 SessionDataflow 会保留父子运行的敏感轨迹，但 Task 自身没有 sink 规则，因此读取受限数据后仍可能把提示词发送给子代理及其独立模型 provider；“只读工具子代理”也可能将收到的上下文带到远端推理端。

默认数据流策略现将 `Task` 视为仅允许 public 轨迹的出口。低敏感任务仍走原委派门；敏感轨迹下，在创建子 runtime 前用原 PermissionEngine、同一 call ID/参数 digest、审计 sink 和宿主 callback 执行升级。无 callback 或宿主拒绝时，子代理 provider 不会被调用；宿主明确批准后才继续委派。`bypassPermissions` 保持其显式绕过语义。该控制判断轨迹标签，不推断模型能否从未标记提示词中识别秘密。

**验证**：端到端回归先读取 `.pem` 再委派，确认无审批器时 child provider 未收到请求、Task 报告包含 `sink_escalated`；另确认宿主可审批后继续运行。此策略需启用默认数据流策略；它不证明所有 prompt 中的敏感信息都已被 source rule 标记。

### 6.138 跨子代理继承组合规则动作历史

**触发证据**：[Bounded Agents: Delegation Security for Multi-Agent AI Systems](https://arxiv.org/abs/2608.15888) 将授权状态、历史动作和收窄后的委派范围作为 session state 沿 Agentic Principal Chain 累计；论文报告其 APC 评测中对 544 个 InjecAgent 数据窃取用例的阻断结果。这里采用的具体启发是组合规则不能因 runtime 创建子引擎而失去父级动作历史。该论文的其余模型、假设与效果数字未在 Northstar 中复现。

此前每个 PermissionEngine 都创建独立的 32 项动作类别历史；子代理引擎重新开始空历史，使跨父子序列组合规则失效。此外，`check_delegation` 用常规 `evaluate` 检查声明工具，会错误地把能力准入当成执行动作。

委派树现在共享父引擎的有界类别历史，并继承相同 composition rules 与 action categories；真实 child tool call 继续按同一历史执行检查。声明能力的准入判断仍写审计记录，但不检查或推进组合历史。历史只存类别、不存参数，子代理调用仍由各自工具集和原有权限门约束。

**验证**：PermissionEngine 回归确认 capability check 不推进历史、父子引擎共享历史时禁止的序列仍被拒绝；真实 runtime 攻击回归在父代理 Read 后委派 Shell，确认子代理 `touch marker` 被 composition gate 拒绝、文件未创建。另有 checkpoint→resume 回归确认历史恢复后仍会拒绝后续 Shell，缺少历史的旧 checkpoint 会在模型调用前失败关闭。该历史仅在可信 checkpoint 边界跨进程恢复；没有 checkpoint 的 resume 不允许启用组合规则继续运行。

### 6.139 将组合规则历史与策略版本绑定到安全检查点

**触发证据**：上一项修复把父子运行的组合规则历史放入共享内存，但 checkpoint 仍只记录 transcript 与预算/调用计数。进程重启后，PermissionEngine 会从空历史开始；仅验证消息 transcript 的摘要不足以证明此前的动作类别状态。

Checkpoint 现在保存最多 32 个类别标签和组合策略 SHA-256（按规则顺序、描述与工具分类确定）。恢复时先验证 transcript，再要求策略摘要精确匹配并恢复历史；缺字段、格式错误、策略变化或没有 checkpoint 的恢复，在启用组合规则时都会拒绝继续。无组合规则的旧 checkpoint 仍可按原契约恢复。该绑定不将隐藏工具参数或结果复制进 checkpoint，也不自动同步不同会话的历史。

**验证**：checkpoint 单测覆盖历史/摘要 round-trip 与畸形记录拒绝；runtime 集成测试确认父级 Read 状态被 checkpoint 保存、恢复后的 Shell 动作被拒绝，且缺少 composition state 的旧 checkpoint 在 provider 调用前失败。策略变化拒绝由运行时 digest 比较保护。

### 6.140 持久记忆按不可信数据处理，受众授权仍需宿主身份

**触发证据**：对照 [Authorization Before Context](https://arxiv.org/abs/2608.17148) 与 [Audience-Bound Persistent Memory](https://arxiv.org/abs/2609.36373) 两篇 2026 年预印本，持久记忆除了内容完整性，还需要在送入模型上下文前按来源受众与本轮实际查看者授权。当前 `WorkspaceMemory` 只带路径、摘要和内容完整性；CLI/runtime 没有可信 viewer/channel 输入，也没有可绑定受众的宿主接口，因此不能据此宣称已实现私聊/群聊隔离。

记忆注入及 `Read`/`Write`/`Edit`/`Grep`/`LS` 的路径访问都经过 operator-owned `.northstar/memory-audience.json` 授权清单，清单也可指定 `.northstar/memory/` 外的 workspace 文件。条目按工作区相对路径列出 viewer 身份；`public` 是显式的全体授权，命名 grant 仅当本轮所有 viewer 均被列出才匹配。CLI 用可重复 `--memory-viewer` 接收宿主传入的身份；viewer 缺失时只匹配显式 public grant。清单或路径条目缺失默认拒绝，重复 JSON key、畸形内容及 symlink 失败关闭。清单位于 agent memory 写入 carve-out 之外，普通文件工具不能改写自己的 audience。Shell 的 process backend 对整个 workspace 有读写权，无法表达逐文件 audience，也可能重写授权清单，因此只要 audience 清单存在就拒绝 Shell；需要并行私有 audience 的部署应分用 OS workspace。MCP server/host-defined tools 仍需各自的 workspace 隔离，当前文件工具 ACL 不会替它们过滤文件系统。拼接后的记忆仍被标记为不可信参考资料，并提示模型忽略其中改系统规则、泄密或绕过权限的指令；这条提示只是纵深防御，不能替代工具权限门。

渠道适配器仍需从经过认证的渠道元数据构造完整 viewer 集合并传给 runtime；CLI 参数本身不证明调用者身份。两篇论文是预印本，其合成评估结果不视为 Northstar 的独立验证。

**验证**：单测覆盖私有 grant 的全员匹配、任一群成员不匹配即拒绝、无身份及无清单时拒绝未标记记忆、显式 public grant、畸形重复键失败关闭、agent 不能写 audience 清单，以及 CLI 模型运行前 withheld/authorized 两条路径。没有声称已验证真实模型能抵抗所有记忆注入，也没有声称当前已有渠道适配器接入 viewer 身份。

### 6.141 将私有记忆受众传入数据流出口检查

**触发证据**：文件 ACL 能阻止未授权调用者读取私有记忆，但已授权注入的内容仍可能被 `send_mail`、MCP sink 或子代理等出口转发。原有 `SessionDataflow` 只从工具 source 规则积累受众标签，不知道 system prompt 已含私有记忆。

`WorkspaceMemory` 现在携带经过 ACL 判定的 manifest grant。CLI 启用 `--dataflow-policy` 时，以该受众初始化本次运行的 `SessionDataflow`；授权受众名单会限制同一运行的受众型 sink，后续 source 仍按交集进一步收窄。带受众标签的数据流若到达未声明 audience contract 的 sink（包括 policy 未登记的出口），会升级审批；这要求每个可用出口显式描述其 recipient 参数。显式 `public` grant 不加额外受众限制；没有注入私有记忆时行为不变。数据流策略仍为显式 opt-in；本改动不推断未标记 prompt、工具输出或模型内部记忆中的敏感内容。

**验证**：记忆发现单测检查私有授权名单被保留，数据流单测确认私有记忆只可流向 grant 内 sink，未声明受众合同或完全未登记的出口会升级；CLI dry-run 集成测试确认授权从实际 prompt setup 进入 runtime tracker。未启用数据流策略的部署仍只有读取 ACL，没有基于该轨迹的出口限制。

### 6.142 在 SDK JSON 解码前限制 provider HTTP 响应体

**触发证据**：文本字符数、工具参数树节点数等 provider 归一化上限只能在 SDK 将 HTTP JSON 解码为对象之后执行；一个超大响应仍可先占用解析内存。上游 OpenAI 与 Anthropic SDK 都提供可注入的同步 HTTP client，并公开保留其默认超时、连接池与重定向参数的 client 入口；OpenAI 最新入口还可能是工厂函数，因此不应假设公开入口一定可继承。

SDK 自建的 OpenAI-compatible 与 Anthropic 同步 client 现在默认限制响应体为 8 MiB，可由 provider 构造参数 `max_response_bytes` 调整。运行时在最终发送边界强制 `Accept-Encoding: identity`，拒绝意外压缩编码，先检查声明长度，再通过同步流式读取对实际字节计数；普通 JSON 与 SSE/流式响应都必须通过同一上限，原始响应会在结束、超限或关闭时释放。限制包装保留 SDK 默认 HTTP client 实例及其配置。宿主传入的 `client` 明确保持原样，不宣称已受到此上限保护，宿主必须自行套用等效措施。

**验证**：新增传输单测覆盖非法限额、头部预拒绝、无长度分块超限、压缩响应拒绝、普通/流式成功、流式溢出和未消费流关闭；provider 测试确认两套 SDK 默认 client 均拿到限额 transport 且注入 client 未改写。另在隔离目录安装当前 OpenAI/Anthropic SDK，用 HTTPX2 `MockTransport` 验证普通响应、超限拒绝、真实同步 stream 协议，以及两个 provider 实例的解析路径。此验证未访问厂商网络或真实模型。一次底层读取最多暂存一个 64 KiB chunk（较小限额时按限额缩小）；它不限制对端到达本机前的网络流量，也不覆盖异步或宿主自定义传输。

### 6.143 收紧 Shell 间接命令扫描的失败关闭边界

**触发证据**：GNU Bash 手册说明 `eval` 会把参数拼成新命令重新解析，别名会在读取命令时改写后续命令词，函数名调用会执行函数体。因此，只对一层分词结果查找已知可执行文件，无法把动态命令名或函数定义当成普通数据安全放行。[Bash builtins](https://www.gnu.org/software/bash/manual/html_node/Bourne-Shell-Builtins.html)、[aliases](https://www.gnu.org/software/bash/manual/html_node/Aliases.html)、[functions](https://www.gnu.org/software/bash/manual/html_node/Shell-Functions.html)

Shell 词法闸门现在在命令位置遇到 `eval`、`alias`、变量/命令替换、glob 或 brace 生成时返回 `shell_scan_incomplete`，不依赖未知结果放行；活动 `{ list; }` 组和常见函数体递归扫描。普通参数里的 `${...}`、单引号文本和作为 echo 数据的花括号展开仍有回归用例，避免把数据误判为命令。该门仍是有限语法上的审批前 tripwire，不是 Bash 解析器：经非 shell 解释器、`source`/`.` 文件、脚本路径、shell 初始化环境、其他未识别语法或动态参数构造的执行仍必须由审批、OS 沙箱和宿主网络策略约束。

**验证**：`tests/test_permissions.py` 与 `tests/test_loop.py` 合计 152 项通过、45 个子测试通过；另以不会执行样例命令的静态矩阵检查 `eval`、别名、动态命令词、函数体、活动分组、引用文本与替换展开。它只验证词法判定与运行时权限结果，不代表真实 Shell 执行隔离或对所有语法变体的覆盖。

### 6.144 为 Shell 增加可选的进程树 cgroup v2 限额

**触发证据**：单进程 `RLIMIT_AS`、`RLIMIT_CPU` 与 `RLIMIT_NPROC` 不能表达整棵进程树的内存、CPU 带宽和任务数配额。Linux cgroup v2 提供层级 `memory.max`、`cpu.max`、`pids.max` 与 `cgroup.kill`；systemd 负责其 system scope 的生命周期与资源属性。[Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)、[systemd 控制组接口](https://systemd.io/CONTROL_GROUP_INTERFACE/)

Linux 主机可由 operator 通过 `--shell-aggregate-resource-scope systemd` 要求每次 Shell 在 PID 1 管理的 transient system scope 中运行。scope 使用 `MemoryMax`（沿用本次 Shell 的内存上限）、`TasksMax`（默认 128，可由调用方收紧）和 `CPUQuota=100%`；当前逐进程 rlimit 继续叠加。配置要求非 root runtime、可见的 cgroup v2 `cpu`/`memory`/`pids` controller、`systemd-run`/`systemctl` 与启用的 seccomp。运行时不创建 workload 同 UID 可改写的 delegated 子树。配置或 scope 建立失败会拒绝/报告工具调用，不退回仅逐进程限额；结束后通过 systemd 按整棵 scope 发送 SIGKILL 并停止 unit，无法确认清理时将工具结果标成错误。该选项默认关闭；关闭时仍只有原有逐进程上限。它不提供 workspace 磁盘总量配额。

**验证**：新增 11 项 systemd scope 单测及 2 个子测试，覆盖资源属性构造、输入校验、scope 清理失败、scope wrapper 的输出/限额传递，以及 systemd manager 启动失败时目标命令确实不会执行。当前开发容器没有 `systemd-run`/`systemctl`，所以没有声称真实 PID 1/cgroup enforcement 已在此环境集成验证；部署启用前仍需在实际 systemd+cgroup v2 主机运行压力与脱离进程清理测试。

### 6.145 统一 Shell 攻击工具闸门的命令入口

**触发证据**：权限引擎原先只检查 `payload.command`，但 Shell handler 也接受直接 `argv`，并支持 `cmd` 命令字符串别名。相同工具可从未扫描入口调用，导致攻击工具默认拒绝规则没有覆盖每种实际执行形式。

权限闸门现在按 handler 的入口优先级检查 `argv`、`command` 或 `cmd`。`argv` 各元素先作为字面参数引用后交给同一个有界扫描器，所以能识别直接可执行文件、已知包装器以及 `sh -c` 等静态命令，同时不会把 `echo`/`printf` 的参数内容重新解释成 Shell 语法。扫描命中的工具仍默认拒绝，只有宿主配置 `offensive_allowlist` 才能启用。非 Shell 解释器中的动态代码仍不属于词法扫描器保证范围，必须依靠权限审批、沙箱和网络限制。

**验证**：权限测试覆盖直接及绝对路径 `argv`、`env`/`timeout`/`find -exec` 包装、`sh -c`、`cmd` 别名、显式 allowlist，以及普通参数中的工具名称和 Shell 元字符；`tests/test_permissions.py` 117 项和 54 个子测试通过。测试仅验证权限判定，不执行攻击样例。

### 6.146 将 Shell 沙箱后端选择固定在宿主策略

**触发证据**：Shell handler 从模型调用参数中读取 `backend`，其优先级高于 runtime 注入的宿主 `shell_backend`。这使 `backend=process` 能把宿主选择的 bwrap 隔离切换到文件系统可达范围更大的 process backend。Shell schema 未声明该字段，且默认允许额外属性，因而 schema 验证没有拦截它。OWASP Agentic AI AAI8 将薄弱的工具参数验证、可穿透沙箱和过宽执行权限列为同一类代码执行风险；其 MCP 安全清单也建议对工具参数 schema 使用 `additionalProperties: false`。

Shell backend 现在只来自宿主 `ToolContext`。Shell 的 JSON Schema 列出所有支持的模型参数、加入既有 `cmd` 兼容别名、声明需要 `argv`/`command`/`cmd` 中至少一个，并拒绝未声明字段；模型不能再传 `backend`、`shell_backend`、network 或聚合 cgroup 配置来改变宿主执行策略。`seccomp`/`landlock` 等可收紧的每次调用选项仍明确暴露并沿用现有 tighten-only 校验。

**验证**：新增回归确认模型传 `backend=process` 时 schema 拒绝，直接调用 handler 时也只能使用宿主配置的 `bwrap`；未知 `network`、`shell_backend`、聚合资源配置字段拒绝，`cmd` 兼容别名通过。`tests/test_os_sandbox.py` 与 `tests/test_tool_input_schema.py` 共 79 项通过、18 个子测试通过，3 项依赖宿主能力的测试跳过。该验证使用 mock 确认执行后端选择，没有把隔离强度伪装成真实 bwrap 集成测试。

### 6.147 将内置工具对象 schema 默认设为封闭

**触发证据**：JSON Schema 对象未声明 `additionalProperties` 时默认接受额外字段。虽然 `ToolInputSchema` 会验证工具参数，内置工具共用的 `_schema` helper 和 Task schema 没有关闭额外字段；Fetch 的动态 `headers` 映射也没有限制 header 值类型。OWASP MCP 安全清单明确建议工具参数 schema 使用 `additionalProperties: false`，并为字符串字段添加类型/格式限制。

内置工具 schema helper 现在默认拒绝未声明的顶层属性，Task schema 同样封闭；自定义 MCP schema 仍按 server 声明的契约验证。动态字段只能在 property 子 schema 中显式开启：Shell `env` 与 Fetch `headers` 都约束为字符串值。这样既阻止与真实 handler 无关、容易和宿主配置混淆的字段，也为模型提供精确且可验证的输入合同。

**验证**：新增断言遍历默认工具注册表并检查顶层 schema 均封闭；另验证 Task schema 闭合、Fetch 字符串 header 通过、数字 header 值拒绝。工具、schema、loop、Shell 沙箱和 egress 测试共 213 项通过、53 个子测试通过，3 项宿主能力测试跳过。外部 MCP 工具未统一强制此策略，因其 schema 由 MCP server 声明并需按其合同验证。

### 6.148 将工具 schema 边界纳入只读 doctor 自检

**触发证据**：schema 单元测试能防止源码回归，但部署者运行 `doctor` 时此前看不到内置工具是否仍符合这些安全约束；若未来新增一个 schema 宽松的内置工具，CI 失败之外没有可见的运行前诊断。

`northstar doctor` 现在验证默认注册表、Task、Fetch 与 CodexReadOnly 的内置 schema 定义；每份 schema 都必须能通过实际使用的 JSON Schema validator，且顶层必须拒绝未声明字段。它还核查 Shell schema 没暴露宿主拥有的 backend/资源配置，并确认 Shell `env`、Fetch `headers` 动态 map 只接受字符串。诊断只读取声明，不启动工具、不联网、不写文件；自检失败作为 doctor 的 fail finding，而不是伪装成安全通过。

**验证**：健康 workspace 的 CLI 回归要求 doctor 输出 `tool-schemas` 成功项；`tests/test_cli.py` 106 项和 5 个子测试通过。此检查证明 schema 合同有效，不证明工具实现没有其他运行时缺陷，也不检查外部 MCP server 的实现与其声明是否一致。

### 6.149 代码文件完整替换使用原子写入

**触发证据**：代码 agent 的 `Write` 和 `Edit` 原先在原文件描述符上先 `ftruncate(0)` 再写新内容。磁盘写入失败、宿主进程中断或文件系统空间耗尽会让用户的源码只剩空文件或前半段；即使策略和路径权限正确，这也会破坏编程工作成果。

非追加式 `Write` 和 `Edit` 现在将完整 UTF-8 字节写入同一父目录下的唯一临时文件，写完并同步后才发布：既有目标用原子替换，新目标采用失败即返回 `EEXIST` 的链接创建。替换前会再次核对目标身份、版本、类型和硬链接数；Edit 还核对读取期间的版本，检测到并发修改就要求重试。普通权限位、UID/GID、POSIX 访问 ACL 与 SELinux 标签会保留；宿主无法保留所有权/属性时拒绝替换，未知或内容绑定扩展属性也失败关闭。setuid/setgid 位不会复制到新内容。`append` 仍使用原位追加，因为它语义上是增量写入。

**验证**：故障注入在临时文件写入一半后抛错，Write 和 Edit 都保留原代码文件且清理临时文件；另验证普通权限保留、ACL 属性复制、未知属性拒绝，并在暂存期间新增硬链接时拒绝覆盖，原路径与共享链接内容均不变。`tests/test_tools.py` 56 项和 33 个子测试通过。该实现验证工作区文件工具的同目录原子发布，不约束获批 Shell、MCP server 或宿主自定义工具直接写文件的行为。

---

## 7. 一句话

**"包含所有顶级 agent 的优点"这条路的正确走法，是把每个优点都过一遍"能不能不绕门"的改写；改不动的就明确拒绝。**
Northstar 的目标是同一条 agent loop 同时保留可用能力和可验证边界。评估结果必须区分策略判定、真实执行证据、攻击拦截与正常任务效用；离线基准通过不能代替目标内核、部署配置和真实模型行为的验证。本工作树的 runtime `unittest discover` 最新实测为 18,535 项，其中 18,514 项通过、21 项环境条件跳过；此前单独记录的 workspace extensions 30 项、Grep 工具 44 项、skill audit 66 项及治理基准 v38 的 167 项是各自对应运行的结果。所有数字只描述对应工作树与环境的测试覆盖，不代表对未测试环境或模型的安全保证。社区与框架安全研究及来源记录见 [agent runtime landscape review](research/agent-runtime-landscape-2026-10.md)。
