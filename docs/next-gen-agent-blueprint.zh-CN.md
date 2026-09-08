# 次世代 Agent 蓝图：顶级工具的优点，哪些能收、哪些必须改、哪些要拒

> 编制日期：2026-09-08 ｜ 触发问题：**"能不能包含所有顶级 agent 的优点，因为我们要创造次世代的 agent"**
> 本文是设计与取舍文档；本批已按其中 P0 四条落了代码（见 §6）。配套现状对标见 [benchmark-top-agents-2026-09.zh-CN.md](benchmark-top-agents-2026-09.zh-CN.md)。

---

## 1. 直接回答

**不能"全都要"。不是能力不够，是那些优点彼此冲突，而且有 8 组与 Northstar 的不变量直接矛盾。**

把 2026 年头部工具的优点摊开看，它们并非同向叠加：Claude Code 的"无 per-server MCP 工具上限"与它自己的"上下文是公共财产"互相拉扯；Codex 的 Full Auto 与可审计确定性互相拉扯；OpenAI Agents SDK v2 的 snapshot/rehydrate 需要可变工作区状态，而"append-only 审计"要求不可变；Cursor 的多模型自由切换与"成本可预测"互相拉扯。**头部工具的做法是各自选边，形成一个产品人格**；把它们的优点做布尔并集，得到的是一个没有一致语义的框架，而不是次世代 agent。

所以"次世代"的定义必须换掉：

> **不是"拥有他们所有的能力"，而是"把每一项能力都重写成穿过同一道门的治理原语"。**
> 同一条工具调用，在 Claude Code 里是"能跑"，在 Northstar 里必须是"能跑 + 谁批准的 + 花多少 + 留下什么证据 + 崩了从哪儿续"。

这件事有一个可检验的判据，本仓已经具备而头部工具都没有：

> **零凭据、零网络、1485 项测试跑通同一套语义。** 任何被吸收进来的优点，若不能在没有 API key 的情况下被确定性测试，就不算吸收成功——那只是多了一条无法回归的功能面。

按这个判据，顶级工具的优点分成三类。

---

## 2. 八组硬冲突（必须显式选边，不能默默并集）

| # | 想吸收的优点 | 来源 | 与 Northstar 哪条不变量冲突 | 裁决 |
|---|---|---|---|---|
| C1 | 任意 shell 工具 + Full Auto | Codex Full Auto、Devin/OpenHands 长自主 | 根 README 的"不是通用 shell 执行 API"；且本仓**无 OS 级沙箱**（对标报告 F/维度 #3） | ⛔ **推迟**：先有 bwrap/seatbelt 级隔离与网络 egress 策略，再谈 shell。顺序反了就是把治理叙事换成攻击面 |
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
| OS 级沙箱 | Claude seatbelt/bubblewrap、Gemini gVisor | 可选 `bwrap` 包装器（只读 bind + no net + cgroup），CI 真跑 | 🔧 待做（P1-4，C1 的前置） |
| 技能供应链校验 | 无人做（第三方审计：99% 坏味道/36% 缺陷） | `skills check`：规则纯函数 + `skills.lock` 摘要钉定 + 漂移拒跑 | ✅ 已落地（第十五批） |
| 会话 rewind/fork | Claude /rewind、LangGraph time-travel | `--resume-from`：从任一检查点分叉新 session（摘要校验），**绝不回写**旧文件 | ✅ 已落地（与 append-only 兼容） |

---

## 4. 五项"只有 Northstar 组合起来才有"的次世代能力

吸收完上面那些只是"齐平"。真正让别人抄不动的是这几条——它们的共同点是**用治理机制实现别处用自由度实现的功能**：

1. **可证明的策略变更（policy as code, with revision）**
   `.northstar/config.toml` 带 `schema_version` + `revision`，只能收紧、非法即拒绝启动；本批起 `revision` 进 `init` 事件与审计 feed，`doctor` 直接对比 git HEAD 报漂移（P0-4）。
   → 头部工具的权限配置是"行为开关"，这里是**可评审、可归因、可 diff 的策略文档**。CI 场景里这是合规资产，不是 DX 糖。

2. **确定性回归治理（治理本身的 golden test）**
   scripted provider + 1485 项离线测试 + guard 红绿 harness，意味着"把 deny 改成 allow 会让哪些测试变红"是可计算的。
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

---

## 7. 一句话

**"包含所有顶级 agent 的优点"这条路的正确走法，是把每个优点都过一遍"能不能不绕门"的改写；改不动的就明确拒绝。**
Northstar 的次世代位置不在功能并集上，在于：**同一个 agent loop，别人要牺牲确定性或牺牲边界来换能力，这里两样都不换——而且每一项能力都能在 CI 里用 1485 个无 key 测试证明它今天和昨天行为一致。**
