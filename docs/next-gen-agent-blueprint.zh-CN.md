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

> **零凭据、零网络、890 项测试跑通同一套语义。** 任何被吸收进来的优点，若不能在没有 API key 的情况下被确定性测试，就不算吸收成功——那只是多了一条无法回归的功能面。

按这个判据，顶级工具的优点分成三类。

---

## 2. 八组硬冲突（必须显式选边，不能默默并集）

| # | 想吸收的优点 | 来源 | 与 Northstar 哪条不变量冲突 | 裁决 |
|---|---|---|---|---|
| C1 | 任意 shell 工具 + Full Auto | Codex Full Auto、Devin/OpenHands 长自主 | 根 README 的"不是通用 shell 执行 API"；且本仓**无 OS 级沙箱**（对标报告 F/维度 #3） | ⛔ **推迟**：先有 bwrap/seatbelt 级隔离与网络 egress 策略，再谈 shell。顺序反了就是把治理叙事换成攻击面 |
| C2 | settings 里声明 command hooks | Claude Code（31 事件 × 5 类 handler） | 仓库文件=可执行代码 → 绕过权限门；clone 即执行 | ✅ **改造后收**：本批 P0-3 落地，但只允许否决型事件 + 无 shell + 脚本必须在工作区内 + 默认关 + 子进程环境变量清洗 |
| C3 | 无限工具/无限技能（no per-server cap、几百个 skill） | Claude Code Tool Search、Skills 生态 71k+ | `MAX_TOOLS_PER_SERVER=25`、`MAX_SKILLS=40`、listing 上限——"仓库文件不得无界撑大上下文" | 🔧 **改造**：数量可有界放宽（如 25→100），但必须配 **deferred definitions**（按需取 schema）；直接去上限 = 放弃边界 |
| C4 | 模型分类器自动批准（`auto` mode） | Claude Code auto、Cursor auto-review | 三层权限门的确定性；"谁批准了这次调用"必须可复现 | ⛔ **拒绝原样**：分类器只能作为**额外否决**挂在 PreToolUse 上（可 deny、不可 allow），默认关 |
| C5 | 插件市场 / install 即得能力 | Claude Code marketplace、skills 目录 | "策略只能收紧"（`policy_file` fail-closed）；市场内容未签名 | 🔧 **改造**：只取**打包格式**（plugin = config/agents/skills/hooks 的 bundle），安装 = 一次 git 可见的落地 + `skills check` 校验；不做在线市场 |
| C6 | 容器快照/恢复（sandbox 丢了能续） | OpenAI Agents SDK v2 snapshot+rehydrate | 需要可变工作区生命周期；本仓 `northstar-host` 只有 0700 分配，无 lease/回收 | 🔧 **改造**：先接 F3（durable-run 的 checkpoint/lease 与 runtime 接线），快照属于 host 层，不进 runtime |
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
| 多模型 | OpenAI 100+ / Cursor | `providers/openai_compat.py`：一个 Chat Completions 适配器覆盖一片模型 | ✅ 已落地（P1-2） |
| 独立完成判定 | 无人做（各家都把"模型自述"当完成） | `postconditions.py`：`--verify` / `[[verify]]`，运行前后快照比对 | ✅ 已落地 |
| token 级流式 | 全员 | `StreamDelta` 事件，仍保证唯一 ResultMessage | 🔧 待做 |
| 显式重试/退避/降级 | Claude fallback | provider 层策略化（当前只有 sidecar 重试） | 🔧 待做 |
| MCP 现行规范 2026-07-28 | 标准 | 无状态请求 + MRTR + `Mcp-Method/Name` 头 + 旧代际 fallback | 🔧 待做（P1-1） |
| elicitation ↔ 审批回合 | MCP 特性 | 把"服务器问用户"映射到权限门（**这是别人没有的角度**） | 🔧 待做，优先级高 |
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
   scripted provider + 890 项离线测试 + guard 红绿 harness，意味着"把 deny 改成 allow 会让哪些测试变红"是可计算的。
   → 别人有 output eval；**没有人在 eval 权限决策**。这条可以直接做成公开基准（denial correctness / 注入抵抗 / 预算命中率），是 Northstar 唯一能自定义考题的赛道。

3. **可归因的委派链（contract → execution → receipt）**
   本批把 runtime↔contract↔sidecar 三方字段焊成一份（漂移即测试失败），`run_id` 贯穿 runtime transcript 与 sidecar 日志；interop 组件已有签名 attestation + narrowed handoff + typed receipt。
   → 多代理生态现状是"消息能传"，没人能回答"**这一步是谁授权的、结果被谁验证过**"。A2A 不管这个，Claude Agent Teams 不管这个。这是 Northstar 的正面战场。

4. **后置条件验证，独立于模型** ✅ 本批已接进 runtime
   durable-run 的 `verifier.py` 用文件系统工件摘要判定 `verified|failed|unknown`；本批在 runtime 侧落为 `postconditions.py`（`exists`/`absent`/`changed`/`unchanged`/`contains`），运行前取摘要、结束后由**本进程**比对，失败即 `error_postconditions_failed`（exit 6）并写入独立审计记录类型 `postconditions`。
   → 即：**agent 说"我改完了"不再算数**。这比任何"自我批评/反思"式提示技巧都更接近次世代该有的定义。
   → 关键约束：**验证条件绝不进 prompt**——告诉模型要查什么，模型就去写那句话；`contains` 因此被明确标为"便利而非证据"，可依赖的是结构型四种。

5. **把协议的"问用户"变成治理的"要审批"**
   MCP 2026-07-28 的 MRTR/elicitation 让服务器能中途要输入；把它接到权限门上，远端工具的确认请求就走与本地写操作**同一道**门、进**同一条**审计流。
   → 头部工具把 MCP 当"工具管道"；这里是"带审批的管道"。工程量小（客户端已有，只补一轮），叙事价值大。

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
| F3 | `checkpoints.py` + `--checkpoint-turns` / `--resume-from` / `--resume-record`；恢复时**继承**花费与计数器；fork 写新文件、父文件字节不变；前缀摘要不符即拒跑；SDK 平价 | `tests/test_checkpoints.py` 26 项，其中"预算不能被 resume 洗掉"直接断言 exit 4 |

**这一项的真实动机不是便利，是漏洞**：上限是 per-run 的，而 `--resume` 会新开一次运行——
所以"恢复"一直是绕过 `max_budget_usd` 的后门。现在它必须把父花费带过来；
嵌入式调用忘了传 seed 过的 `Budget` 会直接报错，而不是拿到更宽的额度。

### 6.2 第十四批（多模型 + 独立验证）

| 项 | 内容 | 验证 |
|---|---|---|
| P1-2 | `providers/openai_compat.py` + `--provider openai`：双向翻译、`thinking` 只出请求不出 transcript、非 JSON `arguments` 失败闭合、reasoning 代际自动换 `max_completion_tokens`、价格不臆造、`--model`/`--provider` 组合在触网前校验 | `tests/test_provider_openai_compat.py` 28 项，含"聊天形状的工具调用仍过同一道权限门" |
| §4-4 | `postconditions.py` + `--verify` / `[[verify]]`；协议新增 `error_postconditions_failed`(exit 6) 与 `RECORD_TYPES` 第 12 项 `postconditions`；面板渲染 | `tests/test_postconditions.py` 32 项：条件对模型不可见、符号链接/越界配置期拒绝、仓库只能加不能减、只读评估（mtime 不变） |
| 漂移防护 | `py-modules` 与磁盘模块集合一致性；面板 record 词表测试如期报警 | 反向验证：从 `pyproject.toml` 删掉一行即失败 |

全仓 954 项测试全绿（runtime 660）。**未做**：流式（`StreamDelta`）、`skills check`、F3。

**F3 与 skills check 均已完成**（见 §6.15、§6.20）。下一批顺序改为：**P1-1 MCP 代际 + elicitation-as-approval → 流式 → durable-run 与 runtime 检查点的统一（lease/verifier 复用）**。理由：skills check 差异化最高、依赖最少；MCP 代际是唯一会持续变大的"过期风险"；把 runtime 的 checkpoint 与 durable-run 的 `EventStore`/`Lease` 统一是最后的"零件合整机"，需要在两个组件之间定一个接口，值得单独一批。

---

**未做且刻意留在后面的**：sidecar 侧真正校验 binding（要动它那个"只允许三字段"的协议——这是安全敏感组件的协议决策，不该在一次功能批次里顺手改）；F3 durable 接线；P1 全组。

下一批建议顺序：**T-durable（F3）→ P1-1 MCP 代际 + elicitation-as-approval → P1-2 多模型与流式 → skills check**。理由：F3 是"有零件没整机"里最亏的一块；MCP 代际是唯一的"过期风险"（会随规范演进持续变大）；skills check 是差异化收益最高、依赖最少的一条。

---

## 7. 一句话

**"包含所有顶级 agent 的优点"这条路的正确走法，是把每个优点都过一遍"能不能不绕门"的改写；改不动的就明确拒绝。**
Northstar 的次世代位置不在功能并集上，在于：**同一个 agent loop，别人要牺牲确定性或牺牲边界来换能力，这里两样都不换——而且每一项能力都能在 CI 里用 890 个无 key 测试证明它今天和昨天行为一致。**
