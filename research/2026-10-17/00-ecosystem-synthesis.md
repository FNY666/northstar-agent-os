# Northstar Agent OS 生态研究综合：M0/M1 的有界增量排序

**研究日期：** 2026-10-17
**约束基线：** [Northstar 次世代编程 Agent OS 蓝图 v2.1](../../docs/next-gen-agent-blueprint.zh-CN.md)（下称“蓝图”）
**综合对象：** 同目录 01–10 十份专题报告；外部机制只按其专题报告中已核验的一手规范、官方文档或官方仓库使用。

> **决策结论：** M0/M1 不应扩展为“多 Agent、云端、MCP/插件市场、自动 PR 或记忆平台”的功能并集。应先用冻结的真实仓库任务证明现有闭环，再补齐**持久审批、拒绝/恢复语义、不可信仓库准入、结构化证据和 worktree 绑定的 reconcile**。这五项均服务同一条路径：`任务 → 计划 → 受控执行 → 独立验证 → 补丁 + 可核验证据`。

---

## 1. 综合口径与蓝图不可让渡的约束

### 1.1 事实边界

本报告不将任何外部产品的营销、安全或性能表述升级为 Northstar 的能力保证。例如，云 VM、microVM、`full_access`、自动 PR、内部“减少提示次数”、benchmark 分数和第三方 quality score 都不是 Northstar 的完成证明。一个外部机制只有在以下条件下才被列入候选：

1. 能由专题报告引用的官方规范、官方文档或官方仓库核验；
2. 能映射为 Northstar 宿主拥有的权限、预算、worktree、验证或证据合同；
3. 能以一个有限的本地/离线切片测试；
4. 不改变蓝图中的默认断网、最小权限、不自动提交/推送和未知副作用不自动重放。

公开 GitHub issue 在本报告中只用来设计故障夹具和 failure taxonomy，**不**作为外部产品能力、可靠性比例或安全保证的证据。[23]

### 1.2 蓝图约束如何筛选候选

以下已是约束，不应被候选功能稀释或替换：

- **完成定义：** 修改必须在本 run 拥有的隔离 worktree；读、改、执行、联网均经治理；检查有命令、退出码、输出/环境摘要；补丁可从初始提交重放；只能产生一个可解释终态；不自动提交或推送。[蓝图 §2、§3]
- **执行语义：** 计划仅是审计对象而非权限凭据；每个可变更调用绑定 `call_id`、输入指纹、授权决定、receipt 与文件版本；缺少终态 receipt 的副作用进入 `needs_reconciliation`，不得自动重跑。[蓝图 §4–5]
- **已实现的基础：** `northstar code`、隔离 worktree、四阶段首版、结构化代码工具、独立验证、补丁/证据包和 `code-reconcile` 首版已经存在。候选必须补足它们尚未覆盖的合同，而不是重造工具表面。[蓝图 §9.1]
- **当前次序：** 先冻结模型/环境/网络/预算并测 24 题真实模型基线，再冻结 50 个 SWE-bench 样本，随后补齐阶段恢复与未知副作用 reconcile。[蓝图 §11]

### 1.3 排序方法

排序优先考虑：**(a)** 与上述“当前次序”和 M0/M1 单仓库闭环的直接匹配，**(b)** 来自相互独立的一手来源的机制交叉印证，**(c)** 对已有能力的明确增量，以及 **(d)** 可在不开放网络、云端自治或自动发布的情况下验收。排名不是外部产品能力排名。

| 排名 | 候选增量 | 阶段匹配 | 直接补的缺口 |
|---:|---|---|---|
| 1 | 冻结运行合同的真实模型基线与轨迹硬门 | M0，当前第一刀 | 现有 24 题/评测器尚缺真实模型基线及治理轨迹可复现比较 |
| 2 | 工具调用级的持久审批中断与恢复前重核验 | M0 安全闭环 | 阶段 recovery 尚不能自动续跑；审批不能依赖存活 worker |
| 3 | 不可信仓库准入 preflight 与隔离能力如实披露 | M0/M1 入口门 | RepositorySnapshot 已读取上下文，但缺少“配置执行面 + 后端能力”的可判定准入回执 |
| 4 | 规范化、可封存的 action/evidence 事件合同 | M0 证据闭环 | 已有 evidence bundle，尚需把提议、拒绝、执行、receipt、预算、恢复关系统一为可验证事件语义 |
| 5 | 绑定 worktree 的阶段 checkpoint/reconcile manifest | M1 可靠性增量 | 现有 reconcile 首版不会自动从一致阶段继续，且后端快照不能单独构成恢复证明 |

---

## 2. 候选 1（最高优先）：冻结运行合同的真实模型基线与轨迹硬门

**阶段与排序理由：M0 / 第一优先。** 这是蓝图列出的第一、第二项近期工作，而不是另起评测平台。现有 24 题夹具和本地评测器证明夹具/参考补丁有效，但尚未给出在固定真实模型、执行环境和治理配置下的 Northstar 基线；没有这个锚点，之后的恢复、权限或证据改动无法判断是提升、退化还是环境漂移。[蓝图 §8、§9.1、§11]

### 来源机制与可采纳部分

- SWE-agent 将 patch 生成与独立 benchmark evaluation 分开，并支持每实例成本上限；可采纳的是**生成、验收和成本记录分离**，不是其研究吞吐或榜单叙事。[1][2]
- Langfuse/Braintrust 的版本化 dataset 与 immutable experiment 说明了将失败 trace 固定为可比较回归对象的工程形状；Promptfoo 的 trajectory assertions 则说明工具顺序、错误和参数可成为硬断言。[3][4][5]
- OpenTelemetry GenAI 可作为阶段、模型、工具之间的可互操作导出映射，但其语义约定仍在演进，不能成为权威账本。[6][7]

### 为什么不与既有能力重复

蓝图已经冻结了 24 个离线题的夹具、公开/隐藏检查与参考对照，也已有补丁重放评测器；这不是“再建评测器”。增量是建立一份**真实 provider 运行的冻结 `RunContract`**：模型/版本、容器或沙箱摘要、网络策略、预算、精确初始 HEAD、验证命令、Northstar 版本与 evidence schema 版本均被绑定到每一条结果。它还增加拒绝、未知副作用、检查 receipt 和交付 diff 的轨迹硬门，避免只比较最终文本或平均分。

### 最小可测试切片

选择 24 题中各一题：缺陷修复、功能添加、测试/构建修复。对每题执行两次同一冻结合同的 `northstar code` run（不允许未声明网络）。每次输出 `baseline-manifest.json`、`CodeRunReport`、补丁、检查 receipts、预算账本摘要和 sealed evidence reference；再由干净副本重放补丁并运行隐藏检查。

### 明确验收标准

1. 每个 run manifest 都含：任务 ID、初始 HEAD、模型与版本、容器/沙箱摘要、网络 policy revision、预算上限与实际用量、检查命令、Northstar/evidence schema 版本及 artifact hashes。
2. 两次运行的环境合同字节级相同；如果模型输出或补丁不同，记录为结果差异而非悄然覆盖实验记录。
3. `success` 仅在独立重放和声明检查均有成功 receipt 时出现；检查未运行只能是 `success_unverified`，检查失败绝不能产生 `success`。
4. `denied`、`budget_exhausted`、`needs_reconciliation` 与工具轨迹中的实际调用严格一致；未被授权的网络、写入或 shell 不能被质量分数抵消。
5. 形成可运行的 trajectory assertions：至少断言 `SubmitPlan` 先于写入、验证在最终交付前发生、delivery seal 对应最终 diff、未声明网络为零。
6. 最小切片通过后，才用同一合同跑完整 24 题建立**描述性基线**；它不是发布宣称，发布仍受蓝图的 20/24、SWE-bench、成本、恢复和 0 次虚假 success 门约束。

### 明确拒绝

- 拒绝把 LLM-as-a-judge、平均分、第三方 trace 或产品 benchmark 排名当成完成证明；它们只能是诊断信息。[4][5]
- 拒绝在未冻结模型、镜像、网络和预算的条件下宣称“提升”。
- 拒绝将红队生成或在线评分带入默认生产 run；这属于后续 Labs/CI 的受控工作。[8]

---

## 3. 候选 2：工具调用级的持久审批中断与恢复前重核验

**阶段与排序理由：M0 / 最高安全增量。** 多个独立来源都把“提出副作用”与“获准执行”分开，并支持可恢复的人类输入；同时也明确警告 transcript/session 不是文件系统或外部副作用恢复。[9][10][11][12][13] 这直接补蓝图“自动阶段续跑尚未实现”的空白，且不会增加工具种类。

### 来源机制与可采纳部分

- OpenAI Agents 的 human review 语义是：工具调用先中断、不执行，批准/拒绝后用可序列化 state 继续同一 run；Codex 还区分 sandbox 与 approval policy。[9][10]
- LangGraph 的 `interrupt()` 与 Temporal 的暂停等待展示了持久等待、恢复输入和不占用计算资源的形状；Inngest 的稳定 step ID、checkpoint 与外部副作用幂等要求补足重试边界。[11][12][13]
- AutoGen 明确指出运行中阻塞式 `UserProxyAgent` 不能保存/恢复；这是 Northstar 不应复制的反例。[14]

### 为什么不与既有能力重复

现有 `SubmitPlan` 闸门、阶段 journal、forward-sealed 会话与 `code-reconcile` 已能记录计划和恢复裁决，但并不等于存在一个可持久化的**具体 action approval**。新合同把待批准动作、其限定范围、预算 reservation、policy revision、worktree identity 与 evidence head 绑定；它不是“再显示一次确认 UI”，也不是 resume 聊天记录。

### 最小可测试切片

使用 scripted provider 执行一个已提交计划：先只读，再提出一次具有副作用的 `RunCheck`（或受控 `ApplyPatch`）。运行到审批点后杀死 worker；由独立操作者提交 signed/认证 approval 或 denial。随后尝试恢复。再分别注入：预算变化、policy revision 变化、worktree lease/HEAD 变化、approval 过期、`action_started` 存在但终态 receipt 缺失。

### 明确验收标准

1. `awaiting_approval` 记录至少包含 `run_id`、`call_id`、规范化 action/参数 digest、影响范围、预计与已预留预算、policy revision、base HEAD/worktree lease、evidence head、创建/过期时间与操作者要求。
2. 进入等待后释放执行 worker；恢复不可依赖旧进程。若 worktree live lease 被释放，恢复须重新取得并验证它，而不能把旧路径视作仍安全。
3. 批准后，宿主按当前 policy、剩余预算、run/worktree/evidence 关联**再次**裁决；只有全部相等或更严格时才给本 call 的短期 grant，并至多执行一次。
4. denial、超时、预算不足、policy 变严、HEAD/lease/evidence head 不一致均不得执行该 action，且应有 sealed 拒绝/失配事件。
5. 若 `action_started` 后缺少完成 receipt，终态必须是 `needs_reconciliation`；不得把“批准仍有效”解释成可自动重放。
6. 审批记录与最终 `CodeRunReport`、补丁和验证 receipt 可交叉验证；伪造或复用另一个 `call_id` 的批准被拒绝。

### 明确拒绝

- 拒绝 `approve all`、默认 auto-approve、模型自批准、长效宽权限 grant，及将 `full_access` 作为快捷恢复路径。[9][15]
- 拒绝阻塞 worker/worktree 等待人的同步 HITL，或把 session/thread ID 当作副作用成功 receipt。[14][16]
- 拒绝在恢复时重放网络写入、凭证使用、push、发布或任何 receipt 缺失的外部 action。

---

## 4. 候选 3：不可信仓库准入 preflight 与隔离能力如实披露

**阶段与排序理由：M0/M1 入口门。** 蓝图已规定仓库内容均为不可信数据，`RepositorySnapshot` 也收集 `AGENTS.md`、项目策略和技能；但“已读取上下文”不等于“仓库中可能改变 agent 行为的配置已被发现、隔离并留下准入证据”。该增量将文件系统/网络执行边界与配置加载边界一起做成可测试 admission。

### 来源机制与可采纳部分

- Gemini CLI 在加载项目配置前发现 hooks、MCP、skills、设置覆盖和 `.env`，不信任时禁用自动加载；其 `--skip-trust` 也证明 bypass 不能成为生产默认。[17]
- Claude 的 deny/ask/allow、managed settings 与 Hook 生命周期说明，策略决策须在副作用前由宿主层执行；Hook 本身并非全数据流拦截证明。[18][19]
- OpenHands 明确区分 Docker sandbox 与无 OS 隔离的 process sandbox；社区公开 issue 仅支持把启动/权限错误做成 preflight 测试，而不支持以 privileged 容器解决默认隔离。[20][23]
- Daytona 将网络、runtime 与组织边界分别建模，说明“沙箱”应拆成可报告的边界与状态，而非一个笼统标签。[21]

### 为什么不与既有能力重复

这不会重写 `RepositorySnapshot` 或默认断网。它在 snapshot **之前或同时**增加一个不可执行的扫描与后端能力探测，生成 host-owned `AdmissionReceipt`：哪些仓库配置/secret 文件被发现，哪些被作为不可信数据而未加载，实际 sandbox 后端有哪些能力，是否满足本次任务要求。这样可证明“项目指令被读取”没有变成“项目自行授予工具、网络或插件权限”。

### 最小可测试切片

准备两个离线 fixture：

- 正常 Python/TypeScript 仓库；
- 恶意仓库，包含 `AGENTS.md` 中的越权文本、`.env`、Gemini/Claude 风格设置、hook 声明、MCP/skills 配置及指向 worktree 外路径的建议。

在一个完整隔离后端与一个刻意缺少所需隔离能力的后端上各运行 `--plan-only` 和受控 execute 尝试，验证输出的 AdmissionReceipt 与实际加载/拒绝行为。

### 明确验收标准

1. 扫描本身不得执行 repo hook、shell、MCP、skill、包管理脚本或读取 `.env` 值；证据只记录路径、类别、受限哈希/大小及决策，不泄露 secret 内容。
2. 仓库配置、模型输出和任务文本均不能添加工具、放宽路径/网络/预算、改变 policy revision，或让 host 加载未批准的插件/MCP server。
3. AdmissionReceipt 至少记录：base HEAD、配置发现摘要、策略来源与 revision、sandbox backend/隔离等级、挂载与可写路径、网络 deny/allow 断言、资源限制和降级原因。
4. 无法满足任务所需的 filesystem/network containment 时，execute 必须 fail closed，或进入被明确标为**非 OS 隔离且不计入 M0 隔离通过率**的受限诊断路径；不得悄然回退为 process/host 执行。
5. 不允许为解决 preflight 失败而使用 privileged 容器、主机宽挂载、`skip-trust` 或永久网络白名单；每次网络例外仍走蓝图规定的精确目标授权。

### 明确拒绝

- 拒绝把 `AGENTS.md`、仓库 settings、skill 描述、Agent Card 或模型文本当作权限凭据。
- 拒绝以“已经在容器里”“secure VM”“trusted folder”之类名称当作隔离完成证明；receipt 必须陈述实际后端能力和限制。[17][20][21]
- 拒绝将公开 issue 当成供应商可靠性统计或普遍事实。[23]

---

## 5. 候选 4：规范化、可封存的 action/evidence 事件合同

**阶段与排序理由：M0 证据闭环。** Northstar 已交付 snapshot、task、phases、patch-replay、delivery-seal、verification、patch、status、manifest 等 evidence bundle 项目，并有 forward-sealed 会话；此候选不替换它们。它要消除“若干文件都有，但 action 的提议、拒绝、授权、开始、receipt、预算和恢复父链无法统一验证”的缝隙，使候选 1–3 的结论可被同一证据合同复核。

### 来源机制与可采纳部分

- `codex exec` 的 JSONL 事件分开表示 thread/turn、命令、文件变化、MCP 和计划；Claude Hooks 将 attempted、denied、executed 的生命周期暴露给宿主。[10][19]
- OpenHands 的 workspace 返回 stdout、stderr、退出码、超时与 Git changes/diff，说明执行 receipt 应来自执行器而非模型文本。[22]
- OTel 的 agent/plan/tool 语义与 Langfuse 的嵌套 observation 可作为**可关闭的导出映射**，但官方 GenAI 语义仍属发展中，不能替代 sealed evidence。[6][7]

### 为什么不与既有能力重复

现有证据包强调产物完整性；本候选提供版本化的**跨产物关联语义**。每个 artifact 仍保留在当前文件结构中，但都由稳定 `run_id`、`step_id`、`call_id`、`source_id`、父 evidence hash 和 policy/budget/worktree 摘要关联。它使“工具提议”不再可能被下游误读为“工具执行”，也让恢复、拒绝和 seal 有统一的审计接口。

### 最小可测试切片

对一个离线代码任务和一个被拒绝的网络/路径任务输出 `evidence.ndjson` v1。事件覆盖：`run.created`、`repository.admitted`、`plan.submitted`、`action.proposed`、`action.denied` 或 `action.authorized`、`action.started`、`action.receipted|action.unknown`、`check.receipted`、`delivery.sealed`。生成 manifest 后故意篡改一行、替换一个 receipt、删除一个 terminal event，运行独立 verify。

### 明确验收标准

1. JSON Schema/版本验证通过；每个 `source_id` 幂等，所有 action 都关联 run/step/call、输入摘要、policy revision、预算前后值、worktree/base/current revision 与父 evidence hash。
2. `action.proposed`、`action.denied`、`action.authorized`、`action.started`、`action.receipted` 是不可混淆的状态；没有 execution receipt 不得导出“executed”或 `success`。
3. seal 覆盖事件流和被引用 artifacts 的内容哈希；篡改、缺链、重复 receipt、未知 action、错误父链或终态不一致都使 verify 失败。
4. `check.receipted` 必有命令摘要、环境摘要、开始/结束、退出码、截断信息和输出摘要；delivery seal 必须证明交付 diff 与检查后的 diff 相同。
5. OTLP/OTel 导出可关闭且经脱敏；导出器失败只能生成诊断事件，不能改变已执行 action 的事实或把无证据的 run 标为成功。

### 明确拒绝

- 拒绝将 span、第三方 trace、日志、模型最终回答或 Git commit 单独视为执行/完成/授权凭据。[5][6][7]
- 拒绝记录未经最小化处理的 secrets、token、完整敏感 prompt 或网络响应；引用摘要与受控 artifact 才是默认值。
- 拒绝为兼容格式而允许 evidence exporter 覆盖 Northstar 的 receipt、终态或 hash-chain。

---

## 6. 候选 5：绑定 worktree 的阶段 checkpoint/reconcile manifest

**阶段与排序理由：M1 可靠性增量。** 这是候选 2 的“审批恢复”之外的执行环境恢复：何时可重新使用一个 worktree、何时只可 reconcile、何时必须失败关闭。它有多份一手材料支持 checkpoint、pause/resume、snapshot 与 stable step 的**有限**机制，但没有任何来源证明外部副作用的通用 exactly-once；因此只应做本地、后端无关 manifest，不应先接入云 sandbox provider。

### 来源机制与可采纳部分

- Inngest 要求稳定 step ID，并明确外部副作用在响应丢失后仍可能重复，需幂等键；Temporal 采用有界重试后停车并等待修正。[12][13]
- LangGraph 区分 replay 与 fork，且 replay 会重新执行后续 API/interrupt；Cline 的代码/对话恢复也显示文件快照与上下文不是同一件事。[11][24]
- E2B、Daytona、Modal 提供 pause/resume、状态机或 filesystem snapshot，但各自有 TTL、覆盖范围和运行时差异；provider snapshot ID 不是 Northstar 证据。[25][21][26]

### 为什么不与既有能力重复

蓝图已经规定：读取/检索可重算、补丁以 before-image 判断幂等、成功 receipt 的命令不重跑、未知命令进入 reconcile；`code-reconcile` 首版可检查链和封存文件。缺少的是一个明确、可迁移的**阶段 checkpoint manifest**，把这些规则落到可验证的 resume 输入上，并将状态、快照/产物、TTL、worktree lease 和 evidence chain 关联；这不是通用“聊天历史 resume”，也不是直接引入 E2B/Modal。

### 最小可测试切片

在单仓库 detached worktree 中，于 `understanding`、`planned`、`executing`（一个已 receipt 的幂等补丁后）和 `verifying` 边界写入 manifest。分别注入：正常崩溃、worktree HEAD 被改、policy revision 收紧、预算耗尽、snapshot TTL 过期、`action_started` 后进程中断。运行 `code-reconcile` 与受控 `resume`。

### 明确验收标准

1. checkpoint manifest 包含版本化 `run_id/step_id/attempt`、base/current HEAD、worktree identity/lease、policy revision、预算快照、evidence head、action 效果状态、artifact/snapshot ID 与内容哈希、TTL/创建时间和允许的下一状态。
2. `resume`、`retry` 与 `fork` 是不同命令和不同 evidence 父链；fork 产生新 run，不覆盖原历史。任何 policy/HEAD/lease/evidence/TTL 不匹配都明确 fail closed。
3. 可安全重算的只读步骤有新的 attempt 记录；已成功 receipt 的检查不重跑；补丁只在 before-image/期望文件版本匹配时幂等应用。
4. `action_started` 后无终态 receipt 的所有外部或不可判定 action 均进入 `needs_reconciliation`，只允许 read-back/人工裁决，不能在 resume 中自动重放。
5. manifest、diff、验证 receipts 与 audit events 可共同定位“恢复到哪个执行边界”；provider snapshot（若将来接入）只作为受校验 artifact ref，不授予权限、不延长预算、不替代 policy 再检查。

### 明确拒绝

- 拒绝将 session transcript、Git reset、checkpoint、worktree 或 provider snapshot 中任一个单独解释为“可安全恢复”。[16][24][25][26]
- 拒绝无限重试、静默 state-not-found fallback、后台进程仍在就认为任务存活，或恢复时扩大权限/预算。[13][21]
- 拒绝把长期语义记忆、跨仓库共享 memory 或全功能 durable workflow 平台塞入此 M1 切片；执行历史和证据仍是权威事实来源。[27][28]

---

## 7. 明确延后或拒绝进入当前五项的方向

下表避免把研究覆盖对象误解为已批准路线。

| 方向 | 当前裁决 | 原因与重新进入条件 |
|---|---|---|
| MCP、A2A、OAuth token exchange、SPIFFE | **延后** | 规范可用于后续窄连接器/显式 handoff，但 token、Agent Card、`AUTH_REQUIRED` 或 workload identity 都不等于 run/call 权限或完成证明。先完成候选 2–5，再以短 TTL、窄 audience/scope、PKCE 和 evidence 绑定做本地模拟。[29][30][31][32] |
| 子 Agent、通用 DAG、并行 fan-out、MCP 插件市场、cloud agent | **延后** | 蓝图将协作置于 M4；编排框架提供状态/控制流，不替代 policy、预算、worktree 和证据。任何未来 child 仅能继承并收窄父权限/预算，且先做有限 DAG 与取消传播夹具。[11][14][33] |
| GitHub 分支/PR adapter、自动合并、自动 push | **延后/拒绝默认** | 当前完成定义明确“不自动提交或推送”。若 M1 后引入，只能导出 patch/证据或进行最小权限、人审合并的适配；不得把自动 PR/merge 设为默认。[34] |
| Letta/Mem0 类长期记忆 | **延后** | 可作为默认只读、按 workspace/run/actor 隔离的事实检索适配器；不可代替 append-only run history、grant、预算、worktree、patch 或 verifier receipt。先做污染/误召回基准。[27][28] |
| Promptfoo 红队/自动攻击 | **Labs，非默认运行时** | 攻防应有独立目标、预算、隔离和批准，符合蓝图 M3 的 Core/Labs 边界；不因“覆盖更全面”扩大生产权限。[8] |
| 供应商沙箱/快照平台 | **后端候选，不是控制面** | 先通过候选 3 与 5 的后端无关合同；再对真实任务测试网络、mount、secret、OOM、TTL、销毁和导出的 evidence，不能把厂商隔离主张转为 Northstar assurance。[20][21][25][26] |

---

## 8. 推荐的单一下一实验

**实验名称：`M0-frozen-baseline-001`。**

在不更改产品权限语义的前提下，先执行候选 1 的三题双运行切片：冻结真实模型/版本、Northstar 版本、容器或沙箱摘要、默认断网策略、预算、精确 HEAD 和验收命令；对每个 run 封存当前 evidence bundle，并在干净副本重放 patch。实验产物必须包括 `baseline-manifest.json`、trajectory hard-gate 结果、`CodeRunReport`、补丁及独立验证 receipts。

**为什么它优先于新增功能：** 它严格遵循蓝图 §11 的第一、二步，并能立即揭示现有 runtime 是否已经出现虚假 success、越权轨迹、证据缺口、不可重放补丁或成本不可解释的问题。只有这一基线可复现后，候选 2 的持久审批/恢复改动才有可比较的安全和效用对照。

---

## References

### 综合报告与本地约束

- [蓝图]: ../../docs/next-gen-agent-blueprint.zh-CN.md "Northstar 次世代编程 Agent OS 蓝图 v2.1"
- [专题 01]: 01-openai-codex.md "OpenAI Codex、Codex CLI 与 Agent SDK"
- [专题 02]: 02-anthropic-claude.md "Anthropic Claude Code、Claude Agent SDK"
- [专题 03]: 03-google-gemini.md "Google Gemini CLI、Jules"
- [专题 04]: 04-open-source-coding.md "Open-source coding agents"
- [专题 05]: 05-orchestration.md "LangGraph、AutoGen、CrewAI、Semantic Kernel"
- [专题 06]: 06-protocol-identity.md "MCP、A2A、Agent identity"
- [专题 07]: 07-sandbox-execution.md "E2B、Daytona、Modal、Dagger"
- [专题 08]: 08-durable-memory.md "Temporal、Inngest、Letta、Mem0"
- [专题 09]: 09-observability-evals.md "OpenTelemetry、Langfuse、Braintrust、Promptfoo"
- [专题 10]: 10-community-radar.md "公开社区、仓库与工程机制雷达"

### 已用于本文结论的一手外部来源

[1]: https://github.com/SWE-agent/SWE-agent "SWE-agent 官方仓库"

[2]: https://swe-agent.com/0.7/usage/benchmarking/ "SWE-agent benchmarking"

[3]: https://langfuse.com/docs/evaluation/experiments/datasets "Langfuse Datasets"

[4]: https://www.braintrust.dev/docs/evaluate "Braintrust evaluation"

[5]: https://www.promptfoo.dev/docs/tracing/ "Promptfoo tracing and trajectory assertions"

[6]: https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-agent-spans.md "OpenTelemetry GenAI agent spans"

[7]: https://opentelemetry.io/blog/2025/ai-agent-observability/ "OpenTelemetry AI agent observability"

[8]: https://www.promptfoo.dev/docs/red-team/ "Promptfoo red teaming"

[9]: https://developers.openai.com/api/docs/guides/agents/guardrails-approvals "OpenAI Agents guardrails and approvals"

[10]: https://learn.chatgpt.com/codex/non-interactive-mode "Codex non-interactive mode and JSONL events"

[11]: https://docs.langchain.com/oss/python/langgraph/interrupts "LangGraph interrupts"

[12]: https://docs.temporal.io/design-patterns/resumable-activity "Temporal resumable activity"

[13]: https://www.inngest.com/docs/durable-execution/primitives "Inngest durable steps and idempotency"

[14]: https://microsoft.github.io/autogen/stable/user-guide/agentchat-user-guide/tutorial/human-in-the-loop.html "AutoGen human-in-the-loop limitations"

[15]: https://developers.openai.com/codex/codex-sdk "Codex SDK sandbox presets"

[16]: https://code.claude.com/docs/en/agent-sdk/sessions "Claude Agent SDK sessions and filesystem limitation"

[17]: https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/trusted-folders.md "Gemini CLI Trusted Folders"

[18]: https://code.claude.com/docs/en/agent-sdk/permissions "Claude Agent SDK permission evaluation"

[19]: https://code.claude.com/docs/en/hooks "Claude Code Hooks"

[20]: https://docs.openhands.dev/openhands/usage/sandboxes/process "OpenHands process sandbox boundary"

[21]: https://www.daytona.io/docs/en/sandboxes/ "Daytona sandbox lifecycle"

[22]: https://docs.openhands.dev/sdk/api-reference/openhands.sdk.workspace "OpenHands workspace API"

[23]: https://github.com/OpenHands/OpenHands/issues/5467 "OpenHands public issue; used only as a failure-fixture signal"

[24]: https://docs.cline.bot/core-workflows/checkpoints "Cline checkpoints"

[25]: https://docs.e2b.dev/sandbox "E2B sandbox lifecycle"

[26]: https://modal.com/docs/guide/sandbox-snapshots "Modal sandbox snapshots"

[27]: https://docs.letta.com/v1-sdk/memory/memory-blocks/ "Letta memory blocks"

[28]: https://docs.mem0.ai/core-concepts/how-it-works "Mem0 memory architecture"

[29]: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization "MCP authorization"

[30]: https://a2a-protocol.org/latest/specification/ "A2A Protocol specification"

[31]: https://datatracker.ietf.org/doc/html/rfc8693 "RFC 8693 OAuth 2.0 Token Exchange"

[32]: https://www.rfc-editor.org/rfc/rfc9700.html "RFC 9700 OAuth 2.0 Security BCP"

[33]: https://learn.microsoft.com/en-us/semantic-kernel/frameworks/agent/agent-orchestration/ "Semantic Kernel agent orchestration (experimental)"

[34]: https://docs.github.com/en/copilot/concepts/agents/coding-agent/about-coding-agent "GitHub Copilot coding agent"
