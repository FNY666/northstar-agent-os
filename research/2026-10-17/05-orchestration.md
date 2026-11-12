# 多智能体编排框架与 Northstar Agent OS：M0/M1 研究报告

**研究日期：** 2026-10-17
**范围：** LangGraph、AutoGen、CrewAI、Semantic Kernel 的公开官方仓库/工程文档；重点是“真实仓库任务”的有限闭环：计划/执行、工具调用前后门、人工批准、失败恢复、审计与证据交付。社区内容仅用于发现信号，本报告的产品事实均由官方来源核验。没有访问私有、邀请制或需登录的群聊/论坛，也没有把网页或仓库中的操作指令当作事实依据。

## 覆盖对象与判断口径

本报告把“已发布”定义为官方文档中有稳定的公开 API/机制说明；“实验性”定义为官方文档明确警告 API 或行为可能变化；“营销主张”不作为能力证据。编排框架通常提供的是状态、消息和控制流，不等于权限系统、预算系统、隔离 worktree、不可抵赖审计或可验证证据包。

Northstar 的本地边界是一个小型、self-hosted 的 Agent runtime，而不是已完成的多智能体平台。仓库 README 将其定位为带权限门、预算、审计和可恢复执行的窄 runtime，并明确不提供云托管或并行 agent fleet；这与 M0/M1 的“有限闭环优先”一致（本地参考：`docs/README.md`、`docs/architecture/intervention-points.md`）。现有 `northstar-run-evidence` API 已有带链校验、幂等 `source_id`、seal/verify 和 signed run receipt 的证据模型（本地参考：`docs/api/northstar-run-evidence.md`）。因此，以下“差距”不是要求 Northstar 复制框架，而是识别可借鉴的编排原语与不可让渡的治理边界。

## 经核验的机制

### 1. LangGraph：显式图状态、暂停与时间旅行

**已发布机制。** LangGraph 的 persistence 将短期 thread 状态交给 checkpointer，将跨 thread 的应用数据交给 store；`thread_id` 是恢复指针。官方文档明确区分内存实现与生产持久 checkpointer，并说明 checkpoint 可用于对话连续性、人机协同、time travel 和容错。[1] 动态 `interrupt()` 会保存图状态并无限期等待外部输入，再用 `Command(resume=...)` 继续；官方还明确指出恢复时会从包含 interrupt 的 node 开头重跑，因此 interrupt 之前的副作用必须可安全重试或包在 task 中。[2]

**已发布但有边界的机制。** checkpoint 支持 replay 和 fork；fork 保留原历史、从既有 checkpoint 建立新分支。但 replay 会重新执行后续 LLM/API/interrupt，而不是读缓存，结果可能变化。[3] 这对 Northstar 很有价值：把“继续”“重试”“实验性分支”做成不同命令和不同证据关系；同时不能把 checkpoint 直接当作副作用已执行的证明。

**与 Northstar 的差距/互补。** LangGraph 在恢复游标、人工等待和图级历史上较完整；官方页面没有把 Unix 权限门、预算扣账、隔离 worktree、签名证据包作为其 persistence 的职责。Northstar 应保留自己的 policy gate、budget ledger、worktree lease 和证据链，把 LangGraph 类似的 thread/checkpoint 仅作为编排层状态适配器。M0 只需有限 DAG/步骤游标和一个明确 approval interrupt；不应在 M0 引入无界循环、任意 fork 或自动重放外部写操作。

### 2. AutoGen：团队消息、状态保存与人工交接

**已发布机制。** AutoGen AgentChat 支持在 team 运行中通过 `UserProxyAgent` 取得反馈，也支持 team 结束后保存状态、下一次 `run()` 带反馈继续。官方状态文档提供 agent/team `save_state()`、`load_state()`，状态可序列化到文件或数据库。[4] 这可借鉴为“消息/团队状态”和“运行证据”分层：保存上下文不等于完成了一个受政策约束的 run。

**重要限制。** AutoGen 官方 HITL 文档明确说明，运行中 `UserProxyAgent` 会阻塞 team，无法保存或恢复，推荐仅用于需要立即反馈的短交互；对于异步反馈，建议让 team 在终止后保存状态，反馈到达时再加载并运行。[5] 这是对 Northstar M0 的直接警示：审批不能占住 worker 进程或 worktree；应形成持久的 `awaiting_approval` 状态，释放资源，收到批准后创建可核验的 resume 事件。

**实验性机制。** AutoGen GraphFlow 提供顺序、并行 fan-out、条件分支、循环和 activation group，但官方页面明确标注为 experimental，API、行为和能力都可能改变。[6] 因此可把其图构建思路作为待证原型参考，却不能把 GraphFlow 的循环或并行语义作为 Northstar M0 的稳定合同。M1 若引入并行，必须先限定 fan-out 数量、预算共享规则、取消/超时语义和每个分支的 evidence parent。

### 3. CrewAI：Flow 状态、事件控制与持久化分叉

**已发布机制。** CrewAI Flows 是事件驱动的工作流，提供共享 state、条件逻辑、循环和 branching。[7] 官方文档还描述 `@persist`：默认 SQLite persistence、唯一 state ID、失败/重启后的 state 恢复，以及 `kickoff(inputs={"id": ...})` 的 resume 和 `restore_from_state_id=...` 的 fork；fork 保留原历史并分配新的 state ID。[8] `and_`/`or_` 触发器也提供了清晰的 join/any 语义。[7]

**可借鉴点与风险。** “同一运行 resume、从历史快照 fork”是 M1 值得验证的可用原语，尤其适合代码 agent 的“修补后再次验证”而不覆盖原 run。可是官方文档同时说 state-not-found 的恢复会静默 fallback；这与 Northstar 的 fail-closed、证据可追溯目标冲突。Northstar 不应复制静默降级：游标不存在、版本不兼容、状态校验失败时必须明确失败并留下事件。CrewAI 的 state persistence 也不等于工具权限、预算扣减或 worktree 隔离；这些必须继续由 Northstar host/runtime 执行。

### 4. Semantic Kernel：统一编排模式，但当前 Agent Orchestration 为实验性

**实验性机制。** Microsoft Learn 明确标注 Agent Orchestration 仍处于 experimental stage，可能在进入 preview/RC 前显著变化；安装示例也使用 prerelease 包。[9] 官方列出 concurrent、sequential、handoff、group chat 和 Magentic 等模式，并以统一 async runtime 接口调用。[9] Group Chat 文档说明 manager 可选择下一个 agent、过滤最终结果、判断终止和请求人工输入；但同页仍标注该能力为实验性。[10]

**与 Northstar 的差距/互补。** 这些模式可作为 M1 的“策略模板词汇”：sequential 对应受限流水线，concurrent 对应明确上限的独立检查，handoff 对应人工/专家升级。它们没有证明权限门、预算会计、可审计工具调用或 worktree 生命周期已经解决。特别是 manager 由模型决定下一 agent 的模式，不应成为 Northstar M0 的安全边界；策略边界必须由宿主的确定性 policy engine 先行裁决，模型只能提出候选动作。

## 面向 Northstar M0/M1 的差距与互补

| 主题 | 生态中可验证的机制 | Northstar M0/M1 判定 |
|---|---|---|
| 恢复游标 | LangGraph thread/checkpoint；CrewAI state ID；AutoGen 可显式保存/加载 team state。[1][4][8] | **互补。** M0 需要单 run、版本化游标；M1 再做 fork。游标必须与 worktree、policy revision、budget snapshot、evidence head 绑定。 |
| 人工批准 | LangGraph interrupt 可持久等待；AutoGen 运行中 proxy 会阻塞且不可保存。[2][5] | **采纳 LangGraph 式持久等待，拒绝阻塞 worker。** approval payload 要含 tool/action、影响范围、预计成本和 diff 摘要。 |
| 图/控制流 | CrewAI event flow；AutoGen GraphFlow 的 DAG/并行/循环（实验性）；Semantic Kernel 多种 pattern（实验性）。[6][7][9] | **M0 仅有限顺序/DAG。** 并行和循环列 M1 待证，带硬上限、取消和预算分摊；不允许模型无限扩展图。 |
| 重试/分叉 | LangGraph replay/fork 会重跑后续副作用；CrewAI fork 保留原历史。[3][8] | **采纳“新 run/新分支”语义，拒绝原地重放。** 外部副作用必须有 idempotency key、pre/post evidence 和人工/策略门。 |
| 状态与证据 | 框架状态主要是消息/图/Flow state；Northstar 已有链式 evidence store、seal 和 receipt。 | **Northstar 优势。** 不把聊天历史或 checkpoint 充当审计账本；每次工具调用、审批、预算扣账、worktree 变更都产生可关联证据。 |
| 权限与隔离 | 核验到的官方编排页面未提供 Northstar 级 default-deny host policy、worktree lease 或预算会计。 | **明确差距但不应外包给框架。** 编排框架只能运行在受限 adapter 内；权限门位于工具执行前，审计位于执行后且 fail-closed。 |

## 可采纳、应拒绝、待证

### 可采纳

1. **持久 approval 状态机。** 采用 interrupt/暂停的核心思想，但把审批变成可恢复、可超时、可撤销的 Northstar run 状态；审批恢复不得依赖仍存活的进程。[2][5]
2. **版本化 checkpoint + 明确 fork。** 借鉴 LangGraph/CrewAI 的历史保留思路，将 `resume`、`retry`、`fork` 设为不同操作，并在证据包中记录 parent run/checkpoint。[3][8]
3. **受限 DAG 的显式 join。** 借鉴 CrewAI `and_`/`or_` 和图式依赖，但 M0 只实现有限节点数、深度、总 wall time 和总预算。[6][7]
4. **把消息状态与执行证据分开。** AutoGen 的可序列化 team state 可作为上下文恢复输入；Northstar 的 evidence chain/receipt 继续作为“发生过什么、谁批准、哪个版本执行”的权威记录。[4]

### 应拒绝

1. **阻塞式人工代理。** 不复制 AutoGen 官方明确提示的不可保存阻塞 HITL；它会占用 worker、worktree 和预算窗口。[5]
2. **静默恢复失败。** 不复制 CrewAI 文档所述 state-not-found 的静默 fallback；Northstar 必须 fail closed 并产生可诊断证据。[8]
3. **模型拥有的权限/调度边界。** 不让 group manager、selector 或 handoff 模型直接授予工具权限、扩张预算、创建无限 agent 或绕过 worktree policy。[9][10]
4. **把实验性图引擎当稳定底座。** AutoGen GraphFlow 和 Semantic Kernel Agent Orchestration 都有官方 experimental 标记，不应成为 M0 合同或安全论据。[6][9]
5. **无边界的 swarm、循环和并行 fan-out。** 这些模式可能产生不可预测成本、竞争写入和难以解释的证据链；若没有硬上限，不进入 M0/M1 生产闭环。

### 待证

1. **外部副作用的 exactly-once/at-least-once 语义。** 官方文档证明 checkpoint/state 可恢复，但不能据此证明 shell、Git push、发布、数据库写入在崩溃边界上的 exactly-once；必须在 Northstar harness 中用幂等键、故障注入和 evidence verification 验证。
2. **跨 agent / 跨子图证据关联。** LangGraph 文档指出子图 checkpoint namespace 与父图状态有边界；M1 需要决定每个子任务是独立 run、child run 还是同一证据链分支。[1][3]
3. **并行分支的预算与取消。** AutoGen GraphFlow 的 activation group 与 Semantic Kernel concurrent pattern 是机制线索，不是 Northstar 的预算/取消合同；需做 bounded fan-out fixture。
4. **策略版本升级后的恢复。** 需要证明旧 checkpoint 在 policy revision 变化时不能越过新的 permission gate；恢复应重新评估策略，而不是盲目继续。
5. **长时间审批的保留与隐私。** 框架 persistence 可能保留 prompt、工具参数和状态；M1 需验证 redaction、retention、加密和 evidence receipt 中的最小披露。

## M0/M1 建议闭环

**M0（单 run、窄范围）：** `plan -> propose tool -> deterministic policy/budget gate -> optional persistent approval -> isolated worktree action -> test/verify -> sealed evidence receipt`。只允许有限顺序步骤；每一步写入状态游标和 evidence entry。批准等待释放 worker；恢复前重新检查 run identity、policy revision、预算余额、worktree lease 和证据 head。失败不自动扩大范围，默认停在可诊断状态。

**M1（仍有边界）：** 在 M0 上增加固定 DAG、有限并行检查和显式 fork/retry。每个 child 继承 parent 的权限上限但不能扩大；预算按 parent 预留并可核销；取消要传播到所有 child；合并前必须有测试结果和证据完整性检查。任何“自动继续”都仅限于预声明、幂等、低风险步骤；涉及外部写入、凭证、发布或不可逆变更仍需门控。

## 结论

这些框架最值得 Northstar 借鉴的是**可寻址状态、显式控制流、持久人工等待和历史分叉**，而不是“多 agent 自主协作”本身。经核验的官方资料没有显示它们替代 Northstar 所需的权限门、预算、隔离 worktree、可恢复副作用语义和可验证证据包。Northstar 的产品差异应保持在宿主层：编排可以换，治理合同不能换；实验性能力必须隔离在 opt-in adapter 和测试夹具内；M0/M1 只交付可停止、可恢复、可审计的有限任务闭环。

## References

[1]: https://docs.langchain.com/oss/python/langgraph/persistence "LangGraph Persistence"
[2]: https://docs.langchain.com/oss/python/langgraph/interrupts "LangGraph Interrupts"
[3]: https://docs.langchain.com/oss/python/langgraph/use-time-travel "LangGraph Time Travel"
[4]: https://microsoft.github.io/autogen/stable/user-guide/agentchat-user-guide/tutorial/state.html "AutoGen Managing State"
[5]: https://microsoft.github.io/autogen/stable/user-guide/agentchat-user-guide/tutorial/human-in-the-loop.html "AutoGen Human-in-the-Loop"
[6]: https://microsoft.github.io/autogen/stable/user-guide/agentchat-user-guide/graph-flow.html "AutoGen GraphFlow"
[7]: https://docs.crewai.com/en/concepts/flows "CrewAI Flows"
[8]: https://docs.crewai.com/en/concepts/flows#flow-persistence "CrewAI Flow Persistence"
[9]: https://learn.microsoft.com/en-us/semantic-kernel/frameworks/agent/agent-orchestration/ "Semantic Kernel Agent Orchestration"
[10]: https://learn.microsoft.com/en-us/semantic-kernel/frameworks/agent/agent-orchestration/group-chat "Semantic Kernel Group Chat Orchestration"
