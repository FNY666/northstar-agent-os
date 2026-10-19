# Temporal、Inngest、Letta 与 Mem0：可恢复执行和记忆方案研究

## 覆盖对象与判断范围

本报告覆盖 Temporal、Inngest、Letta、Mem0 的公开官方仓库、规范或工程文档，并将其机制映射到 Northstar Agent OS 的 M0/M1 真实仓库任务闭环。Northstar 当前强调：隔离 Git worktree、权限门、预算上限、append-only 审计、可恢复执行、独立验证和证据包；其 durable-run 原型已经有事件历史、检查点、租约/ fencing、工具效果账本和恢复后的独立验证。[1] 本研究不把“能长期运行”自动等同于“能安全完成编程任务”，也不建议无边界自动化。

结论分三类：**可采纳**表示机制可以在 M0/M1 的窄闭环中落地；**拒绝**表示与 Northstar 的安全边界冲突或会制造错误保证；**待证**表示官方材料声称了机制，但尚不足以证明它适用于 Northstar 的真实仓库任务、权限或证据要求。

## 经核验的机制

### Temporal：持久化工作流、重试与人工纠正

Temporal 官方将 Durable Execution 定义为能跨进程、跨机器恢复的“crash-proof execution”：系统保存应用状态，崩溃后重建变量和已完成步骤，并支持长时间 sleep。[2] 这对 Northstar 的价值不是复制一个通用调度平台，而是提供一个清晰的恢复语义：**恢复点必须是已持久化且可重放的步骤边界**。

官方 Resumable Activity 模式更贴近 M1：Activity 重试耗尽后，Workflow 进入等待状态，等待授权操作员通过 Signal 提供修正输入，然后从原位置重新执行；等待期间不轮询、不占用计算。[3] 文档同时建议有界重试、状态查询、状态迁移审计、操作员通知和等待超时，并提醒长历史要 Continue-As-New。[3] 这比“自动失败后无限重试”适合 Northstar 的权限门：错误输入或缺失批准应变成可观察的 `awaiting_correction` / `awaiting_approval`，而不是让 Agent 自行扩大权限或重启整项工作。

不过，Temporal 的官方定义和产品页属于平台主张；它们证明了设计模型，不等于 Northstar 已获得分布式服务级别的可用性、身份或隔离能力。Northstar 的 M0/M1 仍应把本地 JSONL 事件历史、租约、fencing 和接收方幂等键作为事实来源，而不是引入“平台会替我保证 exactly-once”的假设。[1]

### Inngest：步骤检查点、重放与流控

Inngest 官方 Durable Workflows 将运行拆成命名 step；成功步骤的结果被保存为 checkpoint，失败步骤可单独重试，sleep 或 waitForEvent 期间不保持 worker 运行，恢复时复用已完成结果并显示 run trace。[4] 其官方 primitives 文档明确要求稳定 step ID；同时明确指出 step 并不让外部副作用 exactly-once，响应丢失时可能重试，因此支付、写入和消息必须使用幂等键。[5]

对 Northstar，Inngest 最有用的是一个**窄步骤协议**：`prepare`、`authorized_action`、`verify`、`package_evidence` 各自有稳定 ID、输入摘要、输出引用、重试策略和超时。它还提供 concurrency、priority、throttling、rate limiting 等流控，但这些是编排能力，不是权限授权。[4] Inngest 官方还给出了自托管和云部署差异，以及 Python 不支持 checkpointing、会使用标准 orchestration 的状态说明。[4] 这些内容属于已发布文档能力；其服务可靠性或对任意编程 Agent 的适配则不能从营销页推断。

不应直接复制 Inngest 的“handler 重放即恢复”心智模型到任意 Agent 代码：文档明确提醒 step 外的非确定性代码会在 replay 时再次运行，且步骤结果/运行状态有 4 MiB/32 MiB 等限制。[4][5] Northstar 应继续把工具副作用放入带 ActionGateway 和 ToolEffectLedger 的受控边界，并把大型输出放进内容寻址 blob，而不是把模型上下文或整个仓库塞进步骤结果。

### Letta：状态型 Agent、核心记忆块与归档记忆

Letta 官方概念文档称，状态型 Agent 的记忆、用户消息、推理和工具调用都持久化到数据库；Agent 由 system prompt、memory blocks、消息和工具组成，单次 run 可包含多个步骤。[6] Memory blocks 是持久化且始终注入上下文的结构化区块；可设置大小限制、只读、挂载到多个 Agent，并由 Agent 工具或开发者 API 修改。[7]

Letta 的 archival memory 是按语义检索的长期数据库，Agent 主要插入和搜索，开发者可通过 SDK 更新或删除。官方明确区分：频繁变化状态应使用 memory blocks，长期参考资料才使用 archival memory；归档内容不应被误当作始终可见的当前状态。[8] 这提供了 Northstar 一个有用的分层：M0 可保留结构化的 run state、policy revision、worktree identity、预算剩余量和待批准动作；M1 再考虑只读项目事实索引。它不应把“Agent 可修改自身记忆”当作权限来源。

状态需谨慎标注：当前 `letta-ai/letta` 仓库 README 指向 `letta-code` 作为活跃源码，并称 Letta Cloud 可跨设备保留 memory、identity 和 conversation；上述 V1 SDK 页面本身标作 legacy。[9][6] 因此，核心记忆块/归档记忆是可核验的公开机制，但具体版本、托管能力和当前运行时接口应在集成前锁定版本并做本地测试，不能把历史文档当作当前产品承诺。

### Mem0：应用侧 add/search 与可追溯记忆变更

Mem0 官方文档把自己定位为应用与模型之间的记忆层：应用在响应后调用 `add`，在下一次模型调用前调用 `search`，应用决定把哪些返回结果放进 prompt。默认保存抽取后的事实而不是原始 transcript，并支持按 `user_id`、`agent_id`、`run_id` 与 metadata 进行作用域过滤。[10]

其官方流程包括相关记忆查找、LLM 事实抽取、去重/embedding、实体抽取和检索排序；文档明确说自动抽取是 additive，修正或删除应使用显式 update/delete，并建议不要保存 secrets、原始凭据或未脱敏敏感数据。[10] Mem0 的 history API 进一步返回某条 memory 的输入、旧值、新值、ADD/UPDATE/DELETE 事件、session_id 和时间戳，可作为记忆变更审计的参考。[11]

Mem0 仓库 README 的 benchmark 表格必须降级为营销/实验性主张：它明确写明分数来自包含 proprietary optimizations 的 managed platform，OSS SDK 不会得到完全相同的结果；同时 README 叙述了新的 ADD-only 算法。[12] 这些结果不能支撑 Northstar 的代码正确性或安全性结论。Mem0 适合作为可选的事实记忆组件，不适合作为 run history、权限状态、预算账本或完成证据的唯一来源。

## 与 Northstar M0/M1 的差距或互补

**Northstar 已有而这些项目没有直接替代的部分：** Run Contract 将结构验证、身份认证、授权、执行和后置验证分开；模型产出的 ToolCall 只是提案；工具效果在 in-flight 情形通过接收方幂等键诚实地处理“可能重发”；独立 verifier 只在观察到实际状态和测试结果后签发 verified receipt。[1] 这些是面向受治理编程任务的安全与证据闭环，不应被通用 workflow 或 memory 产品的“durable”标签覆盖。

**M0 的可验证差距：** 需要把恢复状态正式投影为操作员可读的状态机（例如 `running`、`awaiting_authorization`、`awaiting_correction`、`verifying`、`finished`），并为每个状态绑定事件、期限、允许的下一动作和审计引用。Temporal 的 Signal/等待模式和 Inngest 的 wait/checkpoint 说明了如何不轮询地停车，但 Northstar 仍需自己把 Signal/event 映射到已认证的授权请求。[3][4] 另一个差距是稳定步骤 ID 与版本迁移规则；Inngest 的稳定 ID 警告可直接转化为 Northstar 的 step schema/version 规则。[5]

**M1 的可验证差距：** 记忆目前不应阻塞真实仓库闭环；若引入，应先做作用域明确、默认只读的项目事实存储，并将其与 append-only run history 分离。Letta 的 core/archival 分层、只读块和共享块是有启发的；Mem0 的显式 update/delete、作用域过滤和 history API 可借鉴为 memory adapter 接口。[7][8][10][11] 但二者都不能替代 worktree 快照、补丁、测试输出、签名回执和 host-owned evidence。

## 结论：可采纳、拒绝、待证

### 可采纳

1. **有界重试后停车并等待明确授权。** 借鉴 Temporal 的 correction/approval 状态机；等待必须可查询、有超时、有操作者身份、有审计事件，不能由 Agent 自行批准。[3]
2. **稳定步骤 ID + 检查点 + 幂等效果键。** 借鉴 Inngest 的步骤模型，但保留 Northstar 的 ActionGateway、ToolEffectLedger 和 receiver dedup 约束。[5]
3. **把执行记忆与事实记忆分离。** Run/step/event/checkpoint/evidence 是不可替代的事实来源；项目偏好或长期参考信息另存，并带 workspace、actor、run 等作用域。[1][10]
4. **只读、限长的当前上下文块。** Letta memory block 的只读、size limit 和显式 attach 适合作为项目政策/任务摘要的接口设计，而不是让模型拥有策略写权限。[7]
5. **记忆变更历史。** Mem0 history 的 old/new/event/time 结构可作为 adapter 的审计字段参考，但必须进入 Northstar 自己的 evidence policy，不能只依赖第三方日志。[11]

### 拒绝

- 拒绝把任何平台宣传的 durable/exactly-once 当作副作用的通用保证；官方 Inngest 文档已明确外部调用可能重复，Northstar 必须要求接收端幂等。[5]
- 拒绝让可写 Agent memory 改变权限 grant、预算上限、worktree 身份、验证结果或 evidence completeness；这些必须由 host/runtime 和独立 verifier 控制。[1][7]
- 拒绝用向量记忆或摘要替代 append-only 执行历史、原始工具结果引用、补丁和测试证据；相似度检索不可证明“发生过”。[8][10]
- 拒绝 M0 引入无限自治循环、无期限重试、无人工边界的跨仓库记忆共享。共享块/跨用户作用域必须默认关闭，除非有明确授权和可审计的生命周期。[7][10]

### 待证

- Temporal 或 Inngest 在 Northstar 的本地、离线、单机和受限 sidecar 环境中的运维成本、取消传播和证据完整性，需用真实仓库 fault-injection 测试验证；官方文档不足以证明适配。[2][4]
- Letta 当前 `letta-code` 运行时与 legacy V1 memory API 的兼容边界、导出/迁移和并发写入语义，需锁定版本后验证。[6][9]
- Mem0 OSS 在 Northstar 所需的本地部署、删除/保留策略、敏感数据脱敏、检索误召回率和离线可复现性，不能用 managed benchmark 代替。[10][12]
- “记忆写入”是否应进入 M1，取决于真实任务基准：先测它是否减少重复读取且不污染权限/证据；没有该基准前不应扩大范围。

## M0/M1 建议的最小闭环

M0 只增加一个本地 durable state projection：每个 step 记录稳定 ID、输入 digest、授权 grant digest、attempt、started/completed/failed、幂等 key、输出 artifact refs 和下一状态。失败后只允许三种路径：有界重试、等待经过认证的纠正/批准、或失败并生成证据包。M1 再增加一个独立 memory adapter，默认只读、按 workspace/run/actor 作用域隔离，显式 add/update/delete，所有变更引用原始事件；检索结果只能作为上下文建议，不能成为授权或完成判断。

## References

[1]: https://github.com/FNY666/northstar-agent-os "Northstar Agent OS repository"
[2]: https://temporal.io/blog/what-is-durable-execution "The definitive guide to Durable Execution"
[3]: https://docs.temporal.io/design-patterns/resumable-activity "Resumable Activity (AKA Pause On Failure)"
[4]: https://www.inngest.com/docs/durable-execution/durable-workflows "Durable Workflows"
[5]: https://www.inngest.com/docs/durable-execution/primitives "Primitives and steps"
[6]: https://docs.letta.com/v1-sdk/concepts/stateful-agents/ "Introduction to Stateful Agents"
[7]: https://docs.letta.com/v1-sdk/memory/memory-blocks/ "Memory blocks (core memory)"
[8]: https://docs.letta.com/v1-sdk/memory/archival-memory/ "Archival memory"
[9]: https://github.com/letta-ai/letta "Letta repository"
[10]: https://docs.mem0.ai/core-concepts/how-it-works "How Mem0 Works"
[11]: https://docs.mem0.ai/api-reference/memory/history-memory "Memory History"
[12]: https://github.com/mem0ai/mem0 "Mem0 repository"
