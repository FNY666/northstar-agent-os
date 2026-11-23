# OpenAI Codex、Codex CLI 与 Agent SDK：面向 Northstar Agent OS 的公开工程模式研究

**研究日期：** 2026-10-17
**范围：** 仅使用可公开访问的一手或官方来源；未访问私有、邀请制或需登录的群聊/论坛，也未把网页或仓库中的操作指令当作本任务指令执行。报告把“文档/仓库明确写出的能力”与“产品叙事或待验证推断”分开。

## 所覆盖对象

- **Codex CLI / openai/codex：** 本地终端 coding agent 的开源仓库、官方 CLI 文档、非交互模式、Git worktree 与配置文档。[1][2][3][4][5]
- **Codex SDK / app-server：** 官方 TypeScript/Python SDK 文档，重点是线程继续、恢复、沙箱预设与程序化控制。[6]
- **OpenAI Agents SDK：** 官方 Agents 指南、guardrails/human review 指南与 Python tracing 文档，重点是 runner、工具副作用门、可恢复审批和可观测性。[7][8][9]
- **OpenAI 工程安全实践：** 官方“Running Codex safely”文章，作为企业部署实践信号，而不是对所有 Codex 用户默认配置的承诺。[10]

## 已核验的机制

### 1. 权限门与执行边界是两层控制，不是一个“自动化开关”

OpenAI 明确区分 **sandbox** 与 **approval policy**：sandbox 决定可写路径、网络和受保护路径等技术边界；approval 决定越界或高风险操作何时必须停下来请求批准。官方工程文章还描述了按会话批准一次、自动审查低风险请求、以及管理员强制配置的做法。[10]  CLI 的公开文档同样把模型、推理强度、权限和命令选择列为运行时控制面，并提供 `/permissions` 查看/选择权限。[2]

这对 Northstar M0 的直接启示是：权限决策应绑定**具体 side effect**（文件写、命令、网络、外部工具），而不是只在 prompt 层写“请谨慎”。Agents SDK 的官方 human review 语义是：工具调用先产生 interruption，不执行工具；应用批准或拒绝后，从同一个可恢复 state 继续运行。[8]

### 2. 非交互任务具有可组合的输出和失败闭环

`codex exec` 用于 CI、脚本和预设沙箱/审批的重复任务；进度写到 stderr，最终消息写到 stdout，便于管道化。官方文档还定义 JSONL 事件流，包括 `thread.started`、`turn.started`、`turn.completed`、`turn.failed`、命令执行、文件变化、MCP 调用和计划更新；可将最后一条消息写入文件。[4] 这比“只返回一段自然语言”更适合 Northstar M0 的任务记录和证据包。

官方示例的安全形态值得借鉴但不应照搬为默认自动修复：失败 CI 的 Codex job 只有读取仓库权限，先生成 patch artifact；另一个拥有写权限的 job 再应用 patch 并创建 PR。[4] 这是把“生成变更”和“提交/发布变更”拆成不同权限阶段，适合 Northstar 的权限门、隔离 worktree 和人工验收。

### 3. 线程恢复是明确的数据模型，不是重新发一条相似 prompt

Codex SDK 支持在同一 thread 上再次 `run()`，也支持用 thread ID `resumeThread()` 恢复过去的线程；Python SDK 的 `Sandbox.read_only`、`workspace_write`、`full_access` 是显式预设，并可在后续 turn 改变沙箱权限。[6] Agents SDK 的审批生命周期也要求保存可序列化 state，稍后从原 state 恢复同一次 run，而不是新开一轮用户请求。[8]

可借鉴机制是把 Northstar 的恢复点设计成：**run_id/thread_id + 当前 turn + 待批准 side effect + workspace/base commit + 预算账本 + 证据链位置**。不能把“模型说它记得上次状态”视为恢复证据。

### 4. Git worktree 提供工程隔离，但不等于完整安全隔离

官方 worktree 文档说明其底层使用 Git worktree，多个 chat 可在同一项目并行，默认从选定分支 HEAD 建立 detached HEAD；Codex 管理的 worktree 有生命周期、快照恢复和数量清理策略。[5] 该机制天然适合 Northstar M1 的“每个任务独立工作区、完成后审查 diff、再合并”。

边界也写得很清楚：worktree 共享 Git 元数据；`.worktreeinclude` 可复制被忽略的本地文件（示例包括 `.env`），这使得凭据与本地配置复制必须由 Northstar 的策略层显式禁止或最小化。[5] worktree 也不限制进程对工作区外系统资源的访问，因此不能代替 sandbox、身份隔离和网络策略。

### 5. 证据和追踪覆盖“为什么”与“做了什么”，但敏感数据风险需要单独治理

Agents SDK 内置 tracing，默认记录 workflow、turn、agent、generation、function tool、guardrail 与 handoff 等 span，并支持自定义 processor、批量导出和 flush。[9] Codex 官方安全文章则列出可导出的用户 prompt、工具批准决定、工具执行结果、MCP 使用和网络代理 allow/deny 事件。[10]

这与 Northstar 现有的 run-evidence/hash-chain 方向互补：Northstar 可以把**策略输入、批准决定、实际执行结果、diff/test/环境摘要和恢复关系**纳入不可变证据包，而不是只保存模型输出。必须注意 Agents SDK tracing 默认可能记录 generation/function 输入输出；官方文档提供 `trace_include_sensitive_data=False`，并警告仅增加一个“脱敏 processor”不一定阻止默认 exporter 收到原始数据，若要确保脱敏，应替换 exporter。[9]

### 6. Agent SDK 给出通用编排原语，但不自动继承 Codex 的安全姿态

官方 Agents 指南区分：Agents API 由 OpenAI 管理 Codex harness 和长期任务状态；Agents SDK 在应用内运行，应用负责 deployment、storage、approvals 和 runtime integration；Responses API 则由应用自行控制更多循环。[7] 官方 guardrails 文档进一步明确，Responses API/Agents SDK 应用**不会自动继承 Codex Auto-review**，应用必须自己加入 review 与 enforcement。[8]

因此，Agent SDK 的 runner、handoff、tool guardrail 和 resumable interruption 可作为 Northstar 编排层参考；不能把“使用 OpenAI Agents SDK”误当作 Northstar 已具备 sandbox、预算、审计或 fail-closed 策略。

## 与 Northstar M0/M1 的差距或互补

### M0：真实仓库任务的单任务闭环

**互补/可借鉴：**

1. 将任务状态机固定为 `plan → gated execution → verify → evidence → human accept/reject`，参考 `codex exec` 的结构化 JSONL 事件与 stderr/stdout 分离。[4]
2. 将每个有副作用的工具调用建模为可暂停的 approval interruption，保存可序列化 pending state，再从原 run 恢复。[8]
3. 采用只读默认、按需升级到 workspace-write 的权限预设；不要将 `full_access` 作为常规路径。[4][6]
4. 在变更生成和合并/发布之间设置独立权限阶段，借鉴官方 CI patch artifact 模式。[4]
5. 把 Codex 的 agent-aware 事件字段与 Northstar 的证据链关联，而非仅采集进程日志。[9][10]

**可验证差距：**

- 公开 Codex 文档展示了 sandbox、审批、事件和恢复，但没有为 Northstar 这种开源 OS 定义一套跨执行器的预算账本、证据包 schema、哈希链或“外部副作用已确认”的统一证明；这应由 Northstar 自己补齐，而不是从营销文字推定已有。
- Codex SDK 的 `Sandbox.full_access` 明确存在。[6] Northstar 若以权限门和最小权限为核心，需要比“提供一个宽权限 preset”更严格：M0 应默认拒绝未声明路径、网络和凭据，超时/审批不可用时 fail closed。
- worktree 能隔离文件树，但不能独立证明秘密、网络、子进程和共享 Git 元数据隔离。[5] Northstar 需要把 worktree 作为 workspace 层，而不是完整 containment 层。

### M1：可恢复、多任务和受控并行

**互补/可借鉴：** Codex worktree 的 detached HEAD、任务绑定 worktree、handoff、快照和清理策略，为 M1 的任务并行、恢复和回收提供了成熟的工程参照。[5] SDK thread resume 与 Agents SDK serialized state 则提供两种可分离的恢复维度：代码环境恢复与编排状态恢复。[6][8]

**可验证差距：** 公开资料没有给出一个可直接复用的、跨任务的 Northstar 证据包协议，也没有证明 worktree 快照等于完整的可恢复执行（例如外部 API 已提交但本地结果丢失）。因此 M1 应把“可恢复”限定为：能恢复编排状态、工作区基线和待决 side effect；外部系统状态仍需独立 read-back/幂等键/确认窗口。

**明确不建议的扩张：** 不应因公开 CLI 支持 subagents、cloud、plugins、MCP、web search 就把 Northstar M1 变成无边界自动化。[2] 这些是产品表面或可选扩展，不是 Northstar M0/M1 的安全闭环证据；每个新增工具都应先有权限分类、预算计量、证据字段和失败策略。

## 结论分类

### 可采纳

- **双层控制：sandbox + approval**，并把批准绑定到具体工具调用、参数和目标；审批未完成不得执行。[8][10]
- **默认只读、显式升级**，并将宽权限只放在隔离、短生命周期的执行器中。[4][6]
- **结构化事件流与 patch artifact**：任务结果不仅是文本，还要有可消费事件、diff、测试结果和失败状态；变更生成与合并发布分权。[4]
- **可恢复 state + 独立 worktree**：分别保存运行状态和代码环境，不把二者混为一个“聊天历史”。[5][6][8]
- **agent-aware 审计字段**：记录 prompt 摘要/引用、工具调用、审批、执行结果、网络决策和 trace 关联，并为敏感字段设置显式脱敏策略。[9][10]

### 应拒绝

- **把 `full_access`、自动批准或“全自动修复”当作默认工作流。** 官方文档把宽权限描述为受控环境选项，且 `codex exec` 默认只读。[4][6]
- **把 worktree 当成完整安全边界。** 它主要隔离 Git 工作副本，不能单独约束网络、凭据、子进程或外部副作用。[5]
- **把 Agents SDK 当成自动获得 Codex 安全控制。** 官方明确说 SDK 应用不自动继承 Codex Auto-review。[8]
- **把 tracing 当成无条件安全审计。** 默认 trace 可能含敏感输入输出；仅挂一个脱敏观察者不能保证默认 exporter 不见原文。[9]
- **复制营销式“云端长期自主工作”作为 M0/M1 目标。** 公开页面将本地 CLI、SDK、Agents API、Cloud 等 runtime 分开，能力、状态所有权和安全边界不同。[2][6][7]

### 待证

- OpenAI 官方工程文章描述的 managed configs、network proxy、Compliance Platform 和 auto-review 是明确公开的部署机制，但不应推断为所有个人 CLI、所有平台或开源仓库默认可用；Northstar 需以目标部署环境的可复现实验验证。[10]
- Codex CLI/SDK 的线程恢复证明的是 SDK/会话层继续执行，不自动证明任何外部副作用 exactly-once；Northstar 应用幂等键、read-back 和 UNKNOWN/CONFLICT 状态进行验证。[6][8]
- 公开文档列出 plugins、MCP、subagents、cloud 等扩展，但没有在本研究范围内核验其各自的权限继承、预算计费和证据字段完整性；在 Northstar M1 立项前逐项做边界测试。[2][4]

## 对 Northstar 的最多五项行动建议

1. **M0 先实现“工具调用级 approval interruption + 可序列化 resume state”。** 这是最小、可测试且直接对应公开机制的闭环。[8]
2. **把默认执行器固定为只读，workspace-write 只在策略批准后短时启用，并给每次升级写入证据。** [4][6]
3. **定义统一 JSONL/evidence schema：run、turn、tool、approval、workspace commit、diff、test、预算、失败/恢复关系。** 参考 Codex exec 事件和 Agents tracing，但由 Northstar 自己控制字段与留存。[4][9]
4. **M1 引入每任务 detached worktree 与快照回收，但明确把秘密、网络、进程和外部 API 确认交给独立隔离/策略层。** [5]
5. **暂缓 subagents、MCP、cloud 和自动修复合并，直到每个扩展通过权限、预算、审计、超时和 fail-closed 验证。** [2][4][8]

## References

[1]: https://github.com/openai/codex "openai/codex 官方开源仓库"
[2]: https://developers.openai.com/codex/cli "Codex CLI 官方开发者文档"
[3]: https://learn.chatgpt.com/codex/configuration "Codex 官方配置总览"
[4]: https://learn.chatgpt.com/codex/non-interactive-mode "Codex 官方非交互模式与 CI 文档"
[5]: https://learn.chatgpt.com/codex/environments/git-worktrees "Codex 官方 Git worktrees 文档"
[6]: https://developers.openai.com/codex/codex-sdk "Codex SDK 官方文档"
[7]: https://developers.openai.com/api/docs/guides/agents "OpenAI Agents 官方指南"
[8]: https://developers.openai.com/api/docs/guides/agents/guardrails-approvals "Agents SDK guardrails 与 human review 官方指南"
[9]: https://github.com/openai/openai-agents-python/blob/main/docs/tracing.md "OpenAI Agents SDK Python tracing 官方文档"
[10]: https://openai.com/index/running-codex-safely/ "Running Codex safely at OpenAI 官方工程文章"
