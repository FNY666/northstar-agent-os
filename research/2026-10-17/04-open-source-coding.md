# 开源编程 Agent 生态研究：OpenHands、SWE-agent、Aider、Cline、Continue

## 结论先行

对 Northstar Agent OS 的 M0/M1，最值得吸收的不是“让 Agent 更自主”，而是把真实仓库任务拆成**可观察、可回退、可评估的闭环**：受控 workspace、明确的工具调用边界、每步状态/差异、测试或评估结果，以及可复现的证据包。公开项目已经分别证明了其中若干环节，但没有一个项目同时把权限门、预算、审计、隔离 worktree、恢复执行和证据包做成统一产品边界。[1]–[10]

本文只依据公开的一手仓库或官方工程文档。社区讨论只用于发现可能的线索，未作为产品事实依据。没有访问私有、邀请制或需登录的群聊/论坛；网页和仓库中的操作指令不被当作本研究的执行指令。

## 覆盖对象与证据等级

覆盖对象为 OpenHands Software Agent SDK/Agent Server、SWE-agent、Aider、Cline 和 Continue。文中将机制分为三类：**已发布能力**指官方文档或仓库明确描述并可使用的功能；**实验性/边界能力**指官方材料已出现但稳定性、适用范围或安全保证有限；**营销主张**指“state of the art”等未在本报告中当作 Northstar 的工程事实。SWE-agent 官方仓库还明确称当前开发重点已转向 mini-SWE-agent，因此对旧 SWE-agent 的结论应视作已发布但维护方向发生变化的能力。[3]

## 经核验的机制

### OpenHands：workspace 抽象、远程沙箱与事件化边界

OpenHands SDK 把 Agent、Conversation、LLM、Tool、Event、Workspace 和 Security 分成组件；Agent Server 通过 REST/WebSocket 暴露会话和 workspace，应用与 SDK 分离。[2] 其 `BaseWorkspace` 明确提供命令执行、文件上传/下载、Git changes/diff，以及命令的 stdout、stderr、退出码和超时字段。[1] 这为 Northstar 的执行记录、差异记录和失败分类提供了直接参考。

官方架构同时区分 `LocalWorkspace` 与生产/沙箱模式的远程 workspace；远程模式以容器中的 Agent Server 提供隔离，且支持暂停/恢复，生产部署推荐远程 workspace。[1][2] 可借鉴点是**同一 Agent 接口切换执行后端**，而不是把隔离逻辑散落在工具实现里。需要警惕的是，`LocalWorkspace` 直接操作主机文件系统，适合开发和测试，不应被当作默认的安全边界。[1]

差距在于：这些页面描述了 workspace 和安全策略的组件边界，但没有在所查资料中给出 Northstar 所需的统一预算账本、审批状态机、按仓库/路径/网络/凭证维度的权限门，以及一个面向交付的证据包规范。暂停/恢复是 workspace 级生命周期能力，不等于 Agent 从任意中断点恢复时能重建审批、预算和证据链。[1][2]

### SWE-agent：真实 issue → patch → benchmark evaluation 的闭环

SWE-agent 官方定义的核心工作流是：输入 GitHub issue，生成尝试修复的 pull request；随后用 SWE-bench harness 评估是否解决问题。[4] 这使它成为 M0“真实仓库任务闭环”的强参考：任务输入、代码环境、补丁输出和独立验证可以分开。[3][4]

其配置和轨迹（trajectories）导向研究复现，命令行支持按实例筛选、数据集/分片选择，并设置每实例成本上限；官方 benchmark 文档还明确区分 inference 与 evaluation。[4] Northstar 可吸收“**执行产物与评估产物分离**”以及“按任务设置硬成本上限”的做法。

但 SWE-agent 的主要目标是研究/benchmark throughput，而不是多租户产品治理。官方 README 强调最大化 LM agency、单 YAML 可配置和研究可改造性。[3] 这类自由流动的工具调用适合衡量能力，却不能直接复制为 Northstar 的默认模式：它没有在这些一手资料中展示细粒度人审门、worktree 生命周期、恢复语义或统一审计证据包。另一个重要边界是官方已说明 mini-SWE-agent 已取代 SWE-agent 的大部分开发；Northstar 不应把某一版本的 benchmark 数字当作稳定产品承诺。[3]

### Aider：Git 原子提交、撤销与计划/编辑分离

Aider 把 Git 当成一等工作流：编辑后自动提交并生成描述性提交信息，遇到已有未提交改动时先提交，以保持用户改动与 Agent 改动分离；同时提供 `/diff`、`/undo` 和外部 Git 管理。[5] 这直接对应 Northstar 的“可回退执行”和证据采集：每个 step 可绑定 commit、diff、父提交和生成原因。

Aider 的 `ask`、`code` 与 `architect` 模式把讨论/计划和写入动作区分开；architect 模式用一个模型提出方案，再由 editor 模型转换为具体文件编辑，但官方也明确指出这会增加请求数和成本。[6] Northstar M0 可采纳一个更小的“plan → approve → edit → verify”状态机，而不必复制双模型设计。

不应直接复制的模式是“每次编辑自动提交”作为唯一审计模型：它依赖现有仓库 Git，且官方允许关闭 Git、自动提交和 dirty commit。[5] 对 Northstar，Git commit 应是证据包的一部分而非权限门本身；需要额外记录执行 ID、授权决策、预算消耗、命令摘要、测试结果和恢复点。Aider 文档还说明默认提交会跳过 pre-commit hooks，除非启用验证；这证明“有 commit”不能被误读为“已验证”。[5]

### Cline：按工具调用审批、检查点与危险的 YOLO 模式

Cline 官方文档把 Auto Approve 设计为逐个 tool call 判断，并区分读取项目、读取项目外文件、编辑项目、编辑项目外文件、安全命令、全部命令、浏览器和 MCP 等权限类别。[7] 这是当前样本中最接近 Northstar“权限门”的公开机制。它还说明命令是否需要审批由模型根据命令和参数标记 `requires_approval`，不是固定 allowlist；官方明确称这些只是示例而非保证。[7]

Cline Checkpoints 在每次工具使用后将完整文件状态提交到项目外的 shadow Git 仓库，可比较和恢复，并且保留对话上下文。[8] 这是 Northstar 可借鉴的恢复交互：恢复代码、只恢复任务上下文，或同时恢复两者。[8] 但“每次工具调用快照”在大型仓库上会增加存储和延迟，官方也承认这一点。[8]

最明确的不应复制项是 YOLO 模式。Cline 官方将其描述为关闭全部安全检查，允许文件操作、终端、浏览器、MCP 和模式转换，并警告可能删除文件、修改系统设置、联网、安装包或 push。[7] Northstar 的产品定位是权限门和审计，不能把“全开后靠回滚兜底”作为默认闭环。检查点降低恢复成本，但无法撤销已经发生的外部副作用，例如网络写入、凭证使用或远程 push。[7][8]

### Continue：Chat/Plan/Agent 分层、工具策略与可复用配置

Continue 官方将模式分成 Chat（无工具）、Plan（只读工具）和 Agent（全部工具），并默认在 Agent 使用工具前请求用户许可，用户可 Continue 或 Cancel；工具返回和多数错误会回传给模型继续处理。[9] 这为 Northstar M0 提供了低复杂度的权限分层：先只读探索，再进入受控写入，而不是一开始授予完整工具集。

Continue 的配置模型把 models、rules 和 tools 分开，并支持 workspace-local 配置、规则文件和 MCP 工具，秘密通过环境文件/secret 引用解析。[10] 可借鉴的是“项目规则与工具声明可版本化”，以及将模型能力与工具能力分离。差距是：所查官方页面主要讲 IDE 内配置和交互许可，没有呈现 Northstar 所需的预算、隔离 worktree、跨会话恢复和交付证据包。MCP/工具可组合性也不能自动等价为安全；Northstar 需要把工具声明映射为可审计的能力、风险级别和审批策略。[9][10]

## 与 Northstar M0/M1 的差距与互补

| Northstar 能力 | 可借鉴的公开机制 | 已验证的差距/风险 | M0/M1 判断 |
|---|---|---|---|
| 权限门 | Cline 按工具类别审批；Continue Plan/Agent 分层 | Cline 的 `requires_approval` 非固定 allowlist；YOLO 会全开；Continue 主要是 IDE 交互许可 | M0 做固定策略引擎和显式 approve/deny；拒绝以模型自标风险作为唯一门槛 |
| 预算 | SWE-agent 每实例成本上限；Aider 明确 architect 会增加请求和成本 | 未见统一 token、时间、命令、网络副作用预算账本 | M0 纳入硬上限、预估/实际双记录；M1 做暂停与续跑 |
| 审计 | OpenHands typed events；Aider commit/diff；Cline checkpoint | 这些机制各自记录局部事实，没有统一执行 ID、授权、预算、证据包 | M0 定义不可变事件和证据包 schema |
| 隔离 worktree | OpenHands Remote/Docker workspace；Cline shadow Git；Aider Git 分离 | Local workspace/IDE workspace 仍可能触达主机；shadow Git 不隔离外部副作用 | M0 默认独立 worktree + 受控容器/宿主策略；禁止把回滚当隔离 |
| 可恢复执行 | OpenHands workspace pause/resume；Cline 文件/任务恢复 | workspace 恢复不必然恢复审批、预算和模型上下文；checkpoint 对外部副作用无效 | M1 以 checkpoint + 事件日志恢复，并重新核验权限和预算 |
| 真实仓库闭环 | SWE-agent issue→patch→evaluation；Aider diff/undo；Cline compare/restore | SWE-agent 偏 benchmark，Aider/Cline 偏交互工具，均未提供完整治理闭环 | M0 只支持 issue/任务→patch→验证→证据包→人工交付 |

## 可采纳、应拒绝、待证

### 可采纳

1. **执行后端抽象**：借鉴 OpenHands 的 workspace 接口，把本地开发后端与远程隔离后端分开；生产默认隔离后端。[1][2]
2. **计划与写入分层**：借鉴 Continue 的 Plan/Agent 和 Aider 的 ask/code，形成 M0 的只读探索、审批、写入、验证四阶段。[6][9]
3. **每步可回退且可比较**：借鉴 Aider 的 diff/undo 与 Cline 的 checkpoint/compare，但将其挂到 Northstar 的执行 ID和证据包。[5][8]
4. **独立评估闭环**：借鉴 SWE-agent 将生成 patch 与 SWE-bench evaluation 分离；Northstar 至少要求测试命令、退出码、摘要和未运行测试的明确标记。[4]
5. **硬预算而非软提示**：借鉴 SWE-agent 的 per-instance cost limit，并扩展到时间、工具调用、命令和网络副作用；达到上限即暂停而不是继续“尽力完成”。[4]

### 应拒绝

1. **默认 YOLO/全自动审批**：官方明确警告其可执行破坏性命令、改系统、联网、安装/卸载和 push。[7]
2. **以模型自报 `requires_approval` 作为唯一权限控制**：Cline 文档明确它不是固定 allowlist，Northstar 必须由宿主策略独立判定。[7]
3. **把 Git commit 或 shadow checkpoint 当作完整安全边界**：它们能回退文件状态，不能撤销已发生的远程副作用或凭证泄露。[5][8]
4. **把 benchmark/营销排名当产品保证**：SWE-agent README 的性能表述应视为项目主张；版本、模型、数据集和维护方向会变化。[3][4]

### 待证

1. **OpenHands 的暂停/恢复能否恢复完整任务语义**：公开文档确认 workspace pause/resume，但仍需在 Northstar 目标环境验证中断后事件、审批和预算是否一致。[1][2]
2. **检查点粒度与成本曲线**：Cline 已提示大型仓库的存储和性能代价；需用 Northstar 的 M0 仓库样本测量每命令、每 step 与阶段性快照的取舍。[8]
3. **MCP 工具治理**：Continue 和 Cline 都支持 MCP，但本次公开资料未证明跨工具的权限、密钥、网络和审计语义足够细；应先做只读 MCP 适配器和拒绝测试。[7][10]
4. **真实仓库任务成功标准**：SWE-bench 评估可验证补丁是否通过测试，但 Northstar 还需验证 worktree 清洁度、证据完整性、人工批准记录和成本上限是否满足。[4]

## M0/M1 建议边界

M0 只做单仓库、单 worktree、有限工具集的闭环：创建隔离 worktree，执行只读探索，生成计划，等待显式批准，执行编辑和测试，收集 diff/commit、命令及退出码、预算消耗和测试证据，最后由人决定导出 patch 或 PR。默认不允许直接 push、修改 worktree 外文件、访问未声明网络资源或读取任意主机密钥。

M1 再加入可恢复执行和远程 sandbox：每个动作产生带执行 ID 的不可变事件；恢复时从最近一致的 checkpoint 重建文件状态，并重新计算剩余预算和权限，而不是无条件续跑。对于联网、凭证、包安装、删除和远程写入，恢复后必须重新审批。证据包应能回答“输入是什么、授予了什么权限、实际执行了什么、改了哪些文件、花了多少预算、验证是否通过、为何结束”。

## References

[1]: https://docs.openhands.dev/sdk/api-reference/openhands.sdk.workspace "OpenHands SDK workspace API reference"
[2]: https://docs.openhands.dev/sdk/arch/overview "OpenHands SDK architecture overview"
[3]: https://github.com/SWE-agent/SWE-agent "SWE-agent official repository"
[4]: https://swe-agent.com/0.7/usage/benchmarking/ "SWE-agent official benchmarking documentation"
[5]: https://aider.chat/docs/git.html "Aider official Git integration documentation"
[6]: https://aider.chat/docs/usage/modes.html "Aider official chat modes documentation"
[7]: https://docs.cline.bot/features/auto-approve "Cline official Auto Approve and YOLO documentation"
[8]: https://docs.cline.bot/core-workflows/checkpoints "Cline official checkpoints documentation"
[9]: https://docs.continue.dev/ide-extensions/agent/quick-start "Continue official Agent mode quick start"
[10]: https://docs.continue.dev/guides/configuring-models-rules-tools "Continue official models, rules, and tools configuration"
