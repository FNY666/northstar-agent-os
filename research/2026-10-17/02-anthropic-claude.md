# Anthropic Claude Code、Claude Agent SDK 与公开工程模式研究

**研究日期：2026-10-17**
**面向：Northstar Agent OS 的 M0/M1 真实仓库任务闭环**

## 所覆盖对象

本报告核验了六类公开对象：Claude Code 官方 Hooks 与设置规范；Claude Agent SDK 总览、权限和会话文档；官方 Python SDK 仓库；Anthropic 的 Claude Code 沙箱工程文章；Anthropic experimental `sandbox-runtime` 仓库；以及 Claude Code GitHub Actions 官方文档。社区帖子只被视为发现线索，本报告没有用私有、邀请制或需登录的群聊/论坛，也没有把社区内容作为产品事实依据。

“已发布”表示官方文档或仓库明确提供并有接口/配置说明；“实验性”表示官方明确标注 beta、research preview 或 API 可能变化；“主张”表示官方文章中的内部测量、定位或建议，不能直接等同于 Northstar 可复现能力。网页或仓库中的命令和操作文字仅作为资料内容阅读，没有在本研究中执行。

## 经核验的机制

### 1. 权限门是分层决策，不是单一 allowlist（已发布）

Agent SDK 的工具请求按顺序经过 Hooks、deny 规则、ask 规则、permission mode、allow 规则和 `canUseTool` 回调。[1] `allowed_tools` 只是自动批准匹配工具，并不会从模型工具集中删除未列出的工具；`disallowed_tools` 才能删除工具或对特定调用作永久拒绝。[1] 官方规范还明确指出，Hook 的 `allow` 不会跳过后续 deny/ask 规则，因而更接近“可组合的政策流水线”而非一个宽松的白名单。

这对 Northstar M0/M1 的直接启发是：继续保持宿主拥有最终决策权，把**策略匹配、运行时询问、执行结果**分成可审计阶段。Northstar 已有 host-owned `CodeTask`、独立验证回执、phase journal、证据 manifest 和 detached worktree 生命周期；Claude 的评估顺序可作为兼容适配器的参考，但不能替换 Northstar 自己的权限语义。[6]

差距在于：公开 Claude 规范详细描述工具授权，却没有在这些页面中给出 Northstar 所需的**预算预留、跨子代理累计预算、证据包封存条件**的一体化合同。Northstar 也不应把“工具允许”当作“任务完成”。

### 2. Hooks 提供确定性的生命周期拦截和反馈（已发布）

Claude Code Hooks 可挂接 session、turn 和每次工具调用；`PreToolUse` 可返回 `allow/deny/ask/defer`，`PostToolUse`、`Stop`、`TaskCompleted` 等事件也有不同的阻断语义。[2] Hook 输入包含工具名、工具参数和调用 ID；文档还特别说明 `PreToolUse` 不会覆盖通过 `@` 引用文件时的直接内容注入，不能把它误当成所有数据流的拦截点。[2]

Python SDK 将 Hook 暴露为宿主 Python 函数，官方示例用 `PreToolUse` 按命令模式拒绝 Bash，并将 Hook 定义为由 Claude Code 应用调用、不是模型调用。[3] 这与 Northstar 的“先 schema 校验、再权限回调、再 handler 副作用”的防线相容。[6]

可借鉴的是事件化审计：至少记录 attempted、denied、executed 三种状态，并将拒绝理由和工具调用 ID 关联。应保留 Northstar 已有的证据封存与 redaction 约束，因为 Claude Hook 文档本身并不证明执行结果已形成不可变证据包。

### 3. 权限配置有组织级锁定能力，但配置意图不等于强制隔离（已发布）

Claude 设置规范支持 `permissions.allow/ask/deny`、`defaultMode`、禁止 bypass mode、工作目录外读取阻断，以及 `sandbox`；还支持 managed settings、只允许 managed 权限规则、以及限制插件来源和自定义化来源。[4] 这些机制显示了从个人配置到组织政策的层级化设计。

对 Northstar 而言，值得采用的是**高优先级、不可由工作区自我放宽的宿主策略**：例如 secrets 读取拒绝、外部目录拒绝、工具类别上限和受控插件来源。应拒绝复制“把策略放在仓库内的可修改配置就视为安全边界”的模式；Northstar 的权限与证据目录必须继续由宿主和运行时持有，不能由 agent 可写目录覆盖。

### 4. 沙箱采用文件系统与网络双边界（已发布设计；实现有实验性状态）

Anthropic 工程文章将有效沙箱定义为两个边界：文件系统隔离与网络隔离。文章说明 Claude Code 的 sandboxed bash 使用 OS 原语，子进程也受限，并通过代理控制网络域名。[5] 同文披露“内部使用中减少 84% 权限提示”是 Anthropic 的内部测量，属于营销/工程主张，不是独立复现实验，也不能直接转化为 Northstar 的安全指标。

`anthropic-experimental/sandbox-runtime` 是 Apache-2.0 开源仓库，明确标为 **Beta Research Preview**，并说明 API/配置可能演进。[7] 它支持进程树级文件、网络和 Unix socket 限制；Linux 使用 bubblewrap 与网络命名空间，网络默认经宿主代理；仓库同时列出 Linux 代理可能被不遵守环境变量的程序绕过这一已知限制。[7]

可采纳的是双边界原则和“默认不写、网络 allow-only、敏感路径 deny”的分层模型，适合作为 Northstar M1 的可选执行后端或对照实现。不可复制的是把实验性 runtime 直接当成跨平台、内核级完备隔离，也不可用静态域名 allowlist 证明任务范围内的数据流合规。Northstar 的现有研究基线已经要求把 process-only、seccomp、Landlock、namespace/container 和 network isolation 分开陈述；这比笼统称“sandbox”更适合证据包。[6]

### 5. Agent SDK 重用 Claude Code agent loop、内置工具、Hooks、MCP、子代理和会话（已发布）

官方总览明确：Agent SDK 以库的方式运行 Claude Code binary，提供相同的工具、agent loop、context management、permissions、sessions 和 hooks。[8] Python 仓库进一步说明 CLI 默认随包捆绑；`query()` 返回异步消息流；可配置 `cwd`、工具授权、MCP server、Hook 和错误类型。[3] 这是一种“成熟 CLI 运行时作为库”的公开工程模式，而不是一个只调用模型 API 的薄封装。

对 Northstar M0/M1 的差距是：Claude SDK 已提供通用消息流、子代理、MCP 和会话恢复的产品化入口；Northstar 的优势则在于更明确的任务合同、隔离 worktree、host-owned 验证和证据包。Northstar 不需要复制整个通用 runtime，应优先补齐真实仓库任务的窄闭环：准备任务、在 detached worktree 执行、串行宿主验证、捕获 patch、封存 manifest、清理或保留工作区。

需要警惕 SDK 的 in-process SDK MCP server：官方强调其无 IPC、部署简单和调试方便。[3] 这些是性能/工程便利主张，不是隔离保证。对 M0/M1，含副作用的 MCP/宿主工具仍应放入独立权限与工作区边界，不因同进程而放宽策略。

### 6. 会话恢复只恢复对话，不恢复文件系统快照（已发布且有明确限制）

SDK 会话文档说明 session 持久化的是 prompt、工具调用、结果和响应；`continue`、`resume`、`fork` 可恢复或分叉对话。[9] 文档明确警告：session 持久化的是 conversation，不是 filesystem；分叉历史也不会自动分叉文件修改，文件快照需另用 file checkpointing。[9] 恢复还可因 `error_max_turns` 或 `error_max_budget_usd` 后续继续，但这不等于自动证明此前副作用状态。

这是 Northstar 的关键互补点。Northstar 已将 checkpoint 携带 bounded action history 与 composition-policy digest，并只在策略精确匹配时恢复；对缺失持久化 dataflow 的恢复采取 fail-closed 升级。[6] 因此应**拒绝复制“resume transcript = 可恢复执行”**的简化模式。Northstar 的恢复合同应继续要求证据包、策略摘要、worktree 状态和未决副作用逐项重核验；Claude 的 session ID 可作为会话索引，但不能作为完成收据。

### 7. GitHub Action 展示了有限的仓库闭环，但权限面偏大（已发布）

官方 GitHub Actions 文档区分 interactive mode（由 `@claude` 触发）和 automation mode（由 workflow prompt 自动执行），并要求触发者通常具有仓库写权限、拒绝 bot 触发循环。[10] 示例支持读取问题/提交、生成报告、评论 PR 或提出修改；官方同时要求把 API key 放进 Secrets、按需授予 workflow 权限并在合并前审查变更。[10]

该模式可借鉴为 Northstar 的 M1 外部适配器：输入 issue/PR，映射成一个 host-owned `CodeTask`，在隔离 worktree 中改动，运行独立验证，输出 patch、验证回执和审计链接，最后由人合并。不可复制的是直接采用官方 GitHub App 的完整权限集合：文档列出的安装权限包括 Actions、Contents、Issues、Pull requests、Workflows 等读写能力，且官方承认可建立只覆盖 Action 所需权限的自定义 App。[10] Northstar 应默认最小权限、禁止 agent 直接合并/发布，避免无边界 cron 自动化。

## 与 Northstar M0/M1 的差距和互补

**可验证差距。** Claude SDK 已把通用 agent loop、session、MCP、subagent 和 Hook 做成可调用接口；公开资料没有证明其默认提供 Northstar 要求的不可变证据 manifest、宿主验证收据、独立 worktree 清理/保留合同、策略摘要绑定恢复或跨委托累计预算。相反，session 文档明确把对话恢复与文件恢复分开。[8] [9]

**互补优势。** Claude 的 Hook 决策模型、权限评估顺序、组织级 managed settings 和双边界沙箱为 Northstar 提供可借鉴的接口形状。Northstar 现有 API 已定义 detached task worktree、immutable host task、verification receipts、phase journal、patch capture 和 evidence-preserving cleanup。[6] 这些机制正好约束 Claude SDK 的“运行时能力很强、任务完成证明仍由宿主负责”的空白。

**M0/M1 重点。** M0 应只承诺单仓库、单任务、单隔离 worktree、有限工具集、明确预算、串行验证和可读证据包。M1 再增加受控 resume/fork、有限子代理或 MCP 适配，但每次委托必须继承并收窄权限、预算、工作区和审计上下文。不要把云端 Agent、PR 自动合并、定时无人值守或开放插件市场作为 M0/M1 的必要条件。

## 结论分类

### 可采纳

1. **采纳分层权限评估。** 将 Hook/策略/询问/执行/结果分开记录；拒绝优先级和工具参数规范化应在副作用前完成。[1] [2] [3]
2. **采纳双边界沙箱模型。** 文件系统与网络必须分别声明和验证；`sandbox-runtime` 只能作为实验性后端候选，不作为安全证明。[5] [7]
3. **采纳组织级不可放宽策略。** 借鉴 managed settings、deny/ask/allow 层级，但保持策略和证据由宿主拥有。[4]
4. **采纳有限 PR/issue 适配器。** 仅以任务合同、detached worktree、独立验证和人工合并为闭环。[10]

### 拒绝

1. **拒绝以 SDK session resume 代替文件/副作用恢复。** 官方文档已明确两者不同。[9]
2. **拒绝以 `allowed_tools` 当作完整工具隔离。** 未列工具仍可能可见并进入后续权限流程；需要 deny 或宿主策略。[1] [3]
3. **拒绝将内部“减少 84% 提示”当作 Northstar KPI 或安全证据。** 这是官方内部使用测量/工程主张。[5]
4. **拒绝在 M0/M1 引入全权限 GitHub App、自动合并、无边界 cron 或可自扩展插件市场。** 官方文档本身显示其权限面和 bot/触发风险。[10]
5. **拒绝把 in-process MCP 的性能便利解释为隔离。** 同进程工具仍需独立权限和工作区边界。[3]

### 待证

1. 在 Northstar 的真实仓库基准上测量 Hook/策略层对拒绝、超时、进程崩溃和重试的证据完整性；不能只测模型最终文本。
2. 评估 `sandbox-runtime` 在 Northstar 支持的平台、子进程、符号链接、代理绕过和网络失败路径上的实际强度；尤其验证仓库已披露的 Linux 代理限制。[7]
3. 设计 Claude SDK 作为可替换 provider 时的预算映射：`max_turns`/`max_budget_usd` 是否能与 Northstar 的 reservation、委托累计预算和终止原因一一对应；公开资料不足以证明这种映射。[9]
4. 验证恢复前的 worktree、证据 manifest、策略 digest 与数据流状态是否一致；在证据不足时沿用 Northstar 的 fail-closed 恢复，而不是直接 resume。[6] [9]

## References

[1]: https://code.claude.com/docs/en/agent-sdk/permissions "Claude Agent SDK permissions"
[2]: https://code.claude.com/docs/en/hooks "Claude Code Hooks reference"
[3]: https://github.com/anthropics/claude-agent-sdk-python "Anthropic Claude Agent SDK for Python"
[4]: https://code.claude.com/docs/en/settings-reference "Claude Code settings reference"
[5]: https://www.anthropic.com/engineering/claude-code-sandboxing "Beyond permission prompts: making Claude Code more secure and autonomous"
[6]: https://github.com/FNY666/northstar-agent-os "Northstar Agent OS repository and local runtime/API documentation"
[7]: https://github.com/anthropics/claude-code-sandbox-runtime "Anthropic Sandbox Runtime (srt)"
[8]: https://docs.claude.com/en/api/agent-sdk/overview "Agent SDK overview"
[9]: https://code.claude.com/docs/en/agent-sdk/sessions "Work with sessions"
[10]: https://code.claude.com/docs/en/github-actions "Claude Code GitHub Actions"
