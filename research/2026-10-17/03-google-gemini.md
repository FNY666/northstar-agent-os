# Google Gemini CLI、Jules 与公开工程模式：Northstar M0/M1 研究报告

**研究日期：2026-10-17**

Northstar 当前只做 M0/M1：先固定真实模型、版本、沙箱、网络、预算和容器摘要；在冻结题集上建立真实模型基线；补齐阶段恢复与未知副作用 reconcile；通过离线门槛后再扩展长任务和 Labs。Northstar 的目标不是“让代理一直自动跑”，而是完成真实代码任务，同时证明改了什么、为何获准、如何验证、失败后从哪里继续。[1]

## 所覆盖对象

本次覆盖三类公开对象：

1. **Gemini CLI 开源仓库及官方工程文档**：仓库定位、工具策略引擎、沙箱、Trusted Folders、非交互模式与 MCP/扩展入口。[2][3][4]
2. **Jules 产品与官方文档**：Jules 网页文档、Google 官方产品公告，以及 Jules API。重点看异步任务、计划审批、云 VM、分支/PR 产物、活动记录和 API 自动化边界。[5][6][7]
3. **Jules Tools 官方公告**：命令行作为远程任务的控制面，以及 Gemini CLI 与 Jules 组合的公开示例。[8]

没有访问私有、邀请制或需登录的群聊/论坛。社区材料没有被用来支撑产品事实；本报告的产品事实均来自官方仓库、官方文档、Google 官方博客或 Google Developers 文档。网页中的命令仅作为文档内容读取，未执行。

## 经核验的公开机制

### Gemini CLI：把“工具调用”放进可组合的策略门

Gemini CLI 的 Policy Engine 对工具调用提供 `allow`、`deny`、`ask_user` 三种决策；规则可按工具名、参数正则、命令前缀、MCP server、交互/非交互环境和 approval mode 匹配，并以优先级解决冲突。[2] 对 Northstar 最有价值的不是 TOML 格式本身，而是把授权从模型意图中抽离成可解释的、在执行前评估的决策层。

该引擎还区分 default、autoEdit、plan、yolo 等运行模式，并支持用户与管理员层级。官方文档明确写出：`ask_user` 在非交互环境按 deny 处理；全局 deny 的工具甚至不会提供给模型；而 workspace policy 当前“non-functional”，不会生效。[2] 这既是可借鉴的机制，也是一个重要警示：策略层级必须有运行时自检和启动时证明，不能仅因文件存在就声称治理生效。

**已发布能力**：工具策略、模式化审批、MCP 工具定向规则、管理员策略目录和非交互语义均在公开文档中描述。[2] **待谨慎看待**：文档同时标注 workspace 层目前禁用，因此不能把项目内 policy 文件当作 M0/M1 的强制边界。[2]

### Gemini CLI：多种沙箱与一次性权限扩展

Gemini CLI 官方沙箱文档描述了 Docker/Podman、macOS Seatbelt、gVisor/runsc 和实验性的 LXC/LXD 等后端。容器模式将工作区挂载到容器内相同的绝对路径；默认只围绕当前项目工作区，外部目录可通过显式 mount 指定，且未给出写权限时默认为只读。[3] 文档还描述了 tool-level sandboxing，以及命令因路径或网络限制失败时触发的 Sandbox Expansion Request：用户批准后只对该次运行扩展权限。[3]

这与 Northstar 的“权限门 + 隔离 worktree + 可恢复执行”互补，但不是等价物。Gemini 文档强调降低风险，不声称沙箱消除风险；网络、挂载和自定义 sandbox flags 仍可能扩大攻击面。[3] 对 M0/M1，应借鉴“默认窄、按次扩展、记录扩展原因”，不复制“用户一旦批准就把额外权限当成长期信任”的隐含风险。

### Gemini CLI：项目可信度是配置加载前的门

Trusted Folders 在启用后，会在加载项目级配置前要求信任选择，并扫描命令、MCP server、hooks、skills、设置覆盖等内容。[4] 不信任时，项目设置、`.env`、扩展管理、工具自动接受、自动记忆加载、MCP 连接和自定义命令都会被禁用。[4] 这是一种很实用的“配置即代码执行面”防护：不只限制 shell，还限制会改变代理行为的项目内容。

但该功能官方标注为默认禁用；headless 环境还可通过 `--skip-trust` 或环境变量绕过当前会话的信任检查。[4] 因此它适合成为 Northstar admission 的参考，不适合直接作为 Northstar 的安全保证。Northstar M0/M1 应将“信任声明、发现摘要、会话范围、绕过理由”写入审计事件，并在无交互时 fail closed，而不是把 bypass 当普通配置。

### Jules：把任务拆成计划、执行、审阅和 PR 产物

Jules 官方文档称其为 **experimental coding agent**。它接入 GitHub 仓库，在虚拟机内 clone 代码、安装依赖和修改文件；用户先提交任务并点击“Give me a plan”，计划可在代码修改前审阅和批准。[5] Google 的公开 beta 公告进一步描述了异步执行、云 VM、分支/ GitHub 工作流、计划与 reasoning、diff、用户在执行前后 steer，以及并行任务。[6]

这些材料支持一个清晰的任务闭环：**输入仓库与分支 → 计划 → 用户批准/反馈 → 隔离执行 → 测试/验证 → diff/PR → 人类审阅**。[5][6] Jules 还自动寻找仓库根部的 `AGENTS.md`，把输入输出约定和工具说明作为项目上下文。[5] 这是 Northstar 可借鉴的“任务契约”入口，但 `AGENTS.md` 是指导模型的上下文，不应被视为权限策略或不可篡改的安全边界。

**已发布/公开 beta 能力**：异步任务、GitHub 集成、云 VM、计划与 diff、并行任务和 steerability。[6] **明确实验性能力**：Jules 产品文档直接称 experimental；API 文档直接称 alpha，规格、API key 和定义可能变化。[7] **营销主张与工程事实的区分**：诸如“secure VM”“private by default”“doesn’t train on private code”是 Google 官方产品公告的产品主张；报告可记录其公开承诺，但没有把它当作 Northstar 可验证的隔离证明。[6]

### Jules API：可编排，但默认语义必须显式化

Jules API 的公开资源模型包括 Source、Session 和 Activity。API 可列出已连接仓库，创建带起始分支的 session，读取活动，发送消息，并在 `requirePlanApproval=true` 时显式批准计划。[7] 文档特别说明：API session 默认会自动批准计划；只有设置该字段才要求显式批准。`automationMode` 还可选择自动创建 PR。[7]

这对 Northstar 是一条重要的可验证差距：自动化接口往往把“无需批准”作为默认便利路径，而 Northstar M0/M1 要求预算、权限和证据门明确可见。可借鉴的是资源化的 session/activity 事件流和 plan approval 状态；不应复制默认 auto-approve 或自动 PR 作为通用默认。API 当前为 alpha，不能作为稳定协议依赖。[7]

### Jules Tools：远程执行的 CLI 控制面

Google Developers 官方公告把 Jules Tools 描述为 Jules 异步任务的命令行伴侣：可创建任务、列出远程任务、检查进展、发送输入，并通过脚本把 issue 或 TODO 管道化。[8] 公告还明确说任务在临时 VM 中运行，完成后返回 pull request；CLI 既是 dashboard 也是 command surface。[8]

该模式值得借鉴为“本地控制面 + 远程隔离执行面”，尤其是查询任务状态和把活动转为可审计记录。但公告展示的 `TODO` 循环、issue 管道和 Gemini→Jules 串接属于可组合能力示例，不是 Northstar 应默认开启的无边界调度。M0/M1 应限制为有界任务数、固定预算、固定 repo/branch、明确终止状态，并为每次委派保留授权与产物摘要。

## 与 Northstar M0/M1 的差距或互补

**权限与信任**：Gemini CLI 已公开实现细粒度工具 policy、Trusted Folders 和沙箱扩展。[2][3][4] Northstar 的互补点是把授权原因、预算消耗、作用域、审计和结果 provenance 串进同一 run contract；差距不是“缺少一个 allow/deny 开关”，而是要证明每次决策确实覆盖了替代执行路径，并可在恢复时重放。

**隔离执行**：Jules 提供云 VM + GitHub 分支/PR 的远程闭环，Gemini CLI 提供本地多后端沙箱。[3][6] Northstar 应保持隔离 worktree 为 M0/M1 的确定性边界，不把外部云 VM 的安全承诺当作可复现证据。可吸收的是环境摘要、基线 commit、变更 diff、测试输出和 PR/工件引用形成的 evidence packet。

**计划与人类控制**：Jules 把计划批准放在代码变更之前，并允许中途 steer。[5][6] Northstar 可在 M0/M1 为“计划→执行”增加显式门，但应继续支持非交互运行的可验证 deny/stop 语义，而不是把一个 UI 审批等同于完整治理。

**恢复与未知副作用**：公开 Jules 材料展示了 session/activity 进度，但未在这些来源中给出 Northstar 所需的 checkpoint 语义、幂等恢复协议、未知副作用 reconcile 或证据包格式。[5][7] 这仍是 Northstar 的差距与差异化重点。Gemini CLI README 公开列有 checkpointing 和 stream-json 等能力入口，[9] 但本次核验没有把这些入口扩展为已证明的跨阶段恢复保证；应进入待证而非直接采纳。

**预算与审计**：本次核验的官方 Gemini/Jules 来源强调权限、沙箱、计划、活动和 PR，但没有给出与 Northstar 相当的端到端、不可抵赖预算账本或证据包规范。[2][3][7] Northstar 不应因对方有“活动列表”就推断其满足成本上限、授权链和恢复审计。

## 结论分类

### 可采纳

1. **把工具调用策略做成独立、可解释、可分层的 admission 门**：支持 allow/deny/ask、参数/命令范围、交互与 headless 区分；将最终决策、规则版本和原因写入审计。[2]
2. **默认窄权限，按次扩展并记录扩展原因**：参考 Gemini CLI 的 sandbox expansion 和只读外部挂载语义；扩展必须绑定单个 run/step，不自动升级为永久信任。[3]
3. **在加载仓库级 agent 配置前做发现与信任判定**：扫描 hooks、MCP、skills、设置覆盖和环境文件；不可信时禁用自动加载。[4]
4. **采用 plan → approval → isolated execution → verification → diff/evidence 的真实仓库闭环**：这是 Jules 公开工作流中最适合 M0/M1 的部分。[5][6]
5. **把 session/activity 作为事件模型参考**：保留可查询的阶段、输入、授权、进度、验证结果和最终工件摘要；不把活动流误当作恢复证明。[7]

### 明确拒绝

1. **拒绝无边界的自动化默认值**：不复制 Jules API 的默认自动批准计划，也不默认开启自动 PR；Northstar 的批准和发布必须绑定明确策略与预算。[7]
2. **拒绝把 yolo、`--skip-trust` 或类似 bypass 当作正常生产模式**：可作为显式实验开关，但不能绕过 M0/M1 的权限、审计和隔离门。[2][4]
3. **拒绝把“secure VM”“private by default”等营销/产品承诺当作本地可验证安全证据**：必须以 Northstar 自己的容器、worktree、网络、secret 和工件测试证明。[6]
4. **拒绝把 `AGENTS.md`、项目 settings 或模型文本当作权限策略**：它们最多是上下文；策略必须由不可被任务文本改写的运行时门执行。[4][5]

### 待证

1. **跨阶段恢复与未知副作用 reconcile**：Jules 的 session/activity 是否能提供可重放、幂等且覆盖外部副作用的恢复证据，公开材料不足。[5][7]
2. **真实成本/预算控制**：公开来源没有核验到 Jules API 或 Gemini CLI 的端到端预算账本；Northstar 需要用固定模型、版本、网络和容器做本地实验。[2][7]
3. **Gemini CLI workspace policy 当前禁用后的治理替代**：应测试 user/admin policy 在 Northstar 场景的最小配置，并验证恶意项目配置不能影响 admission。[2]
4. **checkpointing 与 stream-json 能否满足 Northstar 证据包要求**：仓库 README 仅列出能力入口，不能据此宣称恢复保证；需要固定版本的可复现实验。[9]

## M0/M1 最小研究动作

建议只做三项有界验证，不扩展成自动化平台：

- 在冻结的真实代码任务样本上，记录 Northstar 与 Gemini CLI 的同一 run contract：模型/版本、sandbox、网络、预算、基线 commit、工具决策、diff、测试和失败状态。
- 构造一个包含恶意 `.gemini` 配置、MCP、hook 和 `.env` 的不可信仓库，验证 Northstar 的 admission 是否在所有替代路径上仍 fail closed；将 Gemini Trusted Folders 作为对照机制，而不是安全背书。[4]
- 对一个会在测试后留下外部副作用的任务注入中断，验证恢复、reconcile 和 evidence packet；仅当输出能回答“改了什么、谁批准、花了多少、验证到哪、失败后从哪继续”时，才把机制纳入 M1。

## References

[1]: https://github.com/google-gemini/gemini-cli "Northstar 蓝图中 M0/M1 目标的本地项目依据（工作区文件：docs/next-gen-agent-blueprint.zh-CN.md）"
[2]: https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/policy-engine.md "Gemini CLI Policy Engine 官方文档"
[3]: https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/sandbox.md "Gemini CLI Sandboxing 官方文档"
[4]: https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/trusted-folders.md "Gemini CLI Trusted Folders 官方文档"
[5]: https://jules.google/docs/ "Jules 官方 Getting started 文档"
[6]: https://blog.google/innovation-and-ai/models-and-research/google-labs/jules/ "Google 官方博客：Build with Jules, your asynchronous coding agent"
[7]: https://developers.google.com/jules/api "Google Developers：Jules API 官方文档"
[8]: https://developers.googleblog.com/en/meet-jules-tools-a-command-line-companion-for-googles-async-coding-agent/ "Google Developers Blog：Meet Jules Tools"
[9]: https://github.com/google-gemini/gemini-cli "Gemini CLI 官方开源仓库 README 与公开能力入口"
