# S10 策略与审批决策可审计边界研究报告

- **研究截止/来源 pin**：2026-09-22（Asia/Shanghai）；仅检索官方 `google-gemini/gemini-cli` GitHub 文档、源码、测试/API。源码统一 pin 到提交 [`d5b3e3accb26000d273abf16e0f1dd83aa5428a9`](https://github.com/google-gemini/gemini-cli/commit/d5b3e3accb26000d273abf16e0f1dd83aa5428a9)，该提交 API 元数据时间为 2026-09-21T20:36:40Z。
- **范围排除**：未访问/读取/写入任何 shared/P0、事故目录、D10/L12/D14、canonical、140、tri-line、systemd、真实服务或凭据；未 clone 全仓库；没有执行真实工具调用或远端副作用。
- **证据标记**：`verified`=官方源码/测试/文档直接证明；`inferred`=由结构推断；`unknown/conflict`=官方材料未证明或存在冲突/边界。

## 结论摘要

Gemini CLI 的策略判定是“规则匹配→优先级最高者先取→若为 shell 再做安全启发式/复合命令聚合→额外保护与 checker 后处理”的流水线，而不是简单的 allow > ask > deny 固定排序。规则层面高优先级胜出；但最终决策可能被解析失败、危险命令、未信任目录、重定向、路径保护和 safety checker 降级/拒绝。`yolo`、Plan Mode、Trusted Folder、MCP server `trust` 是不同层次：approval mode 参与策略规则匹配；Plan Mode 主要是 mode-scoped deny/allow 规则；Folder Trust 控制工作区安全态（含禁用 MCP 连接、禁用自动接受）；MCP `trust` 只对该 MCP server 的工具确认绕过生效（且源码还要求 trusted folder）。

官方公开材料**没有证明**审批请求、用户拒绝、UI 超时/取消会形成可检索的持久审计事件，也没有证明一次 policy decision 与后续 tool-call、policy mutation、业务结果可通过稳定 correlation ID 关联。CLI activity logger 是 console/network JSONL 活动记录机制，但公开源码未证明其自动记录每个策略判定或审批生命周期。因此“日志存在”不能外推为“决策审计链存在”。更不能把审批/策略日志当作业务副作用成功、远端提交、回滚或 exactly-once 的证明。

## 逐条结论与证据

### C1 — 决策顺序不是 allow/deny/ask 的固定全局排序（verified）

**结论**：PolicyEngine 构造时按 `priority` 降序排序规则；check 时遍历匹配规则，命中第一条即取其 decision。相同优先级的并列次序没有在这些材料中被定义为稳定审计契约。

**证据**：
- [policy-engine.ts#L255-L263](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policy-engine.ts#L255-L263)：rules/checkers/hookCheckers 按 priority 降序排序。
- [policy-engine.ts#L650-L750](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policy-engine.ts#L650-L750)：注释明确“first matching rule (already sorted by priority)”，命中后 `break`。
- [policy-engine.md](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/reference/policy-engine.md)：文档称 highest-priority matching rule wins。

**caveat**：同优先级的排序稳定性、跨来源装载顺序不应当当作审计依据。

### C2 — policy tier 与 TOML priority 共同覆盖，Admin > User > Workspace > Extension > Default（verified / 文档边界）

**结论**：官方 reference 文档给出 tier base（Default 1、Extension 2、Workspace 3、User 4、Admin 5）及 `final_priority = tier_base + toml_priority/1000`；因而高 tier 覆盖低 tier。文档同时警告 Workspace tier 当前 non-functional；不要把表格中的 Workspace 覆盖关系当成当前运行事实。

**证据**：
- [policy-engine.md#Priority-system-and-tiers](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/reference/policy-engine.md#priority-system-and-tiers)。
- [config.ts](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/config.ts)：策略配置/来源优先级实现入口（本片未运行真实 CLI）。

**caveat**：官方文档同段明确 Workspace `.gemini/policies` 当前不生效，并链接 issue #18186；这是文档声明与抽象 tier 表之间的已知边界，标记为 conflict/unknown（具体版本何时修复未在本片确定）。

### C3 — `deny` 不会被 `ask_user` 或默认逻辑升级；`ask_user` 在 non-interactive 转为 deny（verified）

**结论**：源码在 shell 检查中对 `DENY` 立即返回；无匹配规则时默认 interactive 为 `ASK_USER`、non-interactive 为 `DENY`。官方文档直接说明 non-interactive 下 `ask_user` treated as `deny`。

**证据**：
- [policy-engine.ts#L296-L303](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policy-engine.ts#L296-L303)：`defaultDecision`。
- [policy-engine.ts#L364-L365](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policy-engine.ts#L364-L365)：已有 deny 立即保留。
- [policy-engine.md#Decisions](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/reference/policy-engine.md#decisions)。
- [non-interactive.toml](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policies/non-interactive.toml)：`ask_user` 工具在 non-interactive priority 999 deny。

**caveat**：这是策略 decision，不是“用户拒绝事件”或业务结果记录。

### C4 — allow 可能被后处理降级为 ask_user/deny；deny 与安全检查优先保留（verified）

**结论**：即使规则先给 `allow`，shell 危险命令、越界 cwd、未信任文件夹中的 git、重定向、额外权限路径越界、build-file protection 可能转为 `ask_user`（non-interactive 时部分转 deny）；复合 shell 子命令遇到 deny 立即返回、遇到 ask 聚合为 ask。safety checker 可进一步 deny 或 ask。

**证据**：
- [policy-engine.ts#L350-L438](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policy-engine.ts#L350-L438)：危险/越界/未信任 git/known-safe 等启发式。
- [policy-engine.ts#L514-L590](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policy-engine.ts#L514-L590)：重定向及 shell 子命令聚合。
- [policy-engine.ts#L775-L905](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policy-engine.ts#L775-L905)：额外权限、build-file protection、checker 后处理。

**caveat**：这证明 decision pipeline，不证明任何调用已实际执行或副作用成功。

### C5 — YOLO 是 approval-mode 参与的策略层，不是对所有特殊工具的无条件放行（verified）

**结论**：YOLO policy 文件对 `yolo` mode 以 priority 998 allow-all，但 priority 999 的 `ask_user` 工具仍 ask_user，`enter_plan_mode`/`exit_plan_mode` 在 yolo deny；源码在 YOLO 无匹配时默认 allow，且危险命令可保留 decision，但解析失败的受限 argsPattern 命令仍可 deny。

**证据**：
- [yolo.toml](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policies/yolo.toml#L31-L55)：priority 999 特例、998 catch-all。
- [policy-engine.ts#L741-L755](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policy-engine.ts#L741-L755)：YOLO no-match allow。
- [policy-engine.ts#L455-L498](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policy-engine.ts#L455-L498)：解析失败时 deny/allow 分支。

**caveat**：YOLO 的“allow all”仅指该 policy 配置语义，不能推导越过 Trusted Folder、MCP 连接门槛或系统/服务器失败。

### C6 — Plan Mode 是独立 approval mode + mode-scoped policy；默认执行面是只读（verified）

**结论**：Plan Mode 并非仅 UI 标签：`plan.toml` 为 plan mode 设置 catch-all deny（priority 40），列出只读工具 allow/ask，并保护 enter/exit 转换；文档定义其为 read-only，计划可写入限定 plans 目录。退出/批准计划是流程控制，不等于业务工具成功。

**证据**：
- [plan.toml](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policies/plan.toml#L35-L81)：enter/exit 与 plan catch-all。
- [plan.toml#L83-L203](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policies/plan.toml#L83-L203)：允许工具和写入限制。
- [plan-mode.md](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/cli/plan-mode.md)：计划流程含用户确认、批准、Esc 取消。

**caveat**：Plan Mode “只读”是工具策略边界，不是 OS sandbox 或远端事务回滚保证。

### C7 — Trusted Folder 是工作区安全态，独立于 approval mode；不信任时禁用 auto-accept 与 MCP 连接（verified）

**结论**：Trusted Folder 的文档明确不信任工作区进入 safe mode：忽略 workspace settings/.env，禁用扩展管理、工具 auto-accept、自动 memory、MCP server 连接和自定义命令。其信任结果另存 `~/.gemini/trustedFolders.json`；这与 policy rule 的 decision/priority 和 approval mode 是不同配置面。

**证据**：
- [trusted-folders.md](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/cli/trusted-folders.md)：safe mode 列表、持久文件与 headless 行为。
- [trust.ts](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/utils/trust.ts)：TrustLevel、env/IDE/file 来源和最长路径匹配。
- [policy-engine.ts#L307-L315](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policy-engine.ts#L307-L315)：PolicyEngine 可接收 isTrustedFolder，并在启发式中单独处理。

**caveat**：Trusted Folder 文件的持久化证明的是 trust decision，不是每次审批请求/结果的审计日志。

### C8 — MCP server `trust` 是 server/tool confirmation 层；不是全局策略 allow（verified）

**结论**：MCP 文档将 `trust: true` 定义为绕过该 server 的所有 tool-call confirmations（默认 false）；源码的 MCP invocation 还要求 `isTrustedFolder()` 与 server trust 同时为真才直接跳过 confirmation。用户的 “always allow server/tool” 是会话内 allow-list；“always allow and save” 的持久 policy update 由 scheduler 中央处理，而不是 MCP invocation 自身直接写入。

**证据**：
- [mcp-server.md#Server-specific-configuration](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/tools/mcp-server.md#server-specific-configuration)：trust 语义。
- [mcp-server.md#Tool-execution-flow](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/tools/mcp-server.md#tool-execution-flow)：server/tool allow-list及 Cancel。
- [mcp-tool.ts#L309-L383](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/tools/mcp-tool.ts#L309-L383)：`isTrustedFolder() && trust`、会话 allowlist、scheduler 注释。

**caveat**：MCP `trust` 不证明远端 server 的行为可信，也不证明调用成功或副作用可回滚。

### C9 — policy mutation 可持久化，但并非审批生命周期日志（verified + audit gap）

**结论**：官方测试直接证明 `ProceedAlwaysAndSave` 通过 policy updater 可把规则写入 TOML；更新可能含 MCP name/toolName。源码/测试还表明 invocation 的 onConfirm 不直接 publish update，更新由 scheduler 中央处理。这里可审计的是“策略变更持久化”，不是“谁在何时对哪次请求批准/拒绝/取消”。

**证据**：
- [policy-updater.test.ts](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policy-updater.test.ts)：`UPDATE_POLICY`、persist true 写 TOML、MCP mcpName 持久化测试；并断言 invocation onConfirm 不直接 publish。
- [persistence.test.ts](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/persistence.test.ts)：持久化成功/失败/原子 rename 等 policy file 行为。

**caveat**：持久 policy file 未显示审批请求 ID、用户身份、原始调用参数、拒绝/取消/超时、执行结果等字段。

### C10 — 审批请求/拒绝/超时/取消是否持久记录：unknown；不能由 activity logger 外推（unknown）

**结论**：官方 MCP 文档证明 Cancel 会 abort execution，源码证明 MCP execute 以 AbortSignal race call；但在本片核验的官方 activity logger 中，持久 JSONL 是 console/network 类型并带 sessionId/timestamp，未见其自动写入 policy decision 或 ToolConfirmationOutcome 审批生命周期。故：

- **审批请求是否持久记录**：unknown / 未被官方材料证明；
- **用户拒绝是否持久记录**：unknown；
- **审批 UI 超时是否持久记录**：unknown（官方材料未建立统一审批超时语义）；
- **取消是否持久记录**：unknown；可 verified 的仅是取消/abort 的控制流，不是审计落盘；
- **当前会话临时 allow-list 是否跨会话持久**：官方源码显示 `static allowlist` 内存集合，未证明跨会话持久；`ProceedAlwaysAndSave` 才进入 policy updater 路径。

**证据**：
- [mcp-server.md#Tool-execution-flow](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/tools/mcp-tool.ts#L347-L451)。
- [mcp-tool.ts#L347-L451](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/tools/mcp-tool.ts#L347-L451)：confirmation details、outcome、AbortSignal。
- [activityLogger.ts#L686-L725](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/cli/src/utils/activityLogger.ts#L686-L725)：session JSONL 记录 console/network。

**caveat**：这是“未被本片官方公开材料证明”，不是断言所有运行配置下绝对不存在额外日志；需避免把未发现写成否定事实。

### C11 — 策略变更与工具调用是否可关联：unknown / 未证明，不能以 sessionId 代替 call correlation ID

**结论**：activity logger 的 JSONL entry 带 `sessionId` 和 timestamp，但公开片段未证明 policy update event、approval request、tool call 共享稳定 call ID/decision ID，也未证明时间戳可唯一关联。policy updater 测试关注 TOML 结果与 addRule 调用，不构造端到端审计关联链。

**证据**：
- [activityLogger.ts#L686-L725](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/cli/src/utils/activityLogger.ts#L686-L725)。
- [policy-updater.test.ts](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/policy/policy-updater.test.ts)。
- [mcp-tool.ts#L337-L383](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/tools/mcp-tool.ts#L337-L383)。

**caveat**：sessionId 只标识 session；不能证明单次 tool call、approval、policy mutation 的 exactly-once 关联。

### C12 — 审批/策略日志不等于业务副作用、远端提交、回滚或 exactly-once（verified boundary / inferred operational conclusion）

**结论**：本片证据最多能证明策略返回 decision、确认回调更新内存 allow-list/触发 policy updater、以及 MCP call 受 AbortSignal/timeout 控制；没有官方材料证明：

1. `allow`/批准后业务副作用成功；
2. 远端 MCP server 已提交或完成事务；
3. 取消/超时后远端副作用一定未发生；
4. 失败后自动回滚；
5. 重试或中断提供 exactly-once。

因此任何审计系统都必须把 `policy decision`、`approval outcome`、`tool execution started/finished/error/aborted`、`remote acknowledgement/commit` 分开建模，不能用前者替代后者。

**证据**：
- [mcp-tool.ts#L415-L451](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/tools/mcp-tool.ts#L415-L451)：call 与 abort race；未给远端事务/回滚/幂等承诺。
- [mcp-client.ts](https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/tools/mcp-client.ts)：transport timeout/abort 机制，不是业务提交语义。

**caveat**：这是审计边界结论；“源码未证明”不等于每个 MCP server 都没有幂等/事务，只是 CLI 不提供此保证。

## 审计建模建议（不宣称官方已实现）

如果要构建可审计边界，至少分离并带不可变 ID：

`policy_eval_id → matched_rule/source/priority/mode/trust_context → approval_request_id → outcome (approved/rejected/cancelled/timed_out) → execution_id → transport result → remote receipt/commit id`。

这些字段和关联链是设计建议（`inferred`），不是 Gemini CLI 官方现状证明。特别要记录 policy 文件版本/hash、来源 tier、effective priority、approval mode、folder trust、MCP server trust、policy mutation 的 before/after；并显式标注“未收到远端提交回执”而不是把本地工具返回当成提交证明。

## 覆盖与冲突

- 已检索：policy reference、policy engine/types、内置 yolo/plan/read-only/write/non-interactive policy、policy persistence/updater tests、trusted folders、Plan Mode、MCP server/tool docs and source、activity logger source。
- 未检索：任何非官方来源、真实服务、凭据、旧切片目录和被明确排除的路径；未 clone 全仓库；未运行真实工具/远端调用。
- 冲突/边界：reference 文档给出 Workspace tier 抽象优先级，但同时明确 Workspace policy 当前 non-functional；以当前“不生效”警告为运行边界。
- 未证明：审批事件完整持久性、审批超时统一语义、policy↔tool-call correlation ID、远端提交/回滚/exactly-once。
