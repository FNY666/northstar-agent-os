# Gemini CLI 生命周期、权限边界与可观测性研究（S4）

- **资料范围**：仅 `google-gemini/gemini-cli` 官方公开仓库的 docs、源码、测试；研究基线为官方 `main` 在提交 `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`（2026-09-21）。
- **排除**：未访问任何私有账号、凭据、真实服务、旧研究目录或用户事故目录；未执行 Gemini CLI 业务任务。
- **状态词**：`verified`=一手文本/源码/测试直接证明；`inferred`=由直接证据合理推断但非明文承诺；`unknown`=本批官方资料未证明；`conflict`=同一问题存在未消解的一手冲突。
- **证据等级**：A=官方实现+对应测试/规范；B=官方实现或官方 docs；C=官方说明但未见配套行为测试；D=缺证据，仅边界声明。

## 结论

### 1. 任务/工具调用生命周期

1. **[verified | A]** 工具调用状态机显式区分 `validating → scheduled → executing → success/error/cancelled`，并有 `awaiting_approval`；终态只有 success、error、cancelled。源码类型定义还保留 request、response、start/end/duration、approval mode 等字段。调度器按“先校验（policy/confirmation），再执行，最后终态化”的顺序运行；未准备好时会等待审批或执行外部事件。 
2. **[verified | A]** 调度器只有在所有活动调用均为 scheduled 或终态时才执行 scheduled 调用；连续可并行工具可批量并发，而编辑/特定工具被强制串行，`wait_for_previous` 可要求等待。**因此“模型提出调用”不等于执行已发生**，批准和执行是不同边界。
3. **[inferred | B]** “计划/批准/执行/结束”可操作地对应：Plan Mode 中只读研究与计划文件写入；正式计划获批准后退出 Plan Mode 并开始实现；每个工具调用则经过 validating/approval、scheduled、executing、terminal。源码没有定义一个跨整轮任务的统一 durable 状态机或业务任务 ID，因此不可把工具终态等同于整个用户任务成功。
4. **[verified | A]** 终态化会把调用从 active map 移入 completed batch，并向 MessageBus 发布 `TOOL_CALLS_UPDATE`；取消的调用仍带结构化错误响应，执行中已有的 live output 会保留。

### 2. Plan Mode、YOLO、policy 与信任边界

5. **[verified | A]** Plan Mode 的默认 policy 是 catch-all deny；显式只放行文件读取/搜索、研究子代理、交互询问、只读 MCP resource 等；计划目录的 `.md` 可写，源码写入被 deny。Plan Mode 中 `enter_plan_mode`/`exit_plan_mode` 的交互/非交互决策也有单独规则。
6. **[verified | B]** 官方 Plan Mode 文档定义其为 read-only 环境：讨论策略时等待用户确认，形成 Markdown 计划，随后用户选择自动或手动接受编辑，或按 Esc 取消。文档同时明确 Plan Mode 在 YOLO 中不可用/被阻止。
7. **[verified | A]** YOLO policy 对除 `ask_user`、Plan Mode 进出之外的工具使用 allow-all（并允许重定向）；因此它是自动批准层，不是只读层。`ask_user` 仍需交互，Plan Mode 转换在 YOLO 中 deny。
8. **[verified | B]** policy 决策为 allow/deny/ask_user；deny 的全局工具从模型记忆中排除，非交互模式下 ask_user 按 deny 处理。优先级由 tier 与 TOML priority 组成，Admin > User > Workspace > Extension > Default；官方 docs 明示当前 Workspace tier 非功能性，不能假定项目级 policy 生效。
9. **[verified | B]** 文件夹信任是更外层的边界：不信任时忽略 workspace settings 与 `.env`、禁止扩展管理、禁用自动接受、不开 MCP、不加载自定义命令和自动 memory；headless 且未信任会抛 `FatalUntrustedWorkspaceError`，除非显式 skip-trust/环境变量绕过本次检查。该信任是“是否加载项目能力”的门槛，不是对单次工具调用结果的审计证明。
10. **[verified | A]** MCP 工具的确认逻辑同时检查：文件夹是否 trusted 且 server `trust` 为 true；会话 allowlist 是否已有 server 或 server.tool。否则返回用户确认详情；ProceedAlwaysServer/Tool 写入会话 allowlist，ProceedAlwaysAndSave 也写工具 allowlist并交由 scheduler 处理持久 policy 更新。
11. **[verified | A]** MCP server 连接还受 admin allowed/blocked 列表、用户 session/file enablement 过滤；不在允许列表或在 blocked 列表会被阻断，用户 disable 也会阻断。故“server trusted”与“server 被允许连接”是两层不同判断。

### 3. 审计/可观测性与效果证明

12. **[verified | B]** 官方 telemetry 文档提供 OpenTelemetry logs/metrics/traces，默认 telemetry disabled、traces disabled；可输出 local 文件或 OTLP/GCP，配置含是否记录 prompts。源码 scheduler 在工具调用状态处理处调用 `logToolCall`/`ToolCallEvent`，状态更新通过 MessageBus 发布。
13. **[inferred | B]** 这些信号可证明调用过程的部分可观测性（调用、时序、错误/终态、工具输出在本地状态中的变化），但**不能单独证明业务效果、文件内容正确、外部副作用已提交或 exactly-once**。官方 docs 没有给出效果指标、业务验收钩子或端到端审计不可抵赖保证；telemetry 默认关闭也是重要 caveat。
14. **[unknown | D]** 本批未发现官方承诺“每次用户任务均有不可篡改 audit record”、审计日志保留期、跨进程关联/导出成功保证、telemetry 丢失补偿或基于 telemetry 的业务结果证明。不能把 local `.gemini/telemetry.log` 或 MessageBus 更新称为合规审计。

### 4. 取消、超时、失败恢复

15. **[verified | A]** AbortSignal 触发时 scheduler 会把等待中的调用转为 cancelled、将队列中未运行调用批量转为 cancelled，并停止调度循环；取消响应写入 `[Operation Cancelled]`，执行中 partial/live output 可保留。MCP tool 也 race `callTool` 与 abort signal，并返回 `AbortError`。
16. **[verified | A]** shell 执行的 abort 会终止进程组；官方测试明确验证先 SIGTERM 后 SIGKILL。shell tool 有“不活动超时”，超时 abort 后返回“Command was automatically cancelled because it exceeded…”；这是取消/错误结果，不是成功。
17. **[verified | A/B]** MCP server 默认 timeout 为 10 分钟（可按 server 配置覆盖）；官方测试验证 discovery 刷新超时会 abort 并记录错误。此证据覆盖 MCP discovery/请求超时边界，不足以证明所有工具、所有传输的统一超时语义。
18. **[verified | A]** 模型网络层 retry 默认最多 10 次，针对 429、499、5xx 与列出的网络/流错误；使用 backoff/jitter，AbortSignal 会停止重试；400 明确不重试。retry 可能在切换 fallback model 后将 attempt 计数重置。
19. **[verified | B]** checkpointing 默认关闭；启用后，在获批的文件修改工具执行前创建 shadow Git snapshot，同时保存会话历史和即将执行的 tool call；`/restore` 会恢复文件与对话并重新提出原调用。snapshot 创建失败时实现记录错误并尝试当前 commit；没有证据表明该错误会自动中止所有写入。
20. **[inferred | B]** checkpoint/restore 提供人工回滚与重提议能力，不是事务回滚：官方说明是“工具运行前快照”，未证明外部副作用、MCP 远端变化、shell side effect、并发写入可回滚。若工具已执行外部副作用，restore 仅能恢复项目 shadow Git/对话范围。
21. **[verified | A/B]** 官方测试证明 session resume、checkpoint restore 与上下文再现存在实现路径，且有 resume regression test；但 resume 是重载历史/上下文的恢复，不是对未确认工具执行结果的分布式恢复协议。
22. **[unknown | D]** 对崩溃、断线后“最后一次工具是否已生效”、重连去重、幂等键、重复调用抑制、exactly-once、远端事务回滚，本批没有官方 end-to-end 证据。仓库中存在 `idempotentHint` 等 MCP annotations 的测试数据，但未见 Gemini CLI 对远端副作用实施 exactly-once 语义的承诺；不能由该字段推导保证。

## 关键边界图（证据约束内）

```text
用户 goal
  └─ Plan Mode research/read-only ──> plan.md ──(human approval/iterate/Esc)
       └─ approved mode (default/autoEdit/YOLO policy dependent)
           └─ tool request
               └─ validating: policy + folder/MCP trust + confirmation
                   ├─ denied/cancelled/error  [terminal]
                   └─ scheduled
                       └─ executing (AbortSignal, timeout, live output)
                           └─ success | error | cancelled [terminal + MessageBus/telemetry if enabled]
                               └─ next model turn / tail call / optional checkpoint restore
```

图中最后一行的跨轮次恢复、外部副作用和业务成功，不能从终态或 telemetry 单独推出。

## 未解决问题与下一片 S5 的窄范围核验

S4 将以下项目保留为 unknown，而不是以“源码存在”代替证明：

- tool 执行期间进程崩溃/网络断线后的 durable 状态与重复调用；
- `/resume` 是否会重放未明确完成的工具调用；
- MCP `idempotentHint` 是否仅元数据还是被 CLI 用于去重/重试；
- checkpoint 创建失败、工具部分写入后失败时的精确恢复边界；
- timeout/abort 对外部过程真正退出与远端副作用的保证。

S5 仅核验上述官方源码/测试窄问题，不扩大到非官方资料。

## 来源与证据索引

完整来源清单见 `sources.md`；机器可读 claim-to-source 映射见 `research-manifest.json`。
