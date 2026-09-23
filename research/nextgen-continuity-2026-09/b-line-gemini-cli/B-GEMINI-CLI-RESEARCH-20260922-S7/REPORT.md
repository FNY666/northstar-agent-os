# S7 调度审计研究报告

- 研究切片：S7
- 时间：2026-09-22（按官方 `main` 当前公开内容核验）
- 范围：仅 `google-gemini/gemini-cli` 官方公开 GitHub 的源码、测试与 GitHub API/Raw 内容；未 clone 仓库，未访问任何真实服务、凭据或受保护目录。
- 目标目录：`/tmp/B-GEMINI-CLI-RESEARCH-20260922-S7/`

## 结论（逐条标注）

### C1 — 状态枚举覆盖题设七种状态（verified）
**证据等级：A（官方源码，直接定义）**。官方 `packages/core/src/scheduler/types.ts` 的 `CoreToolCallStatus` 明确定义 `validating`、`scheduled`、`error`、`success`、`executing`、`cancelled`、`awaiting_approval`。同文件把它们分别映射到判别联合类型（包括 `WaitingToolCall`）。

**Caveat：** 这是类型/数据模型证据，不是所有运行路径都一定经过每个状态，也不是持久化审计日志。

### C2 — 调度器的主生命周期是 validating → awaiting_approval（可选）→ scheduled → executing → terminal（success/error/cancelled）（verified）
**证据等级：A（官方源码 + 状态管理器）**。`scheduler.ts` 先创建 `validating` call；验证/政策确认后，取消分支进入 `cancelled`，否则进入 `scheduled`；处理循环挑出 `scheduled` 并执行，执行器结果再转为终态；中止/异常转换为 `cancelled` 或 `error`。`state-manager.ts` 对各状态转换有专门的辅助函数和输入校验，终态由 `finalizeCall` 收集。

**Caveat：** 源码显示的是实现允许/使用的路径；没有据此断言一个统一、形式化且穷尽的状态转移图。`awaiting_approval` 由确认流程触发，可能是条件路径。

### C3 — 默认调度可并行；连续可并行请求成批执行，非并行工具形成串行波次（verified）
**证据等级：A（官方源码 + 官方测试）**。`_isParallelizable` 默认在未给出 flag 时返回 true，但 `update_topic` 与编辑类工具强制 false；处理循环用 `Promise.all` 并行验证和执行；只收集连续可并行队列项，因此串行工具会分隔执行波次。官方 `scheduler_parallel.test.ts` 直接断言只读工具并行、非只读工具串行，以及多波次顺序。

**Caveat：** “并行”是同一调度批次/波次内由 Promise.all 发起，不等于跨进程、跨实例或无限并发；实现也没有在这些证据中给出吞吐、资源上限或公平性保证。

### C4 — `wait_for_previous` 是显式串行/并行开关，但工具类别规则优先（verified）
**证据等级：A（官方源码 + 官方测试）**。当参数是 boolean 时，`wait_for_previous: true` 使请求不可并行，false 使其可并行；省略时默认并行。`update_topic`/编辑工具即使 flag 为 false 仍强制串行。测试直接覆盖“非只读工具 flag=false 并行”“只读工具 flag=true 串行”和编辑类强制串行。

**Caveat：** 该字段位于工具请求 args，具体工具是否接受/解释它仍取决于调用方与队列分组；证据不是业务级“前序完成后数据可见”保证。

### C5 — MessageBus + TOOL_CALLS_UPDATE + terminal callback + ToolCallEvent 形成“可关联的运行审计链”，但不是完整、不可变审计日志（inferred）
**证据等级：B（官方源码组合推断，部分直接）**。`SchedulerStateManager` 状态变更后 `emitUpdate` 发布工具调用快照（包含 `schedulerId`）；终态 `finalizeCall` 调用 `onTerminalCall`，而 `Scheduler` 构造时把该回调接到 `logToolCall(config, new ToolCallEvent(call))`。`ToolCallEvent` 记录工具名/参数、success、decision、error/error_type、prompt_id、start/end、duration 和 native/MCP 维度。MessageBus 提供 publish/subscribe 与带 correlationId 的 request-response，并为确认消息处理 policy。

这支持：在单次运行中，状态快照与终态 ToolCallEvent 可通过 `callId`（请求对象）、`schedulerId`、`prompt_id`、时间字段等进行关联；但“形成可追溯审计”是基于这些组件组合的推断，而非官方声明的审计合规保证。

**Caveat：** ToolCallEvent 主要由完成调用记录，题设的中间状态并不自动等价为每次变更都进入遥测；MessageBus 是事件传输机制而非明确的 append-only、持久化、不可抵赖审计存储。`TOOL_CALLS_UPDATE` 的快照也不等于历史链。

### C6 — 这些证据不能证明业务效果（verified）
**证据等级：A（由证据边界直接得出）**。源码/类型/单元测试能够证明设计与被测试的控制流（状态转换、队列分组、并发断言、事件字段），不能证明真实业务中的成功率、延迟改善、数据一致性、用户满意度、成本、规模化稳定性或因果 ROI。现有测试使用 mock executor/测试事件顺序；`ToolCallEvent.success` 只说明一次工具调用的终态是否为 success，不是业务目标达成指标。

**Caveat：** 这是“不能由当前材料推出”的边界结论，不是否定 Gemini CLI 在其他未核验材料中可能存在业务评估；本切片没有扩展检索。

## 审计链最小模型

`request(callId, schedulerId, prompt_id)` → 状态快照/MessageBus（可能多次）→ terminal call → `ToolCallEvent`（success/error、decision、timing）。这足以支持运行期间的关联分析；要称为合规/不可变审计，还需要官方定义的持久化、完整事件覆盖、重放/防篡改、保留期和端到端测试证据，本切片未找到，故不能宣称。

## 关键边界与未决项

1. 只核验官方公开 GitHub 源码/测试/API；未访问 issue 外部讨论、生产服务、私有数据或凭据。
2. 未 clone 全仓库；仅定向读取 `scheduler.ts`、`types.ts`、`state-manager.ts`、`scheduler_parallel.test.ts`、MessageBus 和 telemetry 文件。
3. `main` 是移动中的分支；本报告以 2026-09-22 研究时可读的公开内容为准。建议后续若需复核，固定 commit SHA。
4. 未证明跨 scheduler 实例的全局串行，也未证明跨批次的全局顺序；证据只支持该 Scheduler 的队列分组/波次。
5. 未证明遥测一定成功送达或长期保存；`logToolCall` 与 Clearcut/OpenTelemetry 连接是代码路径，不是外部存储结果证明。
6. 未将“verified”解释为业务有效性；该标签仅表示官方材料直接支持所述实现事实或证据边界。

## 官方来源索引

详见同目录 `sources.md`；完整机器可读索引见 `research-manifest.json`。
