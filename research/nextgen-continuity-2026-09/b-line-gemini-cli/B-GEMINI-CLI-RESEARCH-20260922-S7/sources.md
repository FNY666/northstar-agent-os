# S7 官方来源与证据索引

仅使用 `google-gemini/gemini-cli` 官方公开 GitHub。访问方式为定向 Raw/API 请求，未 clone 全仓库。

## S1 — scheduler 类型与状态枚举
- URL: https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/scheduler/types.ts
- Raw: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/scheduler/types.ts
- 发布/更新：未在文件页固定记录；研究时读取 `main`（2026-09-22）
- 证据等级：A；来源层级：primary
- 直接证据：`CoreToolCallStatus` 定义 validating、scheduled、error、success、executing、cancelled、awaiting_approval；联合类型定义对应 call 形态。
- 支持结论：C1；部分支持 C2。
- Caveat：类型定义不等于所有路径均被运行，也不等于持久化审计。

## S2 — Scheduler 主循环、确认、执行与取消
- URL: https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/scheduler/scheduler.ts
- Raw: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/scheduler/scheduler.ts
- 发布/更新：未在文件页固定记录；研究时读取 `main`（2026-09-22）
- 证据等级：A；来源层级：primary
- 直接证据：请求先生成 validating；验证并处理确认后进入 scheduled；主循环筛选 scheduled 并用 Promise.all 执行；确认取消与 Abort/异常路径分别产生 cancelled/error；terminal 调用 finalize。
- 支持结论：C2、C3、C4；部分支持 C5。
- Caveat：源码支持控制流事实，不支持业务效果、全局并发上限或跨实例顺序承诺。

## S3 — 状态管理与发布快照
- URL: https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/scheduler/state-manager.ts
- Raw: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/scheduler/state-manager.ts
- 发布/更新：未在文件页固定记录；研究时读取 `main`（2026-09-22）
- 证据等级：A；来源层级：primary
- 直接证据：updateStatus 通过 transitionCall 进行状态转换校验；finalizeCall 收集 terminal call 并调用 onTerminalCall；状态更新触发快照发布，快照含 schedulerId。
- 支持结论：C2、C5。
- Caveat：快照是当前状态传播，不自动构成历史、append-only 或防篡改日志。

## S4 — 并行/串行测试
- URL: https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/scheduler/scheduler_parallel.test.ts
- Raw: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/scheduler/scheduler_parallel.test.ts
- 发布/更新：未在文件页固定记录；研究时读取 `main`（2026-09-22）
- 证据等级：A；来源层级：primary
- 直接证据：测试断言连续只读工具并行、非只读工具串行、多波次顺序；断言非只读工具 wait_for_previous=false 时并行、只读工具 true 时串行，并覆盖强制串行工具。
- 支持结论：C3、C4。
- Caveat：测试使用 mock executor 与事件顺序；不代表生产负载、资源容量或业务一致性。

## S5 — MessageBus
- URL: https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/confirmation-bus/message-bus.ts
- Raw: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/confirmation-bus/message-bus.ts
- 发布/更新：未在文件页固定记录；研究时读取 `main`（2026-09-22）
- 证据等级：A；来源层级：primary
- 直接证据：publish 校验并发出消息；subscribe/unsubscribe 管理监听；request 生成 correlationId、订阅响应并等待匹配响应；确认请求经 policy 分支处理。
- 支持结论：C5。
- Caveat：MessageBus 是异步消息机制，不是官方声明的持久、不可变审计存储。

## S6 — ToolCallEvent 与日志入口
- URL: https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/telemetry/types.ts
- Raw: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/telemetry/types.ts
- 发布/更新：未在文件页固定记录；研究时读取 `main`（2026-09-22）
- 证据等级：A；来源层级：primary
- 直接证据：ToolCallEvent 从 CompletedToolCall 填充 function_name、args、duration、success、decision、error/error_type、prompt_id、start_time/end_time、tool_type 等。
- 支持结论：C5、C6。
- Caveat：它主要记录完成调用；字段存在不证明所有中间状态、传输成功、长期保存或业务目标完成。

- URL: https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/telemetry/loggers.ts
- Raw: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/telemetry/loggers.ts
- 证据等级：A；来源层级：primary
- 直接证据：`logToolCall` 将 ToolCallEvent 交给 Clearcut/OpenTelemetry 相关日志路径。
- 支持结论：C5。
- Caveat：代码路径不是外部遥测存储成功或保留策略的证明。

## 证据判定边界

- C1–C4 的实现事实为 verified（manifest 对应 schema 用 confirmed 表示）。
- C5 的“组件形成可关联审计链”标 inferred：组件连接由源码直接显示，但“审计”语义超出单个组件的官方合规声明。
- C6 的“不能证明业务效果”标 verified：当前材料是实现、类型和 mock/单元测试，缺少业务指标、对照、真实运行结果和因果设计。
- 未核实项标 unknown：跨实例全局串行、生产吞吐/延迟、遥测送达与长期保存、业务成功率/ROI；本切片不扩展检索。
