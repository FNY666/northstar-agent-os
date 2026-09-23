# S9 研究报告：跨进程/跨重启审计与恢复边界

- 研究范围：仅 google-gemini/gemini-cli 官方公开 GitHub 文档、源码、测试与 API；检索截止 2026-09-22。
- 版本口径：`main` 分支公开内容（源码文件显示 2025/2026 copyright；main 会变化）。本片只覆盖 MessageBus/工具状态事件/telemetry、session/checkpoint/history、scheduler 与恢复边界。
- 结论标签：`verified`=官方文本/实现直接支持；`inferred`=由实现行为推导但官方未作该语义承诺；`unknown`=公开证据不能证明；`conflict`=官方材料存在需要保留的张力。
- 证据等级：A=官方文档明确行为；B=官方实现直接行为；C=官方测试覆盖；D=实现旁证/负面证据（不能替代缺失的规范）。

## 结论摘要

1. **MessageBus 不是持久化总线**（verified，B）：它是进程内 `EventEmitter`；publish 直接 emit，未见磁盘、队列或跨进程 transport。工具状态更新也是 fire-and-forget publish。因此发送失败、无监听者、进程终止造成的完整性并未得到持久化保证。
2. **MessageBus 没有已证实的自动重试/确认语义**（verified/inferred，B）：request 只等待 correlation response 并在超时 reject；publish 捕获错误并发 `error` 事件而不重发。不能把 request timeout 当作远端执行失败或回滚。
3. **telemetry 有内存批处理及显式 flush/shutdown，但不是 durable audit log**（verified，A/B）：local 文件 exporter 使用 append stream；OTel Batch processors 缓冲并异步导出；shutdown/forceFlush 路径存在。源码没有 WAL、fsync、跨重启补发或端到端 ack 的保证。
4. **session JSONL 的单条记录写入是 append，不是 crash-atomic/durable commit**（verified，B）：`appendFileSync` 写一行后更新内存；无 fsync、校验和、事务边界。读取器会忽略坏 JSON 行，所以部分尾行可以被容忍，但这不是“恢复未写完记录”的证明。
5. **session 的全量 rewrite 采用 temp+rename，并保留 unreadable 旧文件；但 backup→rename 之间仍有未定义崩溃窗口**（verified + unknown，B）：原文件先改名为 `.unreadable-*`，之后写 temp、rename；无法从公开代码证明目录 fsync、rename 后 durable、并发协调或孤儿 temp 的恢复。
6. **checkpoint 将 Git snapshot 与 JSON checkpoint 分两步构造，不能证明原子配对**（verified/inferred，B/C）：Git snapshot 失败会 fallback 到 current commit 或跳过；checkpoint JSON 由调用方后续写入，公开实现没有跨仓库事务、去重或提交标记。`/restore` 对 JSON 逐文件读取并 schema 校验，坏 JSON 被拒绝/列举时忽略。
7. **scheduler 状态是进程内可观察快照，不是重启可重建的业务审计**（verified，B）：`SchedulerStateManager` 维护 Map/queue/completedBatch，每次状态变更发 `TOOL_CALLS_UPDATE`；没有 session/checkpoint 持久化或 replay log。跨重启无法仅凭该状态恢复队列、活动调用或每次状态转移。
8. **跨进程/跨重启 remote session 续接未被证明**（verified/inferred，B）：`RemoteSessionInvocation.sessionState` 是静态 Map，明确只在当前 Node 进程中的 invocation 实例间保留 contextId/taskId；进程退出即丢失。远端服务是否保留副作用/上下文、重发是否去重，官方这组证据未覆盖。
9. **完整业务审计、exactly-once、回滚与远端副作用一致性均 unknown**：公开 telemetry/session/scheduler 记录是观测或恢复辅助，不构成包含 intent→dispatch→effect→result 的不可抵赖事务账本；没有公开的全局事件 ID/幂等协议/两阶段提交/补偿事务证明。

## Claim-to-evidence ledger

### C1 — MessageBus 的落盘与跨进程边界
- **status: verified；evidence level B**
- **结论**：`MessageBus` extends Node `EventEmitter`；`publish()` 校验后直接 `emitMessage()`，普通消息直接 emit，未写文件/数据库/网络，也未建立 durable queue。派生 bus 仍绑定父 bus 的订阅/emit 方法。
- **exact sources**：
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/confirmation-bus/message-bus.ts
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/confirmation-bus/message-bus.test.ts
- **direct support**：实现中的 `class MessageBus extends EventEmitter`、`emitMessage()` 和普通消息 `this.emitMessage(message)`；测试断言 publish 后 listener 收到消息。
- **caveat**：未检索到一个名为 `ToolCallEvent` 的 durable event-log API；因此不能把 MessageBus 事件推断成跨进程审计事件。

### C2 — MessageBus 发送失败、重试与丢失
- **status: verified（无重试）；inferred（可能丢失）**；**evidence level B/C**
- **结论**：publish 的异常路径是 `catch` 后 `this.emit('error', error)`，没有 retry/backoff/持久 outbox。`request()` 用 correlation ID 和定时器等待 response，超时 reject；这只是等待协议，不是 delivery/执行确认。无监听者时 ASK_USER 分支直接发 confirmed=false/requiresUserConfirmation。
- **exact sources**：
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/confirmation-bus/message-bus.ts
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/confirmation-bus/message-bus.test.ts
- **direct support**：`publish()` catch emits error；`request()` timeout cleanup/reject；测试覆盖 policy error 不抛出而触发 error handler。
- **caveat**：EventEmitter listener 的同步异常与 `publish` 自身策略不能代表所有调用方；官方没有 delivery guarantee 声明，故“特定崩溃下必丢”标 unknown 而不作 verified。

### C3 — telemetry 是否落盘、失败是否重试
- **status: verified（配置路径/批处理）；unknown（端到端 durability/retry）**；**evidence level A/B**
- **结论**：官方文档支持 local `outfile`；File exporters 以 append `WriteStream` 写 span/log/metric，并以 callback 返回 success/failed；SDK 使用 `BatchSpanProcessor`/`BatchLogRecordProcessor`，并提供 `forceFlush()` 与 `shutdown()`。GCP log exporter维护 pending promise并报告 success/failed。公开代码没有 telemetry WAL、失败持久队列、跨重启 replay 或 exporter 级 retry policy 的证据。
- **exact sources**：
  - https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/telemetry.md
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/telemetry/file-exporters.ts
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/telemetry/gcp-exporters.ts
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/telemetry/sdk.ts
- **direct support**：文档的 local telemetry `outfile` 示例；FileExporter `createWriteStream(...,{flags:'a'})`；SDK processors/buffer/flush/shutdown；GCP write promise catch 返回 FAILED。
- **caveat**：底层 OpenTelemetry/exporter 依赖可能有自己的行为，但本片只把仓库直接可见行为计入；不能从 `forceFlush` 推出 fsync 或远端 durable acknowledgement。

### C4 — session 写入、读取和部分写入恢复
- **status: verified（实现事实）；unknown（崩溃完整恢复）**；**evidence level B/C**
- **结论**：新 session 先 append metadata；消息和 metadata update 逐条 `appendFileSync` 为 JSONL。读入逐行 JSON，单行 parse error 被忽略；因此 reader 对坏行具容忍性，但没有修复/截断/校验后续边界的事务协议。append 成功后才更新 cached in-memory record；空间不足会关闭 recording 并继续运行。没有 fsync 或 record checksum/sequence proof。
- **exact sources**：
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/services/chatRecordingService.ts
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/services/chatRecordingTypes.ts
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/services/chatRecordingService.test.ts
- **direct support**：`appendRecord()` 的 `fs.appendFileSync`；`loadConversationRecord()` 的逐行 JSON.parse 和 catch ignore；ENOSPC warning 文本说明 conversation continues but will not be saved。
- **caveat**：单行 append 在常见文件系统上的实际短写/崩溃表现没有官方测试覆盖；不能宣称每个 partial line 都能安全恢复，也不能宣称 append 的完整性边界。

### C5 — session rewrite 的原子性边界
- **status: verified（temp+rename 设计）；unknown（全链路原子 durable）**；**evidence level B**
- **结论**：`rewriteConversationFile()` 将 unreadable 旧文件先 rename 成 `.unreadable-${Date.now()}`，再把完整内容写到 `.tmp-${pid}` 并 rename 到 session 路径；rename 失败时尝试删除 temp。该路径比直接覆盖有清晰的替换语义，但代码没有 directory fsync、文件 fsync、跨进程 lock 或启动时扫描/恢复 backup/temp 的逻辑证据。
- **exact sources**：
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/services/chatRecordingService.ts
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/services/chatRecordingService.test.ts
- **direct support**：源码注释明确写“new file is written atomically (temp file + rename)”；实现先 backup 再 temp write/rename。
- **caveat**：这里的 verified 只针对代码采用 temp+rename；“机器掉电后一定旧或新且不丢”是 unknown。

### C6 — checkpoint 与 restore 的配对、失败和去重
- **status: verified（流程事实）；unknown（原子配对/去重/回滚）**；**evidence level B/C/A**
- **结论**：checkpoint 数据包含 history/clientHistory、Git commitHash、toolCall、messageId；处理工具调用时先 `createFileSnapshot`，失败 fallback current commit，仍无 hash 则跳过；JSON checkpoint 内容由结果 map 交给上层写入。restore 只接受 JSON 文件、读取后 schema 校验，坏 JSON/缺 messageId 的列表项被忽略。没有跨 shadow Git repo 与 checkpoint JSON 的事务 marker、唯一提交协议或恢复时自动检测两者不一致。
- **exact sources**：
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/utils/checkpointUtils.ts
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/utils/checkpointUtils.test.ts
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/cli/src/ui/commands/restoreCommand.ts
  - https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/checkpointing.md
- **direct support**：`processRestorableToolCalls()` 的 snapshot/fallback/map；`getCheckpointInfoList()` catch invalid JSON；restore command 的 `safeParse` 和 `performRestore`；文档说明 snapshot/history/tool call 的组成及本地存储。
- **caveat**：Git 自身 commit durability/atomicity 不等于应用级 checkpoint transaction；官方 integration test 证明正常 create/restore，不覆盖 kill -9 或跨文件崩溃窗口。

### C7 — scheduler 状态与 TOOL_CALLS_UPDATE
- **status: verified**；**evidence level B/C**
- **结论**：`SchedulerStateManager` 仅持有 `activeCalls Map`、`queue`、`_completedBatch`；enqueue/dequeue/status/finalize/cancel 等变化调用 `emitUpdate()`，其通过 `void this.messageBus.publish({type: TOOL_CALLS_UPDATE, toolCalls: snapshot, schedulerId})` fire-and-forget。状态快照不是持久事件日志，scheduler dispose 只结束当前运行的协调。
- **exact sources**：
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/scheduler/state-manager.ts
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/scheduler/state-manager.test.ts
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/scheduler/scheduler.ts
- **direct support**：字段定义、`getSnapshot()`、`emitUpdate()` 的注释“Fire and forget”；测试只捕获 mock publish 并验证快照顺序/状态。
- **caveat**：下游可能另行记录消息，但本片没有证据证明所有状态更新都被 session recording 接收并持久化。

### C8 — scheduler 是否可重建完整业务审计
- **status: unknown（不能证明）**；**evidence level D**
- **结论**：从公开 state manager/scheduler 证据，不能重建跨重启时的 queued/active/completed 全部历史，更不能重建每次确认、派发、执行开始、远端效果和结果的不可变顺序。`TOOL_CALLS_UPDATE` 是当前 snapshot 而不是 append-only event stream；MessageBus 又是进程内非持久总线。
- **exact sources**：
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/scheduler/state-manager.ts
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/confirmation-bus/message-bus.ts
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/services/chatRecordingService.ts
- **caveat**：这是证据边界结论，不是断言系统绝对没有其他 integration；未见公开的 scheduler event-sourcing/replay API。

### C9 — remote session 的跨进程/重启边界与远端副作用
- **status: verified（本地保存范围）；unknown（远端持久化/副作用/去重）**；**evidence level B**
- **结论**：`RemoteSessionInvocation` 用 static `Map` 按 name+target URL 保存 A2A `contextId/taskId`，用于 ephemeral invocation instances 之间续接；这只能覆盖同一 Node 进程。源码未给出跨重启 durable storage、远端 effect journal、idempotency key 或 exactly-once handshake。重发、断连、客户端崩溃与远端已执行但本地未记账的窗口均未由这些官方资料定义。
- **exact sources**：
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/agents/remote-session-invocation.ts
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/agents/local-session-invocation.ts
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/agents/remote-subagent-protocol.ts
- **direct support**：源码注释明确 `static map` “across ephemeral invocation instances”，key 为 name+URL；execute seed prior state then send/getResult。
- **caveat**：远端 A2A 服务自身的实现不在本片允许范围，故远端是否持久化 context/task 或具备幂等性必须标 unknown。

### C10 — exactly-once、去重、回滚和崩溃窗口
- **status: unknown**；**evidence level D**
- **结论**：官方公开证据未覆盖以下保证：消息/工具调用的 exactly-once 投递或执行；全局去重键与幂等存储；远端副作用的提交确认；跨 session/telemetry/scheduler 的事务；崩溃后自动补偿/回滚；checkpoint 恢复对已发生远端副作用的撤销。checkpoint 的 Git restore 只能证明受 Git snapshot 管理的项目文件可恢复，不能推导外部副作用回滚。
- **exact sources**：
  - https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/checkpointing.md
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/utils/checkpointUtils.ts
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/scheduler/state-manager.ts
  - https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/telemetry/sdk.ts
- **caveat**：unknown 不等于不存在；仅表示本片限定的官方公开材料没有可核查承诺或测试。

## 覆盖范围与收口

已首轮直接读取：官方 checkpointing/session-management/telemetry 文档；MessageBus 实现/测试；telemetry file/GCP exporters 与 SDK；ChatRecordingService/types；checkpoint utilities/tests/restore command；scheduler/state manager/scheduler/tests；remote/local session invocation；checkpointing/telemetry integration tests。未 clone 仓库，未访问任何私有、事故、真实服务或凭据。

未做的事是有意的：没有把本片扩展到一般可靠性、模型重试策略、systemd、canonical、tri-line、其他目录或非 google-gemini/gemini-cli 资料。官方资料没有提供可用于证明的 kill/restart fault-injection、跨进程 replay、远端 effect ledger 或 exactly-once 测试；对应结论保持 unknown。

### 最小可验证下一步（不改变本片结论）
若未来要把 unknown 变成 verified，需要官方仓库新增或公开：带进程杀死点的 crash-injection 测试；append/rename 后 fsync 语义；跨进程 durable outbox/replay；scheduler append-only event log；远端调用幂等键及 effect receipt。当前不能用正常集成测试替代这些证据。
