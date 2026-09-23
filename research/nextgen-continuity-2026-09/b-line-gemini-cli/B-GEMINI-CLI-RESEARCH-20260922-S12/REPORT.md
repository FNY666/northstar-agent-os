# S12：官方持久化审计边界（Google Gemini CLI）

- 研究时间：2026-09-22（Asia/Shanghai）
- 研究对象：`google-gemini/gemini-cli` 官方公开 GitHub 文档、源码与测试；取证基线为 `main` 当前提交 `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`。
- 允许范围：仅官方 GitHub 页面/raw 源码；未 clone 全仓库，未访问任何真实服务、凭据或被禁止目录。
- 术语：正文用 `verified / inferred / unknown / conflict`；manifest 为兼容既有官方 schema，将其映射为 `confirmed / inferred / unverified / conflicting`。

## 结论摘要

1. **verified（实现层）**：正常会话记录采用 JSONL；追加记录的顺序是先 `appendRecord(message)`，再更新内存，随后 `updateMetadata` 追加 `$set`。消息/工具调用等记录不是先改内存再异步落盘。
2. **verified + unknown（边界）**：不可读文件重写路径使用临时文件后 `renameSync` 发布，并尝试先把旧文件重命名为 `.unreadable-*` 备份；这证明了“发布替换”的原子命名操作意图，但没有 `fsync`/目录 fsync，因此**不能证明断电 durable**，也不能证明每种失败下总有完整可恢复版本。
3. **verified（部分写入风险）**：常规追加使用 `appendFileSync`，摘要/工作流元数据对 JSONL 使用 `fs.appendFile`；没有事务、长度校验或校验和。进程/设备在单条 JSON 行写完前中止时，恢复结果与截断尾行行为不能从源码证明为完整，故该耐久性/低损失结论为 **unknown**。
4. **unknown**：在本次官方源码范围内没有发现名为 checkpoint 的独立持久化协议或 checkpoint 创建/恢复原子提交语义。会话 `rewind` 是追加 `$rewindTo` 标记并在读取时解释，不等于 checkpoint 快照；因此“checkpoint 部分写入可安全恢复”不能宣称。
5. **verified + unknown**：文件 OTel exporter 以 append stream 写入；`forceFlush` 通过排队空写的 callback 等待此前 stream 写入完成，`shutdown` 调用 `writeStream.end`。SDK 也有 `forceFlush`/`shutdown`。这些证明了应用级队列排空/stream 结束路径；没有 `fsync`，所以**不证明磁盘 durable、不可丢失或低损失**。
6. **verified**：`MessageBus` 是内存中的 `EventEmitter`，publish 直接 emit；其源码没有文件/数据库写入。事件本身不会因 MessageBus 自动落盘，重启后不能从 bus 重放。
7. **unknown**：日志/OTel 事件确实包含工具调用、decision、success、时长等字段，并有 API response、rewind 等事件入口；但异步 batch、采样/导出失败、截断/脱敏及事件与具体批准请求/副作用的绑定完整性，源码不足以证明。因此日志/OTel **不足以被宣称能完整重建审批链和工具副作用**。
8. **unknown（immutable/complete）**：JSONL 可追加且重写会产生备份，但源码没有哈希链、签名、不可变存储或独立副作用账本；不能证明记录 immutable、complete，或工具副作用与批准一一对应。

## 逐条审计

| ID | 结论（窄主题） | 状态 | 证据等级 | caveat |
|---|---|---|---|---|
| S12-C1 | 会话消息写入顺序是 append 消息，再更新内存，再 append `$set` 元数据。 | verified | A（官方源码直接证据） | `appendFileSync` 成功仅表示 Node 调用完成；不等于设备已持久化。异常时调用者可收到错误，但中止窗口仍未建模。 |
| S12-C2 | 不可读会话的重写使用 temp + rename，并保留旧文件到 `.unreadable-*`。 | verified | A | `renameSync` 是文件系统命名发布；代码没有 fsync 文件或父目录，故 durable/断电一致性 unknown；在备份成功而后续写入失败时，主路径可能暂时不存在。 |
| S12-C3 | 会话追加与 JSONL 摘要追加不是事务；截断尾行、写入中断及跨进程并发下的完整性/低损失未被证明。 | unknown | A（直接源码）+ B（边界推论） | 测试覆盖常规调用与若干错误恢复，但不是断电、kill -9、文件系统故障或多进程模型；不要把测试名称中的 durable 当作操作系统 durability 证明。 |
| S12-C4 | 官方源码没有可确认的独立 checkpoint 创建/恢复协议；`rewind` 是日志标记，加载时解释。 | unknown | A | “未找到”受本次固定提交与公开源码搜索范围限制；不能据此断言项目永远没有 checkpoint。 |
| S12-C5 | 文件 exporter 的 forceFlush/shutdown 等待 Node stream 队列/结束，但未证明 fsync 或 durable export。 | unknown | A（源码）+ B（边界推论） | `write('', callback)` 与 `end(resolve)` 的语义是应用/stream 层；远端 OTLP/collector 更涉及网络确认与服务端持久化，本次不访问真实服务。 |
| S12-C6 | MessageBus publish 是同步事件分发到内存 EventEmitter；MessageBus 自身不落盘。 | verified | A | 调试日志可选且不是 MessageBus 的持久化协议；监听器是否另行记录须单独审计。 |
| S12-C7 | OTel/日志有工具调用 decision/success 与相关 API/rewind 事件字段，但不足以证明完整审批链和工具副作用重建。 | unknown | A（字段/调用路径）+ B（完整性边界） | batch processor、异步导出、错误处理、事件缺失/脱敏/截断和独立工具真实副作用账本均使“complete reconstruction”不可证明。 |
| S12-C8 | 会话/日志没有被源码证明为 immutable、complete 或低损失审计账本。 | unknown | A | 追加文件、备份、OpenTelemetry 不自动带来哈希链、签名、WORM、事务或副作用证明；不得将“有记录”升级成这些性质。 |

## 证据阅读要点

- `ChatRecordingService.pushMessage` 明确先调用 `appendRecord(msg)`，成功后才更新 `cachedConversation`；`recordMessage` 随后调用 `updateMetadata`。这回答的是代码调用顺序，不是崩溃/断电后的 durable 顺序。
- `rewriteConversationFile` 的注释明确写 “atomically (temp file + rename)”；实现先备份旧文件，再 `writeFileSync(tempFile, content)`，再 `renameSync(tempFile, conversationFile)`。未见 `fsync`。
- `loadConversationRecord` 按行 JSON.parse，遇到 `$rewindTo` 修改内存中的 message map；这是日志重放/裁剪，不是 checkpoint 恢复协议。
- FileExporter 的文件以 `{ flags: 'a' }` 打开；export 使用 `write` callback；forceFlush 不调用 `fs.fsync`；shutdown 只调用 `end`。
- `MessageBus` 只继承 EventEmitter，publish 经 policy check 后 `emitMessage`；源码无文件、数据库、journal 或 checkpoint 写入。
- OTel `logToolCall` 通过 logger.emit 写入 tool-call 事件与 metrics；事件可含 decision/success，但这只证明观测字段存在，不证明每次审批、执行前后状态和外部副作用都被 durable、无缺口地记录。

## 覆盖与未决问题

已覆盖：session JSONL 追加/重写顺序、原子命名替换、rewind 读取、摘要 append、OTel file exporter flush/shutdown、SDK shutdown、MessageBus、工具调用观测字段。

未能从公开官方源码证明：操作系统崩溃一致性、fsync/磁盘缓存策略、跨进程并发、独立 checkpoint 协议、远端 collector 服务端 durable、所有审批事件与副作用的关联/完整性、WORM/签名/哈希链。按要求全部保留为 unknown，未把推断写成 durable、immutable、complete 或 low-loss。

## 来源

详见同目录 `sources.md` 与 `research-manifest.json`。原始取证副本仅位于本次全新目标目录的 `evidence/`。
