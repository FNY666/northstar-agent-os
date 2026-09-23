# S13 审计重建与缺口研究报告

- 研究目录：`/tmp/B-GEMINI-CLI-RESEARCH-20260922-S13/`
- 研究时间：2026-09-22（Asia/Shanghai）
- 允许范围：仅 `google-gemini/gemini-cli` 官方公开 GitHub 文档、源码、测试/API；未 clone 仓库。
- 禁止范围遵守：未访问、读取、写入或验证 shared/P0、事故目录、D10/L12/D14、canonical、140、tri-line、systemd、真实服务或凭据；未修改 S4-S12。
- 证据等级：L1=官方文档；L2=官方源码；L3=官方测试/API（本片主要使用 L1/L2）。

## 最小审计视图

给定 session JSONL、checkpoint shadow Git、OTel events、MessageBus/tool events，以及 policy/telemetry 设置，最多可重建：

1. **会话/对话视图（部分）**：会话 ID、按历史记录保存的 prompt/模型响应、tool execution 的输入/输出、token usage（如果该 session 记录存在且未被保留策略清除）。源码还显示历史转换会把现代 `content` 作为来源，并从旧格式的 `toolCalls` 重建 function call/response；稳定 tool ID 可被补齐。不能把“可读取/可转换”提升为每行 schema、原子写入或无损历史的证明。
2. **调度/工具视图（部分）**：tool `callId`、tool name/args、状态转换/结果，以及 session ID 与 OTel tool span 的关联。MessageBus/confirmation 路径可以解释调度层的等待/批准交互；但所见 CoreEvent/EventEmitter 是进程内事件通道，不是独立持久化审计日志。
3. **文件变更回退视图（有边界）**：checkpoint 记录 checkpoint 文件名、`commitHash`、tool call（name/args）、`messageId`；shadow Git snapshot 可提供 AI 文件修改前的项目文件状态，并可将对话历史恢复到该点、重新提出原 tool call。
4. **遥测视图（条件性）**：可按 `gen_ai.conversation.id`（CLI session ID）、`gen_ai.tool.call_id`、operation name、tool name、输入/输出（仅启用详细 trace 时）和工具/会话事件属性进行相关。配置为 file exporter 且正常 flush/shutdown 时，可从文件得到 exporter 写出的记录；OTLP/GCP/console 等路径只能说明提交/导出尝试，不能由输入材料单独证明后端已收到。
5. **策略/设置上下文（有限）**：可以将当时可获得的 approval mode、telemetry 开关/trace 开关作为上下文；不能据此重建不可变的政策版本、完整匹配规则快照或授权主体快照。

## 逐条结论与缺口

### C1 — session JSONL 能重建对话和工具调用的最小时间线

**结论：VERIFIED（L1/L2）；证据等级 L1+L2。** 官方 session 文档明确说历史自动保存，并包括 prompts、model responses、所有 tool executions 的 inputs/outputs 与 token usage；源码的 session 转换逻辑显示现代 `content` 是来源，旧格式的 tool metadata 可转换为 function call/response，且提供 stable tool IDs。

**可重建字段**：session 文件/ID（若存在）、对话 content、tool name/args/result、稳定的 tool-call 对应关系（对合法且完整记录）。

**Caveat**：官方材料没有在本研究中证明每一行 JSONL 的公开固定 schema、写入原子性、崩溃前最后一行是否落盘；session retention 默认 30 天且可删除 artifacts。因此缺行、截断或已清除记录不能补推。

### C2 — scheduler/tool/MessageBus 具备关联字段，但不是完整持久化事件链

**结论：VERIFIED（关联字段）；UNKNOWN（持久性/全链路）。证据等级 L2。** `ToolCallRequestInfo` 包含 `callId`、name、args 等；Scheduler 按 callId 查找/更新状态，ToolExecutor 用同一 callId 生成 tool span 属性；trace 还将 session ID 写入 `gen_ai.conversation.id`。CoreEvent 中包含 approval-mode、consent、MCP progress 等事件，且 EventEmitter 带有限 backlog。

**可重建视图**：request → validating/scheduled/executing/success/error/cancelled/waiting 的调度层状态（以可用事件/结果为限），以及同一 tool call 与 session/span 的 join。

**Caveat**：EventEmitter/backlog 是运行时内存结构；源码证据不等于事件已写入 session JSONL 或可靠日志。因而审批请求、批准响应、tool response、重试之间的完整链条仍可能断裂；缺少 event 的部分保持 unknown。

### C3 — checkpoint shadow Git 的恢复边界可明确

**结论：VERIFIED（机制/边界）；UNKNOWN（外部副作用）。证据等级 L1+L2。** 官方 checkpoint 文档说明：文件修改前在 `~/.gemini/history/<project_hash>` 的特殊 shadow Git repository 创建 snapshot，并另存 conversation history 与 tool call JSON；源码的 `ToolCallData` 包含可选 `commitHash`、tool call 与 `messageId`，restorable tool call 以 `callId` 映射 checkpoint 文件。创建 snapshot 失败时源码会尝试当前 commit，并记录错误。

**可重建视图**：项目文件在修改前的 Git snapshot（如果 snapshot 成功）、触发它的 tool name/args、对应 messageId/callId、checkpoint 文件名；`/restore` 可恢复文件和对话，并重新提出原 tool call。

**Caveat**：这是文件状态与 CLI 历史的恢复，不是远端系统事务日志。已发送网络请求、已执行外部命令的非文件副作用、第三方状态、模型服务端状态不由 shadow Git 回滚；snapshot 失败/无 `file_path`/当前 commit fallback 时恢复能力降级。

### C4 — OTel attributes/events 可做相关分析，但默认不构成完整审计副本

**结论：VERIFIED（字段/默认设置）；INFERRED（交付性边界）；UNKNOWN（远端送达）。证据等级 L1+L2。** 官方 telemetry 文档列出 operation name、tool name、tool call ID、conversation ID、input/output messages 等 span attributes，并明确详细 trace attributes（完整 prompt/tool output 等）默认关闭，需要显式启用。源码把 session ID 作为 resource/common attribute，ToolExecutor 给 span 设置 tool call ID；logger 先写 UI/Clearcut 路径并通过 `bufferTelemetryEvent` 排队 OTel 写出。

**持久性**：官方 file exporter 源码使用 append stream，并提供 flush（空写入回调等待先前写入）和 shutdown；SDK 采用 batch span processor/不同 exporter。故仅在 file exporter 的文件实际存在且 flush/shutdown 成功时，才能把“写出文件”视为本地持久性证据。

**Caveat**：attributes/events 的生成、buffer、export callback 不证明 collector/backend 收到或永久保存；采样、禁用详细 traces、崩溃/中止、网络失败均可造成缺口。OTel 视图不能替代 session JSONL 或 approval ledger。

### C5 — policy/telemetry 设置只能作为当时上下文，不能证明策略与授权快照

**结论：UNKNOWN（完整策略版本/授权快照）；VERIFIED（approval mode 被若干事件/属性暴露）。证据等级 L1+L2。** 官方 policy 文档描述规则、优先级、approval modes 与持久批准的 mode 语义；事件模型包含 approval-mode-changed 且 payload 有 sessionId；telemetry 文档列出 approval mode 属性。

**不能证明**：给定一条 tool event 时使用的完整规则集合、规则文件内容 hash/版本、最终匹配规则、授权人/授权主体、批准时的完整 UI/身份/凭证快照。若这些输入材料没有显式快照，结论必须保持 unknown，不能从 mode 字符串反演。

### C6 — 远端副作用、去重、exactly-once、回滚语义保持 unknown

**结论：UNKNOWN；证据等级 L1/L2 的负面边界推断。** 资料支持 checkpoint 回滚项目文件、session 恢复和 tool-call 重提，但没有证明跨远端系统的事务、幂等键、去重日志、补偿事务、exactly-once 交付或远端回滚。`callId` 是关联标识，不应当被当作幂等/去重承诺。

**审计处置**：报告中不得把 tool event 数量等同于远端执行次数；不得把一次 exporter callback 等同于后端接收；不得把 `/restore` 等同于已撤销外部副作用。

## 缺口矩阵

| 视图/问题 | 最小可见证据 | 结论 | 保持 unknown 的部分 |
|---|---|---|---|
| JSONL history | session history、content、tool input/output、token usage | verified（部分时间线） | 固定行 schema、原子性、崩溃尾部、已清理历史 |
| scheduler/tool/MessageBus | callId、sessionId、状态、confirmation/consent 运行时事件 | verified（关联）；unknown（完整链） | 进程外持久性、审批请求-响应完整配对、重试/丢失 |
| checkpoint shadow Git | commitHash、tool call、messageId、文件 snapshot | verified（文件回退边界） | 非文件副作用、远端事务、snapshot 失败时完整性 |
| OTel | conversation.id、tool.call_id、operation/attributes/events | verified（生成字段） | 默认详细内容关闭、采样、collector/backend delivery、永久保存 |
| policy/telemetry settings | approval mode、trace 开关、规则文档语义 | verified（上下文） | policy version/hash、授权主体/快照、最终匹配证明 |
| exactly-once/dedup/rollback | 未发现官方承诺或 ledger | unknown | 不得从 callId、span 或 checkpoint 推断 |

## 证据使用规则

- 只采用下方官方 URL；源码链接使用 `main` 分支公开文件，记录以本次抓取内容为准。
- 本片没有 clone 全仓库，没有创建自定义 validator，没有运行真实服务或使用凭据。
- 已使用既有 `/var/minis/skills/evidence-first-research/scripts/validate_research.py` 校验 manifest，并使用 `sha256sum -c SHA256SUMS` 校验本目录文件。
