# S14：崩溃窗口恢复判定——官方 Gemini CLI 证据切片

- **研究日期**：2026-09-22（Asia/Shanghai）
- **范围**：只核验 `google-gemini/gemini-cli` 官方公开 GitHub 文档、源码和测试；窄主题限定为 AbortSignal/timeout、stream failure/retry、tool execution failure、checkpoint/session 恢复及 history 的部分写入。
- **判定词**：**VERIFIED**=官方源码/测试/文档直接支持；**INFERRED**=由实现行为推导、但没有证明更强的语义；**UNKNOWN**=本批官方资料没有证明；**CONFLICT**=官方材料之间存在不一致。本片没有把单次工具调用完成当成远端副作用已确认。

## 结论（先给可操作判定）

1. **AbortController 是本地协作取消信号，不是远端撤销确认。VERIFIED。** UI 取消先 `abort()`，再调用工具队列的 `cancelAllToolCalls(signal)`；取消后的内容事件被丢弃。核心重试器在进入重试前、每次循环前和错误处理后检查 signal，已 abort 时抛 `AbortError`，且测试确认不会开始下一次尝试或发出 `onRetry`（证据 C1、C2、C3）。这证明“本地恢复/显示状态停止”的窗口，不证明已经到达远端 API，也不证明远端没有执行工具或模型请求。
2. **timeout 覆盖的是可分类的网络/Undici 超时重试路径，而非通用的‘操作未发生’判定。VERIFIED + UNKNOWN 边界。** 官方测试直接覆盖 `UND_ERR_HEADERS_TIMEOUT`，并在失败后第二次调用成功；源码将 `UND_ERR_HEADERS_TIMEOUT`、`UND_ERR_BODY_TIMEOUT`、`UND_ERR_CONNECT_TIMEOUT`列入网络重试分类。没有在本批官方测试中找到 `AbortSignal.timeout(...)` 的直接测试，也没有看到“超时后远端副作用必未发生”的断言。因此：超时可判定为本地请求失败/进入重试（在可重试分类内），**不能**判定远端副作用未发生。
3. **流已产出部分 chunk 后的 503 stream failure 可以重试。VERIFIED。** 官方测试让第一次 stream 产出 `First part` 后抛 503，第二次产出 `Retry success`；断言事件包含首 chunk、`RETRY` 和成功 chunk。对于 generic fetch/socket 错误，只有开启 `retryFetchErrors` 时该路径重试；400 `ApiError` 明确不重试并向调用者抛出。源码也将 `fetch failed`/incomplete JSON（需配置开关）纳入分类。该行为是“重发请求”的恢复策略，不是 exactly-once；测试没有证明首个远端请求是否已经被服务端处理。
4. **tool execution failure 在 UI/agent 事件层面被标记为 Error；取消则标记 Cancelled。VERIFIED。** Agent stream 对 `tool_response.isError` 设置 `CoreToolCallStatus.Error`，对成功设置 Success；取消流程对 shell tool 设置 Cancelled。此状态是客户端观察到的事件/状态，不是对工具外部副作用的事务性结论。没有官方测试证明 tool 的远端或外部系统副作用能够回滚、去重或 exactly-once。
5. **checkpoint 保存的是本地 Git 快照 + conversation/client history + 待执行 tool call；恢复会恢复本地文件与 CLI 会话历史，并重新提出原 tool call。VERIFIED。** 官方文档明确描述保存内容和 `/restore` 语义；测试验证快照后修改/删除文件，再恢复到快照状态；工具 checkpoint 单元测试验证写入 commit hash、history、clientHistory、toolCall、messageId。**这不是对远端副作用的回滚。** 文档和测试只涉及项目文件/本地会话。
6. **checkpoint 创建失败有降级，但不是原子安全保证。VERIFIED + INFERRED。** `createFileSnapshot`失败时官方单测验证回退到当前 commit hash；若无 hash 则跳过 checkpoint 并记录错误。由此可推断 checkpoint 可能不可用、恢复窗口可能缺失；不能把 fallback hash 或错误记录解释为工具尚未执行，更不能解释为远端状态已回滚。
7. **session history 可恢复、可回滚到指定本地长度；部分写入/崩溃后的精确重建仍不能判定。VERIFIED + UNKNOWN。** `AgentChatHistory.rollback(length)` 只裁剪内存中的 durable turns；其注释将 stream failure 作为用途。session 文档说 history 自动保存并可 resume，包含 prompts、responses、tool executions/outputs。UI 还维护 pending history item，只有在完成/终止状态时推入显示历史；取消时可立即写入被取消的 shell tool。没有本批官方测试直接模拟“进程在写入一半时崩溃”，也没有证明持久化文件写入原子性、截断文件修复、最后一条 message 是否重建。因此崩溃窗口中 message history 的完整性为 UNKNOWN，最多只能说设计存在本地 rollback/resume 机制。
8. **崩溃后远端状态、去重、回滚、exactly-once 均 UNKNOWN（本片硬边界）。** 官方公开资料核验到的是客户端取消、重试、工具 UI 状态和本地 checkpoint/session；未找到远端副作用提交确认、幂等键/去重协议、分布式事务回滚、崩溃恢复后的远端查询核对或 exactly-once 证明。即使收到部分 stream、tool success 或本地 checkpoint，也不能据此断言远端副作用“已发生”或“未发生”。

## 恢复判定窗口矩阵

| 窗口/观测 | 官方直接覆盖 | 可安全判定 | 不能判定 |
|---|---|---|---|
| `AbortController.abort()` 前后 | retry 单测 + UI 源码 | 本地重试循环停止；本地后续内容可被抑制；可见取消状态 | API/工具是否已在远端接收、执行或提交 |
| Undici headers/body/connect timeout 分类 | retry 单测/源码 | 失败可进入配置允许的重试；最终可能抛最后错误 | 超时发生在远端处理前还是处理后；副作用是否存在 |
| stream chunk 后 503 | GeminiChat 网络重试单测 | 会发 `RETRY` 并重建 stream（该错误类别） | 首次请求的服务端处理结果；重试是否重复副作用 |
| generic fetch/socket failure | 单测（需 `retryFetchErrors=true`） | 配置开启且分类命中时可重试 | 失败前发送的请求是否已生效 |
| tool response `isError` | Agent stream 源码 | 客户端 tool 状态为 Error | 外部工具是否做了部分副作用、是否可补偿 |
| checkpoint 成功 | checkpoint 文档/单测/集成测试 | 本地项目文件和保存的会话元数据可回到 snapshot | 远端 API/tool 状态回滚 |
| checkpoint snapshot 失败 | 单测 | 可回退 current commit；无 hash 时记录错误并跳过 | tool 是否尚未执行；是否存在远端未回滚状态 |
| session resume/rollback | session 文档、AgentChatHistory 单测/源码 | 已持久化的本地历史可 resume；内存 turns 可按长度裁剪 | 崩溃时最后一条/部分 message 是否完整、持久化写是否原子 |
| 进程崩溃后远端状态 | 未发现官方直接证明 | UNKNOWN | 已发生/未发生、去重、回滚、exactly-once |

## 证据逐项核验

### 1) AbortSignal 与 timeout

- **C1 VERIFIED（E1，直接测试）**：`retryWithBackoff` 收到已 abort signal 会抛 `AbortError`；在第一次 500 后、下一次 backoff 期间 abort，测试确认只调用 mock 一次。另两个测试确认错误处理或 content-retry 判断中触发 abort 时，不调用 `onRetry`。
- **C2 VERIFIED（E2，生产源码）**：`retryWithBackoff` 在初始、while 循环和 catch 后检查 signal；`AbortError` 原样抛出。UI 取消顺序是先 abort，再清理待执行工具。
- **C3 VERIFIED（E1+E2）**：直接 timeout 测试是 `UND_ERR_HEADERS_TIMEOUT`；源码还列出 body/connect timeout。**UNKNOWN**：本次官方范围没有 `AbortSignal.timeout()` 直接测试，也没有 deadline 与远端提交确认的测试。

### 2) stream failure/retry 与 tool execution

- **C4 VERIFIED（E1）**：503 发生在 stream iteration、且首 chunk 已产生时，测试仍期待 RETRY 和第二 stream 成功 chunk；generic fetch error 需 `retryFetchErrors` 开关；400 不重试。
- **C5 VERIFIED（E2）**：UI/agent stream 将 tool response 的 `isError` 映射为 Error，并将取消的 shell tool 映射为 Cancelled；内容流在用户取消后不再接受额外输出。
- **C6 UNKNOWN**：上述测试没有远端副作用探针、幂等键、tool invocation ID 的服务端去重或补偿事务。因此 stream retry 不能升级为 exactly-once，tool Error 不能升级为“未执行”。

### 3) checkpoint 创建失败/恢复后 session history 重建

- **C7 VERIFIED（E3+E1）**：文档规定 checkpoint 同时包含 Git snapshot、完整 conversation history、待执行 tool call；restore 恢复文件和会话历史并重新提出 tool call。集成测试验证文件新增/修改/删除后的本地 restore。
- **C8 VERIFIED（E1+E2）**：checkpoint 单测验证 `history`、`clientHistory`、tool call、messageId；snapshot 失败回退 current commit；无可用 hash 时 checkpoint 不写入并记录两项错误。
- **C9 INFERRED/UNKNOWN**：`AgentChatHistory` 提供按长度 rollback，注释明确用于 stream failure；session 文档描述自动保存/resume。没有崩溃中断持久化写的直接测试，所以“部分 message 写入后能否精确重建”保持 UNKNOWN。

### 4) 官方未证明事项

- **C10 UNKNOWN（明确负面结论）**：没有找到官方公开测试/文档证明 crash 后远端副作用已发生或未发生。
- **C11 UNKNOWN**：没有找到远端幂等/去重承诺或机制足以证明重试不会重复执行。
- **C12 UNKNOWN**：没有找到远端事务 rollback 或 compensating action 证明。
- **C13 UNKNOWN**：没有找到 exactly-once 端到端证明；本地 checkpoint/历史恢复不等于远端 exactly-once。

## 证据等级与限制

- **E1（最高）**：官方仓库测试中的可执行断言（Vitest 单测/集成测试）。
- **E2**：官方仓库当前 `main` 的实现源码及注释；能证明当前实现路径，但不自动证明所有运行时/服务端语义。
- **E3**：官方 CLI 文档；描述产品设计与用户可见语义，不能替代服务端协议证明。
- **取样限制**：没有 clone 全仓库；只读取 GitHub API 的树索引和上述窄范围公开 raw 文件。结论是截至 2026-09-22 对公开 `main` 内容的切片，不是对所有历史版本或 Gemini 服务端的保证。

## 官方来源索引

详见同目录 `sources.md`；机器可验证 claim/source 映射见 `research-manifest.json`。
