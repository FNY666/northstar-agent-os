# S15 官方资料研究报告：恢复/重试/取消窄范围复核

- 研究目录：`/tmp/B-GEMINI-CLI-RESEARCH-20260922-S15/`
- 研究时间：2026-09-22（Asia/Shanghai）
- 目标：仅核查 `google-gemini/gemini-cli` 官方公开 GitHub 文档、源码与测试；不把本地控制流外推为远端或外部资源事实。
- 边界：未 clone 仓库；通过 GitHub raw/API 读取公开文件。未访问 shared/P0、事故目录、D10/L12/D14、canonical、140、tri-line、systemd、真实服务或凭据；未修改 S4-S14。

## 结论切片

### C1 — retry/backoff 会对符合条件的模型调用自动重试（verified）
**证据等级：A（官方源码 + 官方单元测试）**。`retryWithBackoff` 默认最多 10 次，针对 429、499、5xx 以及可选网络错误重试；延迟为带抖动的指数退避并受 `maxDelayMs` 限制。官方测试验证成功前重试、达到次数后抛最后错误、默认 10 次、400 不重试和延迟上限。  
**Caveat：**这是 CLI 进程内函数级行为；不证明远端请求已成功、未执行两次，或任何外部副作用安全。

### C2 — 重试不是通用的去重/幂等机制（inferred）
**证据等级：A（官方源码的可见参数/控制流）**。retry API 的参数是函数、次数、延迟、错误/内容判定、AbortSignal 与回调；可见实现没有幂等键、请求去重缓存、远端 operation ID 或提交确认。  
**Caveat：**源码未见这些机制不等于远端 API 全部不存在；本结论只说该 CLI retry 层没有被证实提供它们，不能推断服务端语义。

### C3 — 流式响应已产生片段后仍可能触发重试（verified）
**证据等级：A（官方网络重试测试）**。测试先产出 `First part`，随后抛 503，再验证 RETRY 事件与 `Retry success` 片段。  
**Caveat：**该测试只验证 mock stream/CLI 事件序列；没有证明模型端或任何 tool/外部副作用会被去重，也没有证明首个流的远端处理已回滚。

### C4 — retry 支持取消信号，但取消只证明停止继续 retry/等待（verified）
**证据等级：A（官方源码）**。开始前、每次尝试前、捕获错误后检查 `signal.aborted`；退避等待把 signal 传给 `delay`，AbortError 会直接抛出。  
**Caveat：**这只约束 retry 控制流；不能由此推出已发出的 HTTP 请求、远端生成、tool execution 或外部资源已终止。

### C5 — checkpoint 保存文件快照、会话历史和即将执行的 tool call；restore 会重新提出 tool call（verified）
**证据等级：A（官方文档 + 官方集成测试）**。文档明确 checkpoint 在文件修改工具前创建，存 shadow Git snapshot、完整会话历史和 tool call；restore 恢复文件/会话并 re-propose 原 tool call。集成测试实际创建 snapshot、修改/删除文件并验证 restore 回到快照。  
**Caveat：**证据覆盖项目文件与会话元数据；没有证明任意 tool 的 in-flight 状态、已发出的网络请求或外部副作用可恢复/回滚。

### C6 — session resume/上下文 GC 恢复对话上下文，不证明恢复 tool execution 的 in-flight 副作用（verified + unknown）
**证据等级：A（官方文档 + 官方集成测试）**。session 文档说自动保存完整对话（含 tool executions 的输入/输出），`--resume` 加载上下文；resume-GC 测试只验证继续运行后得到已知响应，并检查上下文 GC trace。  
**判定：**“恢复对话/上下文”是 verified；“覆盖 tool execution 的 in-flight 副作用”是 **unknown**。  
**Caveat：**没有找到测试证明崩溃/退出时正在运行的 tool 会被重连、恰好一次执行、补偿、回读远端状态或回滚。

### C7 — 取消 shell execution 有进程组终止实现，官方测试验证 SIGTERM→SIGKILL 调用顺序（verified）
**证据等级：A（官方源码 + 官方测试）**。shellExecutionService 的 abort handler 调用 `killProcessGroup(..., escalate: true)`；测试断言 abort 后 `result.aborted === true`，并断言对 mock PID 先 SIGTERM 后 SIGKILL；另有 kill() 销毁 PTY、清理活动表的测试。  
**Caveat：**这些测试使用 mock PTY/`process.kill`，验证的是 CLI 发出的终止控制流，不是操作系统上旧进程一定已退出，更不是外部服务/资源已停止。

### C8 — 官方测试没有证明“取消后旧进程真实终止”或“外部资源停止”（unknown）
**证据等级：A（官方测试边界；反面结论限于已检索文件）**。取消测试把进程 kill 与 PTY 行为 mock 化，断言信号调用、aborted 标志、退出回调和清理；后台测试也以 mock child/PTY 及日志历史验证。未见独立存活探针、真实子进程 PID 轮询、网络服务端确认、资源 read-back 或取消后副作用审计。  
**Caveat：**这是在本切片检索范围内无法证明，不是断言整个项目或所有版本绝对没有此类测试。

### C9 — 未发现恢复窗口、幂等键或远端状态 read-back 的官方证据（unknown）
**证据等级：B（官方仓库树/窄检索 + 上述源码文档）**。本片检查 checkpointing/session-management 文档、retry 实现与测试、GeminiChat network retry 测试、shell execution 取消测试和 resume-GC/checkpointing 集成测试；未找到“恢复窗口”“idempotency key”“远端状态 read-back/确认”实现或断言。  
**Caveat：**“未找到”不能证明服务端没有这些能力；只能标记本 CLI 公开资料在本窄范围内无法证明。

## 回答 S14 未知项

- 自动重发：**verified（限定为符合判定的 CLI 模型调用/流重试）**。
- 去重/幂等键：**unknown**；retry 证据不构成去重或幂等承诺。
- 恢复窗口：**unknown**；未见 retry/checkpoint/session 的时间窗口保证。
- 远端状态 read-back：**unknown**；未见远端状态查询或提交确认闭环。
- checkpoint/session 是否覆盖 tool execution 的 in-flight 副作用：**unknown**；可见证据仅覆盖本地文件快照、会话/工具调用记录与重新提出。
- 取消后旧进程真实终止：**unknown**；源码有终止信号控制流，测试为 mock，缺乏真实存活验证。
- 取消后外部资源停止：**unknown**；没有外部资源停止或远端 read-back 证据。

## 方法与停止条件

只使用官方仓库 `google-gemini/gemini-cli` 的公开 `main` 分支 raw 文件/API；没有 clone。首轮定位后固定为上述 9 个结论，未扩展到非官方来源、真实服务、凭据或旧目录。manifest 中将“无法证明”映射为 schema 的 `unverified`，将已验证映射为 `confirmed`，推断映射为 `inferred`。
