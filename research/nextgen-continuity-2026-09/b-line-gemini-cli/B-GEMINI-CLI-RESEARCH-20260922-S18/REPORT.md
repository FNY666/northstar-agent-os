# S18：Gemini CLI 官方资料中的可操作缓解措施与残留缺口

- 研究目录：`/tmp/B-GEMINI-CLI-RESEARCH-20260922-S18/`
- 资料边界：仅 Google Gemini CLI 官方文档、`google-gemini/gemini-cli` GitHub `main` 分支源码与测试；未访问旧切片或禁区。
- 结论状态含义：`verified`=资料直接陈述或测试/源码直接显示；`inferred`=从官方实现作出的有限推断；`unknown`=官方资料未给出足够保证；`conflict`=官方资料之间存在冲突。证据等级：A=官方文档直接说明，B=官方源码/测试直接显示，C=受限推断。

## 执行摘要

1. **checkpointing 可启用，但官方公开配置只有 `general.checkpointing.enabled`；没有官方 `checkpoint interval` 配置或承诺。** 它是本地、项目相关、修改文件前的 shadow-Git + 对话/工具调用快照，不是外部审计日志，也不覆盖任意外部副作用。
2. **session resume 的正确用法是 `gemini --resume`、索引/UUID，或交互式 `/resume`；它恢复 CLI 会话上下文，不是业务状态回滚。** 会话按项目根目录隔离并有 retention 清理，因此不可当作永久审计或外部提交确认。
3. **OTel 可以把观测复制到追加文件、Console exporter（默认无文件/OTLP 时的本地分支）或 OTLP/GCP 后端，并可在正常清理时 forceFlush/shutdown。** 这降低“正常退出时尚未排出的本地观测”丢失风险，但不提供崩溃/断电、网络、后端接收、完整业务事件或 exactly-once 保证。
4. **MCP OAuth retry 是连接认证后的重连路径，不是工具调用的业务重试策略。** `idempotentHint` 只是 MCP 工具 annotation 被保留/传递的提示；官方 CLI 没有据此给外部副作用加幂等键、read-back 或 fencing 的证据。
5. **幂等键、read-back、fencing、outbox、外部耐久审计与提交确认必须由外部系统/工具服务承担。** 不应把 CLI 的 checkpoint、resume、OTel 或 OAuth retry 外推成这些补偿能力。

## 可操作措施与边界

### 1) Checkpoint / checkpoint interval

**用户/开发者能做什么**

在用户或项目 `settings.json` 中启用：

```json
{
  "general": {
    "checkpointing": { "enabled": true }
  }
}
```

启用后，在批准会修改文件系统的工具（官方示例 `write_file`、`replace`）之前，CLI 创建 checkpoint；可用 `/restore` 列表，或 `/restore <checkpoint_file>` 恢复。配置要求重启；文档注明 0.11.0 起 `--checkpointing` 已移除，只能通过 `settings.json` 启用。

**官方给出的限制**

- 默认关闭。
- 数据存于本机：shadow Git 在 `~/.gemini/history/<project_hash>`；对话/工具调用在项目临时目录 `~/.gemini/tmp/<project_hash>/checkpoints`。
- 官方资料没有 `checkpoint interval`、按时间/每 N 次 checkpoint、远端复制、跨项目恢复或外部提交确认的配置/承诺。
- checkpoint 的对象是 CLI 文件修改前的本地快照；资料没有证明它捕获 MCP 服务、数据库、网络 API、云资源或其他外部副作用。

**结论：verified（A/B）；interval=unknown（A/B）**。启用 checkpoint 是降低 CLI 自身文件修改回滚成本的措施；不能把“没有 interval 配置”解释为固定间隔、每次请求或全局审计。

### 2) Session resume

**正确用法**

- 最近会话：`gemini --resume`。
- 先 `gemini --list-sessions`，再 `gemini --resume 1`；也可 `gemini --resume <full-session-UUID>`。
- 运行中输入 `/resume` 打开浏览器，选择会话；命名分支可用 `/resume save decision-point`、`/resume list`、`/resume resume decision-point`。
- 会话自动保存提示、模型响应、工具执行输入/输出、token usage（官方文档称完整会话历史），位置为 `~/.gemini/tmp/<project_hash>/chats/`，按项目根目录 hash 隔离。

**不能恢复什么**

官方资料只承诺恢复“会话上下文/历史”；没有承诺恢复外部服务状态、未确认的远程写入、数据库事务、MCP 服务进程状态、OAuth 服务端状态或网络请求的 exactly-once 结果。会话 retention 默认启用、默认 maxAge `30d`、默认 minRetention `1d`；因此不能当永久证据库。恢复会话后，任何外部副作用是否已经发生必须由外部服务 read-back/状态查询确认，而不能由 resume 推断。

**结论：正确命令与项目范围 verified（A）；“不恢复外部状态”是官方承诺边界推断，具体外部语义 unknown（A/C）**。

### 3) OTel：file / stdout / backend、forceFlush 与 shutdown

**配置路径**

官方 telemetry 文档给出 `.gemini/settings.json` 的 `telemetry` 配置，环境变量可覆盖。关键选项为 `enabled`、`target`（`gcp`/`local`）、`otlpEndpoint`、`otlpProtocol`（`grpc`/`http`）、`outfile`；文档明确 `outfile` 保存到文件并覆盖 `otlpEndpoint`。官方实现读取 `GEMINI_TELEMETRY_*` 和 `OTEL_EXPORTER_OTLP_ENDPOINT` 等设置。

官方实现分支（源码直接显示）：

- 有 GCP direct 条件时使用 GCP exporters；
- 有 OTLP endpoint 且没有 outfile 时使用 OTLP gRPC/HTTP exporters；
- 有 outfile 时使用 `FileSpanExporter`、`FileLogExporter`、`FileMetricExporter`；
- 否则使用 `ConsoleSpanExporter`、`ConsoleLogRecordExporter`、`ConsoleMetricExporter`。这证明有 Console 路径；“stdout”是该 Console exporter 的通常输出语义，官方 Gemini CLI 源码片段本身未把文件描述符写死，因此 stdout 标签应视为 **inferred**，不要当成耐久文件。

文件 exporter 以 append 打开；其 `forceFlush()` 通过排队空写并等待 callback，确保此前 stream writes 已完成；`shutdown()` 调用 `writeStream.end()` 并等待回调。CLI 的 `flushTelemetry()` 并行调用 span/log/metric processor 的 `forceFlush()`；`shutdownTelemetry()` 调用 `sdk.shutdown()`。SIGINT/SIGTERM handler 触发 shutdown，但源码注释明确正常进程退出不能依赖同步 `process.on('exit')` 等待异步 shutdown，而是由 cleanup 路径处理。

**能降低什么丢失**

- 正常退出、`/clear` 等关键操作前显式 flush（源码注释）可降低已生成但仍在 batch processor/文件 stream 队列中的观测丢失。
- file 追加输出提供本地可读取副本；OTLP/GCP/collector 提供外部接收路径，便于集中留存和监控。

**残留缺口**

- 官方资料没有 crash/power-loss、SIGKILL、进程被强制终止、磁盘 fsync、OTLP 网络失败重传/持久队列、后端已 durable-ack、去重或 exactly-once 的保证。
- OTel 事件是观测数据，不能证明业务副作用已提交；没有官方证据表明每个 MCP 工具请求、响应、重试意图和外部提交都被完整且不可篡改地记录。
- 因而 OTel 是“降低正常路径审计丢失概率”的补充，不是 outbox、事务日志或提交确认。

**结论：配置/分支/flush/shutdown verified（A/B）；Console=stdout inferred（B/C）；降低正常排队丢失 inferred；耐久审计、完整性、exactly-once unknown（A/B）**。

### 4) MCP OAuth retry 与 `idempotentHint`

**OAuth retry 的正确用法边界**

官方 MCP server 文档说明：远程 MCP（SSE/HTTP）可使用 OAuth 2.0；CLI 可从 401、服务器元数据等发现配置、完成授权/令牌管理，再以有效 token 重试连接。`mcp-client.ts` 的 `retryWithOAuth()` 源码更具体：HTTP 401 时先用 OAuth token 重试 HTTP；若 HTTP 404 表示 SSE-only，则只用 OAuth token 重试 SSE；测试覆盖 OAuth discovery/连接恢复路径。

这是一种**建立/恢复 MCP 传输连接的认证 retry**。不能把它用于“工具调用失败后安全重放”；官方源码/测试没有显示按业务操作生成幂等键、判断远程副作用是否提交，或对工具 call 做 read-back。

**`idempotentHint` 的正确用法边界**

官方 `mcp-client.test.ts` 构造带有 `readOnlyHint`、`destructiveHint`、`idempotentHint` 的工具定义，测试断言 CLI 注册工具时保留完整 annotations，并据 `readOnlyHint` 设置 `isReadOnly`。这直接证明 CLI 传递/保留 hint；没有证明 CLI 因 `idempotentHint: true` 自动重试工具、自动去重、自动补幂等键或保证服务器实现确实幂等。

因此：工具作者只能在操作真实语义符合时声明 hint；调用方仍必须按服务端契约决定是否可重放。对“创建订单、扣款、发送消息、写数据库”等副作用，hint 不是外部幂等机制。

**结论：OAuth 认证重连 verified（A/B）；将其视为业务 retry 或把 hint 视为去重保证 conflict/unknown（A/B）；CLI 保留 hint verified（B）**。

### 5) 必须由外部系统承担的缺口

| 缺口 | 外部系统应承担的可操作补偿 | CLI 官方能力不能替代的理由 | 状态 |
|---|---|---|---|
| 请求重放/超时下的重复副作用 | 工具服务/业务 API 使用客户端幂等键，持久保存 key→结果并定义冲突语义 | OAuth retry 是连接级；`idempotentHint` 不是去重存储 | verified 边界 + inferred |
| “请求已发出但响应丢失” | read-back（按业务唯一键查询）、状态机、对账；把 `unknown` 结果显式化 | resume/OTel 只能恢复或记录 CLI 上下文/观测，不能知道远端提交 | inferred/unknown |
| 并发旧客户端继续写入 | fencing token/lease epoch，由服务端拒绝旧 epoch | checkpoint 是本地 shadow Git，不能约束远端并发者 | inferred/unknown |
| 跨进程可靠投递与审计 | transactional outbox、持久队列、消费者去重、后端 durable ack | OTel exporter/flush 没有事务绑定或 exactly-once 证据 | inferred/unknown |
| 进程崩溃/断电期间的数据 | 外部 durable journal、同步落盘策略、恢复扫描与重放/对账 | 官方仅说明正常 flush/shutdown 语义 | verified 边界 + unknown |

## 最小落地建议（不外推 CLI 能力）

1. 对仅涉及工作区文件的实验，启用 `general.checkpointing.enabled`，并在操作前后保留外部 Git/CI 记录；不要寻找不存在的官方 `checkpoint interval` 配置。
2. 需要续作时按项目选择 `--resume <UUID>` 或 `/resume`；续作任何外部写操作前，以服务端 read-back 或业务幂等键判断上次结果，而不是依据会话是否可恢复。
3. 为本地诊断启用 `telemetry.outfile`，正常清理路径调用/等待 flush；生产观测可使用 OTLP/GCP/collector，但同时设计后端 durable retention、失败告警和去重。不得把 telemetry 文件当事务日志。
4. MCP 工具 schema 仅在真实语义满足时填写 `idempotentHint`；把 OAuth retry 限定为认证后连接恢复。业务重试由外部 API 的幂等键、read-back、fencing、outbox 规则决定。

## 状态与冲突记录

- **未发现官方 `checkpoint interval` 配置**：checkpoint 文档、configuration 文档和 settings schema 只显示 `general.checkpointing.enabled`；状态 `unknown`（资料未证明不存在于所有未来版本），不是将“未找到”写成 verified negative。
- **OTel stdout**：CLI 源码选择 Console exporter，官方 CLI 文档主要列 file/backend；因此“有 Console 路径”verified，“等同 stdout 且耐久”仅 inferred，后者不可用作审计保证。
- **外部补偿**：本报告将幂等键、read-back、fencing、outbox列为外部设计要求，而非 Gemini CLI 已提供功能。
