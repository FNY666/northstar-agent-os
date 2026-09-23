# S17：Gemini CLI 官方补偿/修复证据研究切片

## 结论摘要

研究范围仅限 `google-gemini/gemini-cli` 官方公开 GitHub 文档、源码、测试和 GitHub API；未访问任何本地事故、shared/P0、canonical、真实服务或凭据目录。这里的“补偿/修复”严格解释为 CLI 本地状态、会话上下文、历史结构或本地遥测写入的修复/恢复能力，不外推为外部副作用的补偿。

- **verified**：Checkpointing 在文件修改工具执行前写入本地 shadow-Git 快照，并保存会话历史与待执行 tool call；`/restore` 可恢复项目文件和会话历史，并重新提出原 tool call。官方证据没有证明外部副作用回滚、fencing 或 exactly-once。
- **verified**：会话 resume 是从本地会话历史继续；官方文档描述自动保存完整对话、工具执行等，并支持按 ID/索引 resume。它是上下文恢复，不是对已执行外部动作的 replay/补偿协议。
- **verified**：历史 hardening 源码会在本地修补 Gemini API 历史不变量，包含缺失 tool response 的 sentinel、孤立 response 的 synthetic call、call/response 排序和 signature 修补。它证明的是请求历史结构修复，不证明 tool 被重新执行或外部结果真实存在。
- **verified**：本地 OTel 文件 exporter 追加写 JSON，并提供 forceFlush/shutdown；telemetry 文档描述 local/GCP export 和事件字段。但没有官方证据证明 crash 后日志补发、跨重启 re-export、端到端审计完整性或无丢失保证。
- **verified**：MCP 集成支持发现、调用、响应处理、连接状态/超时、OAuth 连接失败后的 discovery/auth/retry；但没有发现 server-side recovery、补偿事务、tool-call replay、资源 fencing 或 exactly-once 语义的官方承诺。
- **inferred/unknown**：policy 具有确认、持久化和完整性相关实现/测试线索，但本片未找到“policy re-approval”或 audit replay 的官方公开语义承诺；因此不能把策略更新/确认推断成补偿机制。

## 证据矩阵

| ID | 结论（不把 claims 写成对象） | 状态 | 证据等级 | 关键边界 |
|---|---|---|---|---|
| S17-C01 | Checkpointing 在文件修改前创建 shadow Git snapshot，并保存 conversation history 与待执行 tool call；`/restore` 恢复本地文件/会话并重新提出原 tool call。 | verified | A（官方文档+官方源码） | 仅覆盖 CLI 本地文件/会话；不证明外部副作用回滚、fencing、审计完整性、exactly-once。 |
| S17-C02 | Session resume 从本地保存的会话历史继续；保存内容包括对话、tool executions 等，并可按 ID/索引恢复。 | verified | A（官方文档） | 恢复上下文不是 replay 已执行 tool，也不证明外部动作补偿。 |
| S17-C03 | `hardenHistory` 本地修补角色交替、tool call/response 配对、缺失 response、孤立 response、signature、排序等 API 历史结构。 | verified | A（官方源码） | sentinel/synthetic 仅为结构修复；不能证明 tool 真执行过、结果真实或副作用已补偿。 |
| S17-C04 | OTel FileExporter 追加 JSON 记录；`forceFlush` 等待写入流排空，`shutdown` 结束流。 | verified | A（官方源码+官方文档） | flush 是当前进程写入排空，不等于 crash recovery、re-export、审计完整性或无丢失。 |
| S17-C05 | 官方 telemetry 文档描述 local 文件输出、OTLP/GCP 发送和 session/tool 相关事件字段。 | verified | A（官方文档） | 可观测性/导出不是补偿协议；没有发现官方 re-export/flush recovery 语义。 |
| S17-C06 | MCP client 支持 server discovery、tool execution、response processing、timeout/connection state；OAuth 401 流程包含认证后 retry。 | verified | A（官方文档） | 连接重试/认证重试不是 tool replay 或 server-side compensation；外部副作用语义未知。 |
| S17-C07 | MCP/server-side recovery、tool call replay/repair、资源 fencing、外部副作用补偿、业务 exactly-once：在所审官方材料中无证明。 | unknown | A（范围内负面证据） | “未找到官方证明”不等同于证明不存在；不得从本地 checkpoint/history/flush 推出。 |
| S17-C08 | policy re-approval 或 audit replay 作为补偿机制：在所审官方材料中无证明。 | unknown | B（官方源码路径/测试线索，未见语义承诺） | policy confirmation/integrity 不能升级为 re-approval/audit replay；需保持 unknown。 |
| S17-C09 | 外部副作用补偿、资源 fencing、审计完整性、业务 exactly-once：本片结论为 unknown，不能由上述本地机制证明。 | unknown | A（边界分析） | 外部服务、凭据和真实运行状态未访问，也不应访问。 |

## 机制—可证明性边界

Checkpoint restore 能证明“恢复本地项目文件快照、恢复会话上下文、再次提出某个原始工具调用”；history hardening 能证明“把待发给 Gemini API 的历史修补到结构约束”；session resume 能证明“重新载入本地历史继续交互”；OTel flush 能证明“当前 exporter 将已交给 stream 的 pending writes 排空”。以上均属于本地状态/请求记录层。

这些机制不能证明：外部 API、数据库、队列、MCP server 或其他真实系统已回滚；重复调用不会产生第二次副作用；已有副作用被 fencing；日志在崩溃/网络中断后完整、可重放且无篡改；业务操作 exactly-once。MCP OAuth connection retry 只证明连接/认证流程的重试，不改变上述边界。

## 研究限制

只取证官方公开 `google-gemini/gemini-cli` GitHub 文档、源码、测试/API；没有 clone 仓库，没有运行真实服务，没有读取/写入任何受限目录或凭据，也没有创建自定义 validator。GitHub `main` 内容可能随时间变化；URL 均为精确文件或 API URL，必要时应以访问时内容为准。
