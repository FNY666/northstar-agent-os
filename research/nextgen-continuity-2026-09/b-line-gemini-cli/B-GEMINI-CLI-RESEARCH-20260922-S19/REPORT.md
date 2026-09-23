# S19：Gemini CLI 跨重启/崩溃恢复、历史保留与工具调用审计边界

- **研究切片**：B 线 Gemini CLI / S19
- **研究问题**：官方公开资料是否证明 Gemini CLI 在跨重启、进程崩溃或断电后，能够恢复会话与悬空（dangling）工具调用，并安全重试；其 session history 的保留/清理规则是什么；工具调用恢复与审计证据能支持到什么边界？
- **资料边界**：仅 Google Gemini CLI 官方文档、官方 GitHub 源码和官方测试。未访问既有 S1–S18 目录、任何本地研究产物、shared/P0、事故目录、D10、L12、D14、canonical、staging、140、tri-line、systemd、真实服务或凭据。
- **源码快照**：`google-gemini/gemini-cli`，commit `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`（本地 clone 时间：2026-09-22；上游提交时间：2026-09-21T20:36:40Z）。
- **结论状态词**：`confirmed`=源文档/代码/测试直接支持；`inferred`=由实现机制推导但官方没有同强度声明；`unverified`=在本切片允许的官方材料中没有证明；`conflicting`=存在直接冲突；`inaccessible`=本切片边界下不能访问/验证。

## 1. 结论摘要

1. **`confirmed`：Gemini CLI 的 Checkpointing 是“文件修改前”的本地恢复点，不是已证明的崩溃/断电恢复协议。** 官方文档说，在获批的文件系统修改工具运行前创建 checkpoint，保存 shadow Git 快照、截至当时的完整会话历史和将执行的工具调用；`/restore` 会恢复文件/会话并重新提出原始工具调用。文档明确默认关闭、需 `settings.json` 开启。资料没有把它定义为进程崩溃、操作系统重启或掉电后自动恢复机制。
2. **`confirmed`：正常的跨启动恢复入口是 `--resume`/`-r` 和 `/resume`，恢复的是已保存的聊天历史（文档也称 memory），并可浏览/删除会话。** 会话记录在本机项目临时目录的 `chats` 下以 JSONL 等形式读写；`--delete-session`、`/exit --delete` 与自动 retention 都是删除路径。
3. **`confirmed`：默认历史 retention 是启用、最大年龄 30 天（设置表的默认值）；实现按启动时清理，按 `lastUpdated` 处理年龄，支持 `maxAge`、`maxCount`，当前活动会话不作为可删除会话。损坏的 session 文件被识别为待删除对象。** 测试验证了旧会话删除、当前会话保留、损坏文件删除、子代理相关清理以及配置错误时不启动清理。
4. **`confirmed`：会话记录的工具调用模型允许“只有调用而没有结果”：`ToolCallRecord.result` 是可选且可为 null，`status` 是调用状态。** 完成工具调用的记录会包含名称、参数、结果（若有）、状态、时间戳等，并按调用 ID 合并更新同一条记录。由此，历史可以审计“已记录的调用/状态”，但不能仅凭记录证明外部副作用完成、未完成或被回滚。
5. **`confirmed`：JSONL 写入是逐条追加；恢复会话时读取记录并重建内存状态。** 代码使用同步 `appendFileSync`；无法重载 resumed 文件时，保留内存副本并尝试原子重写新文件，同时保留不可读旧文件。官方没有声明每次追加都做 `fsync`、跨介质掉电原子性或日志事务协议。
6. **`confirmed`：Checkpoint 的工具调用恢复是显式的人工/命令式恢复，而不是隐式自动重试。** checkpoint 数据包含会话 history、client history、工具名称/参数、Git commit hash 和 message ID；`/restore` 后原始工具 prompt 重新出现。生成 checkpoint 要求工具参数含 `file_path`；创建 snapshot 失败时退回当前 commit，仍无 commit 则跳过该工具调用。
7. **`inferred`：如果进程在工具调用记录或结果记录之间终止，恢复后可能看到一个没有结果、仍带中间状态的工具调用；这是数据模型和追加式写入允许的状态，不是官方已验证的 crash replay 语义。** 本快照没有发现专门模拟进程崩溃/掉电并验证 dangling call 的官方测试。
8. **`inferred`：`/restore` 重新提出工具调用意味着重复执行风险必须由操作者、工具本身或外部系统处理；官方材料没有提供 exactly-once、调用去重键语义、远端副作用回滚或幂等性保证。** 因此不能把恢复后的重提解释成安全自动重试。
9. **`unverified`：官方公开材料未证明以下任一项：掉电后必然恢复到最后一个一致点；启动时自动识别并修复 dangling tool call；自动重试未完成的远端调用；跨重启 exactly-once；恢复前探测远端副作用；或对生产环境做过验证。** 这些结论应保持 `unknown`，不能以“有 session 文件/有 checkpoint”替代证明。
10. **`unverified`：本切片没有找到 checkpoint JSON、shadow Git snapshot 或 tool-output 文件具有独立 retention/清理期限的官方承诺。** session retention 实现明确处理 `chats` 中的 session 文件和关联 session artifacts；这不等于证明所有 checkpoint、shadow Git 或远端日志都会按同一规则清理。

## 2. 证据矩阵

| ID | 主题 | 结论 | 状态 | 证据边界 |
|---|---|---|---|---|
| C1 | 文件修改前 checkpoint | 保存 shadow Git、会话历史和待执行工具调用；`/restore` 恢复并重提 | confirmed | 只覆盖启用 checkpointing 且代码修改前的本地工作流 |
| C2 | checkpoint 默认/配置 | 默认关闭；通过 `settings.json` 开启；旧 `--checkpointing` flag 已移除 | confirmed | 文档说明，非 crash 测试 |
| C3 | 正常 resume | `--resume`/`-r` 恢复聊天历史与 memory；`/resume` 浏览会话 | confirmed | 已保存记录可读时 |
| C4 | 手动删除 | `/resume` 的 x、`--delete-session`、`/exit --delete` 删除历史；退出删除也删 tool output 文件 | confirmed | 仅本地会话/工具输出 |
| C5 | 默认 retention | 设置表为 enabled=true、maxAge=30d | confirmed | 默认配置文档，不代表每个平台实际时钟/权限 |
| C6 | 清理算法 | startup 调用；按 age/count；按 lastUpdated；当前活动会话跳过；损坏文件列入删除 | confirmed | 源码及 Vitest/integration tests |
| C7 | 工具调用审计字段 | `id/name/args/result?/status/timestamp`，可含 agentId 和 UI 字段 | confirmed | 类型定义及 recording tests |
| C8 | 调用更新 | 按工具 call ID 合并，结果由 completed-call 记录传入 | confirmed | recording service 与 GeminiChat 源码 |
| C9 | append/rewrite | 逐条同步 append；恢复失败时保留不可读文件并 temp+rename 重写 | confirmed | ChatRecordingService |
| I1 | dangling call 可能性 | 中间终止可留下无 result/中间 status 的历史形态 | inferred | 数据模型+追加机制推导；无 crash harness |
| I2 | resume 重试风险 | `/restore` 是 re-propose；不能推出幂等/安全重试 | inferred | 官方文档行为描述；无 exactly-once 声明 |
| U1 | power-loss 自动恢复 | 不知道 | unverified | 未发现官方 crash/power-loss 证明 |
| U2 | exactly-once/去重 | 不知道 | unverified | 未发现调用去重或事务承诺 |
| U3 | 远端副作用回滚 | 不知道 | unverified | shadow Git 仅是本地项目文件快照 |
| U4 | checkpoint/远端日志 retention | 不知道 | unverified | 未发现对应官方保留期限 |

## 3. 关键技术读取

### 3.1 Checkpoint 的真实边界

`docs/cli/checkpointing.md` 将功能限定为 AI 工具进行文件系统修改前的 snapshot。快照位于本机 `~/.gemini/history/<project_hash>` 的 shadow Git 仓库；会话历史和工具调用在项目临时目录的 checkpoint JSON 中。恢复动作包括恢复本地项目文件、恢复对话，并让原始工具 prompt 再出现。

这能支持“在已知 checkpoint 上回到修改前并由人决定是否再执行”，不能支持“工具执行到一半时自动判断远端是否已成功”。文档没有声明 checkpoint 覆盖任意非文件副作用，也没有声明进程崩溃后的自动扫描/回放。

### 3.2 session history 的持久化和 retention

当前源码的 `ChatRecordingService`：

- 新会话写入 metadata 后以 JSONL 记录消息；恢复时加载文件并重建缓存。
- 每次消息/工具调用更新通过 `appendRecord()` 写入一行；代码路径是同步 `fs.appendFileSync`，但没有显式 `fsync`。
- resumed 文件无法读取时，代码采用交给定内存 conversation 的 fallback，并尝试保留不可读文件、写临时文件后 rename。
- `ToolCallRecord.result` 可选或 null；`recordCompletedToolCalls()` 在工具完成时带入 response parts（如果存在），并把 `status`、timestamp 等写入记录。
- `recordToolCalls()` 以 `id` 合并，意味着同一工具调用可以从初始状态变为完成/错误状态；但在终止发生在两次写入之间时，没有官方证明会被自动补齐。

启动清理实现：`cleanupExpiredSessions()` 在 retention 开启时扫描项目 `chats`；`identifySessionsToDelete()` 先把损坏项列入待删，再对有效会话按 `lastUpdated` 做年龄和数量判断。当前 active session 被从可删除列表排除。测试覆盖不存在目录、禁用配置、无效配置、老会话删除、当前会话保留、损坏文件删除、子代理 artifacts 清理等。

### 3.3 “恢复后 dangling tool call”

官方代码明确提供两种不同机制，不能混写：

- **普通 `--resume`**：加载已有 session conversation；代码/文档没有声明它会寻找未完成工具并自动执行。
- **Checkpoint `/restore`**：checkpoint 中有一个待执行工具调用；恢复后把原始 prompt re-propose 给用户。这里的“重提”是可见的恢复动作，不是 exactly-once replay。

工具状态枚举包含 `validating`、`scheduled`、`executing`、`awaiting_approval`、`success`、`error`、`cancelled`。历史 `result` 可空，所以“记录里出现调用但没有结果”是 schema 允许的事实；但该事实不提供 crash 时刻、远端执行状态或副作用状态。

### 3.4 审计证据边界

可由官方本地记录直接支持的审计事实：会话 ID/时间、消息、工具名称和参数、call ID、记录时状态、可选结果 parts、部分显示字段、agent ID（如有）。

不可由这些记录单独支持的事实：

- 远端 API/服务是否收到请求或执行成功；
- 本地文件修改是否与远端副作用处于同一事务；
- 进程崩溃前最后一条 append 是否已达到稳定存储；
- 重启后是否发生重复执行；
- “无结果”是否等价于“未执行”；
- `/restore` 后重跑是否幂等、是否被服务端去重；
- 是否能够回滚任何远端副作用。

## 4. 研究方法、覆盖与未决项

### 已搜索的官方材料

- 官方文档：checkpointing、session management tutorial、CLI settings、telemetry/相关命令引用。
- 官方源码：`ChatRecordingService`、`chatRecordingTypes`、`checkpointUtils`、session cleanup、session utilities、resume/restore commands、scheduler status types。
- 官方测试：`checkpointUtils.test.ts`、`chatRecordingService.test.ts`、`sessionCleanup.test.ts`、`sessionCleanup.integration.test.ts`，以及仓库中与 resume 的集成响应样例。

### 没有把“没搜到”升级成“系统不存在”

本报告只说在该官方快照和允许范围内**未发现专门的 power-loss/crash replay 证明**。没有访问运行中的真实服务，没有人为杀进程/断电，没有对远端副作用做实验，也没有读取任何既有研究产物。因此 power-loss durability、自动恢复、生产验证均保持 unknown。

### 下一独立切片建议

**S20：Gemini CLI checkpoint 与 session JSONL 的故障注入验证设计**。只使用临时隔离项目和官方测试 harness，构造“append 前/后、工具执行前/后、结果写入前/后、rename 前/后”的进程终止点，比较 `--resume` 与 `/restore` 的可观察状态；不触发真实远端副作用，不接入凭据。交付重点应是可复现的本地状态机与证据缺口，而不是宣称 exactly-once。
