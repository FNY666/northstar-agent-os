# S16 官方来源索引

> 仅列 `google-gemini/gemini-cli` 官方 GitHub 页面或其 `raw.githubusercontent.com` 对应公开文件；所有链接均为 exact URL。证据等级按 validator schema：primary。

| ID | Exact URL | 证据等级 | 用途与 caveat |
|---|---|---|---|
| S1 | https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/policy-engine.md | primary | 官方 policy engine 文档：规则、优先级、approval mode、持久审批与 policy locations。只证明本地策略控制，不证明执行授权快照或 pinning。 |
| S2 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/checkpointing.md | primary | 官方 checkpoint 文档：文件修改前 shadow Git snapshot、会话/工具调用保存、`/restore`。范围是本地项目文件/会话；不证明远端副作用回滚。 |
| S3 | https://github.com/google-gemini/gemini-cli/blob/main/packages/cli/src/config/policy.ts | primary | 官方 policy 配置源码：policy paths、workspace trust、PolicyIntegrityManager、更新确认状态。源码局部实现不等于全链路审计/版本 pinning。 |
| S4 | https://github.com/google-gemini/gemini-cli/blob/main/packages/cli/src/config/policy-engine.integration.test.ts | primary | 官方 policy 集成测试：ALLOW/DENY/ASK_USER、模式与规则行为。测试未证明版本哈希绑定、恢复语义或完整审批日志。 |
| S5 | https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/reference.md | primary | 官方 hooks reference：session_id、transcript_path、事件名称、Before/After tool、SessionStart/End。事件钩子可用于扩展，不自动成为不可篡改/无损审计。 |
| S6 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/session-management.md | primary | 官方会话管理：完整会话/工具执行保存、项目路径、resume、默认 30 天 retention、删除 artifacts。明确存在自动清理，不能推出长期审计保存。 |
| S7 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/tools/tool-registry.ts | primary | 官方 ToolRegistry 源码：按工具名注册，重复名称覆盖并警告，列表去重。名称层去重不等于副作用调用幂等键。 |
| S8 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/settings.md | primary | 官方设置表：默认 approval mode、session cleanup/maxAge、显示用户身份、loop detection、永久审批。配置项存在不等于跨进程身份/fencing/exactly-once。 |
| S9 | https://github.com/google-gemini/gemini-cli/blob/main/integration-tests/user-policy.test.ts | primary | 官方 user-policy 集成测试：含“BeforeAgent and AfterAgent exactly once per turn despite tool calls”测试，以及 hook telemetry。该断言仅针对 agent hook 事件，不是工具副作用 exactly-once。 |
| S10 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/services/chatRecordingService.ts | primary | 官方会话记录源码：session metadata、消息/工具记录、rewind/metadata 更新、磁盘满时禁用记录警告。源码不证明 durable delivery 或不可篡改保存。 |
| S11 | https://github.com/google-gemini/gemini-cli/blob/main/integration-tests/checkpointing.test.ts | primary | 官方 checkpoint 测试：文件恢复与隔离 Git identity 测试。隔离的 Git identity 不等于跨进程执行主体身份。 |
| S12 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/session-management.md#parallel-sessions-with-git-worktrees | primary | 官方 session 文档：Git worktrees 给并行会话独立副本。工作区隔离不等于资源端 fencing token。 |
| S13 | https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/reference.md#sessionend | primary | 官方 hook reference 的 SessionEnd/清理语义。事件触发定义不证明退出、崩溃、磁盘满时可靠送达。 |
| S14 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/settings.md#session-retention | primary | 官方设置中的 sessionRetention/maxAge/maxCount/minRetention。保留策略可配置不等于长期不可变审计存档。 |

## 访问与方法说明

- 使用 GitHub REST API 获取仓库元数据/树索引，并通过单文件 `raw.githubusercontent.com` 读取公开文档、源码和测试；没有 clone 全仓库。
- 本目录之外未写入任何研究产物；没有访问旧切片、shared/P0、事故目录、D10/L12/D14、canonical、140、tri-line、systemd、真实服务或凭据。
- 报告中的每个能力判断都以“官方公开证据是否足以证明目标保证”为问题，而不是“是否存在某段相关代码”。
