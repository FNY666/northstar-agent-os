# Gemini CLI S6：取消、checkpoint 与 resume 窄范围核验

- 日期：2026-09-22（Asia/Shanghai）
- 资料范围：Gemini CLI 官方公开 GitHub 源码、测试和文档；基线 commit `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`。
- 本片未访问真实服务、凭据、shared/P0、事故目录、D10/L12/D14、canonical、140、tri-line、systemd；未运行生产任务。
- 状态词：`verified`=官方源码/测试直接支持；`inferred`=受限推断；`unknown`=本片没有证明；`conflict`=一手证据冲突。

## 结论

1. **verified / high**：shell 取消路径以 AbortSignal 终止进程组；官方测试覆盖先发送 SIGTERM、再发送 SIGKILL。shell inactivity timeout 会触发 abort，并返回自动取消错误，而不是成功。
2. **verified / high**：MCP 工具调用与 AbortSignal 竞争；取消时返回 AbortError/取消结果。MCP discovery timeout 会 abort 并记录错误；这证明调用/发现层的取消边界，不证明远端副作用已撤销。
3. **verified / high**：工具取消后，Gemini CLI 保留结构化取消响应/部分 live output；resumed session 中 dangling tool-response 会在新用户消息到来前被关闭或修复，避免历史消息错误拼接。这是会话历史修复，不是自动重做或去重协议。
4. **verified / medium**：checkpoint 保存 shadow Git commit、会话历史、客户端历史、待执行 tool call 和 message id；restore 恢复项目文件/对话并重新提出原工具调用。该恢复对象不包含远端副作用事务状态。
5. **inferred / medium**：checkpoint/restore 可作为人工恢复和重新决策机制，但不能视为事务回滚；若原工具已有 shell、MCP 或第三方副作用，restore 不证明这些副作用被撤销。
6. **unknown / high**：官方本片证据未证明 checkpoint 创建失败或工具部分写入后失败时，所有写入会自动回滚、自动中止或自动进入安全状态。实现有错误记录/回退到当前 commit 的路径，但不构成全局回滚保证。
7. **unknown / high**：官方本片证据未证明 resume 会安全判断最后一次 shell/MCP 调用是否已产生远端副作用，也未证明它会依据幂等键跳过、查询、补偿或重放该调用。
8. **unknown / high**：崩溃/断线后的远端状态、调用去重、幂等执行键、远端回滚、exactly-once 仍未被官方端到端证据证明。

## 证据边界

- “进程组终止”只证明 CLI 对本地 shell 子进程发出终止动作；不证明子进程已在所有平台瞬间消失，也不证明已发出的网络请求或第三方副作用被撤销。
- “模型流 retry”只适用于模型响应流；不能外推为 shell/MCP 工具重试安全。
- `idempotentHint` 只作为 MCP tool annotation 保留/暴露的证据，不等于 CLI 对远端执行做去重。
- 会话历史 durable ID、callId、prompt_id 是关联/历史字段；本片没有证据把它们升级为跨重启幂等凭证。

## 来源 URL

1. https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/tools/shell.ts
2. https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/tools/mcp-client.ts
3. https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/core/geminiChat.ts
4. https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/core/geminiChat.test.ts
5. https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/utils/checkpointUtils.ts
6. https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/utils/checkpointUtils.test.ts
7. https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/docs/cli/checkpointing.md
8. https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/tools/shell.test.ts

## 未解决项

- 取消信号发送后，外部 shell 子进程在任意平台的最终退出确认。
- MCP 远端请求在取消时的服务器侧实际状态。
- checkpoint 部分失败/并发写入的完整恢复矩阵。
- resume 与未确认工具副作用之间的权威 read-back、补偿和幂等协议。
