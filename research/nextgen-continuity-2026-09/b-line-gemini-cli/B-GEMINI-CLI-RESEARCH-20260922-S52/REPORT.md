# B-S52-OFFICIAL — Hooks、子代理与工具隔离边界

- 访问日期：2026-09-22
- 来源：Google Gemini CLI 官方 GitHub 文档，固定快照 `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`；只读。

## 结论

1. **verified**：Hooks 同步运行在 agent loop 中；CLI 等待匹配 hook 完成。事件包括 SessionStart、BeforeAgent、AfterAgent、BeforeTool、AfterTool、PreCompress；hook 可注入上下文、阻断 tool/turn、触发 retry/halt。
2. **verified**：Hook stdout 必须是 JSON；exit 0 解析 JSON，exit 2 是 system block，其他非零为 warning；默认 hook timeout 为 60000ms。Hook `continue:false` 可终止整个 agent loop，`decision:deny` 可拒绝工具/动作。
3. **verified**：项目级 hooks 会被 fingerprint；名称或 command 变化会被视为新的不信任 hook，并在执行前警告。CLI 提供查看、启用/禁用全部及单个 hook 的命令。
4. **verified**：自定义 subagent 可定义 tools、mcpServers、max_turns（默认30）、timeout_mins（默认10）；省略 tools 时继承父会话工具。subagent 具有独立历史和工具隔离，不能递归调用其他 subagent；可配置 subagent-specific policy/model override。
5. **inferred**：这些机制提供准入和隔离控制，但 hook/process exit、tool block、agent return 或 isolated tool list 都不是外部副作用提交证明。
6. **unknown**：hook 崩溃/超时前是否已产生外部效果、并行 hooks 的重复与顺序影响、subagent 断连后的远端状态、完整审计投递、exactly-once 和回滚，官方文档没有统一保证。

## 不能证明边界

- hook exit/status ≠ 外部副作用 postcondition；
- `decision:deny` ≠ 目标系统未接受此前请求；
- tool isolation ≠ 远端服务隔离；
- `max_turns`/`timeout_mins` ≠ 取消、fencing 或回滚；
- project fingerprint 警告 ≠ 对 hook 内容的完整安全审计；
- subagent 返回 ≠ 目标状态已提交。

## 研究限制

未运行 Gemini CLI、未执行 hooks/subagents、未使用凭据、未访问真实服务；未触碰 shared/P0、事故目录、D10/L12/D14、canonical、140、tri-line、systemd 或生产。
