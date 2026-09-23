# B-S40 官方研究报告：Gemini CLI 遥测、ACP 与 MCP 连接边界

访问日期：2026-09-22（Asia/Shanghai）。仅使用 Google Gemini CLI 官方仓库/文档；本地快照 commit `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`。未运行真实 CLI、未访问凭据或真实服务。

## 结论

1. **verified**：Telemetry 可由 `.gemini/settings.json` 和环境变量配置；官方文档列出 enabled、target、otlpEndpoint/outfile、logPrompts、useCliAuth 等字段，并区分 Google Cloud 与 local 输出。
2. **verified**：官方 telemetry 文档列出 session、prompt、approval mode、tool call、file operation、API request/response/error 等事件/字段；`logPrompts=false` 时 prompt 内容可被排除。文档描述的是观测数据模型，不是完整审计保证。
3. **verified**：ACP 支持 `newSession`、`loadSession`、`prompt`、`cancel`，并可通过 `setSessionMode` 改变工具调用审批级别；ACP 也可与 MCP 组合。
4. **verified**：MCP discovery 会获取 server 的 tool definitions、prompts/resources；MCP tool wrapper 管理执行、连接状态和 timeout。服务器配置支持 allowed/excluded、includeTools/excludeTools、默认请求 timeout 600000ms，以及环境变量展开。
5. **verified**：官方文档说明启动 MCP server 时会对继承环境做自动脱敏；若变量必须传给 server，需要显式 override。该保护面向环境传递，不等于 MCP server 本身可信。
6. **inferred**：telemetry 中存在 tool/API/error 字段可帮助关联与诊断，但官方文档没有说 telemetry 覆盖所有事件、不可丢失、不可篡改或等价于业务效果证明；因此外部副作用仍需独立 read-back。
7. **unknown**：本切片未验证 telemetry flush、网络中断、exporter failure、MCP 重连/重试、OAuth token 生命周期、ACP cancel 是否撤销已发出的外部副作用、exactly-once、生产审计完整性。

## 证据窗口

- `telemetry.md` lines 33–48：配置字段和默认值；lines 154–225：direct/local export；lines 272–400、480–551：日志、session/prompt、tool、file、API 与 error 事件。
- `acp-mode.md` lines 40–70：协议与 MCP 组合；lines 78–94：newSession/loadSession/prompt/cancel、session mode；lines 101–125：debugging/telemetry。
- `mcp-server.md` lines 26–55：discovery/execution/connection state；lines 90–188：配置、timeout、tool filtering；lines 190–248：环境变量展开、自动脱敏与显式 override；lines 610–625：discovery 流程。
- `mcp-resources.md` lines 1–42：list/read resource 的发现、定位和读取边界。

## 不能证明

官方文档不证明任何特定机器已启用遥测、事件一定成功导出、数据完整不可篡改、MCP server 无恶意行为、工具调用已提交、cancel 已撤销第三方状态、OAuth/重试/重连具备 exactly-once，或 production readiness。
