# B-S51-OFFICIAL — Gemini CLI 隐私、遥测与配置优先级边界

- 访问日期：2026-09-22
- 来源：Google Gemini CLI 官方 GitHub 文档，固定快照 `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`；只读。

## 结论

1. **verified**：不同认证方式对应不同服务条款与隐私通知；官方将 Google 账号、Gemini Developer API、Vertex AI 分开列出，并提供 usage statistics opt-out。
2. **verified**：Telemetry 通过 settings/env 控制 enabled、target、endpoint/outfile、logPrompts、collector；日志/指标/trace 可包含 prompt、用户身份、工具调用、审批、会话与文件事件，具体字段受设置影响。
3. **verified**：官方 settings 文档区分 user 与 workspace 配置，workspace 覆盖 user；环境变量可覆盖设置，且安全、审批、遥测、重试、模型、hooks 等设置均可能改变有效行为。
4. **inferred**：本地/云端遥测是可观测性通道，不是完整审计；日志存在不证明事件完整、已导出、已持久化或外部副作用已提交。
5. **unknown**：遥测 exporter 失败/进程崩溃/断网时的完整性、prompt 脱敏覆盖、跨进程配置一致性、最终保留与账单/业务效果，本文档未给出统一保证。

## 不能证明边界

- privacy notice ≠ 逐事件数据流证明；
- telemetry record ≠ complete audit or postcondition；
- workspace override ≠ 所有子进程/外部 MCP 都采用相同配置；
- enabled/exported ≠ collector 已收到并持久化；
- prompt logging disabled ≠ 其他 metadata 不含敏感信息。

## 研究限制

未登录、未使用凭据、未运行真实 CLI/collector、未访问生产，未触碰 shared/P0、事故目录、D10/L12/D14、canonical、140、tri-line、systemd。
