# B-S49-OFFICIAL — Headless、Plan Mode 与 Model Steering 官方边界

- 访问日期：2026-09-22
- 来源：Google Gemini CLI 官方 GitHub 文档，固定快照 `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`；只读。

## 结论

1. **verified**：Headless mode 支持单对象 JSON 与 JSONL streaming；JSONL 可含 message、tool_use、tool_result、error 事件；CLI 用退出码区分成功、一般/API 错误与输入错误。
2. **verified**：Plan Mode 的默认工具集合以只读探索为主；`write_file`/`replace` 仅限计划目录中的 `.md`，`web_fetch` 需要显式确认，MCP 只读工具和资源有明确限制。
3. **verified**：Plan Mode 先研究、询问用户、生成计划并等待正式批准；批准后退出 Plan Mode 开始实施；Esc 可取消计划。
4. **verified**：Plan Mode 的 approval 按模式隔离；Default/Auto-Edit 中的持久批准不自动适用于 Plan Mode。计划模式工具限制可通过 policy 配置定制，故实际能力必须与生效 policy 一起审计。
5. **verified**：Model Steering 是 experimental、默认关闭；工作中的文本会作为 steering hint，CLI 可重新评估当前计划并调整后续动作，但这不是取消、回滚或外部状态确认。
6. **inferred/unknown**：JSONL 的 `tool_result`/退出码只证明 CLI 报告了工具结果或进程状态；不证明外部副作用已持久化、恰好一次、断连后是否执行、日志完整或生产效果。

## 不能证明边界

- exit 0 ≠ 外部业务提交；exit 1 ≠ 外部业务未提交；
- plan artifact/approval ≠ implementation success；
- steering hint ≠ cancellation/fencing/rollback；
- hook archive 示例 ≠ 审计上传已完成（示例显式后台执行）；
- 默认 Plan Mode 限制 ≠ 自定义 policy 下的最终限制。

## 研究限制

未运行 Gemini CLI、未启用 steering、未访问真实服务、未使用凭据、未触碰 shared/P0、事故目录、D10/L12/D14、canonical、140、tri-line、systemd 或生产。
