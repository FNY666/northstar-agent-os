# Sources — Gemini CLI S8

以下为本片使用的官方公开来源；源码以 S8 目录中已落盘的固定版本副本为证据材料。

1. https://github.com/google-gemini/gemini-cli/tree/main/packages/core/src/core — core 事件与工具调用关联。
2. https://github.com/google-gemini/gemini-cli/tree/main/packages/core/src/core/events — 事件类型、状态和 translator 相关源码。
3. https://github.com/google-gemini/gemini-cli/tree/main/packages/core/src/core/messageBus.ts — MessageBus 公共源码路径；事件订阅/分发边界。
4. https://github.com/google-gemini/gemini-cli/tree/main/packages/core/src/core/event-translator.ts — 工具调用事件翻译路径。
5. https://github.com/google-gemini/gemini-cli/tree/main/packages/core/src/core/events.test.ts — 事件行为测试。
6. https://github.com/google-gemini/gemini-cli/tree/main/packages/core/src/core/event-translator.test.ts — translator 行为测试。
7. https://github.com/google-gemini/gemini-cli/tree/main/packages/core/src/telemetry — telemetry 类型与属性源码路径。
8. https://github.com/google-gemini/gemini-cli/tree/main/packages/core/src/telemetry/semantic.ts — semantic 属性定义。
9. https://github.com/google-gemini/gemini-cli/tree/main/packages/core/src/telemetry/sdk.ts — SDK 初始化/导出边界。
10. https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/telemetry.md — 官方 telemetry 文档。

证据等级：以上均为 Gemini CLI 官方一手公开资料。路径中未明确固定 commit 的页面用于来源定位；S8 的本地副本和 pinned 文件用于本片内容核对。未证明的持久性、完整性、送达、审计合规、远端业务提交与 exactly-once 均保持 unknown。
