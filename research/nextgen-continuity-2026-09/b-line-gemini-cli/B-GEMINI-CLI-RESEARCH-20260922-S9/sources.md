# S9 官方来源清单

研究范围：仅 google-gemini/gemini-cli 官方公开 GitHub 文档、源码、测试、API；访问口径为 `main` 分支，截止 2026-09-22。以下 URL 均为 exact source URL。

| ID | 官方来源 | 类型/证据等级 | 本片用途 |
|---|---|---|---|
| S1 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/checkpointing.md | 官方文档 / A | checkpoint 组成、本地存储、restore 语义 |
| S2 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/session-management.md | 官方文档 / A | session 自动保存、resume、保留策略 |
| S3 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/telemetry.md | 官方文档 / A | telemetry local outfile、OTLP/GCP 配置 |
| S4 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/confirmation-bus/message-bus.ts | 官方源码 / B | MessageBus 进程内 EventEmitter、publish/request/error/timeout |
| S5 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/confirmation-bus/message-bus.test.ts | 官方测试 / C | MessageBus listener、错误处理、request 行为 |
| S6 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/telemetry/file-exporters.ts | 官方源码 / B | append stream、export callback、forceFlush/shutdown |
| S7 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/telemetry/gcp-exporters.ts | 官方源码 / B | GCP pending writes、success/failed 回调 |
| S8 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/telemetry/sdk.ts | 官方源码 / B | Batch processors、buffer、flush、shutdown 生命周期 |
| S9 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/services/chatRecordingService.ts | 官方源码 / B | JSONL append、逐行恢复、rewrite temp+rename、ENOSPC |
| S10 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/services/chatRecordingTypes.ts | 官方源码 / B | session/message/tool-call record 格式 |
| S11 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/services/chatRecordingService.test.ts | 官方测试 / C | session recording 正常路径与恢复相关覆盖 |
| S12 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/utils/checkpointUtils.ts | 官方源码 / B | Git snapshot、checkpoint JSON 内容与失败 fallback |
| S13 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/utils/checkpointUtils.test.ts | 官方测试 / C | checkpoint schema、snapshot 失败与 invalid JSON |
| S14 | https://github.com/google-gemini/gemini-cli/blob/main/packages/cli/src/ui/commands/restoreCommand.ts | 官方源码 / B | restore 文件枚举、JSON/schema 校验 |
| S15 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/scheduler/state-manager.ts | 官方源码 / B | queue/active/completed 内存状态与 fire-and-forget snapshot event |
| S16 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/scheduler/state-manager.test.ts | 官方测试 / C | scheduler snapshot/status transition 行为 |
| S17 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/scheduler/scheduler.ts | 官方源码 / B | scheduler 生命周期、dispose、状态驱动执行 |
| S18 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/agents/remote-session-invocation.ts | 官方源码 / B | static A2A contextId/taskId map 的进程边界 |
| S19 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/agents/local-session-invocation.ts | 官方源码 / B | local subagent activity publish 旁证 |
| S20 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/agents/remote-subagent-protocol.ts | 官方源码 / B | remote session send/result 协议边界 |
| S21 | https://github.com/google-gemini/gemini-cli/blob/main/integration-tests/checkpointing.test.ts | 官方集成测试 / C | 正常 Git snapshot/restore，不覆盖崩溃注入 |
| S22 | https://github.com/google-gemini/gemini-cli/blob/main/integration-tests/telemetry.test.ts | 官方集成测试 / C | telemetry event/metric 正常发送，不覆盖跨重启 durability |

## 证据限制

- 未 clone 全仓库；只读取上述官方公开 URL。
- 未找到能证明 crash-window、fsync、跨进程 replay、端到端 durable ack、exactly-once、幂等去重、远端副作用回滚的公开证据；这些在报告中标为 unknown，manifest 中对应使用 `unverified`。
- 正常路径测试不等于崩溃恢复证明；`forceFlush` 不等于 fsync；Git 文件恢复不等于外部副作用回滚。
