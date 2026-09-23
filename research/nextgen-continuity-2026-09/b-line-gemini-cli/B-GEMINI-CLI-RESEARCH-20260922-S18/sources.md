# S18 sources — official Google Gemini CLI only

检索时间：2026-09-22（Asia/Shanghai）。所有来源均为公开官方文档或 `google-gemini/gemini-cli` 官方 GitHub `main` 原始文件；未 clone 仓库。

| ID | Exact URL | Official evidence | Used for | Caveat |
|---|---|---|---|---|
| S18-01 | https://geminicli.com/docs/cli/checkpointing/ | Official CLI documentation | checkpoint enablement, `/restore`, local shadow Git/history, default disabled, removed flag | Web documentation is versioned site content; no interval option is documented |
| S18-02 | https://geminicli.com/docs/reference/configuration/ | Official CLI configuration reference | `general.checkpointing.enabled`, restart requirement, session retention, telemetry settings | Configuration reference describes supported settings, not guarantees for external systems |
| S18-03 | https://geminicli.com/docs/cli/session-management/ | Official CLI documentation | `--resume`, UUID/index, `/resume`, project scope, retention | Resume is CLI session history; page does not promise restoration of remote side effects |
| S18-04 | https://geminicli.com/docs/cli/telemetry/ | Official CLI documentation | telemetry file/OTLP/GCP configuration; `outfile` precedence; local file recommendation | Documentation does not guarantee crash durability, backend durable ack, or exactly-once |
| S18-05 | https://github.com/google-gemini/gemini-cli/blob/main/packages/cli/src/config/settingsSchema.ts | Official source | settings schema shows only checkpointing.enabled and restart/default metadata | Current `main` source, not a promise for future versions |
| S18-06 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/telemetry/config.ts | Official source | telemetry settings/env resolution, outfile and OTLP endpoint/protocol | Configuration parsing alone does not prove exporter durability |
| S18-07 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/telemetry/sdk.ts | Official source | exporter selection, Console/File/OTLP/GCP branches, `flushTelemetry`, `shutdownTelemetry`, SIGINT/SIGTERM | Source shows CLI behavior, not OS/filesystem or backend guarantees |
| S18-08 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/telemetry/file-exporters.ts | Official source | append file stream, `forceFlush`, stream callback, `shutdown` end | Stream flush is not an fsync or transaction commit guarantee |
| S18-09 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/telemetry/sdk.test.ts | Official tests | OTLP protocol selection and outfile overriding OTLP exporter initialization | Mocked tests do not establish network/backend durability |
| S18-10 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/tools/mcp-client.ts | Official source | `retryWithOAuth` transport-level HTTP/SSE auth retry; annotation extraction | OAuth retry is connection authentication, not business-operation retry |
| S18-11 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/tools/mcp-client.test.ts | Official tests | preservation of `idempotentHint` and other annotations; OAuth connection tests | Preservation does not imply automatic idempotency or deduplication |
| S18-12 | https://geminicli.com/docs/tools/mcp-server/ | Official CLI documentation | OAuth discovery, 401 handling, token flow, connection retry | Does not define external tool-side idempotency or read-back |
| S18-13 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/utils/checkpointUtils.ts | Official source | checkpoint file generation/list parsing implementation | Local checkpoint implementation is not an external transaction log |
| S18-14 | https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/utils/checkpointUtils.test.ts | Official tests | restorable tool-call checkpoint behavior and parsing | Tests cover CLI checkpoint utilities only |

## Evidence grading

- **A (direct official docs):** S18-01–04, S18-12.
- **B (official source/tests):** S18-05–11, S18-13–14.
- **C (bounded inference):** statements distinguishing normal-path flush risk reduction from crash/backend durability, and the requirement for external idempotency/read-back/fencing/outbox.

## Access note

Only public URLs listed above were fetched. No repository clone was performed. No prior-slice directory, prohibited directory, real service, or credential was accessed.
