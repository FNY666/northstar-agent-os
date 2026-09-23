# S12 sources

取证日期：2026-09-22。所有源码链接均为官方仓库 `google-gemini/gemini-cli` 的固定提交 `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`，避免把可变 `main` 误当成不可变证据。publisher 均为 Google / Gemini CLI 官方仓库。

## S1 — ChatRecordingService
- URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/services/chatRecordingService.ts
- 具体行：`loadConversationRecord` JSONL 逐行解析与 `$rewindTo`（约 L133-L315）；`appendRecord`（约 L559-L572）；`rewriteConversationFile` 的 backup、temp、rename（约 L576-L639）；`updateMetadata`/`pushMessage`（约 L642-L659）；`recordMessage`（约 L686-L716）；`recordToolCalls`（约 L775-L850）。
- publisher: Google Gemini CLI official GitHub repository
- published_or_updated: 2026-09-22 (accessed commit; source file has no separate publication date)
- tier: primary
- evidence_level: A — direct official source code
- support: Shows JSONL line replay, appendFileSync, temp-file + rename rewrite, and message-before-metadata call order. It does not contain fsync, directory fsync, a hash chain, or an external side-effect journal.
- accessed: 2026-09-22

## S2 — ChatRecordingService tests
- URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/services/chatRecordingService.test.ts
- 具体行：重写失败、临时文件清理、recordMessage/recordToolCalls、tokens 排队与写入顺序相关测试（约 L260-L430、L432-L780、L1540-L1650）。
- publisher: Google Gemini CLI official GitHub repository
- published_or_updated: 2026-09-22 (accessed commit; source file has no separate publication date)
- tier: primary
- evidence_level: A — direct official tests
- support: Demonstrates tested normal recording, error cleanup, queued token behavior, and call-order assertions. Tests do not establish crash consistency, kill -9 behavior, power-loss durability, or multi-process atomicity.
- accessed: 2026-09-22

## S3 — Session summary persistence
- URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/services/sessionSummaryUtils.ts
- 具体行：summary/scratchpad metadata update and JSONL `fs.appendFile` (约 L322-L459).
- publisher: Google Gemini CLI official GitHub repository
- published_or_updated: 2026-09-22 (accessed commit; source file has no separate publication date)
- tier: primary
- evidence_level: A — direct official source code
- support: Shows JSONL summary metadata is appended as a `$set` line; legacy JSON uses writeFile. No transaction, fsync, checksum, or atomic JSONL append protocol is shown.
- accessed: 2026-09-22

## S4 — File OTel exporters
- URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/telemetry/file-exporters.ts
- 具体行：append stream constructor (约 L21-L29), `forceFlush` (约 L33-L50), `shutdown` (约 L53-L57), span/log/metric `write` callbacks (约 L60-L110).
- publisher: Google Gemini CLI official GitHub repository
- published_or_updated: 2026-09-22 (accessed commit; source file has no separate publication date)
- tier: primary
- evidence_level: A — direct official source code
- support: Shows append-mode Node WriteStream, callback-based queued-write completion, and stream end. No fsync or remote collector durable acknowledgement is implemented here.
- accessed: 2026-09-22

## S5 — Telemetry SDK lifecycle
- URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/telemetry/sdk.ts
- 具体行：initialization/exporter selection and batch processors (约 L165-L343); SIGTERM/SIGINT handlers (约 L375-L389); `flushTelemetry` and `shutdownTelemetry` (约 L394-L464).
- publisher: Google Gemini CLI official GitHub repository
- published_or_updated: 2026-09-22 (accessed commit; source file has no separate publication date)
- tier: primary
- evidence_level: A — direct official source code
- support: Shows batch processors, forceFlush calls and sdk.shutdown. These are application/SDK lifecycle operations, not proof of disk or collector durability or zero loss.
- accessed: 2026-09-22

## S6 — MessageBus
- URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/confirmation-bus/message-bus.ts
- 具体行：EventEmitter class and `emitMessage` (约 L15-L46); `publish` policy/emit path (约 L93-L164); subscription and request/response (约 L167-L264).
- publisher: Google Gemini CLI official GitHub repository
- published_or_updated: 2026-09-22 (accessed commit; source file has no separate publication date)
- tier: primary
- evidence_level: A — direct official source code
- support: Shows in-memory EventEmitter publish/emit and no file/database/journal write in MessageBus. A listener may separately record an event; that is outside MessageBus itself.
- accessed: 2026-09-22

## S7 — OTel semantic events and logger calls
- URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/telemetry/loggers.ts
- 具体行：`logToolCall` and attributes/metrics (约 L139-L180); API response and rewind event logging (约 L307-L424).
- publisher: Google Gemini CLI official GitHub repository
- published_or_updated: 2026-09-22 (accessed commit; source file has no separate publication date)
- tier: primary
- evidence_level: A — direct official source code
- support: Shows tool-call fields including decision/success/duration and logger emission paths, plus API response/rewind entries. It does not prove every approval request, execution transition, external side effect, or export is durably and completely linked.
- accessed: 2026-09-22

## S8 — OTel semantic definitions
- URL: https://github.com/google-gemini/gemini-cli/blob/d5b3e3accb26000d273abf16e0f1dd83aa5428a9/packages/core/src/telemetry/semantic.ts
- 具体行：tool-call and tool-call-response semantic event definitions (约 L280-L420).
- publisher: Google Gemini CLI official GitHub repository
- published_or_updated: 2026-09-22 (accessed commit; source file has no separate publication date)
- tier: primary
- evidence_level: A — direct official source code
- support: Defines event shapes and size/truncation-related constraints; schema presence is not proof of event completeness, durability, immutable storage, or side-effect reconstruction.
- accessed: 2026-09-22

## Scope/caveat

No non-official sources were used. GitHub API rate limiting was encountered during one probe, but official raw/blob pages and git remote access supplied the cited fixed-commit source. No private account, credential, real service, shared/P0, accident, D10/L12/D14, canonical, 140, tri-line, systemd, S4-S11 directory, or any real service was accessed.
