/**
 * `@northstar/agent-runtime` - the governed agent loop, for TypeScript.
 *
 * Everything here is a thin, typed face on the same `python3 -m cli run --json` the shell uses:
 * one run, one child process, the same permission gate, ceilings, transcript and exit codes. See
 * `README.md` for what that buys and what it costs, and `../sdk.py` for the Python twin.
 */

export {
  createNdjsonSplitter,
  EXIT_CODES,
  initLimits,
  exitCodeFor,
  isResult,
  KNOWN_EVENT_TYPES,
  parseEventLine,
  USAGE_ERROR,
} from "./events.ts";
export type {
  AssistantEvent,
  ContentBlock,
  Denial,
  ResultEvent,
  ResultSubtype,
  RunEvent,
  StreamDeltaEvent,
  SystemEvent,
  UnknownEvent,
  UserEvent,
  Usage,
} from "./events.ts";

export {
  ConfigurationError,
  MCP_PROTOCOLS,
  PERMISSION_MODES,
  POLICY_ONLY_RETRY_KEYS,
  PROVIDERS,
  RETRYABLE_FAULTS,
  supportedFlags,
  toArgv,
  VERIFY_KINDS,
} from "./options.ts";
export type { McpOptions, McpProtocol, PermissionMode, ProviderName, RetryOptions, RunOptions, SidecarOptions } from "./options.ts";

export { defaultCwd, preview, run, streamRun, UsageError, RunFailedError } from "./run.ts";
export type { RunReport, Runner, RunTrace } from "./run.ts";
