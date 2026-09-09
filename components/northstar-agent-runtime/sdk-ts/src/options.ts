/**
 * The governed run, as a TypeScript option object - and the argv it compiles to.
 *
 * This is the only place the SDK knows about command-line flags, and it is deliberately a
 * *closed* set: an option this type does not declare throws instead of being ignored. A
 * silently-dropped key is the worst failure a wrapper can have, because the caller's config
 * keeps looking right while the run it produces is governed by defaults they never chose. The
 * runtime applies the same rule to its policy file and to a plugin manifest; a foreign face for
 * it has to as well.
 *
 * Validation here mirrors the CLI rather than inventing policy: mutual exclusions that the CLI
 * enforces (`--prompt` vs `--prompt-file`, `--script` vs `--scripted-text`, `--context-file` vs
 * `--no-project-context`, MCP servers with an agent run) are refused before a process is
 * spawned, so a caller gets the sentence in a stack trace instead of in a child's stderr.
 */

export const PERMISSION_MODES = ["default", "acceptEdits", "plan", "bypassPermissions"] as const;
export type PermissionMode = (typeof PERMISSION_MODES)[number];

export const PROVIDERS = ["scripted", "anthropic", "openai"] as const;
export type ProviderName = (typeof PROVIDERS)[number];

export const MCP_PROTOCOLS = ["auto", "legacy", "modern"] as const;
export type McpProtocol = (typeof MCP_PROTOCOLS)[number];

/** The ten fault classes `provider_retry.classify` knows; the four unretryable ones are rejected. */
/**
 * The fault classes `--retry-on` accepts, which is `provider_retry.RETRYABLE_CLASSES` and nothing
 * more. `context_overflow` is deliberately absent: it is a `[retry]` policy key
 * (`onContextOverflow`), not a class a caller may opt into per run, and the four classes
 * `NEVER_RETRYABLE_CLASSES` names are refused by construction.
 */
export const RETRYABLE_FAULTS = ["rate_limited", "overloaded", "network", "timeout", "server_error"] as const;
export type RetryableFault = (typeof RETRYABLE_FAULTS)[number];

/**
 * What a caller may set about the transport from here, which is not everything the runtime knows
 * how to bound. The command line exposes only the settings that can *tighten* the workspace's
 * `[retry]` table, so the schedule itself (base/max delay, jitter, `Retry-After` respect, context
 * overflow) is policy-file territory and is refused here by name rather than quietly dropped -
 * an SDK that accepted `jitter` and did nothing with it would hand back a run whose waiting
 * nobody configured.
 */
export type RetryOptions = {
  maxAttempts?: number;
  deadlineMs?: number;
  retryOn?: RetryableFault[];
  /** `false` is the SDK's spelling of `--no-retry`: one request per turn. */
  enabled?: boolean;
};

/** Policy-file keys, listed so the error can name the file they belong in. */
export const POLICY_ONLY_RETRY_KEYS = [
  "baseDelayMs",
  "maxDelayMs",
  "jitter",
  "respectRetryAfter",
  "onContextOverflow",
] as const;

export type McpOptions = {
  /** `"off"` (the default), `"auto"` to search the workspace's own config files, or a path. */
  config?: string;
  /** `NAME=COMMAND...` strings, exactly as `--mcp-server` takes them. */
  servers?: string[];
  timeoutMs?: number;
  protocol?: McpProtocol;
  elicit?: boolean;
  elicitAnswers?: Record<string, unknown>;
  allowSensitiveInput?: boolean;
  allowRoots?: boolean;
  maxRounds?: number;
};

export type SidecarOptions = {
  socket?: string;
  timeoutMs?: number;
  /** One health-check prompt, then exit. */
  probe?: boolean;
};

export type RunOptions = {
  prompt?: string;
  promptFile?: string;
  workspace?: string;
  provider?: ProviderName;
  model?: string;
  baseUrl?: string;
  script?: string;
  scriptedText?: string;
  maxOutputTokens?: number;
  systemPrompt?: string;
  maxTurns?: number;
  /** A ceiling, not a switch: `0` means no tool call is permitted at all. */
  maxToolCalls?: number;
  maxBudgetUsd?: number;
  compactionThresholdTokens?: number;
  compactionKeepMessages?: number;
  permissionMode?: PermissionMode;
  allowTool?: string[];
  denyTool?: string[];
  readOnly?: boolean;
  agent?: string;
  maxSubagentDepth?: number;
  allowNestedDelegation?: boolean;
  haltOnDenial?: boolean;
  requireSkillLock?: boolean;
  verify?: string[];
  checkpointTurns?: number;
  retry?: RetryOptions;
  mcp?: McpOptions;
  sidecar?: SidecarOptions;
  sessionDir?: string;
  sessionLeaseSeconds?: number;
  noSessionLease?: boolean;
  resume?: string;
  resumeFrom?: string;
  resumeRecord?: number;
  redactToolOutput?: boolean;
  stream?: boolean;
  showPricing?: boolean;
  trace?: boolean;
  quiet?: boolean;
  dryRun?: boolean;
  noPolicyFile?: boolean;
  noWorkspaceAgents?: boolean;
  noSkills?: boolean;
  noPlugins?: boolean;
  enableWorkspaceHooks?: boolean;
  allowPolicyWrites?: boolean;
  contextFile?: string;
  noProjectContext?: boolean;
  runId?: string;
};

/** The five kinds `postconditions.KINDS` accepts. */
export const VERIFY_KINDS = ["exists", "absent", "changed", "unchanged", "contains"] as const;
export type VerifyKind = (typeof VERIFY_KINDS)[number];

/** Raised for an option set the CLI would refuse, or a key it has never heard of. */
export class ConfigurationError extends Error {
  override readonly name = "ConfigurationError";
}

/**
 * One flag per scalar option. The three grouped options (`retry`, `mcp`, `sidecar`) compile to
 * several flags each and are therefore listed separately from this table - see
 * `GROUP_OPTION_KEYS` - which is also why `supportedFlags()` walks all four maps.
 */
const OPTION_FLAGS: Record<Exclude<keyof RunOptions, "retry" | "mcp" | "sidecar">, string> = {
  prompt: "--prompt",
  promptFile: "--prompt-file",
  workspace: "--workspace",
  provider: "--provider",
  model: "--model",
  baseUrl: "--base-url",
  script: "--script",
  scriptedText: "--scripted-text",
  maxOutputTokens: "--max-output-tokens",
  systemPrompt: "--system-prompt",
  maxTurns: "--max-turns",
  maxToolCalls: "--max-tool-calls",
  maxBudgetUsd: "--max-budget-usd",
  compactionThresholdTokens: "--compaction-threshold-tokens",
  compactionKeepMessages: "--compaction-keep-messages",
  permissionMode: "--permission-mode",
  allowTool: "--allow-tool",
  denyTool: "--deny-tool",
  readOnly: "--read-only",
  agent: "--agent",
  maxSubagentDepth: "--max-subagent-depth",
  allowNestedDelegation: "--allow-nested-delegation",
  haltOnDenial: "--halt-on-denial",
  requireSkillLock: "--require-skill-lock",
  verify: "--verify",
  checkpointTurns: "--checkpoint-turns",
  sessionDir: "--session-dir",
  sessionLeaseSeconds: "--session-lease-seconds",
  noSessionLease: "--no-session-lease",
  resume: "--resume",
  resumeFrom: "--resume-from",
  resumeRecord: "--resume-record",
  redactToolOutput: "--redact-tool-output",
  stream: "--stream",
  showPricing: "--show-pricing",
  trace: "--trace",
  quiet: "--quiet",
  dryRun: "--dry-run",
  noPolicyFile: "--no-policy-file",
  noWorkspaceAgents: "--no-workspace-agents",
  noSkills: "--no-skills",
  noPlugins: "--no-plugins",
  enableWorkspaceHooks: "--enable-workspace-hooks",
  allowPolicyWrites: "--allow-policy-writes",
  contextFile: "--context-file",
  noProjectContext: "--no-project-context",
  runId: "--run-id",
};

const RETRY_FLAGS: Record<keyof RetryOptions, string> = {
  maxAttempts: "--retry-max-attempts",
  deadlineMs: "--retry-deadline-ms",
  retryOn: "--retry-on",
  enabled: "",
};

const MCP_FLAGS: Record<keyof McpOptions, string> = {
  config: "--mcp-config",
  servers: "--mcp-server",
  timeoutMs: "--mcp-timeout-ms",
  protocol: "--mcp-protocol",
  elicit: "--mcp-elicit",
  elicitAnswers: "--mcp-elicit-answers",
  allowSensitiveInput: "--mcp-allow-sensitive-input",
  allowRoots: "--mcp-allow-roots",
  maxRounds: "--mcp-max-rounds",
};

const SIDECAR_FLAGS: Record<keyof SidecarOptions, string> = {
  socket: "--sidecar-socket",
  timeoutMs: "--sidecar-timeout-ms",
  probe: "--probe-sidecar",
};

/** The options that are namespaces rather than flags, and so are absent from `OPTION_FLAGS`. */
export const GROUP_OPTION_KEYS = ["retry", "mcp", "sidecar"] as const;

/** Every flag name this module can emit, for the parity test against `cli run --help`. */
/**
 * Numbers: `null` and `undefined` both mean "no value set", which is the only spelling that
 * leaves a ceiling where the operator put it. Setting a key to `null` never *raises* a ceiling -
 * the policy file keeps that authority, exactly as it does on the command line.
 */
export function supportedFlags(): string[] {
  const names = new Set<string>(Object.values(OPTION_FLAGS));
  // `--provider` is a choice flag: the *value* is what callers get wrong, so the parity test
  // checks the name too, and it is listed here rather than special-cased there.
  for (const value of Object.values(RETRY_FLAGS)) if (value) names.add(value);
  for (const value of Object.values(MCP_FLAGS)) names.add(value);
  for (const value of Object.values(SIDECAR_FLAGS)) names.add(value);
  // `--no-retry` has no value to carry, so it appears in no flag map above; it is still a flag
  // this module emits, and the parity test is what keeps that statement true.
  names.add("--no-retry");
  // `--json` is deliberately absent: toArgv appends it and a caller cannot set it. Listing it
  // here would tell the parity test (and the reader) that the stream is negotiable.
  return [...names].sort();
}

function fail(message: string): never {
  throw new ConfigurationError(message);
}

function checkUnknownKeys(source: object, allowed: readonly string[], what: string): void {
  const unknown = Object.keys(source)
    .filter((key) => !allowed.includes(key))
    .sort();
  if (unknown.length > 0) {
    fail(`northstar ${what}: unknown option(s) ${unknown.join(", ")}; this SDK does not pass unknown keys through`);
  }
}

function checkNumber(value: unknown, flag: string, bounds: { min?: number; max?: number; integer?: boolean }): number {
  if (typeof value !== "number" || Number.isNaN(value)) fail(`${flag} expects a number`);
  if (bounds.integer && !Number.isInteger(value)) fail(`${flag} expects an integer, got ${value}`);
  if (bounds.min !== undefined && value < bounds.min) fail(`${flag} expects a value >= ${bounds.min}, got ${value}`);
  if (bounds.max !== undefined && value > bounds.max) fail(`${flag} expects a value <= ${bounds.max}, got ${value}`);
  return value;
}

function checkString(value: unknown, flag: string): string {
  if (typeof value !== "string") fail(`${flag} expects a string`);
  return value;
}

function checkStringList(value: unknown, flag: string): string[] {
  if (!Array.isArray(value)) fail(`${flag} expects an array of strings`);
  return value.map((item) => checkString(item, flag));
}

function push(value: string | number, flag: string, argv: string[]): void {
  argv.push(flag, String(value));
}

function pushList(values: readonly string[], flag: string, argv: string[]): void {
  for (const value of values) argv.push(flag, value);
}

/**
 * Compile an option object into `["run", ...flags]`.
 *
 * `--json` is appended here and is not a caller-settable option: an SDK that let a caller turn
 * off the machine-readable stream would have no contract to parse, and a human-readable
 * fallback is exactly the "silently different behaviour" this whole surface avoids.
 */
export function toArgv(options: RunOptions): string[] {
  checkUnknownKeys(options, [...Object.keys(OPTION_FLAGS), ...GROUP_OPTION_KEYS], "run options");
  const argv: string[] = ["run"];

  const hasPrompt = options.prompt !== undefined;
  const hasPromptFile = options.promptFile !== undefined;
  if (!hasPrompt && !hasPromptFile) fail("northstar run options: `prompt` (or `promptFile`) is required");
  if (hasPrompt && hasPromptFile) fail("northstar run options: `prompt` and `promptFile` are mutually exclusive");
  if (hasPrompt) push(checkString(options.prompt, "--prompt"), "--prompt", argv);
  if (hasPromptFile) push(checkString(options.promptFile, "--prompt-file"), "--prompt-file", argv);

  if (options.script !== undefined && options.scriptedText !== undefined) {
    fail("northstar run options: `script` and `scriptedText` are mutually exclusive (the CLI reads them the same way)");
  }
  for (const key of [
    "script",
    "scriptedText",
    "model",
    "baseUrl",
    "systemPrompt",
    "agent",
    "sessionDir",
    "resume",
    "resumeFrom",
    "contextFile",
    "runId",
  ] as const) {
    const value = options[key];
    if (value !== undefined) push(checkString(value, OPTION_FLAGS[key]), OPTION_FLAGS[key], argv);
  }
  if (options.workspace !== undefined) push(checkString(options.workspace, "--workspace"), "--workspace", argv);
  if (options.provider !== undefined) {
    const value = checkString(options.provider, "--provider");
    if (!(PROVIDERS as readonly string[]).includes(value)) fail(`--provider must be one of ${PROVIDERS.join(", ")}`);
    push(value, "--provider", argv);
  }
  if (options.provider !== undefined && options.model !== undefined) {
    // `cli.resolve_model` refuses an impossible provider/model pairing before any credential is
    // read or a turn is spent. Mirroring that here costs the caller nothing; letting it through
    // would mean a child process, a transcript, and a failure that was knowable at build time.
    const model = checkString(options.model, "--model").trim();
    if (options.provider === "openai" && model.startsWith("claude")) {
      fail(
        `provider "openai" cannot serve ${JSON.stringify(model)}: pass a Chat Completions model id ` +
          '(`model: "gpt-4.1"`) or use provider "anthropic" for Claude models',
      );
    }
    if (options.provider === "anthropic" && !model.startsWith("claude")) {
      fail(
        `provider "anthropic" cannot serve ${JSON.stringify(model)}: the Messages API speaks for Claude ` +
          'models; use provider "openai" for Chat Completions endpoints',
      );
    }
  }
  if (options.permissionMode !== undefined) {
    const value = checkString(options.permissionMode, "--permission-mode");
    if (!(PERMISSION_MODES as readonly string[]).includes(value)) fail(`--permission-mode must be one of ${PERMISSION_MODES.join(", ")}`);
    push(value, "--permission-mode", argv);
  }

  const numbers: [keyof RunOptions, { min?: number; max?: number }][] = [
    ["maxOutputTokens", { min: 1 }],
    ["maxTurns", { min: 1 }],
    ["maxToolCalls", { min: 0 }],
    ["compactionThresholdTokens", { min: 0 }],
    ["compactionKeepMessages", { min: 0 }],
    ["maxSubagentDepth", { min: 1 }],
    ["checkpointTurns", { min: 0 }],
    ["sessionLeaseSeconds", { min: 1 }],
    ["resumeRecord", { min: 0 }],
  ];
  for (const [key, bounds] of numbers) {
    const value = options[key];
    if (value === undefined || value === null) continue;
    push(checkNumber(value, OPTION_FLAGS[key], { ...bounds, integer: true }), OPTION_FLAGS[key], argv);
  }
  if (options.maxBudgetUsd !== undefined && options.maxBudgetUsd !== null) {
    const value = checkNumber(options.maxBudgetUsd, "--max-budget-usd", { min: 0 });
    if (value <= 0) fail("--max-budget-usd must be positive when set; leave it undefined for no ceiling");
    push(value, "--max-budget-usd", argv);
  }
  if (options.resumeRecord !== undefined && options.resumeRecord !== null && options.resumeFrom === undefined) {
    fail("`resumeRecord` needs `resumeFrom`: a record index without a parent session is not a fork point");
  }

  for (const [key, flag] of [
    ["allowTool", "--allow-tool"],
    ["denyTool", "--deny-tool"],
  ] as const) {
    const value = options[key];
    if (value !== undefined) pushList(checkStringList(value, flag), flag, argv);
  }
  if (options.verify !== undefined) {
    // Mirrors `postconditions.parse_cli_specs` plus the check `PostCondition.__post_init__`
    // makes, so a malformed verification is a rejected call rather than a run that ends at
    // exit 64 after the model has already been paid.
    const entries = checkStringList(options.verify, "--verify");
    for (const entry of entries) {
      const parts = entry.split(":", 3);
      if (parts.length < 2) {
        fail(`--verify expects KIND:PATH (got ${JSON.stringify(entry)}); kinds: ${VERIFY_KINDS.join(", ")}`);
      }
      const kind = parts[0].trim();
      if (!(VERIFY_KINDS as readonly string[]).includes(kind)) {
        fail(`--verify: unknown postcondition kind ${JSON.stringify(parts[0])}; expected one of ${VERIFY_KINDS.join(", ")}`);
      }
      const path = parts[1].trim();
      if (!path) fail(`--verify needs a path after the kind (got ${JSON.stringify(entry)})`);
      // The same containment rule the verifier enforces: a check that reaches outside the
      // workspace is a configuration error, not a permission the run gets to exercise.
      if (path.startsWith("/") || path === ".." || path.startsWith("../")) {
        fail(`--verify: postcondition path ${JSON.stringify(path)} must be workspace-relative, not absolute or escaping`);
      }
      if (kind === "contains" && !(parts[2] ?? "").trim()) {
        fail("a 'contains' postcondition needs the text to look for: contains:PATH:TEXT");
      }
    }
    pushList(entries, "--verify", argv);
  }

  for (const key of [
    "readOnly",
    "allowNestedDelegation",
    "haltOnDenial",
    "requireSkillLock",
    "redactToolOutput",
    "stream",
    "showPricing",
    "trace",
    "quiet",
    "dryRun",
    "noSessionLease",
    "noPolicyFile",
    "noWorkspaceAgents",
    "noSkills",
    "noPlugins",
    "enableWorkspaceHooks",
    "allowPolicyWrites",
    "noProjectContext",
  ] as const) {
    const value = options[key];
    if (value === undefined) continue;
    if (typeof value !== "boolean") fail(`${OPTION_FLAGS[key]} expects a boolean`);
    if (value) argv.push(OPTION_FLAGS[key]);
  }
  // `--context-file` and `--no-project-context` contradict each other, and the CLI says so;
  // refusing here costs the caller nothing and saves them a child process.
  if (options.contextFile !== undefined && options.noProjectContext) {
    fail("`contextFile` and `noProjectContext` are mutually exclusive");
  }

  if (options.retry !== undefined) appendRetry(options.retry, argv);
  if (options.mcp !== undefined) appendMcp(options.mcp, options, argv);
  if (options.sidecar !== undefined) appendSidecar(options.sidecar, argv);

  argv.push("--json");
  return argv;
}

function appendRetry(retry: RetryOptions, argv: string[]): void {
  for (const key of POLICY_ONLY_RETRY_KEYS) {
    if (key in retry) {
      fail(
        `retry.${key} is not a command-line setting: put it in the [retry] table of ` +
          ".northstar/config.toml, which these flags may only tighten",
      );
    }
  }
  checkUnknownKeys(retry, Object.keys(RETRY_FLAGS), "retry options");
  if (retry.enabled === false) {
    argv.push("--no-retry");
    return;
  }
  if (retry.maxAttempts !== undefined) push(checkNumber(retry.maxAttempts, RETRY_FLAGS.maxAttempts, { min: 1, integer: true }), RETRY_FLAGS.maxAttempts, argv);
  if (retry.deadlineMs !== undefined) push(checkNumber(retry.deadlineMs, RETRY_FLAGS.deadlineMs, { min: 0, integer: true }), RETRY_FLAGS.deadlineMs, argv);
  if (retry.retryOn !== undefined) {
    const list = checkStringList(retry.retryOn, RETRY_FLAGS.retryOn);
    for (const name of list) {
      if (!(RETRYABLE_FAULTS as readonly string[]).includes(name)) {
        fail(
          `${RETRY_FLAGS.retryOn} accepts only ${RETRYABLE_FAULTS.join(", ")}; auth, client_error, unknown and ` +
            "stream_interrupted are never retryable by construction",
        );
      }
    }
    if (list.length === 0) fail(`${RETRY_FLAGS.retryOn} must not be empty (leave it undefined for the default set)`);
    push(list.join(","), RETRY_FLAGS.retryOn, argv);
  }
}

function appendMcp(mcp: McpOptions, options: RunOptions, argv: string[]): void {
  checkUnknownKeys(mcp, Object.keys(MCP_FLAGS), "mcp options");
  if (mcp.config !== undefined) {
    const value = checkString(mcp.config, MCP_FLAGS.config);
    if (!["off", "auto"].includes(value) && !value.endsWith(".json") && !value.endsWith("settings.json")) {
      fail(`${MCP_FLAGS.config} expects "off", "auto", or a path to an MCP config file`);
    }
    push(value, MCP_FLAGS.config, argv);
  }
  if (mcp.servers !== undefined) {
    const servers = checkStringList(mcp.servers, MCP_FLAGS.servers);
    if (options.agent !== undefined && servers.length > 0) {
      fail(
        "an agent-definition run fixes its tool subset by definition, so MCP servers cannot be added to it; " +
          "drop `agent` or drop `mcp.servers` (the CLI refuses the same combination)",
      );
    }
    for (const server of servers) {
      if (!server.includes("=")) fail(`${MCP_FLAGS.servers} expects NAME=COMMAND... (got ${JSON.stringify(server)})`);
    }
    pushList(servers, MCP_FLAGS.servers, argv);
  }
  if (mcp.timeoutMs !== undefined) push(checkNumber(mcp.timeoutMs, MCP_FLAGS.timeoutMs, { min: 100, integer: true }), MCP_FLAGS.timeoutMs, argv);
  if (mcp.protocol !== undefined) {
    const value = checkString(mcp.protocol, MCP_FLAGS.protocol);
    if (!(MCP_PROTOCOLS as readonly string[]).includes(value)) fail(`${MCP_FLAGS.protocol} must be one of ${MCP_PROTOCOLS.join(", ")}`);
    push(value, MCP_FLAGS.protocol, argv);
  }
  if (mcp.maxRounds !== undefined) push(checkNumber(mcp.maxRounds, MCP_FLAGS.maxRounds, { min: 1, max: 8, integer: true }), MCP_FLAGS.maxRounds, argv);
  for (const key of ["elicit", "allowSensitiveInput", "allowRoots"] as const) {
    const value = mcp[key];
    if (value === undefined) continue;
    if (typeof value !== "boolean") fail(`${MCP_FLAGS[key]} expects a boolean`);
    if (value) argv.push(MCP_FLAGS[key]);
  }
  if (mcp.elicitAnswers !== undefined) {
    if (mcp.elicit !== true) fail("`mcp.elicitAnswers` requires `mcp.elicit: true` (answering is opt-in, not a side effect of supplying answers)");
    push(JSON.stringify(mcp.elicitAnswers), MCP_FLAGS.elicitAnswers, argv);
  }
}

function appendSidecar(sidecar: SidecarOptions, argv: string[]): void {
  checkUnknownKeys(sidecar, Object.keys(SIDECAR_FLAGS), "sidecar options");
  if (sidecar.socket !== undefined) push(checkString(sidecar.socket, SIDECAR_FLAGS.socket), SIDECAR_FLAGS.socket, argv);
  if (sidecar.timeoutMs !== undefined) push(checkNumber(sidecar.timeoutMs, SIDECAR_FLAGS.timeoutMs, { min: 1, integer: true }), SIDECAR_FLAGS.timeoutMs, argv);
  if (sidecar.probe !== undefined) {
    if (typeof sidecar.probe !== "boolean") fail(`${SIDECAR_FLAGS.probe} expects a boolean`);
    if (sidecar.probe) argv.push(SIDECAR_FLAGS.probe);
  }
}
