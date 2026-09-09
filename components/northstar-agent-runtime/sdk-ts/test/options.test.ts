/**
 * Option building and refusal. The rule throughout: exactly the flags the CLI has, validated
 * before a process exists, and never a silent drop.
 */
import assert from "node:assert/strict";
import test from "node:test";

import {
  ConfigurationError,
  MCP_PROTOCOLS,
  PERMISSION_MODES,
  POLICY_ONLY_RETRY_KEYS,
  PROVIDERS,
  RETRYABLE_FAULTS,
  supportedFlags,
  toArgv,
  VERIFY_KINDS,
} from "../src/options.ts";

function argvOf(options: Record<string, unknown>): string[] {
  return toArgv(options as never);
}

function flagValue(argv: string[], flag: string): string | undefined {
  const at = argv.indexOf(flag);
  return at === -1 ? undefined : argv[at + 1];
}

test("the minimum call is the minimum command", () => {
  assert.deepEqual(argvOf({ prompt: "hi" }), ["run", "--prompt", "hi", "--json"]);
});

test("every scalar maps to its flag verbatim, and --json is appended exactly once", () => {
  const argv = argvOf({
    prompt: "p",
    provider: "anthropic",
    model: "claude-x",
    baseUrl: "http://127.0.0.1:1/v1",
    maxTurns: 3,
    permissionMode: "acceptEdits",
    workspace: "/tmp/w",
    systemPrompt: "be brief",
    resume: "s-7",
    runId: "run-7",
    sessionDir: "/tmp/w/.northstar/sessions",
  });
  assert.equal(flagValue(argv, "--provider"), "anthropic");
  assert.equal(flagValue(argv, "--model"), "claude-x");
  assert.equal(flagValue(argv, "--base-url"), "http://127.0.0.1:1/v1");
  assert.equal(flagValue(argv, "--max-turns"), "3");
  assert.equal(flagValue(argv, "--permission-mode"), "acceptEdits");
  assert.equal(flagValue(argv, "--workspace"), "/tmp/w");
  assert.equal(flagValue(argv, "--system-prompt"), "be brief");
  assert.equal(flagValue(argv, "--resume"), "s-7");
  assert.equal(flagValue(argv, "--run-id"), "run-7");
  assert.equal(flagValue(argv, "--session-dir"), "/tmp/w/.northstar/sessions");
  assert.equal(argv.filter((a) => a === "--json").length, 1);
  // Flags must follow the option that owns them, so `-m cli run --json` is not read as a value.
  assert.equal(argv.at(-1), "--json");
});

test("booleans are presence flags, so `false` emits nothing rather than a negation", () => {
  const on = argvOf({
    prompt: "p",
    trace: true,
    quiet: true,
    stream: true,
    readOnly: true,
    haltOnDenial: true,
    showPricing: true,
    dryRun: true,
  });
  for (const flag of ["--trace", "--quiet", "--stream", "--read-only", "--halt-on-denial", "--show-pricing", "--dry-run"]) {
    assert.ok(on.includes(flag), flag);
  }
  const off = argvOf({ prompt: "p", trace: false, quiet: false, noSessionLease: false, noSkills: false });
  for (const flag of ["--trace", "--quiet", "--no-session-lease", "--no-skills"]) {
    assert.equal(off.includes(flag), false, flag);
  }
});

test("`--plan` is not duplicated behind `--permission-mode plan`, because the CLI forbids both", () => {
  const argv = argvOf({ prompt: "p", permissionMode: "plan" });
  assert.equal(flagValue(argv, "--permission-mode"), "plan");
  assert.equal(argv.includes("--plan"), false);
});

test("the closed sets are the CLI's closed sets", () => {
  assert.deepEqual(RETRYABLE_FAULTS, ["rate_limited", "overloaded", "network", "timeout", "server_error"]);
  assert.deepEqual(PROVIDERS, ["scripted", "anthropic", "openai"]);
  assert.deepEqual([...PERMISSION_MODES], ["default", "acceptEdits", "plan", "bypassPermissions"]);
  assert.deepEqual([...MCP_PROTOCOLS], ["auto", "legacy", "modern"]);
  assert.deepEqual([...VERIFY_KINDS], ["exists", "absent", "changed", "unchanged", "contains"]);
  assert.ok(RETRYABLE_FAULTS.includes("rate_limited"));
  assert.equal(RETRYABLE_FAULTS.includes("auth"), false);
});

test("a permission mode outside the four is refused by name, and so is a provider outside three", () => {
  assert.throws(() => argvOf({ prompt: "p", permissionMode: "yolo" }), /--permission-mode must be one of/);
  assert.throws(() => argvOf({ prompt: "p", provider: "bedrock" }), /--provider must be one of/);
});

test("an impossible provider/model pairing is refused here, not after a credential is read", () => {
  assert.throws(() => argvOf({ prompt: "p", provider: "openai", model: "claude-sonnet-4-5" }), /cannot serve "claude-sonnet-4-5"/);
  assert.throws(() => argvOf({ prompt: "p", provider: "anthropic", model: "gpt-4.1" }), /cannot serve "gpt-4.1"/);
  // The pairings the runtime itself resolves must pass, including the omitted model: the CLI
  // fills a default per provider, and the SDK has no business guessing what that default is.
  assert.ok(argvOf({ prompt: "p", provider: "anthropic", model: "claude-sonnet-4-5" }).includes("--model"));
  assert.equal(argvOf({ prompt: "p", provider: "anthropic" }).includes("--model"), false);
  assert.ok(argvOf({ prompt: "p", provider: "openai", model: "gpt-4.1" }).includes("--model"));
  assert.ok(argvOf({ prompt: "p", provider: "scripted", model: "anything-at-all" }).includes("--model"));
});

test("`maxToolCalls: 0` means no tool call, which is not the same as leaving it out", () => {
  assert.equal(flagValue(argvOf({ prompt: "p", maxToolCalls: 0 }), "--max-tool-calls"), "0");
  assert.equal(argvOf({ prompt: "p" }).includes("--max-tool-calls"), false);
  assert.throws(() => argvOf({ prompt: "p", maxToolCalls: -1 }), /expects a value >= 0/);
});

test("a ceiling of zero is a mistake, not a policy: only the tool-call ceiling may be zero", () => {
  assert.throws(() => argvOf({ prompt: "p", maxBudgetUsd: 0 }), /must be positive when set/);
  assert.throws(() => argvOf({ prompt: "p", maxBudgetUsd: -2 }), /expects a value >= 0/);
  assert.throws(() => argvOf({ prompt: "p", maxTurns: 0 }), /--max-turns expects a value >= 1/);
  assert.throws(() => argvOf({ prompt: "p", maxOutputTokens: 0 }), /--max-output-tokens expects a value >= 1/);
  assert.equal(flagValue(argvOf({ prompt: "p", maxOutputTokens: 100 }), "--max-output-tokens"), "100");
  assert.equal(flagValue(argvOf({ prompt: "p", maxBudgetUsd: 0.5 }), "--max-budget-usd"), "0.5");
});

test("the compaction and checkpoint zeros mean off, unlike a ceiling's zero", () => {
  assert.equal(flagValue(argvOf({ prompt: "p", compactionThresholdTokens: 0 }), "--compaction-threshold-tokens"), "0");
  assert.equal(flagValue(argvOf({ prompt: "p", compactionKeepMessages: 2 }), "--compaction-keep-messages"), "2");
  assert.equal(flagValue(argvOf({ prompt: "p", checkpointTurns: 0 }), "--checkpoint-turns"), "0");
});

test("prompt and prompt file, script and scripted text, are each one or the other", () => {
  assert.throws(() => argvOf({ prompt: "p", promptFile: "/tmp/p.md" }), /mutually exclusive/);
  assert.throws(() => argvOf({ prompt: "p", script: "/tmp/t.json", scriptedText: "hi" }), /mutually exclusive/);
  assert.ok(argvOf({ promptFile: "/tmp/p.md" }).includes("--prompt-file"));
  assert.equal(flagValue(argvOf({ prompt: "p", scriptedText: "one answer" }), "--scripted-text"), "one answer");
});

test("an agent run cannot gain MCP servers, and a context file cannot be combined with no context", () => {
  assert.throws(
    () => argvOf({ prompt: "p", agent: "reviewer", mcp: { servers: ["x=/bin/x"] } }),
    /an agent-definition run fixes its tool subset by definition/,
  );
  assert.throws(() => argvOf({ prompt: "p", contextFile: "docs/AGENTS.md", noProjectContext: true }), /mutually exclusive/);
  // An empty `mcp.servers` is not "MCP with no servers": the CLI still reads `--mcp-config auto`
  // from the workspace, so the SDK must not turn `[]` into a refusal or into a flag.
  assert.ok(argvOf({ prompt: "p", agent: "reviewer", mcp: { servers: [] } }).includes("--agent"));
  assert.equal(argvOf({ prompt: "p", mcp: { servers: [] } }).includes("--mcp-server"), false);
});

test("resumeRecord without resumeFrom is a fork point with nowhere to fork from", () => {
  assert.throws(() => argvOf({ prompt: "p", resumeRecord: 3 }), /needs `resumeFrom`/);
  assert.deepEqual(
    argvOf({ prompt: "p", resumeFrom: "s-1", resumeRecord: 3 }).slice(1),
    ["--prompt", "p", "--resume-from", "s-1", "--resume-record", "3", "--json"],
  );
});

test("an option this build does not know is refused, not dropped", () => {
  assert.throws(() => argvOf({ prompt: "p", dangerouslyDisableGovernance: true }), /unknown option\(s\) dangerouslyDisableGovernance/);
});

test("retry: the ladder is here, the schedule is policy", () => {
  assert.deepEqual(
    argvOf({ prompt: "p", retry: { maxAttempts: 2, deadlineMs: 5000, retryOn: ["rate_limited", "timeout"] } }).slice(1),
    ["--prompt", "p", "--retry-max-attempts", "2", "--retry-deadline-ms", "5000", "--retry-on", "rate_limited,timeout", "--json"],
  );
  assert.ok(argvOf({ prompt: "p", retry: { enabled: false } }).includes("--no-retry"));
  assert.equal(argvOf({ prompt: "p", retry: { enabled: true } }).includes("--no-retry"), false);
  for (const key of POLICY_ONLY_RETRY_KEYS) {
    assert.throws(() => argvOf({ prompt: "p", retry: { [key]: 1 } }), /not a command-line setting: put it in the \[retry\] table/, key);
  }
  assert.throws(() => argvOf({ prompt: "p", retry: { retryOn: ["auth"] } }), /never retryable by construction/);
  assert.throws(() => argvOf({ prompt: "p", retry: { retryOn: [] } }), /must not be empty/);
  assert.throws(() => argvOf({ prompt: "p", retry: { nope: 1 } }), /northstar retry options: unknown option\(s\) nope/);
});

test("MCP: servers, protocol, elicitation gating, and the config declaration", () => {
  const argv = argvOf({
    prompt: "p",
    mcp: {
      servers: ["fs=/bin/false /tmp", "notes=/bin/notes"],
      config: "/tmp/.mcp.json",
      protocol: "modern",
      timeoutMs: 1500,
      allowSensitiveInput: true,
      elicit: true,
      elicitAnswers: { confirm: { action: "accept", content: { ok: true } } },
      allowRoots: true,
      maxRounds: 2,
      allowExec: true,
      env: ["GITHUB_TOKEN", "HOME"],
    },
  });
  assert.equal(argv.filter((a) => a === "--mcp-server").length, 2);
  assert.equal(flagValue(argv, "--mcp-server"), "fs=/bin/false /tmp");
  assert.equal(flagValue(argv, "--mcp-protocol"), "modern");
  assert.equal(flagValue(argv, "--mcp-timeout-ms"), "1500");
  assert.ok(argv.includes("--mcp-allow-sensitive-input"));
  assert.ok(argv.includes("--mcp-elicit"));
  assert.ok(argv.includes("--mcp-allow-roots"));
  assert.equal(flagValue(argv, "--mcp-elicit-answers"), '{"confirm":{"action":"accept","content":{"ok":true}}}');
  assert.equal(flagValue(argv, "--mcp-config"), "/tmp/.mcp.json");
  assert.equal(flagValue(argv, "--mcp-max-rounds"), "2");
  assert.ok(argv.includes("--mcp-allow-exec"), "reading a declaration and starting it are separate flags");
  assert.equal(argv.filter((a) => a === "--mcp-env").length, 2);
  assert.equal(flagValue(argv, "--mcp-env"), "GITHUB_TOKEN");
  assert.ok(
    !argvOf({ prompt: "p", mcp: { allowExec: false } }).includes("--mcp-allow-exec"),
    "false is not an opt-in",
  );

  assert.throws(() => argvOf({ prompt: "p", mcp: { elicitAnswers: {} } }), /requires `mcp.elicit: true`/);
  assert.throws(() => argvOf({ prompt: "p", mcp: { maxRounds: 0 } }), /expects a value >= 1/);
  assert.throws(() => argvOf({ prompt: "p", mcp: { maxRounds: 9 } }), /expects a value <= 8/);
  assert.throws(() => argvOf({ prompt: "p", mcp: { servers: ["fs /bin/false"] } }), /expects NAME=COMMAND/);
  assert.throws(() => argvOf({ prompt: "p", mcp: { protocol: "2024-01-01" } }), /must be one of auto, legacy, modern/);
  assert.throws(() => argvOf({ prompt: "p", mcp: { config: "yes" } }), /expects "off", "auto", or a path/);
  assert.throws(() => argvOf({ prompt: "p", mcp: { bogus: 1 } }), /northstar mcp options: unknown option\(s\) bogus/);
  assert.throws(() => argvOf({ prompt: "p", mcp: { env: ["7BAD"] } }), /--mcp-env expects a variable name/);
  for (const value of ["off", "auto"]) {
    assert.equal(flagValue(argvOf({ prompt: "p", mcp: { config: value } }), "--mcp-config"), value);
  }
});

test("the sidecar is asked to confirm a turn, and nothing else", () => {
  assert.deepEqual(
    argvOf({ prompt: "p", sidecar: { socket: "/tmp/s.sock", timeoutMs: 400, probe: true } }).slice(1),
    ["--prompt", "p", "--sidecar-socket", "/tmp/s.sock", "--sidecar-timeout-ms", "400", "--probe-sidecar", "--json"],
  );
  assert.throws(() => argvOf({ prompt: "p", sidecar: { timeoutMs: 0 } }), /expects a value >= 1/);
  assert.throws(() => argvOf({ prompt: "p", sidecar: { verifyAll: true } }), /northstar sidecar options: unknown option\(s\) verifyAll/);
});

test("verifications are validated here as well as there, so a typo fails before a process exists", () => {
  const argv = argvOf({ prompt: "p", verify: ["contains:out.md:northstar", "exists:out.md"] });
  assert.equal(argv.filter((a) => a === "--verify").length, 2);
  assert.equal(flagValue(argv, "--verify"), "contains:out.md:northstar");
  assert.throws(() => argvOf({ prompt: "p", verify: ["exists"] }), /--verify expects KIND:PATH/);
  assert.throws(() => argvOf({ prompt: "p", verify: ["nope:out.md"] }), /unknown postcondition kind/);
  assert.throws(() => argvOf({ prompt: "p", verify: ["exists:"] }), /needs a path/);
  assert.throws(() => argvOf({ prompt: "p", verify: ["exists:/etc/passwd"] }), /workspace-relative, not absolute or escaping/);
  assert.throws(() => argvOf({ prompt: "p", verify: ["exists:../outside"] }), /workspace-relative, not absolute or escaping/);
  assert.throws(() => argvOf({ prompt: "p", verify: ["contains:out.md"] }), /needs the text to look for/);
  assert.ok(argvOf({ prompt: "p", verify: ["contains:out.md:hi"] }).includes("--verify"));
});

test("repeatable allow/deny lists keep their order and their repetition", () => {
  assert.deepEqual(
    argvOf({ prompt: "p", allowTool: ["Read", "Grep"], denyTool: ["Write"] }).slice(1),
    ["--prompt", "p", "--allow-tool", "Read", "--allow-tool", "Grep", "--deny-tool", "Write", "--json"],
  );
  assert.throws(() => argvOf({ prompt: "p", allowTool: "Read" }), /expects an array of strings/);
});

test("session-lease rules are enforced the way the runtime enforces them", () => {
  assert.equal(flagValue(argvOf({ prompt: "p", sessionLeaseSeconds: 30 }), "--session-lease-seconds"), "30");
  assert.throws(() => argvOf({ prompt: "p", sessionLeaseSeconds: 0 }), /--session-lease-seconds expects a value >= 1/);
  assert.ok(argvOf({ prompt: "p", noSessionLease: true }).includes("--no-session-lease"));
});

test("no flag here can carry a credential, because credentials come from the environment", () => {
  const flags = supportedFlags();
  for (const flag of flags) {
    assert.equal(/(api[-_]?key|token-secret|secret|password)/i.test(flag), false, `${flag} looks like a credential flag`);
  }
  assert.ok(flags.includes("--base-url"));
  assert.ok(flags.includes("--no-retry"));
  assert.ok(flags.includes("--dry-run"));
  assert.ok(flags.includes("--mcp-server"));
  assert.ok(flags.includes("--max-output-tokens"));
  assert.ok(!flags.includes("--json"), "--json is set by the SDK, not offered to callers");
  assert.ok(!flags.includes("--plan"), "the SDK spells the shorthand out, so --help and the argv agree");
  assert.ok(!flags.includes("--session"), "there is no --session flag on `run`; --resume is the one there is");
});

test("numbers that are not numbers are refused before the CLI sees a string", () => {
  for (const value of [Number.NaN, Number.POSITIVE_INFINITY, "3", {}, 1.5]) {
    assert.throws(() => argvOf({ prompt: "p", maxTurns: value }), /--max-turns expects a number|--max-turns expects an integer/, String(value));
  }
  assert.throws(() => argvOf({ prompt: "p", maxBudgetUsd: "x" }), /--max-budget-usd expects a number/);
  assert.throws(() => argvOf({ prompt: "p", maxTurns: "3" }), /expects a number/);
});

test("`null` means no value set, which is not the same as a zero ceiling", () => {
  // A caller building options from JSON gets `null` for an absent field; treating that as 0 would
  // silently impose the strictest policy in the book on someone who asked for none.
  const argv = argvOf({ prompt: "p", maxToolCalls: null, maxTurns: null, maxBudgetUsd: null, resumeRecord: null });
  for (const flag of ["--max-tool-calls", "--max-turns", "--max-budget-usd", "--resume-record"]) {
    assert.equal(argv.includes(flag), false, flag);
  }
});

test("strings that are not strings are refused too", () => {
  assert.throws(() => argvOf({ prompt: 42 }), /--prompt expects a string/);
  assert.throws(() => argvOf({ prompt: "p", model: 7 }), /--model expects a string/);
});

test("ConfigurationError is the only failure type a build step throws", () => {
  assert.throws(() => argvOf({}), ConfigurationError);
  assert.throws(() => argvOf({}), /`prompt` \(or `promptFile`\) is required/);
});
