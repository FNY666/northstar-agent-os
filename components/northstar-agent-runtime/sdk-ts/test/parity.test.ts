/**
 * The drift gate.
 *
 * `events.ts` and `options.ts` restate contracts that Python owns. Restating them is only safe if
 * something checks the restatement, so this file asks the runtime itself: the exit-code table and
 * the closed value sets come from the modules that enforce them, the flag names come from
 * `run --help`, and the result payload's key set comes from a real `--json` run. A test that
 * compared the two source files as text would pass while both were wrong; this compares behaviour.
 *
 * The same checks run in `tests/test_typescript_sdk.py`, so drift still fails a machine that has
 * no node in it.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { EXIT_CODES, exitCodeFor, KNOWN_EVENT_TYPES, parseEventLine, USAGE_ERROR } from "../src/events.ts";
import {
  MCP_PROTOCOLS,
  PERMISSION_MODES,
  PROVIDERS,
  RETRYABLE_FAULTS,
  supportedFlags,
  toArgv,
  VERIFY_KINDS,
} from "../src/options.ts";
import { cli, componentDir, hasPython } from "./paths.ts";

const skip = hasPython ? false : "python3 and the runtime package are needed to check the mirror";

function runPython(source: string): string {
  return execFileSync("python3", ["-c", source], { cwd: componentDir, encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
}

function cliRun(args: string[]): { code: number; stdout: string; stderr: string } {
  try {
    const stdout = execFileSync("python3", ["-m", "cli", "run", ...args], {
      cwd: componentDir,
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
    });
    return { code: 0, stdout, stderr: "" };
  } catch (error) {
    const failure = error as { status?: number; stdout?: string; stderr?: string };
    return { code: failure.status ?? -1, stdout: failure.stdout ?? "", stderr: failure.stderr ?? "" };
  }
}

test("the exit-code table is the runtime's table, and 64 still means nothing ran", { skip }, () => {
  const payload = JSON.parse(
    runPython(`
import json, sys
sys.path.insert(0, ".")
import cli, events
print(json.dumps({
    "exit_codes": dict(events.EXIT_CODES),
    "fallback": events.EXIT_CODES.get("error_something_new", 1),
    "usage_error": cli.USAGE_ERROR,
    "cli_fallback_is_one": "EXIT_CODES.get(event.subtype, 1)" in open("cli.py").read(),
    "sdk_fallback_is_one": "EXIT_CODES.get(self.subtype, 1)" in open("sdk.py").read(),
}))
`),
  );
  assert.deepEqual(EXIT_CODES, payload.exit_codes);
  assert.equal(USAGE_ERROR, payload.usage_error);
  assert.equal(exitCodeFor("error_something_new"), payload.fallback);
  // The fallback is a source-level convention on purpose: nothing in the runtime can produce an
  // unknown subtype, so the only way to test it is to check that both call sites still say 1.
  assert.equal(payload.cli_fallback_is_one, true);
  assert.equal(payload.sdk_fallback_is_one, true);
  assert.deepEqual(
    [...KNOWN_EVENT_TYPES].sort(),
    ["assistant", "result", "stream_delta", "system", "user"],
    "the event vocabulary is the CLI's, not this file's opinion of it",
  );
});

test("every flag this SDK can emit exists on the command line", { skip }, () => {
  const help = cli(["run", "--help"]);
  const declared = new Set([...help.matchAll(/--[a-z0-9][a-z0-9-]*/g)].map((match) => match[0]));
  const missing = supportedFlags().filter((flag) => !declared.has(flag));
  assert.deepEqual(missing, [], `${missing.join(", ")} is not a flag of \`python3 -m cli run\``);
});

test("the closed value sets are the ones the runtime enforces", { skip }, () => {
  const payload = JSON.parse(
    runPython(`
import json, sys
sys.path.insert(0, ".")
import permissions, postconditions, provider_retry
print(json.dumps({
    "modes": list(permissions.PERMISSION_MODES),
    "kinds": list(postconditions.KINDS),
    "retryable": list(provider_retry.RETRYABLE_CLASSES),
    "never": list(provider_retry.NEVER_RETRYABLE_CLASSES),
}))
`),
  );
  assert.deepEqual([...PERMISSION_MODES], payload.modes);
  assert.deepEqual([...VERIFY_KINDS], payload.kinds);
  assert.deepEqual([...RETRYABLE_FAULTS], payload.retryable);
  // The sets argparse itself enforces are read out of `run --help`, which is where a human sees
  // them too: if the CLI narrows a choice list, this SDK has to follow or it offers a flag value
  // that exits 2.
  const help = cli(["run", "--help"]);
  const choices = (flag: string): string[] | null => {
    const match = new RegExp(`${flag} \\{([^}]*)\\}`).exec(help);
    return match ? match[1].split(",") : null;
  };
  assert.deepEqual(choices("--provider"), [...PROVIDERS]);
  assert.deepEqual(choices("--permission-mode"), [...PERMISSION_MODES]);
  assert.deepEqual(choices("--mcp-protocol"), [...MCP_PROTOCOLS]);
  // The classes a caller may never ask to retry are rejected by name, so the list here has to be
  // the complement of that rule rather than a copy of the CLI's help text.
  for (const never of payload.never) {
    assert.throws(() => toArgv({ prompt: "p", retry: { retryOn: [never] } }), /never retryable by construction/, never);
  }
});

test("a real --json run's payload keys are exactly the keys this SDK reads", { skip }, () => {
  const dir = mkdtempSync(join(tmpdir(), "northstar-parity-"));
  const run = cliRun([
    "--prompt", "parity", "--provider", "scripted", "--model", "scripted", "--scripted-text", "parity",
    "--workspace", dir, "--no-project-context", "--no-skills", "--no-plugins", "--no-session-lease", "--json",
  ]);
  rmSync(dir, { recursive: true, force: true });
  assert.equal(run.code, 0, run.stderr);
  const lines = run.stdout.split("\n").filter((line) => line.trim() !== "");
  assert.ok(lines.length >= 3, `expected init, assistant and result lines, got ${lines.length}`);
  const system = JSON.parse(lines[0]) as Record<string, unknown>;
  const result = JSON.parse(lines.at(-1)!) as Record<string, unknown>;
  assert.deepEqual(Object.keys(system).sort(), ["content", "data", "subtype", "type"]);
  assert.deepEqual(
    Object.keys(result).sort(),
    [
      "duration_ms",
      "errors",
      "is_error",
      "num_turns",
      "permission_denials",
      "pricing_estimated",
      "session_id",
      "subtype",
      "total_cost_usd",
      "total_usage",
      "type",
    ].sort(),
    "the result event grew or lost a field: mirror it in events.ts before changing the runtime",
  );
  assert.deepEqual(Object.keys(result.total_usage as object).sort(), [
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
    "input_tokens",
    "output_tokens",
  ]);

  // Parsing the line here must neither lose nor invent a field the Python side wrote.
  const parsed = parseEventLine(lines.at(-1)!);
  assert.equal(parsed.type, "result");
  if (parsed.type !== "result") assert.fail("unreachable");
  assert.equal(parsed.subtype, result.subtype);
  assert.deepEqual(parsed.total_usage, result.total_usage);
  assert.equal(parsed.session_id, result.session_id);
  assert.equal(parsed.exitCode, undefined, "an exit code is a terminal convention, not a wire field");
  for (const line of lines) {
    assert.equal(parseEventLine(line).type, (JSON.parse(line) as { type: string }).type);
  }
});

test("the mistakes the CLI refuses, this SDK refuses too - with the same facts", { skip }, () => {
  const pairing = cliRun([
    "--prompt", "x", "--provider", "openai", "--model", "claude-sonnet-4-5", "--workspace", componentDir, "--dry-run",
  ]);
  assert.notEqual(pairing.code, 0, "the CLI accepted a pairing the SDK refuses: the mirror is stricter than the tool");
  assert.match(pairing.stderr + pairing.stdout, /cannot serve/);
  assert.throws(() => toArgv({ prompt: "p", provider: "openai", model: "claude-sonnet-4-5" }), /cannot serve/);

  const verify = cliRun([
    "--prompt", "x", "--provider", "scripted", "--scripted-text", "hi", "--workspace", componentDir,
    "--verify", "exists:/etc/passwd", "--dry-run",
  ]);
  assert.equal(verify.code, USAGE_ERROR, `expected a configuration error, got exit ${verify.code}: ${verify.stderr}`);
  assert.match(verify.stderr, /workspace-relative/);
  assert.throws(() => toArgv({ prompt: "p", verify: ["exists:/etc/passwd"] }), /workspace-relative, not absolute or escaping/);

  const unknownKind = cliRun([
    "--prompt", "x", "--provider", "scripted", "--scripted-text", "hi", "--workspace", componentDir,
    "--verify", "frozen:out.md", "--dry-run",
  ]);
  assert.equal(unknownKind.code, USAGE_ERROR);
  assert.match(unknownKind.stderr, /unknown postcondition kind/);
  assert.throws(() => toArgv({ prompt: "p", verify: ["frozen:out.md"] }), /unknown postcondition kind/);
});
