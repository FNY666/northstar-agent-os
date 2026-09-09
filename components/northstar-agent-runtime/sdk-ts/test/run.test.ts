/**
 * Running a real child process, and what a stream that misbehaves does.
 *
 * Most of these drive a fake CLI, for one reason: the failure modes worth pinning (no result
 * event, exit 64, a half-written line, a run that never ends) are exactly the ones the real
 * runtime refuses to produce. The tests that use the real CLI prove the happy path is not a
 * fixture. The fake is generated from a list of lines rather than hand-written as embedded
 * source, because a newline inside a nested string is how this file would otherwise fail for
 * reasons that have nothing to do with the SDK.
 */
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { defaultCwd, preview, run, streamRun, RunFailedError, UsageError, type RunTrace } from "../src/run.ts";
import { isResult } from "../src/events.ts";
import { ConfigurationError } from "../src/options.ts";

const INIT = '{"type":"system","subtype":"init","content":"runtime ready: fake/fake","data":{"limits":{"max_turns":2}}}';
const RESULT_OK =
  '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"duration_ms":3,"total_cost_usd":0,"total_usage":{"input_tokens":4,"output_tokens":2,"cache_read_input_tokens":0,"cache_creation_input_tokens":0},"session_id":"s-1","pricing_estimated":false,"errors":[],"permission_denials":[]}';
const RESULT_DENIED =
  '{"type":"result","subtype":"error_permission_denied","is_error":true,"num_turns":1,"duration_ms":2,"total_cost_usd":0,"total_usage":{},"session_id":"s-2","pricing_estimated":false,"errors":["Write refused by the permission gate"],"permission_denials":[{"tool":"Write","source":"policy:deny","reason":"Write refused by the permission gate","agent":"main","turn_index":0,"kind":"tool"}]}';
const TWO_TOOL_CALLS =
  '{"type":"assistant","content":[{"type":"tool_use","id":"t1","name":"Read","input":{}},{"type":"tool_use","id":"t2","name":"Write","input":{}},{"type":"text","text":"two calls"}],"model":"fake","usage":{},"stop_reason":"tool_use"}';

/** A child that prints exactly these NDJSON lines and exits with `code`. */
function fakeCli(lines: string[], code: number, stderr = ""): string[] {
  const body = [
    "const W = (s) => process.stdout.write(s + String.fromCharCode(10));",
    ...(stderr ? [`process.stderr.write(${JSON.stringify(stderr)});`] : []),
    ...lines.map((line) => `W(${JSON.stringify(line)});`),
    `process.exit(${code});`,
  ].join("\n");
  return [process.execPath, "-e", body];
}

/** A child that prints `lines`, then stays alive until it is signalled. */
function hangingCli(lines: string[], onSignal = ""): string[] {
  const body = [
    "const W = (s) => process.stdout.write(s + String.fromCharCode(10));",
    ...lines.map((line) => `W(${JSON.stringify(line)});`),
    "const timer = setInterval(() => {}, 50);",
    `process.on("SIGTERM", () => {${onSignal} clearInterval(timer); process.exit(143); });`,
  ].join("\n");
  return [process.execPath, "-e", body];
}

function workspace(): string {
  return mkdtempSync(join(tmpdir(), "northstar-ts-"));
}

function scriptedOptions(dir: string) {
  return {
    prompt: "greet the workspace",
    provider: "scripted" as const,
    model: "scripted",
    workspace: dir,
    scriptedText: "hello from northstar",
    maxTurns: 4,
    noProjectContext: true,
    noSkills: true,
    noPlugins: true,
    noSessionLease: true,
  };
}

test("a scripted run comes back as a report, with the CLI's exit code", async (t) => {
  const dir = workspace();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const report = await run(scriptedOptions(dir));
  assert.equal(report.subtype, "success");
  assert.equal(report.isError, false);
  assert.equal(report.exitCode, 0);
  assert.equal(report.processExitCode, 0);
  assert.equal(report.numTurns, 1);
  assert.ok(report.sessionId.startsWith("ns-"));
  assert.ok(report.durationMs >= 0);
  assert.deepEqual(report.errors, []);
  assert.deepEqual(report.permissionDenials, []);
  assert.equal(report.toolCalls, 0);
  assert.equal(report.totalUsage.input_tokens >= 0, true);
  assert.equal(report.pricingEstimated, true);
  assert.equal(report.events[0].type, "system");
  const assistant = report.events.find((event) => event.type === "assistant");
  assert.ok(assistant && assistant.type === "assistant");
  assert.equal(assistant.content[0].text, "hello from northstar");
  assert.ok(isResult(report.events.at(-1)!));
  assert.equal(report.stderr, "");
});

test("a denied tool call is a report, not a thrown error, with the denial fields intact", async () => {
  const report = await run({ prompt: "p" }, { binary: fakeCli([INIT, RESULT_DENIED], 5) });
  assert.equal(report.subtype, "error_permission_denied");
  assert.equal(report.exitCode, 5, "the subtype decides the code a wrapper sees");
  assert.equal(report.processExitCode, 5, "and the child agreed, which is the point of keeping both");
  assert.equal(report.isError, true);
  assert.equal(report.permissionDenials.length, 1);
  assert.equal(report.permissionDenials[0].source, "policy:deny");
  assert.deepEqual(report.errors, ["Write refused by the permission gate"]);
});

test("the child's stderr is kept out of the event stream and inside the report", async () => {
  const report = await run(
    { prompt: "p" },
    { binary: fakeCli([INIT, RESULT_OK], 0, "mcp: server 'fs' speaks the legacy protocol\n") },
  );
  assert.equal(report.subtype, "success");
  assert.match(report.stderr, /legacy protocol/);
});

test("tool calls are counted from the stream, not from a field the result does not carry", async () => {
  const report = await run({ prompt: "p" }, { binary: fakeCli([INIT, TWO_TOOL_CALLS, RESULT_OK], 0) });
  assert.equal(report.toolCalls, 2);
  assert.equal(report.subtype, "success");
});

test("exitCode is the contract and processExitCode is the fact, and they can disagree", async () => {
  // A CLI that printed `error_max_turns` and exited 0 is a broken wrapper, and it is the one case
  // where hiding either number would hurt: the report has to show both.
  const wrong = '{"type":"result","subtype":"error_max_turns","is_error":true,"num_turns":25,"duration_ms":1,"total_cost_usd":0,"total_usage":{},"session_id":"s","pricing_estimated":false,"errors":[],"permission_denials":[]}';
  const report = await run({ prompt: "p" }, { binary: fakeCli([wrong], 0) });
  assert.equal(report.exitCode, 2, "the subtype is what the contract promises a wrapper");
  assert.equal(report.processExitCode, 0, "and the child's own code is still reported, not hidden");
});

test("streamRun yields the same events in the same order, ending with the result", async (t) => {
  const dir = workspace();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const seen: string[] = [];
  for await (const event of streamRun(scriptedOptions(dir))) {
    seen.push(event.type);
  }
  assert.deepEqual(seen.slice(0, 1), ["system"]);
  assert.equal(seen.at(-1), "result");
  assert.ok(seen.includes("assistant"));
});

test("a stream with no result event is an error, with the child's stderr quoted", async () => {
  await assert.rejects(
    () => run({ prompt: "p" }, { binary: fakeCli([INIT], 1, "boom: provider exploded\n") }),
    (error: unknown) => {
      assert.ok(error instanceof RunFailedError);
      assert.equal(error.aborted, false);
      assert.equal(error.processExitCode, 1);
      assert.match(error.message, /produced no result event \(exit 1\)/);
      assert.match(error.message, /provider exploded/);
      assert.match(error.stderr, /provider exploded/);
      return true;
    },
  );
});

test("exit 64 comes back as UsageError, because retrying the same call cannot help", async () => {
  await assert.rejects(
    () => run({ prompt: "p" }, { binary: fakeCli([], 64, "configuration error: workspace: no such path\n") }),
    (error: unknown) => {
      assert.ok(error instanceof UsageError);
      assert.ok(error instanceof RunFailedError, "UsageError must still be catchable as the general failure");
      assert.match(error.message, /no result event \(exit 64\)/);
      return true;
    },
  );
});

test("a line that is not JSON stops the stream instead of being skipped", async () => {
  const body = [
    "const W = (s) => process.stdout.write(s + String.fromCharCode(10));",
    `W(${JSON.stringify(INIT)});`,
    "W('Warning: something');",
    `W(${JSON.stringify(RESULT_OK)});`,
    "process.exit(0);",
  ].join("\n");
  await assert.rejects(() => run({ prompt: "p" }, { binary: [process.execPath, "-e", body] }), /not JSON/);
});

test("aborting mid-run reports an abort, and the child is gone rather than orphaned", async (t) => {
  const dir = workspace();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  // The fake records its own death in a file, because "the child is gone" is a claim about the
  // process table, not about the event stream: an SDK that left a run going after an abort would
  // be a resource leak that no assertion on the iterator could see.
  const receipt = join(dir, "sigterm");
  const fake = hangingCli(
    [INIT],
    ` require("node:fs").writeFileSync(process.env.NORTHSTAR_RECEIPT, "term");`,
  );
  const controller = new AbortController();
  const trace: RunTrace = {};
  const collected = (async () => {
    const types: string[] = [];
    for await (const event of streamRun(
      { prompt: "p" },
      { binary: fake, signal: controller.signal, env: { NORTHSTAR_RECEIPT: receipt } },
      trace,
    )) {
      types.push(event.type);
      controller.abort();
    }
    return types;
  })();
  await assert.rejects(
    () => collected,
    (error: unknown) => {
      assert.ok(error instanceof RunFailedError);
      assert.equal(error.aborted, true, "the caller must be able to tell an abort from a crash");
      assert.match(error.message, /aborted before it produced a result event/);
      return true;
    },
  );
  assert.equal(trace.aborted, true);
  const deadline = Date.now() + 3000;
  while (!existsSync(receipt) && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.ok(existsSync(receipt), "the run was stopped, not abandoned");
  assert.equal(readFileSync(receipt, "utf8"), "term");
});

test("a signal that was already aborted stops the run before it starts", async () => {
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    () => run({ prompt: "p" }, { binary: fakeCli([RESULT_OK], 0), signal: controller.signal }),
    RunFailedError,
  );
});

test("a deadline of the SDK's own kills the run and says so", async () => {
  await assert.rejects(
    () => run({ prompt: "p" }, { binary: hangingCli([INIT]), timeoutMs: 400 }),
    (error: unknown) => {
      assert.ok(error instanceof RunFailedError);
      assert.match(error.message, /exceeded its 400 ms deadline/);
      return true;
    },
  );
});

test("a missing binary is reported as a start failure, not as an empty run", async () => {
  await assert.rejects(
    () => run({ prompt: "p" }, { binary: ["/nonexistent/northstar-not-here"] }),
    (error: unknown) => {
      assert.ok(error instanceof RunFailedError);
      assert.match(error.message, /cannot start/);
      return true;
    },
  );
});

test("dryRun has no event stream, and says so instead of returning an empty report", async () => {
  // A caller who puts `dryRun` on a streaming call is asking for two different things; the worst
  // answer would be an empty report that reads like a run that did nothing.
  await assert.rejects(() => run({ prompt: "p", dryRun: true }), ConfigurationError);
  await assert.rejects(
    (async () => {
      for await (const event of streamRun({ prompt: "p", dryRun: true })) void event;
    })(),
    /produces no event stream; call preview/,
  );
});

test("preview is the CLI's own human-readable resolution, before a request or a write", async (t) => {
  const dir = workspace();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const text = await preview({
    prompt: "say hi",
    provider: "scripted",
    model: "scripted",
    workspace: dir,
    maxTurns: 2,
    permissionMode: "plan",
    readOnly: true,
    noProjectContext: true,
  });
  assert.match(text, /^provider=scripted model=scripted$/m);
  assert.match(text, /^permission_mode=plan$/m);
  assert.match(text, /^tools=\w/m);
  assert.match(text, /^allowed_tools=\(none\)  disallowed_tools=Write,Edit$/m, "readOnly has to be visible in the preview");
  assert.match(text, /max_turns=2/);
  assert.match(text, /dry-run: configuration is valid; no request was sent/);
});

test("a tool-call ceiling of zero reads as zero, because the gate really does refuse everything", async (t) => {
  const dir = workspace();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const zero = await preview({ ...scriptedOptions(dir), maxToolCalls: 0 });
  assert.match(zero, /max_tool_calls=0 \(no tool call allowed\)/);
  // `null` asks for nothing at all, which lands on the workspace's own number (50 unless the
  // policy file says otherwise) rather than on "unlimited": an SDK cannot widen a ceiling the
  // operator set, and the preview reflects that instead of flattering the caller.
  const none = await preview({ ...scriptedOptions(dir), maxToolCalls: null });
  assert.match(none, /^max_turns=4 max_tool_calls=[1-9]\d* max_budget_usd=/m);
  const three = await preview({ ...scriptedOptions(dir), maxToolCalls: 3 });
  assert.match(three, /max_tool_calls=3(?! \()/);
});

test("a preview the CLI refuses raises UsageError carrying the refusal", async () => {
  await assert.rejects(
    () => preview({ prompt: "p", workspace: defaultCwd(), contextFile: "/etc/passwd" }),
    (error: unknown) => {
      assert.ok(error instanceof UsageError);
      assert.match(error.message, /resolves outside the workspace root/);
      assert.equal(error.processExitCode, 64);
      return true;
    },
  );
});

test("the default working directory is the component that ships the CLI", () => {
  assert.ok(existsSync(join(defaultCwd(), "cli.py")));
  assert.ok(existsSync(join(defaultCwd(), "sdk.py")));
  assert.ok(existsSync(join(defaultCwd(), "events.py")));
});
