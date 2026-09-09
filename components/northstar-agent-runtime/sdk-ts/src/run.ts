/**
 * Run one governed Northstar run from Node, over the CLI's `--json` event stream.
 *
 * The shape of this SDK is a deliberate consequence of how the component is built: there is no
 * daemon and no second protocol. A "run" is `python3 -m cli run --json ...` (or the installed
 * `northstar-agent-runtime`), so the TypeScript surface cannot drift from the Python one in
 * permission modes, ceilings, transcripts or exit codes - it inherits them, including the
 * governance choices a caller might otherwise re-implement wrongly.
 *
 * Two rules are worth stating because they are what a caller will otherwise get wrong:
 *
 * 1. **A finished run never throws.** A run that exhausted its turns, hit its budget or was
 *    denied a tool returns a report whose `subtype`/`exitCode` say so - the same way the
 *    runtime reports subtypes and the CLI maps them to exit codes. Throwing would tempt a caller
 *    to treat a refused write as a bug in the SDK.
 * 2. **An unusable stream throws.** No `result` event at all, a line that is not JSON, or exit
 *    64 means nothing ran as asked. Those are errors about the *call*, and `UsageError` exists so
 *    a caller can distinguish "fix the command" from "the run failed" - the same distinction exit
 *    code 64 carries in a shell.
 */

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createNdjsonSplitter, exitCodeFor, isResult, parseEventLine } from "./events.ts";
import type { Denial, ResultEvent, RunEvent, Usage } from "./events.ts";
import { ConfigurationError, toArgv } from "./options.ts";
import type { RunOptions } from "./options.ts";

export type Runner = {
  /** Command and fixed prefix arguments. Defaults to the checkout's module invocation. */
  binary?: string[];
  /** Working directory for the child. Defaults to the component directory holding `cli.py`. */
  cwd?: string;
  /** Extra environment for the child, merged over `process.env`. Keys are never read from options. */
  env?: Record<string, string>;
  /** Abort to stop a run: the child is TERM'd, which is the same signal a Ctrl-C sends. */
  signal?: AbortSignal;
  /** Kill the run after this many milliseconds. 0 or omitted means no deadline of the SDK's. */
  timeoutMs?: number;
};

export type RunReport = {
  subtype: string;
  sessionId: string;
  numTurns: number;
  durationMs: number;
  totalCostUsd: number;
  totalUsage: Usage;
  pricingEstimated: boolean;
  errors: string[];
  permissionDenials: Denial[];
  /** Tool calls counted from `tool_use` blocks in the assistant events of this stream. */
  toolCalls: number;
  /** The exit code the CLI would have used, derived from `subtype`. */
  exitCode: number;
  /** The exit code the child actually returned, so a caller can check it against `exitCode`. */
  processExitCode: number;
  isError: boolean;
  events: RunEvent[];
  result: ResultEvent;
  stderr: string;
};

/**
 * A mutable box a caller can pass to `streamRun` to learn what the *process* did.
 *
 * An async generator yields events, so there is nowhere in the item type to put "the child exited
 * with 5", and inventing a pseudo-event for it would put a non-contract line in a contract stream.
 * A caller that wants to compare the process exit code against the exit code the subtype implies -
 * which is what the parity test does - passes an object and reads it afterwards.
 */
export type RunTrace = {
  /** The child's exit code, once it has closed. An abort that never reached a result event still
   * gets one, because the SDK waits for the child to die before returning. */
  exitCode?: number;
  stderr?: string;
  aborted?: boolean;
};

/** Raised when the event stream could not describe a run at all. */
export class RunFailedError extends Error {
  override readonly name = "RunFailedError";
  readonly processExitCode: number;
  readonly stderr: string;
  readonly aborted: boolean;

  constructor(message: string, options: { processExitCode: number; stderr: string; aborted?: boolean }) {
    super(message);
    this.processExitCode = options.processExitCode;
    this.stderr = options.stderr;
    this.aborted = options.aborted ?? false;
  }
}

/** Raised for exit 64: the command was refused before anything ran. Fix it, do not retry it. */
export class UsageError extends RunFailedError {
  override readonly name = "UsageError";
}

/** The component directory this SDK was built next to, so a checkout works with no install step. */
export function defaultCwd(): string {
  return fileURLToPath(new URL("../..", import.meta.url));
}

function countToolCalls(events: readonly RunEvent[]): number {
  let calls = 0;
  for (const event of events) {
    if (event.type !== "assistant" || !Array.isArray(event.content)) continue;
    for (const block of event.content) {
      if (block && typeof block === "object" && "type" in block && block.type === "tool_use") calls += 1;
    }
  }
  return calls;
}

/**
 * Yield each event as it arrives; the final one is always the `result` event.
 *
 * The child's stderr is buffered rather than forwarded: it carries the run's warnings (the MCP
 * era note, a refused `--mcp-config` declaration, an exhausted retry ladder), which belong in the
 * error message and in `report.stderr`, not in a consumer's event loop.
 */
export async function* streamRun(
  options: RunOptions,
  runner: Runner = {},
  trace?: RunTrace,
): AsyncGenerator<RunEvent, void, void> {
  if (options.dryRun) {
    throw new ConfigurationError("northstar: `dryRun` produces no event stream; call preview() to read the resolved configuration");
  }
  const argv = toArgv(options);
  const binary = runner.binary ?? ["python3", "-m", "cli"];
  const [command, ...prefix] = binary;
  const child = spawn(command, [...prefix, ...argv], {
    cwd: runner.cwd ?? defaultCwd(),
    env: { ...process.env, ...(runner.env ?? {}) },
    stdio: ["ignore", "pipe", "pipe"],
    // A process group of its own, so an abort cannot orphan a tree of tool subprocesses - the
    // same reason the runtime TERM→KILLs its MCP servers as a group.
    detached: true,
  });

  const splitter = createNdjsonSplitter();
  const queue: RunEvent[] = [];
  let stdoutDone = false;
  let failure: Error | null = null;
  let exitCode: number | null = null;
  let stderrText = "";
  let aborted = false;

  const waiters: (() => void)[] = [];
  const wake = () => {
    const resolve = waiters.shift();
    if (resolve) resolve();
  };
  const wait = () => new Promise<void>((resolve) => waiters.push(resolve));

  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    for (const line of splitter.push(chunk)) {
      try {
        queue.push(parseEventLine(line));
      } catch (error) {
        failure = error instanceof Error ? error : new Error(String(error));
        break;
      }
    }
    wake();
  });
  child.stdout.on("close", () => {
    for (const line of splitter.end()) {
      try {
        queue.push(parseEventLine(line));
      } catch (error) {
        failure = failure ?? (error instanceof Error ? error : new Error(String(error)));
      }
    }
    stdoutDone = true;
    wake();
  });
  child.stderr.on("data", (chunk: string) => {
    stderrText += chunk;
    if (trace) trace.stderr = stderrText;
  });
  const exited = new Promise<number>((resolve) => {
    child.on("close", (code) => {
      const value = code ?? -1;
      if (trace) trace.exitCode = value;
      resolve(value);
    });
    child.on("error", (error) => {
      failure = new RunFailedError(`northstar: cannot start ${binary.join(" ")}: ${error.message}`, {
        processExitCode: -1,
        stderr: stderrText,
      });
      wake();
      resolve(-1);
    });
  });

  const kill = (reason: string) => {
    if (exitCode !== null) return;
    aborted = true;
    if (trace) trace.aborted = true;
    failure = failure ?? new RunFailedError(`northstar: run ${reason} before it produced a result event`, {
      processExitCode: exitCode ?? -1,
      stderr: stderrText,
      aborted: true,
    });
    try {
      if (child.pid) process.kill(-child.pid, "SIGTERM");
      else child.kill("SIGTERM");
    } catch {
      child.kill("SIGTERM"); // already gone: the failure we recorded is the interesting part
    }
    wake();
  };
  const onAbort = () => kill("was aborted");
  if (runner.signal) {
    if (runner.signal.aborted) kill("was aborted before it started");
    else runner.signal.addEventListener("abort", onAbort, { once: true });
  }
  const timer =
    runner.timeoutMs && runner.timeoutMs > 0 ? setTimeout(() => kill(`exceeded its ${runner.timeoutMs} ms deadline`), runner.timeoutMs) : undefined;

  let sawResult: ResultEvent | null = null;
  try {
    for (;;) {
      if (queue.length > 0) {
        const event = queue.shift();
        if (event === undefined) continue;
        if (isResult(event)) sawResult = event;
        yield event;
        continue;
      }
      if (failure) throw failure;
      if (stdoutDone) {
        exitCode = await exited;
        break;
      }
      await wait();
    }
    if (!sawResult) {
      exitCode = exitCode ?? (await exited);
      const base = `northstar run produced no result event (exit ${exitCode})`;
      const detail = stderrText.trim() ? `: ${stderrText.trim().slice(0, 2000)}` : "";
      if (exitCode === 64) throw new UsageError(`${base}${detail}`, { processExitCode: exitCode, stderr: stderrText, aborted });
      throw new RunFailedError(`${base}${detail}`, { processExitCode: exitCode ?? -1, stderr: stderrText, aborted });
    }
  } finally {
    if (timer) clearTimeout(timer);
    if (runner.signal) runner.signal.removeEventListener("abort", onAbort);
    if (child.exitCode === null && child.signalCode === null) {
      // An aborted or timed-out run was already sent SIGTERM, which is the signal the runtime
      // treats as "stop and seal the transcript". Escalating to SIGKILL in the same tick would
      // take that away and leave a half-written session behind, so wait briefly for the child to
      // close, then kill the *group* - a run that spawned tools or MCP servers must not leave them
      // behind when the caller stopped reading.
      if (aborted) {
        await Promise.race([exited, new Promise<void>((resolve) => setTimeout(resolve, 2000).unref?.())]);
      }
      if (child.exitCode === null && child.signalCode === null) {
        try {
          if (child.pid) process.kill(-child.pid, "SIGKILL");
          else child.kill("SIGKILL");
        } catch {
          /* already gone: the caller has its events or its error by now */
        }
      }
    }
  }
}

/** Run to completion and return the report the stream ends with. Never throws for a failed run. */
export async function run(options: RunOptions, runner: Runner = {}): Promise<RunReport> {
  const events: RunEvent[] = [];
  let result: ResultEvent | null = null;
  const trace: RunTrace = {};
  for await (const event of streamRun(options, runner, trace)) {
    events.push(event);
    if (isResult(event)) result = event;
  }
  if (result === null) {
    throw new RunFailedError("northstar run ended without a result event", {
      processExitCode: trace.exitCode ?? -1,
      stderr: trace.stderr ?? "",
    });
  }
  const processExitCode = trace.exitCode ?? exitCodeFor(result.subtype);
  const report: RunReport = {
    subtype: result.subtype,
    sessionId: result.session_id,
    numTurns: result.num_turns,
    durationMs: result.duration_ms,
    totalCostUsd: result.total_cost_usd,
    totalUsage: result.total_usage,
    pricingEstimated: result.pricing_estimated,
    errors: result.errors,
    permissionDenials: result.permission_denials,
    toolCalls: countToolCalls(events),
    exitCode: exitCodeFor(result.subtype),
    processExitCode,
    isError: result.is_error,
    events,
    result,
    stderr: trace.stderr ?? "",
  };
  return report;
}

/**
 * The resolved configuration, as the CLI prints it - advisory text, not a contract.
 *
 * `--dry-run` has no events, so this bypasses the JSON stream on purpose: its value is that an
 * embedder can show a human the same tools, ceilings and stance the operator would see, before a
 * request is sent or a file is touched.
 */
export async function preview(options: RunOptions, runner: Runner = {}): Promise<string> {
  const argv = toArgv({ ...options, dryRun: true }).filter((arg) => arg !== "--json");
  const binary = runner.binary ?? ["python3", "-m", "cli"];
  const [command, ...prefix] = binary;
  const child = spawn(command, [...prefix, ...argv], {
    cwd: runner.cwd ?? defaultCwd(),
    env: { ...process.env, ...(runner.env ?? {}) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });
  const code = await new Promise<number>((resolve) => {
    child.on("close", (value) => resolve(value ?? -1));
    child.on("error", () => resolve(-1));
  });
  if (code !== 0) {
    throw new UsageError(`northstar dry-run was refused (exit ${code}): ${(stderr || stdout).trim().slice(0, 2000)}`, {
      processExitCode: code,
      stderr,
    });
  }
  return stdout;
}
