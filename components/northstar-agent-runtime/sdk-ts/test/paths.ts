/** Shared paths for the suite, so no test hardcodes a machine-specific location. */

import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

/** `components/northstar-agent-runtime`, the directory the CLI is invoked from. */
export const componentDir = fileURLToPath(new URL("../..", import.meta.url));

export const cliEntry = join(componentDir, "cli.py");

/** Whether a usable `python3` is here; the drift gate needs it, the rest of the suite does not. */
export function pythonAvailable(): boolean {
  try {
    return execFileSync("python3", ["-c", "print(1)"], { encoding: "utf8" }).trim() === "1";
  } catch {
    return false;
  }
}

export const hasPython = pythonAvailable() && existsSync(cliEntry);

/** Run the component's CLI and return stdout, failing loudly if the invocation itself broke. */
export function cli(args: string[]): string {
  return execFileSync("python3", ["-m", "cli", ...args], {
    cwd: componentDir,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
  });
}

/** Write a fake CLI in JavaScript, for tests that need to drive the stream by hand. */
export function fakeCli(body: string): string[] {
  return [process.execPath, "-e", body];
}
