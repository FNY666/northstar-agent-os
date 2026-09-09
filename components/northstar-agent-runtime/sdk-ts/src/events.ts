/**
 * The event vocabulary `northstar ... run --json` emits, as types.
 *
 * This file is a *mirror*, not a definition: the authoritative list lives in the runtime's
 * `events.py`, and `test/parity.test.ts` fails if the two tables of exit codes drift apart.
 * That is the whole reason a TypeScript caller can trust these types - a wrapper that
 * re-declared the contract would be free to be wrong.
 *
 * One rule is deliberate: an event whose `type` this file does not know still parses. A
 * runtime that learns a new event must not break a caller that has not learned it yet, which
 * is the same forward-compatibility promise the transcript makes to readers.
 */

/** A content block in the provider's own shape; the SDK never rewrites these. */
export type ContentBlock = {
  type: string;
  text?: string;
  id?: string;
  name?: string;
  input?: unknown;
  content?: unknown;
  is_error?: boolean;
  [key: string]: unknown;
};

/** Token counts as `Usage.as_dict()` writes them: all four keys, always present. */
export type Usage = {
  input_tokens: number;
  output_tokens: number;
  cache_read_input_tokens: number;
  cache_creation_input_tokens: number;
};

/**
 * One refusal recorded by the permission gate - `loop.Denial.as_dict()`, field for field.
 *
 * Names, sources and reasons; never a secret, never the tool's payload. That is what makes it
 * safe to log and to show a user why a run stopped.
 */
export type Denial = {
  tool: string;
  source: string;
  reason: string;
  agent: string;
  turn_index: number;
  kind: string;
};

/** The one event every run ends with (and the only one a caller may summarize a run from). */
export type ResultEvent = {
  type: "result";
  subtype: string;
  is_error: boolean;
  num_turns: number;
  duration_ms: number;
  total_cost_usd: number;
  total_usage: Usage;
  session_id: string;
  pricing_estimated: boolean;
  errors: string[];
  permission_denials: Denial[];
};

/** `system` / `init` carries the resolved configuration under `data`; see `initLimits`. */
export type SystemEvent = {
  type: "system";
  subtype: string;
  content: string;
  data: Record<string, unknown>;
};

export type AssistantEvent = {
  type: "assistant";
  content: ContentBlock[];
  model: string;
  usage: Usage;
  stop_reason: string;
};

export type UserEvent = {
  type: "user";
  content: ContentBlock[];
  is_meta: boolean;
};

/** Provisional output while text is streaming: in the vocabulary, never in the transcript. */
export type StreamDeltaEvent = {
  type: "stream_delta";
  [key: string]: unknown;
};

/** Anything a newer runtime emits that this mirror has not caught up with yet. */
export type UnknownEvent = {
  type: string;
  [key: string]: unknown;
};

export type RunEvent = ResultEvent | SystemEvent | AssistantEvent | UserEvent | StreamDeltaEvent | UnknownEvent;

/** The event types this mirror names. Unknown types are still valid events. */
export const KNOWN_EVENT_TYPES = ["result", "system", "assistant", "user", "stream_delta"] as const;

/**
 * Terminal convention per result subtype, mirroring `events.EXIT_CODES`.
 *
 * Only 0 is "the run did what you asked". 64 means nothing ran and the command needs fixing -
 * the one code a caller should never treat as a failed attempt - and 7 means another process
 * owns the session, which is a wait-and-retry rather than an error.
 */
export const EXIT_CODES = {
  success: 0,
  error_during_execution: 1,
  error_max_turns: 2,
  error_max_tool_calls: 3,
  error_max_budget_usd: 4,
  error_permission_denied: 5,
  error_postconditions_failed: 6,
  error_session_busy: 7,
} as const;

export type ResultSubtype = keyof typeof EXIT_CODES;
export const USAGE_ERROR = 64;

export function exitCodeFor(subtype: string): number {
  const codes: Record<string, number> = EXIT_CODES;
  const code = codes[subtype];
  return code === undefined ? 1 : code;
}

export function isResult(event: RunEvent): event is ResultEvent {
  return event.type === "result";
}

function usageOf(value: unknown): Usage {
  const source = value && typeof value === "object" ? (value as Record<string, unknown>) : {};
  const count = (key: string): number => (typeof source[key] === "number" ? (source[key] as number) : 0);
  return {
    input_tokens: count("input_tokens"),
    output_tokens: count("output_tokens"),
    cache_read_input_tokens: count("cache_read_input_tokens"),
    cache_creation_input_tokens: count("cache_creation_input_tokens"),
  };
}

function denialOf(value: unknown): Denial {
  const source = value && typeof value === "object" ? (value as Record<string, unknown>) : {};
  return {
    tool: typeof source.tool === "string" ? source.tool : "",
    source: typeof source.source === "string" ? source.source : "",
    reason: typeof source.reason === "string" ? source.reason : "",
    agent: typeof source.agent === "string" ? source.agent : "main",
    turn_index: typeof source.turn_index === "number" ? source.turn_index : 0,
    kind: typeof source.kind === "string" ? source.kind : "tool",
  };
}

function blocksOf(value: unknown): ContentBlock[] {
  if (!Array.isArray(value)) return [];
  return value.filter((block): block is ContentBlock => !!block && typeof block === "object" && typeof (block as ContentBlock).type === "string");
}

/**
 * Parse one NDJSON line from `--json`.
 *
 * A line that is not a JSON *object with a `type`* is a protocol violation, not a warning:
 * silently skipping it would let a run report "no result event" when the truth is that a byte of
 * output was dropped, and the difference matters exactly when a caller is deciding whether to
 * retry. Known types are normalised, so the fields these types declare as present really are -
 * a caller should not have to re-check whether an older runtime omitted `errors`.
 */
export function parseEventLine(line: string): RunEvent {
  const trimmed = line.trim();
  if (trimmed === "") {
    throw new Error("northstar: empty line in the --json event stream");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`northstar: event stream line is not JSON (${reason}): ${trimmed.slice(0, 200)}`);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed) || !(parsed as { type?: unknown }).type) {
    throw new Error(`northstar: event stream line is not an event object: ${trimmed.slice(0, 200)}`);
  }
  const payload = parsed as Record<string, unknown>;
  const type = typeof payload.type === "string" ? payload.type : String(payload.type);
  switch (type) {
    case "result":
      return {
        type: "result",
        subtype: typeof payload.subtype === "string" ? payload.subtype : "error_during_execution",
        is_error: payload.is_error === true,
        num_turns: typeof payload.num_turns === "number" ? payload.num_turns : 0,
        duration_ms: typeof payload.duration_ms === "number" ? payload.duration_ms : 0,
        total_cost_usd: typeof payload.total_cost_usd === "number" ? payload.total_cost_usd : 0,
        total_usage: usageOf(payload.total_usage),
        session_id: typeof payload.session_id === "string" ? payload.session_id : "",
        pricing_estimated: payload.pricing_estimated === true,
        errors: Array.isArray(payload.errors) ? payload.errors.map(String) : [],
        permission_denials: Array.isArray(payload.permission_denials) ? payload.permission_denials.map(denialOf) : [],
      };
    case "system":
      return {
        type: "system",
        subtype: typeof payload.subtype === "string" ? payload.subtype : "",
        content: typeof payload.content === "string" ? payload.content : "",
        data: payload.data && typeof payload.data === "object" ? (payload.data as Record<string, unknown>) : {},
      };
    case "assistant":
      return {
        type: "assistant",
        content: blocksOf(payload.content),
        model: typeof payload.model === "string" ? payload.model : "",
        usage: usageOf(payload.usage),
        stop_reason: typeof payload.stop_reason === "string" ? payload.stop_reason : "",
      };
    case "user":
      return { type: "user", content: blocksOf(payload.content), is_meta: payload.is_meta === true };
    default:
      // Forward compatibility: keep every field, add none, and let the caller ignore it or
      // switch on `type`. `payload` is exactly what the runtime wrote.
      return payload as UnknownEvent;
  }
}

/**
 * The `limits` table from a `system`/`init` event, or null when the event is not an init line.
 *
 * Typed as far as it is worth typing: the init payload is diagnostics, and a caller that reads a
 * ceiling out of it should compare it against what it asked for rather than assume either side.
 */
export function initLimits(event: RunEvent): Record<string, unknown> | null {
  if (event.type !== "system" || event.subtype !== "init") return null;
  const limits = (event.data as Record<string, unknown>).limits;
  return limits && typeof limits === "object" ? (limits as Record<string, unknown>) : null;
}

/** Split a chunked stdout buffer into events, keeping the trailing partial line for the caller. */
export function createNdjsonSplitter(): {
  push: (chunk: string) => string[];
  end: () => string[];
} {
  let pending = "";
  const clean = (line: string): string => line.replace(/\r+$/, "");
  return {
    push(chunk: string): string[] {
      pending += chunk;
      const lines = pending.split("\n");
      pending = lines.pop() ?? "";
      return lines.map(clean).filter((line) => line.trim() !== "");
    },
    end(): string[] {
      const tail = clean(pending);
      pending = "";
      return tail.trim() === "" ? [] : [tail];
    },
  };
}
