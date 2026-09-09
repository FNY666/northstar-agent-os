/**
 * The event mirror: what a line of NDJSON becomes, and what a stream that stops being
 * machine-readable does to the caller.
 *
 * The fixtures are transcriptions of real `--json` output, not invented shapes - the point of
 * this file is that the types promise what the runtime writes.
 */
import assert from "node:assert/strict";
import test from "node:test";

import {
  createNdjsonSplitter,
  EXIT_CODES,
  exitCodeFor,
  initLimits,
  isResult,
  KNOWN_EVENT_TYPES,
  parseEventLine,
  USAGE_ERROR,
} from "../src/events.ts";

const INIT =
  '{"type":"system","subtype":"init","content":"runtime ready: scripted/scripted","data":{"model":"scripted","provider":"scripted","permission_mode":"default","limits":{"max_turns":25,"max_tool_calls":50,"max_budget_usd":null,"compaction_threshold_tokens":60000},"allowed_tools":[],"disallowed_tools":["Write"],"depth":0}}';
const ASSISTANT =
  '{"type":"assistant","content":[{"type":"text","text":"hello"}],"model":"scripted","usage":{"input_tokens":10,"output_tokens":2,"cache_read_input_tokens":1,"cache_creation_input_tokens":0},"stop_reason":"end_turn"}';
const RESULT =
  '{"type":"result","subtype":"error_permission_denied","is_error":true,"num_turns":2,"duration_ms":12,"total_cost_usd":0.004,"total_usage":{"input_tokens":5,"output_tokens":2,"cache_read_input_tokens":0,"cache_creation_input_tokens":0},"session_id":"ns-1","pricing_estimated":true,"errors":["Write refused"],"permission_denials":[{"tool":"Write","source":"policy:deny","reason":"refused by the permission gate","agent":"main","turn_index":1,"kind":"tool"}]}';

test("the exit-code table is the runtime's table, nine subtypes and 64", () => {
  assert.deepEqual(EXIT_CODES, {
    success: 0,
    error_during_execution: 1,
    error_max_turns: 2,
    error_max_tool_calls: 3,
    error_max_budget_usd: 4,
    error_permission_denied: 5,
    error_postconditions_failed: 6,
    error_session_busy: 7,
    // The drift watch's own code: on a backend that cannot bind the governance tree read-only,
    // "the policy moved under this run" has to be a number a wrapper can page on.
    error_governance_drift: 8,
  });
  assert.equal(USAGE_ERROR, 64);
  assert.equal(exitCodeFor("success"), 0);
  assert.equal(exitCodeFor("error_session_busy"), 7);
  assert.equal(exitCodeFor("error_governance_drift"), 8);
  // A subtype this build has never seen must not read as success: it gets the generic failure
  // code, which is the same fallback the shell uses for `error_during_execution`.
  assert.equal(exitCodeFor("error_something_new"), 1);
});

test("a result event keeps every field the CLI writes", () => {
  const event = parseEventLine(RESULT);
  assert.ok(isResult(event));
  assert.equal(event.subtype, "error_permission_denied");
  assert.equal(event.num_turns, 2);
  assert.equal(event.total_cost_usd, 0.004);
  assert.equal(event.pricing_estimated, true);
  assert.deepEqual(event.errors, ["Write refused"]);
  assert.deepEqual(event.total_usage, {
    input_tokens: 5,
    output_tokens: 2,
    cache_read_input_tokens: 0,
    cache_creation_input_tokens: 0,
  });
  const denial = event.permission_denials[0];
  assert.equal(denial.tool, "Write");
  assert.equal(denial.source, "policy:deny");
  assert.equal(denial.turn_index, 1);
});

test("fields the types promise are there even when an older runtime omitted them", () => {
  const thin = parseEventLine('{"type":"result","subtype":"success"}');
  assert.ok(isResult(thin));
  assert.equal(thin.is_error, false);
  assert.equal(thin.num_turns, 0);
  assert.deepEqual(thin.errors, []);
  assert.deepEqual(thin.permission_denials, []);
  assert.deepEqual(thin.total_usage, {
    input_tokens: 0,
    output_tokens: 0,
    cache_read_input_tokens: 0,
    cache_creation_input_tokens: 0,
  });
  assert.equal(thin.session_id, "");

  // A denial missing its defaults still reads as a complete record, using the dataclass's own
  // defaults rather than inventing new ones.
  const partial = parseEventLine('{"type":"result","permission_denials":[{}]}');
  assert.ok(isResult(partial));
  assert.deepEqual(partial.permission_denials[0], {
    tool: "",
    source: "",
    reason: "",
    agent: "main",
    turn_index: 0,
    kind: "tool",
  });
});

test("assistant content is a list of blocks, and a block without a type is not content", () => {
  const event = parseEventLine(ASSISTANT);
  assert.equal(event.type, "assistant");
  if (event.type !== "assistant") assert.fail("unreachable");
  assert.equal(event.content.length, 1);
  assert.equal(event.content[0].text, "hello");
  assert.equal(event.usage.input_tokens, 10);
  assert.equal(event.stop_reason, "end_turn");

  const junk = parseEventLine('{"type":"assistant","content":[{"text":"no type"},"raw string",null]}');
  if (junk.type !== "assistant") assert.fail("unreachable");
  assert.deepEqual(junk.content, []);
  assert.equal(junk.model, "");
});

test("an unknown event type passes through untouched, so a newer runtime still works", () => {
  const event = parseEventLine('{"type":"future_event","session_id":"s-9","note":"added later"}');
  assert.equal(event.type, "future_event");
  assert.equal((event as Record<string, unknown>).note, "added later");
  assert.equal(KNOWN_EVENT_TYPES.includes("future_event" as (typeof KNOWN_EVENT_TYPES)[number]), false);

  // The runtime's own fallback for an event it cannot render is `{type, repr}`; reading that line
  // must not lose the repr, which is often the only description of what went wrong.
  const fallback = parseEventLine('{"type":"weirdmessage","repr":"WeirdMessage(x=1)"}');
  assert.equal(fallback.type, "weirdmessage");
  assert.equal((fallback as Record<string, unknown>).repr, "WeirdMessage(x=1)");
});

test("a line that is not an event object is an error, not a skipped byte", () => {
  assert.throws(() => parseEventLine("Traceback (most recent call last):"), /not JSON/);
  assert.throws(() => parseEventLine(""), /empty line/);
  assert.throws(() => parseEventLine("[]"), /not an event object/);
  assert.throws(() => parseEventLine("null"), /not an event object/);
  assert.throws(() => parseEventLine('{"subtype":"result"}'), /not an event object/);
});

test("the init event answers the question an embedder actually asks", () => {
  const event = parseEventLine(INIT);
  assert.equal(event.type, "system");
  if (event.type !== "system") assert.fail("unreachable");
  assert.equal(event.content, "runtime ready: scripted/scripted");
  const limits = initLimits(event);
  assert.ok(limits);
  assert.equal(limits.max_turns, 25);
  assert.equal(limits.max_budget_usd, null);
  assert.equal(initLimits(parseEventLine(RESULT)), null);
  assert.equal(initLimits(parseEventLine('{"type":"system","subtype":"note","content":"x"}')), null);
});

test("the splitter reassembles lines across chunk boundaries, and hands back a tail-less final line", () => {
  const splitter = createNdjsonSplitter();
  // The complete line arrives even though the next one is still mid-flight: a caller that had to
  // wait for a whole chunk boundary would lose the point of streaming.
  assert.deepEqual(splitter.push('{"a":1}\n{"b":'), ['{"a":1}']);
  assert.deepEqual(splitter.push('2}\n{"c":3}\n'), ['{"b":2}', '{"c":3}']);
  assert.deepEqual(splitter.end(), []);

  const partial = createNdjsonSplitter();
  assert.deepEqual(partial.push('{"a":1}\n{"b":2}'), ['{"a":1}']);
  assert.deepEqual(partial.end(), ['{"b":2}']);

  // A file copied through Windows line endings, and a chunk that is only a newline: no phantom
  // empty lines, and no stray \r that would make the JSON unparseable.
  const crlf = createNdjsonSplitter();
  assert.deepEqual(crlf.push('{}\r\n\r\n'), ["{}"]);
  assert.deepEqual(crlf.end(), []);

  const lastLineHasNoNewline = createNdjsonSplitter();
  assert.deepEqual(lastLineHasNoNewline.push('{"a":1}\r\n'), ['{"a":1}']);
  assert.deepEqual(lastLineHasNoNewline.end(), []);
});

test("an empty stream yields no lines at all", () => {
  const splitter = createNdjsonSplitter();
  assert.deepEqual(splitter.push(""), []);
  assert.deepEqual(splitter.end(), []);
});
