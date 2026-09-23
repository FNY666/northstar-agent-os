# S20 synthetic-only fixture protocol

All fields are intentionally local fixture data. This file does not claim to observe Gemini CLI, a remote tool, a network, durable storage, crash behavior, or power-loss behavior.

## Inputs
- `cases.json`: 16 fault-injection cases spanning clean execution, restart, crash, power loss, network interruption, missing/malformed/duplicate tool responses, and recovery retry.
- State vocabulary: `none`/`committed:1` journal marker; `not_sent`/`sent` dispatch marker; response values (`none`, `lost`, `success`, `error`, etc.); fixture-only `tool_dedup` boolean.

## Harness and rule semantics
`harness.py` applies deterministic local rules. The rule order is explicit in source and is part of the protocol under test:
1. a success observed before durable result commit remains `UNKNOWN`;
2. `not_sent` is locally decidable as `NOT_DISPATCHED`;
3. sent + unavailable/malformed response is `UNKNOWN`;
4. explicit fixture tool error is `TOOL_ERROR`;
5. fixture dedupe is `DEDUPED_IN_FIXTURE`;
6. a supplied success response is `SUCCESS_IN_FIXTURE`.

The harness is a判定器/协议规则 test only. It is not a Gemini CLI implementation, simulator of its persistence, or evidence of remote semantics.

## Invariants
- Every result has `synthetic_only=true` and `production_verified=false`.
- No result is interpreted as exactly-once, rollback, crash durability, or production safety.
- Missing evidence after dispatch cannot be converted to success or failure by this fixture; it remains `UNKNOWN`.
- Fixture dedupe is not evidence that any real CLI/tool deduplicates.
- Re-running the harness from the same inputs is deterministic.
