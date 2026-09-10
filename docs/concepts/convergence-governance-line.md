# Converging the governance line (`arena/01a080ae`)

Two arena lines branched from the same ancestor (`e8b7252`) and are not close
relatives:

| | `arena/01a07be4` (platform) | `arena/01a080ae` (governance) |
|---|---|---|
| app-server, artifacts, signed receipts | yes | no |
| workspace checkpoints, context rollover | yes | no (adds transcript checkpoints instead) |
| cancellation | yes | no |
| postconditions, command hooks | no | yes |
| streaming, provider retry | no | yes |
| session lease, MCP negotiation, plugins, skill audit | no | yes |

A merge resolved file-by-file with `ours`/`theirs` would therefore delete real
capability on one side or the other, silently. `--ours` loses the governance
boundaries; `--theirs` loses receipts, artifacts, checkpoints, rollover and
cancellation. Neither is a merge; both are a deletion with a merge commit on
top.

So the platform line is the single runtime core and governance capabilities are
ported onto it, one capability per commit, each with its own tests.

## Two collisions that had to be decided, not merged

1. **`checkpoints.py` (add/add).** Two unrelated designs share the name. The
   platform file snapshots the *workspace*; the governance file records a
   *transcript* boundary for resume. They must not become one module: a
   `resume_from` that reads a workspace manifest, or a `rewind` that moves the
   transcript, is a data-loss bug. The platform module keeps its public API; the
   governance one is carried as `transcript_checkpoints.py` when its stage lands.
2. **Exit code 6.** The platform publishes `error_cancelled = 6`. The governance
   line assigns 6 to a failed postcondition. Reusing the code would make "the
   user walked away" and "the claim did not hold" indistinguishable to every
   consumer that already ships against 6. Converged: cancellation keeps 6,
   `error_postconditions_failed` is **8**, `error_session_busy` stays 7.

## Stage 1 — ported and wired (this branch)

- `command_hooks.py` — workspace `[[hooks]]` via a separate audited loader;
  inert unless `--enable-workspace-hooks`; declared-but-inert is reported in the
  CLI note, the doctor output and the dry-run line rather than swallowed.
- `postconditions.py` — end-of-run workspace checks, declared in the `init`
  event, evaluated by the host against the same real root the tools are jailed
  to, emitted as their own `postconditions` system record.
- `policy_file.py` — union: platform `context_window_tokens` kept, governance
  `hooks`/`verify`/`halt_on_denial` added.

Evidence: command hooks 30/30, postconditions 32/32, policy file 40/40, plus the
updated events/CLI/session protocol guards. Full per-file sweep of the runtime
tests shows no other failure; `test_sessions`' single error and
`test_mcp_client`'s timeout reproduce on the unmodified platform base (iSH
multiprocessing limits), as does `test_ssh_forward`.

## Stages still open

Ordered by dependency, each with its own tests, none of them adopted wholesale
from the governance line:

1. `providers/openai_compat.py` + provider factory wiring.
2. `skill_audit.py` / `skill_check.py` — audit and load stay two phases; audit
   cannot be bypassed at load time.
3. Transcript checkpoints as `transcript_checkpoints.py`, then resume budget
   inheritance (turns, tool calls, cost, usage, denials).
4. `mcp_negotiate.py`, `mcp_elicitation.py`, `mcp_config.py` — imported config
   may define servers; it may never inherit approvals or host authorization.
5. Streaming (`StreamDelta`, fidelity helpers) into the platform loop without
   disturbing tool-use, rollover or cancellation; only confirmed assistant text
   is exposed.
6. `session_lease.py` and `durable_bridge.py`, with one lock order defined
   against the platform SessionStore's HMAC chain, and child runs reusing the
   parent claim.
7. `plugin_manifest.py` / `plugin_load.py` on top of hooks and skill audit.
8. `provider_retry.py`, reconciled with the platform's existing context-overflow
   recovery so the two cannot form two escalating recovery loops.
9. `session_replay.py`, last: it depends on the settled transcript checkpoint
   schema and the platform session reader.

Until each stage lands, its module is absent from the tree rather than present
and unwired: a module that exists but is not called reads as a working control
that is not applied.
