# Governance: the permission gate is the moat

Every Northstar component that can take an action treats *policy* as a hard
boundary, not a suggestion. This page explains the shared model so each
README only has to describe its own slice.

## The invariant

No path may bypass all four layers at once. Any tool transport — built-in
tools, sidecar delegation (`CodexReadOnly`), skills, MCP servers, subagents —
eventually crosses:

1. **permission gate** (may this tool run, and under which mode?);
2. **hooks** (observers that can veto or annotate, and whose denials are
   terminal);
3. **budget ceilings** (turns, tool calls, dollars — policy values may only
   tighten, never loosen);
4. **audit trail** (every decision is recorded before the run ends).

MCP is the sharpest recent example: remote tools register as
`mcp__<server>__<tool>` with `kind="other"` and are **mutating by default**, so
under the runtime's `default` permission mode they are denied until an operator
names them with `--allow-tool`. MCP is a tool *transport*, never a policy
bypass.

## Layers and semantics

- **Permission modes** (`default`, `acceptEdits`, `plan`, `bypassPermissions`):
  each tool carries a kind (`read`, `edit`, `exec`, `task`, `network`, `other`);
  mutating tools need explicit approval unless the mode grants them. `plan`
  mode denies mutating tools outright. `acceptEdits` auto-approves **edit**
  only — never `exec` (`Shell`).
- **Deny beats allow**: `--deny-tool`, policy-file `deny_tools` and `--read-only`
  subtract from the allow list; a denied tool can never be re-allowed later in
  the same run (a subagent cannot widen what its parent narrowed).
- **Read-only is structural**: `Write`/`Edit`/`Shell` (and anything declared
  mutating) are refused under `--read-only`; workspaces and skill stores are
  checked file-by-file against symlink escapes.
- **Shell is gated twice**: once by the permission gate (default deny, kind
  `exec`) and once by the OS sandbox backend (`bwrap` when usable, else an
  honestly-labelled `process` backend). See [threat-model.md](threat-model.md).
- **The tree a run is gated by is not writable by that run**: `protected_prefixes`
  (`.northstar/`, `.git/`) is not only a rule the file tools obey — an approved
  `Shell` call reaches those bytes with `printf`, so the sandbox is handed the same
  list and re-binds it read-only *after* the workspace bind (`.northstar/memory` and
  `.northstar/tmp` are re-opened, since those are the documented carve-outs), with a
  per-process probe that makes an unheld bind a hard error. Where there are no
  namespaces to bind with, the run freezes the tree's digest at start, re-checks after
  every exec-shaped result, and ends with `error_governance_drift` (exit 8) instead of
  `success`. Detection is weaker than prevention, so it is labelled as such in
  `--dry-run`, in `doctor`, and in `system:init`; `--no-drift-check` opts out loudly.
- **Subagent subsets**: an agent-definition run fixes its tool subset and
  ceilings by definition, which is why `--mcp-server` cannot be combined with
  `--agent` — silently widening a declared policy would defeat the gate.
- **Configuration is fail-closed**: unknown `deny_tools` names, unknown tool
  references, bad server names and unreachable MCP servers are configuration
  errors (exit 64 in the runtime CLI) — before anything runs.
- **Policy documents are versioned**: both policy surfaces — the runtime's
  `.northstar/config.toml` and the host's `northstar-policy.toml` — speak the
  canonical schema `northstar.policy.v1` (defined in `northstar-run-contract/
  policy.py`; the runtime mirrors it to stay dependency-free). An unsupported
  (future) `schema_version` fails closed instead of being read with today's
  semantics, and an optional/required `revision` id (no whitespace or
  slashes, ≤128 chars) is what authorization grants and audit records carry
  as `policy_revision` — every decision traces to the exact policy revision.
- **The transport budget is a ceiling too**: a retry cannot widen what a run may
  *do*, but it multiplies what it *costs* — requests, waiting, and money at
  per-token prices — so `.northstar/config.toml`'s `[retry]` table (parsed by
  `provider_retry`) sits in the same file as `max_turns` and `deny_tools`. The
  same rules apply there: command-line flags may only tighten it, a plugin
  bundle has no key for it, and an out-of-range or unknown value is a
  configuration error before the run, never a defaulted guess.
- **A workspace may declare its MCP servers in a file, and that file still
  decides nothing**: `.mcp.json` (and the Cursor/VS Code/Gemini dialects) is read
  by `mcp_config.py` only when an operator passes `--mcp-config` on the command
  line. An imported server is mutating by default and denied until `--allow-tool`
  names it; a non-empty `autoApprove`/`alwaysAllow` list is a fatal error rather
  than a hint, because a repository file cannot buy back an approval a human
  withheld; and `mcp list` exits 1 on any refusal, so what a run *would* obey is
  reviewable in CI without a provider key.
- **Reading a declaration and starting it are separate consents.** `--mcp-config`
  imports and reports; only `--mcp-allow-exec` turns those servers into child processes,
  and a deferred one is named on stderr and recorded as `mcp.deferred` in the run's
  `system:init` rather than vanishing. The same flag pair carries a plugin bundle's
  servers, because authorship - not file format - is what the rule is about; a server the
  operator typed themselves is theirs and is not gated. A launched server also gets an
  allowlist environment (`PATH`, `LANG`, `LC_ALL` plus its own declared `env`), so a
  repository file cannot read a credential out of the parent: `${VAR}` resolves only for
  names released one at a time with `--mcp-env`.

## Where each component sits

| Component | Governance slice |
| --- | --- |
| `northstar-agent-runtime` | the gate, modes, hooks, budgets, allow/deny resolution |
| `northstar-host` | default-deny workspace/authorization broker around a verified run |
| `northstar-durable-run` | per-call action gate + independent postcondition verification |
| `northstar-run-contract` | the versioned request/receipt boundary encodes *what was authorized* |
| `northstar-codex-sidecar` | read-only worker: no write tool, no path to host state |
| `northstar-agent-interop` | handoff boundary that re-asserts policy at the next engine |

## Reading on

- Runtime README: [Permissions](../../components/northstar-agent-runtime/README.md#permissions),
  [Hooks](../../components/northstar-agent-runtime/README.md#hooks) and
  [Cost](../../components/northstar-agent-runtime/README.md#cost) sections;
  API reference for `permissions`, `policy_file`, `hooks` and `mcp_client`:
  [docs/api/northstar-agent-runtime.md](../api/northstar-agent-runtime.md).
- Host README: [Default-deny policy](../../components/northstar-host/README.md#default-deny-policy).
- Guide: [governed-run-cookbook](../guides/governed-run-cookbook.md) shows the
  CLI switches in action.
