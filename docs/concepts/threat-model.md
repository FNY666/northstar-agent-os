# Threat model: sandboxed execution (P1)

Northstar is an **Agent OS**: the model proposes actions; the host decides
what is allowed; the audit trail records both. This page is the threat model
for **command execution** — the sharpest edge the product path now exposes
through the `Shell` tool.

It is intentionally short. A threat model that nobody re-reads before a
release is worse than none.

## Assets

| Asset | Why it matters |
| --- | --- |
| Host filesystem outside the workspace | Source code, secrets, SSH keys, sibling projects |
| Credentials in the parent environment | API keys, tokens, cloud configs the agent must not inherit |
| Network egress | Exfil, supply-chain pulls, unexpected C2 |
| The run's own budget and audit trail | A runaway shell that burns tokens or erases evidence |
| Policy files under `.northstar/` | Already write-protected by the tool sandbox; shell must not undo that |

## Actors

- **Operator** — starts `northstar agent` / `cli run`, chooses flags and policy.
- **Model** — proposes tool calls; assumed untrusted for authorization decisions.
- **Tool payload** — argv / command / cwd / env crafted by the model (or a
  hostile prompt).
- **Host process** — the runtime itself; trusted to enforce gates, not to be a
  sandbox.

## Trust boundaries

```
  [model / prompt]
        │  tool call (Shell)
        ▼
  permission gate  ── default DENY (kind=exec; acceptEdits does not cover it)
        │  --allow-tool Shell (or host callback)
        ▼
  hooks (PreToolUse may still veto)
        │
        ▼
  tools.shell  ── argv list preferred; command → /bin/sh -c *inside* sandbox
        │         cwd resolved through ToolSandbox (workspace-relative)
        ▼
  tools.os_sandbox
        ├── bwrap backend   isolation=os      (preferred when usable)
        └── process backend isolation=process (honest fallback; host FS reachable)
        │
        ▼
  audit / session transcript  (backend= and isolation= always recorded)
```

Nothing below the permission gate can grant itself access. A subagent cannot
widen what its parent denied. A plugin cannot flip `Shell` on.

## What each backend actually provides

### `bwrap` (isolation=`os`)

When bubblewrap is installed **and** a real probe succeeds (not merely
`--version`):

- host paths needed to execute (`/usr`, `/bin`, `/lib`, …) are bound **read-only**;
- the workspace is the **only writable bind**;
- network / pid / ipc / uts namespaces are unshared;
- the child dies with the parent (`--die-with-parent`);
- env is scrubbed (no parent secrets; `HOME`/`TMPDIR` pinned inside the workspace).

This is what the product means by **OS sandbox**.

### `process` (isolation=`process`)

When bwrap is missing or unusable on this kernel:

- cwd is pinned inside the workspace;
- env is scrubbed the same way;
- timeout kills the **process group** (TERM → KILL);
- stdout/stderr are byte-capped.

**This is not OS isolation.** A determined command can still `cat /etc/passwd`,
read `~/.ssh`, or open a socket. Doctor, dry-run, the init event, and every
Shell tool result say so out loud (`backend=process isolation=process`).

### Selection rules (no quiet lies)

| `--sandbox` | Behaviour |
| --- | --- |
| `auto` (default) | bwrap if the probe passes, else process |
| `bwrap` | **Hard error** if unusable — never silently falls back |
| `process` | Force the process backend (operator accepts the weaker boundary) |

A run that promised OS isolation and then could not deliver it is a
**configuration error**, not a surprising mid-tool downgrade.

## What Shell still cannot do (by design)

- Run under permission mode `default` without `--allow-tool Shell`.
- Run under `--read-only` or `plan` mode (Shell is in `MUTATING_TOOLS` / kind `exec`).
- Inherit under `acceptEdits` (that mode is for file edits, not command execution).
- Use Python `shell=True` (argv list or explicit `sh -c` inside the sandbox only).
- Set `network=true` (reserved; bwrap always unshares net; process cannot honestly promise egress control).
- Override reserved env keys (`PATH`, `HOME`, `TMPDIR`, `LD_*`, `NORTHSTAR_SANDBOX`).
- Escape the workspace via `cwd` (resolved through `ToolSandbox` before the backend sees it).
- Exceed closed ceilings: timeout, output bytes, argv size, env entry count.

## Residual risks (accepted, labelled)

1. **Process backend on hosts without bwrap** — common in restricted CI and
   some containers. Mitigation: honest labelling + default deny + install
   bubblewrap for production agent hosts.
2. **Read-only host binds still expose content** — bwrap does not hide
   `/etc/passwd`; it prevents writes outside the workspace. Secrets that live
   on the host filesystem remain readable unless the operator further
   restricts the host (separate user, drop paths, secrets manager).
3. **`command` strings still parse shell metacharacters** — intentional, but
   confined *inside* the sandbox. Prefer `argv` lists from the model side.
4. **No seccomp profile yet** — bwrap gives namespaces and bind mounts; a
   tighter seccomp filter is a later hardening step, not claimed today.
5. **Sidecar is a different trust domain** — `CodexReadOnly` stays read-only
   over a Unix socket; it is not a substitute for Shell, and Shell is not a
   path into the sidecar.

## Operator checklist

```sh
# What would a run get on this host?
northstar doctor --workspace .
# or: python3 -m cli doctor --workspace .

# Refuse to start unless OS isolation is real:
northstar agent "…" --sandbox bwrap --allow-tool Shell

# Accept process-level isolation explicitly (lab / no-bwrap CI):
northstar agent "…" --sandbox process --allow-tool Shell

# Never: host Full Auto. Shell stays denied until named.
```

## Related

- Spine priority 1: [next-gen-agent-os.zh-CN.md](../next-gen-agent-os.zh-CN.md)
- Governance layers: [governance.md](governance.md)
- Implementation: `components/northstar-agent-runtime/tools/os_sandbox.py`,
  `components/northstar-agent-runtime/tools/shell.py`
