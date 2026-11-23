# Threat model: sandboxed execution (P1)

Northstar is an **Agent OS**: the model proposes actions; the host decides
what is allowed; the audit trail records both. This page is the threat model
for **command execution** — the sharpest edge the product path now exposes
through the `Shell` tool.

It is intentionally short. A threat model that nobody re-reads before a
release is worse than none.

Audit recovery and public feed verification process records one at a time, so
normal verification memory no longer scales with the total history size.
Strict nonce-deduplication retains the nonce set, and an individual record is
still parsed whole; producers and operators must bound event payloads and use
strict verification only when the nonce policy is required.

Tool argument and schema trees are preflighted against a conservative 1 MiB
serialized-size estimate, a 50,000-node ceiling, and 32-level depth before
copying provider arguments or evaluating JSON Schema. Unsupported Python
objects and non-string object keys are refused before copying as well. This
bounds expanded JSON traversal: repeated in-memory references are charged once
per occurrence, and a wide container is rejected before its children are added
to the traversal queue. Cycles stop at the depth limit. Regex patterns retain
their separate execution deadline.

PreToolUse and SubagentStart hooks receive detached copies of their mutable
input fields. A hook changes the authorized arguments only by returning the
explicit rewrite result; that rewrite is copied and schema-validated again
before permission evaluation and execution.

Tool schemas are copied when a `ToolSpec` is created and copied again for API
views and provider request construction. A provider client that mutates its
request object therefore cannot widen the schema later used by the runtime's
authorization path. The gate reads a separate registration-time snapshot, so
mutating the public compatibility field on a `ToolSpec` cannot change runtime
validation either.

Each governed tool-call ledger input fingerprint binds the provider `call_id`,
tool name, and effective post-hook arguments. `ToolCallReport` returns that
digest, allowing an auditor to match the report to the sealed event even when
the same tool and arguments occur multiple times. The ledger stores only the
digest, not the raw arguments.

Workspace command-hook scripts are read through no-follow file descriptors,
must remain regular files, and are capped at 1 MiB both during registration and
before each dispatch. This bounds parent-process memory use before the hook's
own timeout and output limits can take effect.
On Linux, a hook can opt into `execution = "snapshot"`: the captured registration
bytes are copied into a sealed anonymous file and passed to an explicit Python,
Node, `sh`, or `bash` interpreter through an inherited descriptor. The legacy
`path` mode keeps its path-replacement race for compatibility; snapshot mode
executes registration-time content even if the workspace path later changes.

The OpenAI-compatible and Anthropic adapters cap normalized text and each
tool-argument blob at 1,048,576 characters, all tool-argument blobs together at
4 MiB, and accept at most 128 tool calls per response. Anthropic normalization
also caps content at 256 blocks and checks JSON-tree depth, node count, and
aggregate argument size before copying arguments into runtime blocks. SSE
reassembly applies the OpenAI-compatible cumulative bounds before appending
each fragment.
The SDK has already received the HTTP response by normalization time, so these
are adapter/loop bounds, not transport-level response-body limits.

At the tool boundary, validated JSON arguments are detached from provider-owned
objects before hooks and permission evaluation. The governed runner takes a
second deep snapshot before computing its assess pin and passes that same
snapshot to the executor. This closes the nested-object alias window where a
concurrent hook or caller could otherwise change an argument after assessment
but before execution.

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

Workspace `Read`, `Write`, `Edit`, and directory access resolve friendly paths
first, then perform I/O from directory descriptors opened one component at a
time with `O_NOFOLLOW`, including every ancestor of the pinned workspace root.
This prevents a concurrent symlink replacement above the workspace from
redirecting a validated in-workspace path into a sibling directory.
Full-replacement `Write` and `Edit` stage complete bytes beside the target,
`fsync` the staging file, recheck the original file version, then publish by
atomic replacement. A partial staging failure leaves the original bytes intact;
a detected concurrent target change or newly created hard link refuses the
replacement. The operation preserves owner/group, ordinary permission bits,
POSIX access ACLs, and SELinux labels while clearing setuid/setgid bits;
unknown or content-bound extended attributes make replacement fail closed.
Append remains an in-place operation because it has incremental semantics.

Session writes deep-copy caller data before hash-chain sealing and pass only a
detached copy to optional `on_write` mirrors. A mirror can observe records but
cannot mutate the bytes that the local append-only transcript will persist.
Session genesis and every chained record use the same canonicalization version;
replay verifies the complete chain before reconstructing a transcript, and CLI
or SDK resume refuses both modified chains and legacy transcripts with no
seal. Legacy files remain readable for inspection; unsealed history is never
silently trusted as resume context.
Transcript readers stream lines through bounded buffers and refuse files above
64 MiB, lines above the writer-compatible byte ceiling, or files over 100,000
records; writer restart uses the same bounds, opens with no-follow semantics,
and verifies the full chain before trusting its head or restoring the HLC. A
hostile session file cannot force an unbounded `read()` allocation or seed the
next run with an unverified chain head or clock.
Session transcripts retain prompts and model/tool content by default to support
replay. `--redact-session-content` replaces content-bearing values before hashing
and before `on_write` mirrors see them; the resulting chain remains verifiable,
but those sessions cannot be resumed. The mode preserves workspace paths and
governance metadata, so filesystem protection and host-defined retention remain
necessary. Trace export has separate redaction semantics and does not imply that
the local session file is content-free.

The egress sidecar resolves once, filters the resolved set, and dials the exact
authorized IP without following redirects or ambient proxy settings. Its
default SSRF rule requires `ipaddress.is_global`; shared carrier space such as
`100.64.0.0/10` is denied even though Python does not classify it as private or
reserved. `allow_private_ips=true` remains an explicit policy opt-in.
Egress policy hosts are validated as DNS-style ASCII authorities at load time
and again at the request boundary, so resolver, TLS SNI and HTTP Host cannot
interpret a path, userinfo, empty label or Unicode hostname differently.
For destinations requiring human approval, the signed receipt also binds the
normalized host/port, method, path, body digest, and caller headers that survive
sidecar overrides. Receipts without this request-shape digest fail closed for
egress approval; they remain valid for their existing non-egress use.
Hosts may further narrow an individual run with repeatable `--egress-target`
values or the workspace policy's `egress_targets` array. When both are present,
the runtime intersects them; neither can widen the other. This exact-host subset
is checked after PreToolUse input rewrites but before the permission callback and
network handler, and is inherited by delegated children. It complements rather
than replaces the sidecar's global policy; absent both run and workspace scopes,
the sidecar allowlist remains the target boundary.

Skill script discovery is bounded at 4,096 directory entries per skill before
sorting, and the prompt lists at most 16 runnable scripts per skill. An
oversized directory fails setup explicitly instead of consuming unbounded
memory or presenting an apparently complete, silently truncated list.
Skill discovery scans at most 256 entries in each skill root, accepts at most
40 skills total, and walks at most 4,096 resource-tree entries per skill before
pinning linked text assets. These limits are checked during iteration, before
sorting or retaining the rest of a hostile directory.
Workspace Grep scans incrementally and stops after 16,000 total tree entries;
its result reports truncation rather than implying a complete search. Agent
definition discovery checks at most 256 directory entries and 40 files across
workspace/plugins, with a 256 KiB per-file read cap enforced before parsing.
Installed plugin discovery requires its resolved root to remain inside the
workspace, rejects symlinked roots and plugin directories, and refuses to
return a partial inventory when more than 256 root entries exist.
Project context injection is capped at 64,000 characters and reads at most
256 KiB plus one byte from a no-follow regular-file descriptor before
truncating. The character limit therefore also bounds prompt growth while the
byte limit prevents a huge `AGENTS.md` from being fully materialized first.
Plugin bundle loading applies a 4,096-entry tree scan cap, 200-file cap, 1 MiB
per-file and manifest caps, and a 64 MiB aggregate file cap. Files are opened
without following symlinks and multiply-linked files are refused before their
bytes enter the digest.
Skill catalogue metadata is serialized as one JSON record per entry, labelled
with its workspace or plugin source and `trust=low`; descriptions cannot inject
new prompt lines. A fixed system-prompt instruction says these records are
discovery data, not directives. MCP-served skills are not currently imported.
Delegated child results cross back into the parent as low-trust tool data with
the child agent name attached. This is a provenance cue for the parent model,
not cryptographic authentication of a remote agent or a guarantee that the
child's claims are correct.

Host-configured composition rules are evaluated against one bounded action
history shared across a delegation tree. Capability checks at delegation time
do not count as executed actions; actual child tool calls do. This prevents a
child engine from resetting the parent's composition state while avoiding
false sequence matches caused only by inspecting a child's declared tools.
Composition history retains category labels only (32 entries), not arguments
or tool results. A checkpoint stores that bounded history and a digest of the
composition policy; resume restores it only when the digest matches. With active
composition rules, legacy checkpoints or transcript resumes without a checkpoint
are refused because their prior action state cannot be proven. Enforcement still
depends on complete action categories and rules.

## What each backend actually provides

### `bwrap` (isolation=`os`)

When bubblewrap is installed **and** a real probe succeeds (not merely
`--version`):

- host paths needed to execute (`/usr`, `/bin`, `/lib`, …) are bound **read-only**;
- the workspace is the **only writable bind**;
- `.northstar/` is over-mounted read-only, with `.northstar/tmp/` replaced by an ephemeral `tmpfs` only when the Shell pledge includes `tmppath`; Shell cannot persistently rewrite policy, skill, or memory governance files;
- `/tmp` is a writable `tmpfs` only when no pledge was requested or `tmppath` is included; otherwise it is a non-writable directory;
- network / pid / ipc / uts namespaces are unshared;
- the child dies with the parent (`--die-with-parent`);
- the default capability policy drops all Linux capabilities; before selection,
  Northstar runs a disposable child with `--cap-drop ALL` and a child with the
  actual seccomp filter. If either enabled boundary fails its live probe, Shell
  refuses to spawn instead of running without that boundary. Disabling either
  control requires the corresponding explicit operator setting;
- with the default seccomp policy enabled, descendants cannot use `setpgid` or
  `setsid` to leave the process group Shell terminates on completion, timeout,
  or output exhaustion;
- env is scrubbed (no parent secrets; `HOME`/`TMPDIR` pinned inside the workspace).

This is what the product means by **OS sandbox**.

### `process` (isolation=`process`)

When bwrap is missing or unusable on this kernel:

- cwd is pinned inside the workspace;
- env is scrubbed the same way;
- timeout, output exhaustion, and leader exit terminate the **process group**
  (TERM → KILL); default Linux seccomp denies `setpgid` and `setsid` so
  descendants cannot detach from that cleanup group. Parent-side selector or
  pipe errors also trigger process-group termination before the error escapes;
- stdout/stderr are byte-capped;
- a launcher applies inherited POSIX per-process ceilings for CPU seconds,
  virtual address space, individual file size, and open file descriptors (at
  most 256, further tightened by the host hard limit); core dumps are disabled.
  A setup failure exits 126 before the requested command runs.

These are inherited **per-process** limits, not aggregate process-tree quotas:
forked children each receive their own CPU and address-space allowance. The
individual-file-size ceiling is not a workspace storage quota. Neither backend
provides aggregate process-tree limits by itself. The descriptor ceiling
applies per process, not across the process tree. Wall-clock timeout and output
capping do not replace those controls. Bubblewrap namespaces do not provide
them by themselves.

An operator may additionally select
`--shell-aggregate-resource-scope systemd`. On Linux this places either backend
inside a non-delegated, system-manager-owned scope with aggregate `MemoryMax`,
`TasksMax` (default 128; a call may tighten it), and `CPUQuota=100%`, then kills
and stops the complete scope after the call. This mode requires a non-root
runtime, system cgroup-v2 `cpu`/`memory`/`pids` controllers, systemd tools, and
seccomp; it refuses to start if those prerequisites or scope creation fail.
It does not add a workspace disk quota. The option is off by default, and this
repository's tests use a fake manager rather than a live PID 1, so deployments
must validate it on their target systemd host before relying on the guarantee.

**This is not OS isolation.** A determined command can still `cat /etc/passwd`
or read `~/.ssh`; process-backend network socket creation is denied only when
the supported Linux seccomp filter is active. Doctor, dry-run, the init event,
and every Shell tool result say so out loud (`backend=process isolation=process`).
There is no separate read-only mount for `.northstar/` on this backend; an
explicitly approved Shell command can alter workspace governance that a later
run may consume.

When Landlock is unavailable in `auto` mode, the default full pledge set adds
no narrower per-call rights and may continue under the ordinary process
backend; the missing path-control layer is included in the tool result. Any
narrowed pledge is refused before spawn unless Landlock is available and
enabled. This prevents a requested filesystem restriction from silently
turning into an unrestricted command.

With the process backend's default Landlock profile, `/dev` is not granted as
a recursive hierarchy: only `/dev/null` (read/write) and the standard
`/dev/zero`, `/dev/random`, and `/dev/urandom` read nodes are individually
allowed when they are actual character devices. This keeps host `/dev/shm` and
`/dev/pts` outside the tool's path allowlist.

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
- Exceed closed ceilings: timeout, output bytes, UTF-8 argv bytes, env entry
  count, and UTF-8 bytes across caller-supplied environment entries.
- Aggregate process-tree memory/CPU and process count are bounded only when
  the operator enables `--shell-aggregate-resource-scope systemd`; they remain
  unbounded by this runtime in the default mode. Workspace storage still needs
  deployment-level quota support.

## Residual risks (accepted, labelled)

1. **Process backend on hosts without bwrap** — common in restricted CI and
   some containers. Mitigation: honest labelling + default deny + install
   bubblewrap for production agent hosts. Governance paths are not separately
   protected from an explicitly approved Shell command on this backend.
2. **Read-only host binds still expose content** — the sandbox ro-binds the
   host's `/usr`, `/bin`, `/lib`, `/lib64`, `/sbin` (whatever exists): bwrap
   prevents writes outside the workspace but does not hide readable host
   content, so secrets on the host filesystem remain readable unless the
   operator further restricts the host (separate user, drop paths, secrets
   manager). Deliberately narrowed: `/etc/resolv.conf` and `/etc/ssl` are
   *not* bound (the net namespace is always unshared — `network=true` is
   refused — so nothing inside can do DNS/TLS anyway, and resolv.conf leaks
   the operator's internal DNS layout), and the real `/etc/passwd` and
   `/etc/group` are replaced by synthetic single-user files
   (`tools/os_sandbox._minimal_identity_files`): only the invoking uid/gid
   resolves inside, so other host users' names stay invisible while
   getpwuid/whoami/id/git keep working. The exact bind list is pinned by
   `BwrapArgvSurfaceTests` — any expansion is a deliberate diff. Honest
   boundary: the synthetic identity was validated for tool compatibility in
   a mount namespace (sh, python3, git, whoami), but no bwrap binary exists
   in this dev environment, so the end-to-end bind has not been run here.
3. **`command` strings still parse shell metacharacters** — intentional, but
   confined *inside* the sandbox. Prefer `argv` lists from the model side.
4. **Seccomp denylist, not allowlist** — both backends now load the BPF
   denylist (`tools/seccomp.py`) over escape primitives (ptrace, module
   loading, kexec, BPF, perf, userfaultfd, keyrings, mount/pivot_root,
   cross-process memory, socket creation, and `io_uring_setup`); denied calls
   fail with EPERM. The x86_64 and aarch64 tables are explicit; unknown audit
   architectures and x86_64 x32 syscall numbers fail closed. It is a denylist
   because a default-deny allowlist cannot serve a general Shell tool. bwrap
   loads the filter via `--seccomp FD`; the process backend (Linux) applies
   it through a `python3 -c` prctl wrapper — no `Popen(preexec_fn=...)`,
   which would be unsafe in the threaded runtime. `--seccomp on` is refused
   only where no backend can apply the filter (non-Linux); a per-call payload
   may only tighten the operator's `--seccomp` setting, never loosen it.
   The process backend's socket denial is not destination-scoped egress
   authorization and does not remove network access through any explicitly
   supplied egress-capable descriptor.
5. **Sidecar is a different trust domain** — `CodexReadOnly` stays read-only
   over a Unix socket; it is not a substitute for Shell, and Shell is not a
   path into the sidecar.
6. **Aggregate resource exhaustion** — per-process POSIX limits still give
   each child its own CPU/address-space allowance. The opt-in
   `--shell-aggregate-resource-scope systemd` adds system-manager-owned
   process-tree memory, CPU-bandwidth and task ceilings when the host has the
   required cgroup-v2 controllers. It is disabled by default and has only been
   tested against a fake manager in this repository; validate enforcement and
   detached-descendant teardown on the deployment host. Workspace disk quota
   remains absent, so use an external filesystem/container quota when commands
   are adversarial or multiple runs share a host. The kernel's cgroup v2
   `memory.max`, `cpu.max`, `pids.max`, and `cgroup.kill` interfaces are the
   underlying controls ([kernel documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)).
7. **Shell executable screening is a lexical tripwire, not command policy** —
   the permission gate denies direct invocations of known offensive-security
   executable names in `command` text, the `cmd` alias, and direct `argv`
   execution. Argument-vector entries are quoted as literal words before the
   scanner inspects executable positions and known wrappers such as
   `sudo`, `env`, `timeout`, `xargs`, and `find -exec`, plus active backtick,
   `$(...)`, and process substitutions (including those inside double quotes).
   Statically visible inline commands passed to `sh`, `bash`, `dash`, `zsh`,
   `ksh`, or `ash` with `-c`/combined options are scanned recursively too.
   Single-quoted lookalike text is treated as data. Malformed syntax or
   substitution nesting beyond the scanner's bound is denied as unclassified.
   This is not a complete shell parser and does not detect variable-based
   executable names, obfuscated shell syntax, or code that launches a tool
   from a non-shell interpreter.
   Explicit `offensive_allowlist` entries can re-enable a match.
   Sandbox backend selection is host-owned, and the Shell input schema rejects
   undeclared top-level fields; an agent-supplied `backend=process` cannot
   downgrade a host-selected bwrap run. Per-call seccomp and Landlock settings
   are declared in the schema and remain tighten-only.
   Other built-in tool schemas and Task also reject undeclared top-level
   fields. Intentionally dynamic Shell environment and Fetch header maps accept
   only string values. `northstar doctor` validates the built-in schema
   definitions before a run; this checks the contract, not handler correctness
   or an external MCP server's conformance.
   The `process` backend's default seccomp filter blocks `socket`, `socketpair`
   and `io_uring_setup` on supported Linux x86_64/aarch64 even when Landlock is
   unavailable; bwrap also unshares the network namespace. Residual network
   access remains possible when seccomp is disabled, unavailable, or on an
   unsupported/non-Linux host, and through egress-capable descriptors explicitly
   provided to a command. This is not destination-scoped egress authorization.
   Do not treat executable-name checks or `network=false` as target-scoped
   control. A complete command policy needs host-owned executable/target scope
   plus kernel-enforced egress, with attempted, denied, and executed commands
   recorded separately. Use an externally enforced network namespace/firewall
   for untrusted commands that need stronger egress guarantees.

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

## Non-boundaries

**Instruction hierarchy is not a security boundary.** System > developer >
user > tool ordering helps the model prioritize, but it is probabilistic --
benchmarks (ManyIH, 2026) show it collapses past 3 privilege levels even in
the best models. Northstar never relies on the model "understanding" the
hierarchy for authorization: the permission gate, egress policy, and audit
chain enforce decisions independently of what the model believed.

Similarly, **tool output is never trusted as instructions.** Every
`ToolResult` carries a `ToolProvenance` (source + trust level); MCP and
external tool outputs are `trust="low"` by default. Policy decisions look
at trusted metadata, never at artifact text. Before structured output is
serialized for the next model turn, the runtime estimates its size and bounds
tree traversal (including nesting depth and large integer rendering); oversized
or cyclic structures are replaced with a small omission notice. This bounded
representation is also what hooks and traces observe, so they do not trigger a
second unbounded serialization before the model boundary. Plain strings are
sliced directly under the same result cap, so the cap does not require first
duplicating a huge result into a second string.

**TEE attestation does not defend against physical access.** When Northstar
emits `tee`-grade evidence (TDX/SEV-SNP quotes), it proves *what ran where*
to a remote verifier -- it defends against a malicious operator or cloud
provider. It does **not** defend against an attacker with physical access
to the machine (cf. TEE.Fail, 2025: DDR interposer key extraction). The
threat model is "distrust the operator", not "distrust physics".
