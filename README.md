# Northstar Agent OS

**Open, reliable, and governed runtime for autonomous AI coworkers.**

> 中文名：北辰智能体系统

[English](README.md) · [简体中文](docs/README.zh-CN.md) · [繁體中文](docs/README.zh-TW.md) · [日本語](docs/README.ja.md) · [Español](docs/README.es.md) · [한국어](docs/README.ko.md) · [Français](docs/README.fr.md) · [Deutsch](docs/README.de.md) · [Português (Brasil)](docs/README.pt-BR.md) · [Italiano](docs/README.it.md) · [Türkçe](docs/README.tr.md) · [Tiếng Việt](docs/README.vi.md)

**In one sentence:** Northstar is a **next-generation Agent operating system** with a governed kernel — one entry (`northstar agent`), visible boundaries, auditability, and recoverable execution. The kernel is assembled from explicit subsystems (runtime, contract, host, durable, sidecar, interop). **It is not yet a finished multi-agent platform** (no hosted cloud, no parallel fleets); what ships today is a real product path on top of battle-tested governance primitives, a **default-deny sandboxed `Shell`** (bubblewrap when usable, honest process fallback otherwise — see [docs/concepts/threat-model.md](docs/concepts/threat-model.md)), plus the Northstar Codex Sidecar as a restricted local worker adapter.
> English is the canonical project entry. Translations mirror its scope and security claims; update them when this file changes.

## What it is

Northstar is for people who want to **hand work to an AI coworker** that operates with visible boundaries — not an unconstrained prompt-and-tools loop, and not a pile of libraries you must wire by hand.

- **Product path:** `northstar agent "…"` — session transcript and per-turn checkpoints on by default.
- **Kernel path:** `northstar run …` — every default explicit (embedding, CI, advanced operators).
- **Invariant:** every tool call crosses the permission gate, hooks, budget ceilings, and the audit trail. Policy may only tighten.

Product spine and roadmap: [docs/next-gen-agent-os.zh-CN.md](docs/next-gen-agent-os.zh-CN.md).  
Capability benchmark vs top agents: [docs/benchmark-top-agents-2026-09.zh-CN.md](docs/benchmark-top-agents-2026-09.zh-CN.md).  
Absorb / refuse rules: [docs/next-gen-agent-blueprint.zh-CN.md](docs/next-gen-agent-blueprint.zh-CN.md).

## What ships today

| Layer | What | Role |
| --- | --- | --- |
| **Product entry** | `northstar` / `bin/northstar` | Agent OS CLI (`agent`, `resume`, plus kernel commands) |
| **Kernel** | `components/northstar-agent-runtime/` | Governed loop: events, lifecycle hooks, three-layer permission gate, turn/tool/USD ceilings, subagents, append-only sessions, safe-boundary compaction, span tracing, MCP, skills, plugins |
| **Execution adapter** | `components/northstar-codex-sidecar/` | Local Unix-socket worker: validates requests, runs Codex read-only, bounds I/O, redacts errors, cleans up timed-out process groups |
| **Contract** | `components/northstar-run-contract/` | Versioned Run Request/Receipt, expiring HMAC Run Binding, strict adapter boundary |
| **Host candidate** | `components/northstar-host/` | Explicit host policy grants and opaque private workspaces (local; not production identity) |
| **Durable vocabulary** | `components/northstar-durable-run/` | Run/Step/Event contracts, append-only history, checkpoints, leases, per-call authorization, independent verification |
| **Interop candidate** | `components/northstar-agent-interop/` | Signed attestations, narrowed handoff grants, opaque envelopes, typed receipts; runtime `interop_bridge` mints/verifies grants (local-dev labelled; live CLI backends still host-supplied) |

The agent runtime holds no model credentials for Codex and never spawns a model CLI: Codex execution is delegated to the sidecar over its Unix socket, so reasoning and policy stay in the runtime while execution and sandboxing stay in the sidecar.

## Quick start

**One-line offline demo (no API key, no network, no model SDK):**

```sh
make demo        # or: sh examples/demo/run_offline.sh
```

It runs one full governed agent loop (tool call, permission gate, ceilings, event stream, default session + checkpoint) against the scripted provider and writes an audit transcript under the demo workspace’s `.northstar/sessions/`.

**Product entry from a checkout (no pip install):**

```sh
bin/northstar --version
bin/northstar doctor --workspace .
bin/northstar agent --workspace . --provider scripted --scripted-text "ok" --prompt "hello"
bin/northstar resume latest --workspace . --prompt "continue" --scripted-text "ok"
bin/northstar sessions list --workspace .
bin/northstar bench                  # public governance scorecard (offline)
```

**After `make install` (venv):**

```sh
.venv/bin/northstar agent --workspace . --prompt "summarise README" --dry-run
```

Kernel / advanced path (every default explicit):

```sh
cd components/northstar-agent-runtime
python3 -m cli run --workspace . --provider anthropic --prompt "summarise README" --dry-run
python3 -m cli plugin verify --workspace .
```

`make test` runs every component’s suite, the runtime’s TypeScript face (`sdk-ts/`, 57 tests on node ≥ 22.6 — skipped, never failed, where node is older) and the repository documentation tests (offline).

Extensions arrive as `northstar.plugin.v1` bundles under `.northstar/plugins/` with digests pinned in `plugins.lock`. A bundle may tighten a ceiling, never widen one. There is no marketplace and no remote fetch.

### Sidecar installation

Requirements:

- Linux with Python 3.10 or newer.
- A separately installed `codex` executable available to the service user.
- systemd for the supplied service unit.
- `useradd`/`groupadd` (or `adduser`/`addgroup`) for `install.sh` to create the service account.

```sh
cd components/northstar-codex-sidecar
python3 -m unittest discover -s tests -p 'test_*.py' -v
sudo ./install.sh
sudo systemctl enable --now northstar-codex-sidecar.service
```

Do not expose the Unix socket through a TCP proxy. Review scripts, service account, paths, and permissions before enabling anything.

## How the sidecar works

One JSON request per Unix-socket connection:

```json
{"request_id":"demo-1","prompt":"Reply with OK","timeout_ms":10000}
```

One bounded JSON response:

```json
{"request_id":"demo-1","status":"ok","text":"OK"}
```

Unix socket only; Codex runs with `--sandbox read-only` and `--ephemeral`; separate process group with TERM-to-KILL cleanup; structured error classes and secret redaction.

## Who it is for

Operators and developers building **local or self-hosted AI coworkers** who need a governed Agent OS: testable, auditable, disableable, resumable. It is not a hosted AI product and not a drop-in replacement for a full enterprise identity stack.

## What it is not

- It is **not yet** a complete multi-agent operating system (hosted cloud and auto-launched vendor CLI fleets remain out of scope — see the next-gen doc). OS-sandboxed `Shell` is **default-deny**; read-only tool batches can run with `--parallel-tools N`; signed handoff grants mint via `interop_bridge`; workspace memory + skill-script discovery ship under P4; `northstar bench` is the public governance scorecard.
- It is not a hosted service or a promise of production readiness.
- It is not a general host shell execution API (no unconstrained shell on the host).
- It does not by itself replace enterprise identity, isolation, or cancellation fabrics.
- It does not include Codex credentials or provide a Codex account.

## Relationship to OpenBot

Northstar is an independent, OpenBot-compatible project. It is not affiliated with or endorsed by CopilotKit, OpenBot, or their maintainers. Compatibility describes an integration target, not ownership or security equivalence.

## Security boundary

The sidecar authenticates callers through Unix permissions only. The local `northstar-host` candidate adds a separately testable host-side policy grant and opaque `0700` workspace allocation, but it is not a sandbox or production identity system. Production integrations must still provide caller identity, workspace lifecycle, cancellation propagation, observability without sensitive prompt logging, health/rollback, and a review of Codex’s own configuration.

Do not expose the Unix socket through a TCP proxy. Never commit API keys, OAuth tokens, Codex login state, private keys, production `.env` files, or user transcripts.

## Project status

Northstar is building a **next-gen Agent OS incrementally**. The product entry, governed kernel, default-deny sandboxed `Shell`, checkpoint-fork `resume`, parallel-safe tool batches, and signed handoff bridge are real; hosted cloud and turnkey vendor-CLI fleets remain out of scope. Do not treat this repository as a finished autonomous-agent platform.
## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
