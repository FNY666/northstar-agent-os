# Northstar Agent OS — initial public component

## Unreleased (twenty-third batch) — automatic checkpoint boundaries (T16)

- Added an opt-in `CheckpointPolicy` for deterministic turn and admitted
  mutation boundaries. It requires a persisted session directory, writes
  bounded checkpoint metadata into the append-only transcript, and exposes the
  same metadata through runtime/SDK `RunReport.checkpoints`.
- Automatic retention prunes only policy-labelled checkpoints, preserves manual
  checkpoints, and atomically rebases the retained chain to the nearest
  manual/retained ancestor. It never enables rewind, deletes newly added files,
  or replaces the existing permission and checkpoint controls.
- Added policy validation, retention/rebase, runtime integration and durable
  session tests. Runtime now has 586 tests (582 pass, 4 optional OTel skips) and
  the repository has 896 tests (892 pass, 4 optional OTel skips); this batch
  remains unreleased with no tag, GitHub Release, or PyPI/npm publication.

## Unreleased (twenty-second batch) — host-bound action receipts (T15)

- Added `northstar.receipt-binding.v1`, a strict runtime projection of a
  host-verified authorization grant. It carries the exact signed grant-token
  digest, actor/run/session/workspace/policy identity, narrowed capabilities and
  expiry, but never carries the grant token or any secret into the runtime.
- Added `northstar-host.authorization.make_receipt_binding()`, which requires a
  successful `verify_authorization()` result before producing the projection.
  Bound non-denied action receipts must use a capability covered by the binding;
  session mismatches, unknown fields, expiry and scope widening fail closed.
- Signed action receipts and contract projections now expose the bound
  authorization context. SDK callers can provide `RunOptions.receipt_binding`;
  existing unbound receipts remain backward-compatible.
- Added host, runtime and signed-receipt integration tests. Runtime now has 579
  tests (575 pass, 4 optional OTel skips) and the repository has 889 tests (885
  pass, 4 optional OTel skips); this batch remains unreleased with no tag,
  GitHub Release, or PyPI/npm publication.

## Unreleased (twenty-first batch) — versioned artifact manifests (T14)

- Added `northstar.artifact-manifest.v1`, a bounded canonical manifest for
  tool-reported file, directory, URI, and opaque artifact references. Relative
  workspace locators are normalized and digests/media metadata are validated;
  duplicate, oversized, malformed, or path-escaping entries fail closed.
- `ToolResult` can carry an `artifact_manifest`; the runtime validates it and
  includes it in signed `ActionReceipt` objects and contract postconditions.
  Invalid manifests become failed tool results rather than silently entering the
  audit trail. The manifest remains an observation, not host attestation or a
  permission grant.
- Added artifact contract and signed runtime integration tests, API coverage,
  and documentation. Runtime now has 578 tests (574 pass, 4 optional OTel
  skips) and the repository has 887 tests (883 pass, 4 optional OTel skips);
  this batch remains unreleased with no tag, GitHub Release, or PyPI/npm
  publication.

## Unreleased (twentieth batch) — declared runtime mutation impact sets (T13)

- `ToolSpec` now accepts bounded `affected_input_keys` declarations for custom
  mutating tools whose workspace path is not named `path` or `paths`.
- Pre/post workspace receipts resolve those declared top-level string/list path
  fields through the same sandbox, and `workspace_change` records expose the
  declaration source and keys. Legacy built-ins remain compatible; undeclared
  hidden side effects are still not claimed as covered.
- Added registry introspection, validation, and end-to-end custom-tool receipt
  tests. Runtime now has 574 tests (570 pass, 4 optional OTel skips) and the
  repository has 883 tests (879 pass, 4 optional OTel skips); this batch remains
  unreleased with no tag, GitHub Release, or PyPI/npm publication.

## Unreleased (nineteenth batch) — offline durable-run receipt verification (T12)

- Added the read-only `northstar-durable-run verify-receipt` command. It
  validates a `ControlReceipt` against the authoritative EventStore, including
  exact event IDs/sequences, before/after statuses, and the final state digest.
- Added historical prefix replay so an older receipt remains verifiable after
  later lifecycle events are appended. Verification is fail-closed and never
  mutates the event stream or introduces a receipt ledger.
- Added CLI/EventStore tamper and historical-replay tests, API documentation,
  and local usage guidance. The durable-run suite now has 78 tests; this batch
  remains unreleased with no tag, GitHub Release, or PyPI/npm publication.

## Unreleased (eighteenth batch) — attributable durable-run control receipts (T11)

- Added the versioned `ControlReceipt` v1 contract for local `pause`, `resume`,
  and `cancel` control responses. It binds `run_id`, `actor_id`, `command_id`,
  operation, request time, before/after status and sequence, exact newly
  observed event IDs/sequences, and a canonical final state digest.
- Receipts distinguish event-producing `applied` transitions from terminal or
  already-waiting `noop` controls. They are causal projections over the
  authoritative EventStore, not a second lifecycle state machine or a
  persisted command ledger.
- Added the optional CLI `--command-id`, API reference coverage, schema tests,
  applied/noop CLI assertions, and documentation boundaries. The durable-run
  suite now has 77 tests; this batch remains unreleased with no tag, GitHub
  Release, or PyPI/npm publication.

## Unreleased (seventeenth batch) — local durable persistence fencing (T10)

- EventStore append/read/checkpoint operations now use a POSIX advisory lock
  sidecar; concurrent idempotent writers serialize against one validated event
  stream instead of racing on sequence numbers.
- LeaseManager acquire/assert/heartbeat/release operations use their own lock
  sidecar and retain atomic temporary-file replacement for the lease payload.
- Added a forked-process concurrency test for idempotent event append. This is
  local filesystem fencing only, not a distributed lock service or remote
  worker claim protocol; the batch remains unreleased.

## Unreleased (sixteenth batch) — local durable-run control surface (T9)

- Added the `northstar-durable-run` CLI with read-only `status`, `history`, and
  canonical `audit` views over one validated EventStore stream.
- Added explicit local `control pause|resume|cancel` commands. They require an
  explicit RunContract and owner identity, reuse the owner-bound execution lease
  for fencing, never execute a step, and do not pretend to be a scheduler or
  network control plane.
- Retry remains programmatic so a worker must supply explicit `StepPlan` actions
  and preserve the attempt-specific idempotency boundary.
- Added CLI tests for replay/history/audit output, control ordering and
  fail-closed missing-history errors and owner-bound lease fencing. The
  durable-run suite now has 74 tests; the batch remains unreleased with no tag,
  GitHub Release, or PyPI/npm publication.

## Unreleased (fifteenth batch) — capability leases and verifiable action receipts (T7)

- Runtime `receipts.py` adds bounded `ApprovalLease` / `ApprovalLeaseLedger`
  claims scoped to an exact session, resolved workspace, capability namespace,
  expiry and finite use count. Hard deny lists and plan mode remain stronger
  than a lease; a lease is consumed before the legacy host callback.
- Host `authorization.issue_approval_lease` projects a verified
  `northstar.authorization.v1` grant into the runtime lease shape, narrowing
  capabilities and expiry rather than widening policy.
- Every attempted runtime tool call now has an in-memory `ActionReceipt` with
  canonical input/output and optional workspace-state digests. A host-provided
  secret signs receipts with HMAC-SHA256; tampering is detected by
  `ActionReceipt.verify`. `to_contract_receipt()` keeps the existing
  `northstar.receipt.v1` status/postcondition boundary.
- Python SDK options expose the lease/receipt seam; signed receipts are mirrored
  into sessions without writing the signing secret. Existing unsigned session
  record vocabulary remains compatible.
- Added offline lifecycle, expiry/scope/consumption, host projection, tamper and
  runtime integration tests; runtime now has 572 tests and the repository has
  868 test cases (4 optional OTel skips). This remains unreleased; no tag,
  GitHub Release, PyPI/npm publication or public package push was made.

## Unreleased (fourteenth batch) — reversible execution kernel (T6)

- Runtime checkpoints (`northstar.checkpoint.v1`) snapshot bounded regular files
  with workspace/file hashes, modes, session index, parent checkpoint and
  atomic manifests under `checkpoints/<session-id>/`.
- `sessions checkpoint|inspect|diff|rewind|restore|fork` adds the control plane:
  verified diff, explicit-force rewind with an automatic safety checkpoint,
  conservative handling of files added after a checkpoint, and atomic child
  workspace materialisation with `fork.json` lineage.
- Mutating path-shaped tool calls emit append-only `workspace_change` records
  with pre/post metadata hashes. These receipts do not claim to capture bytes
  for custom tools that do not declare their affected paths.
- Symlink traversal, malformed/tampered manifests, path escape, oversized
  snapshots and unsafe restore targets fail closed; restore never reproduces
  setuid/setgid bits.
- Added offline API/CLI/fork/tamper tests and the reversible-execution concept
  page. Runtime now has 561 tests (four optional OpenTelemetry tests skipped);
  full `make test` is 855 with no release or public package publication.
- Version remains aligned `0.1.0.dev0`; this is unreleased.

## Unreleased (thirteenth batch) — portable Agent Skills and fail-closed validator (T4)

- Runtime discovery now accepts both `.northstar/skills/*/SKILL.md` and the
  portable `.agents/skills/*/SKILL.md` layout.
- `SKILL.md` validation follows the open format: bounded lowercase names that
  match the parent directory, descriptions, `license`, `compatibility`, string
  `metadata`, and space-separated `allowed-tools`. Invalid UTF-8, duplicate
  names, escaping symlinks, and oversized collections fail closed.
- `northstar-agent-runtime skills check` and `skills list --json` provide a
  read-only CI/inspection surface. The validator never executes scripts or
  turns `allowed-tools` into an approval; real runs share the same loader.
- Runtime tests: 536 → 544; current `make test` snapshot: 838 tests with four
  optional OpenTelemetry tests skipped when the tracing extra is absent.
- Version remains aligned `0.1.0.dev0`; this is unreleased.

## Unreleased (twelfth batch) — remote-worker ops substance (T5)

T5 answered the four P3-3 ops gaps with authoritative, code-grounded
artifacts (docs/tests only by batch scope; no transport code ships and no
CI run has touched a real host):

- **Transport specification** (`docs/concepts/northstar-remote-transport.md`):
  Profile A = reuse the existing systemd sidecar socket over an SSH forward
  (zero runtime changes, no remote command execution); Profile B = container
  fleets reusing `DurableRunner`/`EventStore`/`LeaseManager`/verifier;
  vocabulary table cites only real artifacts; failure taxonomy reuses the
  contract's fallback statuses; T5b checklist defines what "done" means.
- **Identity/rotation story** (`docs/concepts/northstar-remote-identity.md`):
  issuance (enrollment secret vs run-scoped binding, policy-revision
  pinning) and rotation (dual-key grace, expiry backstop, revision kill
  switch), grounded in the real binding/authorization/handoff/approval
  machinery; no PKI/no revocation list stated; incidents and open decisions.
- **Operations guide** (`docs/guides/remote-worker-operations.md`):
  Recipe A deployment + rotation steps, Recipe B explicitly not built,
  monitoring table of the three real signals (audit feed / OTEL spans /
  trace_metrics), alert thresholds, incident runbook, first-run validation
  checklist, honesty footer.
- **Operator-run channel canary** (`examples/remote-canary/`): SSH
  reachability → socket forward → deterministic JSON-lines probe that the
  real server rejects before spawning anything (no model, no key), optional
  `NS_REAL=1` real codex run; probe is CI-tested against the real
  `sidecar_socket.serve` on a loopback socket; the full script needs a real
  host and is never run by CI, by design.
- **Scorecard re-scored honestly**: `remote_worker.py --score` 89 → **94/100**
  (ops 33% → 67%) — the two doc-natured gaps (story, guide) now count real
  repo artifacts whose status markers are themselves test-pinned; the two
  implementation gaps (transport code, real canary run) stay MISSING with
  explicit flip conditions. Living docs (concept page, Chinese assessment,
  interop README) updated to 94; P3-3 ledger blocks keep their historical
  numbers, superseded by this batch's record.
- Repository doc tests 28 → 43; full `make test` 812 → 827 green. Aligned
  `0.1.0.dev0`, no release.

## Unreleased (eleventh batch) — observability read-back (P3-4)

- **Concept page** (`docs/concepts/observability.md`): two read-back planes —
  live OTEL spans vs. offline transcripts/audit export — with the real span
  vocabulary (verified against `loop.py`), the ambient-tracer seam stated
  plainly (the runtime never configures an exporter; a bare run exports
  nowhere), and a "which plane when" table.
- **Local trace backend example** (`examples/observability/`): docker compose
  (Jaeger all-in-one OTLP/HTTP receiver + Grafana with provisioned core
  Jaeger data source; no collector — deployment is an open T5 item) plus
  `otel_bootstrap.py`, the provider seam for the CLI (OTLP/HTTP exporter,
  `OTEL_EXPORTER_OTLP_ENDPOINT` override, checkout/site-packages fallback,
  guided exit 3 on missing packages). Honesty pinned by tests: CI never runs
  Docker, tags pinned at write time, exporter not in the tracing extra.
- **Offline session panel** (`examples/session-panel/`): one self-contained
  HTML file (zero network references) rendering session transcripts or
  `audit.ndjson/1` exports via drag-and-drop — stats, errors/denials filter,
  timeline with expandable raw JSON, FNV-1a 64 local fingerprint (labelled
  non-cryptographic). `sample-session.jsonl` is a real transcript including
  a denial path; only the absolute workspace path was masked (documented).
- **Chinese assessment record** (`docs/dx-observability.zh-CN.md`), examples
  index rows, CHANGELOG/batch records.
- Repository doc tests 12 → 28 (panel + observability example suites; the
  panel's JS is `node --check`ed when a Node runtime is present). Full
  `make test` 796 → 812 green. No component behaviour changed and no
  release (aligned `0.1.0.dev0`).

## Unreleased (tenth batch) — remote/hosted worker evaluation (P3-3)

- **Protocol map + decision record** (`docs/concepts/northstar-remote-worker.md`):
  a hosted worker is a transport variant of the sidecar, not a new governance
  surface — same run contract, host-signed short-lived grant, opaque
  workspace, bounded version-pinned process, event/audit trail, verifiable
  structured receipt. Transport options evaluated (sidecar-over-SSH lowest
  cost; durable-run-runner+container for fleets; interop/OpenBot strategic;
  a bespoke HTTP service rejected). Nothing is built or deployed.
- **Reproducible scorecard** (`northstar-agent-interop/remote_worker.py`):
  36 static checks across six areas; every check targets a real symbol in the
  tree and the four ops gaps are explicit `MISSING` probes — the T5 work
  list. Current score 89/100: contracts/host/durable-run/interop/audit all
  100%, ops 33%. `python3 -m remote_worker --score` is CI-runnable and cannot
  drift from the code it measures. Scorecard quality is itself tested
  (kernel checks stay green, MISSING probes stay red until deliberately moved).
- **Chinese assessment** (`docs/dx-remote-worker-assessment.zh-CN.md`):
  TL;DR, asset inventory, protocol mapping, transport options, scores with
  evidence, and the concrete next increment (T5).
- API pages 52 → 53 modules. Interop tests 49 → 54.

## Unreleased (ninth batch) — templates and scaffolding (P3-2)

- **`northstar-agent-runtime new <directory>`** (`scaffold.py`) generates a
  minimal governed project whose defaults are the governance defaults —
  safe first, loosen deliberately:
  - `.northstar/config.toml` — `northstar.policy.v1` + date-based `revision`,
    with `agent = "reviewer"` baked in (every default run is read-only);
  - `.northstar/agents/reviewer.md` — a read-only, plan-mode reviewer agent;
  - `AGENTS.md` — project instructions (auto-injected);
  - `.northstar/hooks/README.md` — hooks are registered in code
    (`AgentRuntime(hooks=…)`), never auto-executed from workspace files; the
    guide ships a correct copy-paste example;
  - `.github/workflows/northstar-review.yml` — governed CI review recipe
    (template; install source and API key left as TODOs);
  - `README.md` — what was created and the three commands to try it.
- Every generated file is validated by the runtime's own loaders: the config
  parses under `load_policy_file`, the agent registers under `agent_files`,
  `doctor` is green in the scaffolded workspace, and `--dry-run` reports the
  policy identity. Refuses a non-empty directory unless `--force` (which
  never deletes).
- Runtime README "Creating a governed project (`new`)" section; layout row,
  `py-modules`, CI compile line and docstring API manifest (51 → 52 modules)
  updated. Runtime tests 522 → 536.

## Unreleased (eighth batch) — policy as code: schema versioning + revision (P3-1b)

- **Canonical policy identity** in `northstar-run-contract/policy.py`:
  `northstar.policy.v1` + revision rules (id charset, ≤128 chars); the
  runtime mirrors the constant locally (dependency-free), both pinned by
  tests.
- **Runtime `.northstar/config.toml`** accepts optional `schema_version`
  (absent → v1) and optional `revision`. An unsupported (future) schema is a
  fail-closed configuration error naming the supported version — a v2 file
  can never be read with v1 semantics. `PolicyFile` carries both; dry-run
  prints `schema=… revision=…`.
- **Host policy as code**: `host_policy.load_host_policy` reads
  `northstar-policy.toml` (schema_version optional/v1, revision required,
  `[actors]` table) into a `HostPolicy`; unknown keys, unsupported schemas,
  bad revisions and unparseable actors are refused at load time. The file's
  `revision` is exactly what `authorize_run()` embeds in grants and the audit
  feed exports as `policy_revision` — decision → policy revision traceability
  end to end.
- Docs: runtime README config example gains the two keys; host README gains a
  "Policy as code" section; governance concept documents the versioned
  policy surfaces. API pages 49 → 51 modules.
  Tests: run-contract 34→41, host 28→37, runtime 515→522.

## Unreleased (seventh batch) — Python SDK embedding surface (T1)

- **Public event vocabulary** (`events.py`): `event_to_dict` shapes + result
  `EXIT_CODES` moved out of `cli.py` into one module shared by `--json`, the
  new SDK and anyone embedding the loop (CLI imports it; same output).
- **`sdk.py` — Python API**: `RunOptions` (governance knobs: permission mode,
  allow/deny, read-only, ceilings, halt-on-denial, session dir, subagents,
  provider), `run(options)` → `RunReport` (subtype, exit code, session id,
  turns, cost, denials, full event list), `stream_run(options)` → event dicts
  as they happen, and session `resume` with the CLI's same-session-id
  semantics. Workspace agent files register like the CLI does; `read_only`
  derives from tool kinds. Scripted provider default keeps it fully offline.
- **Example**: `examples/sdk/` — one run that gets a `Read` through and an
  unallowed `Write` refused at the gate (`python3 examples/sdk/run_sdk_demo.py`).
- Runtime README gains an "Embedding in Python (sdk)" section; layout table,
  `py-modules`, CI compile line and the docstring API manifest (43 → 49
  modules) all updated. Runtime tests 501 → 515.


## 0.1.0 — candidate, NOT yet released

The components are on aligned `0.1.0.dev0` and **no release has been cut**:
this repository releases only when it is ready, and the readiness gate
(`docs/guides/releasing-and-versioning.md` + `tests/test_release.py` +
`.github/workflows/release.yml`) refuses dev-suffixed or misaligned tags.
The batch notes below describe everything accumulated towards 0.1.0:
packaging and CLI engineering (P0/P1), AGENTS.md + policy config + skills +
subagents + MCP client (P2), four-layer documentation (P2-6), the canonical
NDJSON audit feed export (P3-1a), release engineering (T2) and the Python SDK
embedding surface (T1). The roadmap and scoring live in
`docs/dx-benchmark-2026.zh-CN.md`.

> The "Unreleased (first … sixth batch)" sections below are the historical
> batch notes accumulated towards **0.1.0** (P0/P1 through P3-1a + release
> engineering); none of it has shipped — see the readiness gate above.


## Unreleased (sixth batch) — audit export: JSON → NDJSON → SIEM (P3-1a)

- **Canonical audit feed `audit.ndjson/1`** in `northstar-run-contract`
  (`audit.py`): a strictly validated NDJSON envelope (`schema_version`,
  `component`, `event`, `ts`, `level`, `payload` + optional `seq` and
  correlation ids). Unknown envelope fields are rejected — extending the
  envelope is a schema revision, never a silent drift.
- **Runtime bridge** (`audit_export.py` + `cli sessions export`): replays one
  JSONL transcript to stdout as the audit feed. Denials, failed tool results
  and `error_*` results carry `"level":"error"`; `ts` is the record's original
  timestamp, never re-stamped. Mirrors the envelope locally: the runtime stays
  dependency-free.
- **Durable-run bridge** (`durable_audit.py`): every `EventStore` event maps
  into the feed with its identity preserved (`event_id`/`task_id`/`run_id`/
  `step_id`/`trace_id`/digest); failed/denied/error statuses raise the level to
  `error`.
- **Host bridge** (`host_audit.py`): verified authorization grants export as
  `authorization_grant` records (actor, run, workspace, capabilities, policy
  revision, expiry); tampered tokens stay verification errors, never records.
- SIEM shipping guidance and the normative envelope table live in
  `docs/concepts/audit-trail.md`; API pages regenerated (43 → 47 modules).
  Tests: run-contract 22→34, host 24→28, durable 59→65, runtime 488→501;
  repository total 701 → 736.

## Unreleased (fifth batch) — documentation in four layers (P2-6)

- **Per-component README link targets.** Every component README now opens with
  a `## Concepts, guides and API reference` section pointing to the
  cross-component concept pages, the guide pages and its own API page —
  quick start → concepts → guides → API reference, instead of one flat file.
- **Concept and guide pages** under `docs/concepts/` (governance, audit trail,
  handoff and contracts) and `docs/guides/` (governed-run cookbook, packaging
  and CI), each with accurate cross-links into the READMEs and API pages.
- **Docstring-generated API reference.** `tests/docbuild.py` (pure `ast`,
  stdlib-only and offline-safe — it never imports the modules it documents)
  renders `docs/api/<component>.md` for all six components (43 modules,
  committed). `python3 tests/docbuild.py build` regenerates; `verify` checks
  freshness byte-for-byte and that every internal markdown link resolves.
- **`examples/README.md` index page** covering every example recipe (demo,
  ci-readonly-review), with a "where to start" decision list.
- **CI documentation job = structure + build + links** (`test.yml`):
  structure unit tests plus a dedicated `python3 tests/docbuild.py verify`
  step. Repository documentation tests 3 → 8.

## Unreleased (fourth batch) — minimal MCP stdio client

- **MCP stdio client** (`northstar-agent-runtime`, experimental). `--mcp-server
  NAME=COMMAND...` (repeatable) connects one Model Context Protocol server as a
  child process speaking JSON-RPC 2.0 over stdio; `--mcp-timeout-ms` bounds each
  request. The handshake (`initialize` → `notifications/initialized` →
  `tools/list`) runs under the deadline, and a server that stops answering is
  TERM→KILLed as a process group (client-side line/call caps bound output).
- **Governed by default:** every remote tool registers as
  `mcp__<server>__<tool>` with `kind="other"`/mutating-by-default, so under the
  `default` permission mode it is denied until `--allow-tool` names it; policy
  files may deny `mcp__*` names ahead of connection (forward-looking, like
  `CodexReadOnly`); all calls still cross the gate and fire hooks. MCP is a
  tool transport, never a policy bypass.
- **Fail-closed CLI:** an unreachable server, a bad `NAME=`, a server that
  exceeds the tool/schema caps, or `--mcp-server` combined with `--agent` (an
  agent run's tool subset is fixed) are configuration errors (exit 64).
  `--dry-run` and `doctor` list configured servers without spawning them.
- Verified offline against `tests/fixtures/mcp_echo_server.py` (pure stdlib),
  including timeout, error-result, and process-group cleanup paths. Runtime
  tests 470 → 488.

## Unreleased (third batch) — repository agents and skills

- **Repository-defined subagents (`.northstar/agents/*.md`)**. A markdown file
  with strict frontmatter (`name`, `description`, `tools`, optional `read_only`,
  `permission_mode` limited to `default`/`plan`, ceilings no higher than the
  runtime's built-in limits, `model`, `allow_delegation`, `require_verdict`)
  and a prompt body compiles into the same `AgentDefinition` a built-in agent
  uses: runnable with `--agent`, delegatable through `Task` under the existing
  delegation gate, listed by `cli agents --workspace`. Names may not shadow a
  built-in agent or another file; `read_only` only narrows the tool set;
  unknown keys, unknown tools, loosening modes/ceilings, unparseable
  frontmatter, and symlinks escaping the workspace are configuration errors
  (exit 64) — never silently ignored. `--no-workspace-agents` skips discovery.
- **Agent Skills, read-only (`.northstar/skills/*/SKILL.md`)**. Progressive
  disclosure: only each skill's `name` and `description` enter the system
  prompt; the model reads the full file with the ordinary sandboxed `Read`
  tool when a task matches. Skill files are knowledge, not an execution or
  permission channel; everything resolves strictly inside the workspace root.
  `--no-skills` disables the listing.
- **Strict frontmatter reader** (`frontmatter.py`): a dependency-free subset of
  YAML frontmatter shared by both file types, with duplicate/malformed/unknown
  content failing closed.
- **Visibility:** `doctor` and `run --dry-run` report `workspace_agents=` and
  `skills=` lines; the demo workspace now ships one repository agent and one
  skill. Tests: runtime suite grows to 470 offline tests (24 new across
  frontmatter, skills, agent files, and CLI integration).

## Unreleased (second batch) — repository policy and project context

- **`.northstar/config.toml` workspace policy file** (`northstar-agent-runtime`).
  A repository that ships one pins the run's defaults; it may only ever
  *tighten*: `permission_mode` limited to `default`/`plan`, `allow_tools`
  rejected (approvals stay per-run CLI decisions), ceilings may only lower the
  built-in values, denials and `read_only` are an additive floor that even
  `--allow-tool` cannot resurrect, and file denials stay terminal in the
  permission gate's first layer. Unknown keys, unreadable TOML, unknown tool
  or agent names, and loosening values are configuration errors (exit 64) —
  policy is never silently ignored. When both the file and the CLI set a
  ceiling, the lower wins; `halt_on_denial` is true if either says so;
  `--no-policy-file` skips the file for one run.
- **Project context (`AGENTS.md`)**. A `AGENTS.md` in the workspace root (or the
  file named by the policy's `project_context`, or an explicit `--context-file`)
  is appended to the system prompt behind a clear delimiter. Discovery resolves
  strictly inside the workspace root — a symlink pointing out is refused, never
  followed — and oversized files are truncated with a marker.
  `--no-project-context` disables discovery.
- **Visibility:** `cli doctor` and `run --dry-run` report the effective
  `policy_file=` and `project_context=` inputs before anything is sent; a
  policy error fails a dry run exactly as it fails a real run.
- **Demo:** `examples/demo/workspace/` now carries an `AGENTS.md` showing the
  convention. Tests: 446 offline runtime tests green; the tighten-only limits
  are asserted to stay in sync with the loop's built-in defaults.

## Unreleased — DX foundations: installable packages, CLI self-checks, session read-back

Phase 0–1 of the DX roadmap (see `docs/dx-benchmark-2026.zh-CN.md` for the full
analysis and remaining phases). Everything below is additive; no runtime
semantics changed.

- **All six components are pip-installable.** Each `components/*/pyproject.toml`
  declares `version = "0.1.0.dev0"`, real dependencies, and flat-module layouts
  that match the existing in-tree names. The agent runtime additionally ships a
  `northstar-agent-runtime` console script with lazy SDK imports (`[anthropic]`,
  `[tracing]`, `[full]` extras; no hard dependency).
- **The `tools.py` / `tools/` name collision is gone.** The module moved into
  `tools/__init__.py`, so `import tools` and `import tools.verify_invariants`
  both resolve; the guard-verification harness now mutates
  `tools/__init__.py` and runs in CI.
- **Dependencies are declared, not spliced.** `northstar-host` depends on
  `northstar-run-contract`; `northstar-durable-run` and `northstar-agent-interop`
  depend on both. All `PYTHONPATH=` prefixes are gone from CI and the Makefile
  (the test modules bootstrap sibling paths themselves); CI installs by
  dependency chain and runs a packaging smoke per component; `make install`
  builds one virtualenv with every component.
- **New CLI surface (`python3 -m cli`):** `--version` (single source
  `_version.py`), `doctor` (side-effect-free environment self-check; fails on
  broken checks, warns on missing optional SDKs), `run --dry-run` (prints the
  resolved tools/allow-deny/ceilings/pricing and exits without constructing the
  provider or sending a request), and `sessions list|show [--json]` (read-only
  read-back of the append-only audit transcripts). `--probe-sidecar` with the
  live provider now explains how to install the missing SDK instead of
  tracebacking.
- **One-line offline demo:** `make demo` (or `sh examples/demo/run_offline.sh`)
  runs a full governed loop with a tool call, policy, ceilings, and an audit
  transcript — no API key, no network, no SDK.
- **CI-only read-only review recipe:** `examples/ci-readonly-review/` — governed
  PR review with `--read-only`, turn and dollar ceilings, `--halt-on-denial`,
  and a session transcript kept outside the reviewed workspace; includes a
  GitHub Actions template and the exit-code contract.
- **Releasing guide** added to `CONTRIBUTING.md` (dependency-graph release
  order, immutable tags, semantic majors for contract components).
- Tests: 621 offline tests green across the repository (agent runtime 413,
  including 4 skipped where the SDK is absent); the five-guard invariant
  harness turns each reverted guard red and keeps the untouched copy green.


This repository establishes the Northstar Agent OS name and publishes five independently maintained components: Northstar Codex Sidecar, the Northstar Run Contract, the Northstar Agent Runtime, host-side candidates, and backend-neutral Agent Interop foundations.

## Agent Runtime (unreleased)

- **Governed agent loop with the Claude Agent SDK capability surface:** `SystemMessage` / `AssistantMessage` / `UserMessage` events and exactly one `ResultMessage` per run, whose subtype distinguishes `success` from `error_max_turns`, `error_max_tool_calls`, `error_max_budget_usd`, `error_permission_denied`, and `error_during_execution`. Every foreseeable condition is an event; a foreseeable failure never reaches the caller as an exception.
- **Reasoning here, execution there:** the runtime holds no Codex credentials and never spawns a model CLI. The `CodexReadOnly` tool is registered only when a sidecar socket path is supplied, and one request travels over one private Unix-socket connection to `components/northstar-codex-sidecar`.
- **Ten lifecycle hooks** with a uniform handler signature: `PreToolUse` (veto or rewrite input), `PostToolUse`, `PostToolUseFailure`, `UserPromptSubmit`, `Stop` (may refuse to stop and feed its reason back), `SubagentStart`, `SubagentStop`, `PreCompact`, `SessionStart`, `SessionEnd`. A deny is terminal — later hooks cannot overturn it — and a hook that raises on a veto-capable event fails closed.
- **Three permission layers in a fixed order:** `disallowed_tools` always wins, then `allowed_tools`, then `permission_mode` plus the optional host `can_use_tool` callback. Under `default`, a mutating tool with no approval callback is denied rather than executed.
- **Three independent ceilings** (`max_turns`, `max_tool_calls`, `max_budget_usd`), priced from real per-million-token rates including cache-read 0.1× and cache-write 1.25×; an unknown model falls back to conservative pricing and marks `pricing_estimated`.
- **Subagents** with their own context, declared tool subset, ceilings, and optionally a different provider. Delegation is gated per tool the subagent declared, never by the literal name `Task`; nested delegation is off by default with `max_subagent_depth` as a backstop. The built-in `evaluator_agent()` is read-only and default-FAIL.
- **Append-only JSONL sessions** with an `fsync` per write, `0600` files under a `0700` directory, and a truncated final line skipped rather than treated as corruption. A session id is generated even when nothing is persisted.
- **Compaction that only cuts at a safe boundary** with no pending tool call, so a summary can never orphan a `tool_use` from its `tool_result` and produce an API 400 the model cannot recover from.
- **Span tracing** as `run → turn[n] → generation | tool:Name | subagent:Type` with cost attributes, recording usage before the span ends (OpenTelemetry discards a late attribute write silently) and never recording prompt text or tool output bodies.
- **Sandboxed tools** with symlink-resolution-before-containment-check, plus caps of 256 KB per `Read`, 200 matches per `Grep`, and 500 entries per `LS`, each announced in the tool result itself.
- **383 offline tests**, including an integration test that starts the real sidecar `serve()` on a temporary Unix socket and pushes a 100,000-Chinese-character prompt through a full agent loop. Each core invariant has been verified to fail when its guard is individually reverted.
- **Known gaps:** the live Anthropic API is unverified in this repository's sandbox (only an injected fake client is exercised), MCP is not implemented, and process-group `TERM`→`KILL` cleanup is not verified on real Linux here. See `components/northstar-agent-runtime/README.md`.

## Run Contract foundation

- **Versioned Run Request:** strict schema, bounded IDs and prompt, timeout limits, task-kind allowlist, and requested-capability syntax.
- **Versioned Run Receipt:** explicit statuses and postcondition verdicts (`verified`, `failed`, `unknown`).
- **Authenticated Run Binding:** expiring HMAC-SHA256 binding for `run_id`, `actor_id`, and `workspace_id`; host-key possession is kept separate from authorization.
- **Strict Sidecar adapter:** only `request_id`, `prompt`, and `timeout_ms` cross the legacy Sidecar boundary; unknown fields and unverified bindings are rejected.

The contract is a local foundation, not a production authorization or workspace broker. Native Linux deployment, caller identity, per-run workspace creation, and policy grants remain separate host-level responsibilities.

## Fixes since the initial component

- **`CODEX_HOME` is no longer double-nested under systemd.** The unit set `CODEX_HOME=/var/lib/northstar-codex/codex-home` while the sidecar appended a second `/codex-home`, so Codex looked for credentials in a directory the host never populated. `CODEX_HOME` is now passed to the child verbatim, and the workspace default is decoupled from it so run inputs and credentials never share a directory. Tests assert the unit's `Environment=` lines against `service.service_config()`.
- **A maximum-length prompt is no longer rejected by framing.** The socket reader capped input at 200,000 bytes while the validator capped the prompt at 100,000 characters, so a 100,000-character CJK prompt (300,054 bytes raw, 600,182 bytes as `\uXXXX` escapes) came back as `invalid or oversized request`. The wire cap is now derived from the prompt cap and covers both serialisations.
- **`serve()` enforces the socket path contract.** `service.validate_socket_path` was previously asserted only in tests; the listener now refuses to bind any path it rejects, and does so before creating a socket file.
- **`install.sh` produces a startable service.** It now requires root, creates the `northstar-codex` system account and the `/var/lib/northstar-codex` state directories, normalises `PATH` so the sbin account tools are found, warns when `codex` is absent, and is idempotent. Both lifecycle scripts are now mode `0755` so the documented `sudo ./install.sh` works from a fresh clone.

## Host-side local candidates

- **Host authorization and workspace candidate:** `components/northstar-host/`
  adds explicit actor-to-capability default-deny policy grants and
  host-derived opaque `0700` workspace allocation. It re-verifies the Run
  Binding and grant at allocation time and never executes commands.
- **Durable Run vertical slice:** `components/northstar-durable-run/` adds a
  local candidate for canonical task/run/step/event identity, append-only
  replayable history, checkpoints, leases, per-call action gates, independent
  postcondition verification, minimal trace metrics, and a deterministic
  10-fixture task-level evaluation harness. Its local suite proves component
  and fixture behavior only; it is not a production scheduler, sandbox, or
  deployment.

These candidates are local-only and have not been deployed to 103, 104, a
dormitory host, or production OpenBot. They are not a complete workspace
broker, sandbox, identity system, or production safety proof. Native Linux
concurrency, filesystem race, lifecycle, and deployment validation remain
outstanding.

- **Agent interoperability candidate:** `components/northstar-agent-interop/`
  adds a backend-neutral signed attestation, narrowed handoff grant, context
  envelope, typed adapter receipt boundary, and a local-only
  `orchestrator → Claude Code → Codex → Hermes` canary. The canary uses fake
  executors only and does not connect real vendor backends.
- **CLI process adapter candidate:** the interop component includes a bounded,
  no-shell process adapter and disabled-by-default specifications for Codex,
  Claude Code, and Cursor. No vendor CLI is installed or authenticated here.

## Scope of this release

- restricted Unix-socket transport;
- bounded request validation;
- read-only, ephemeral Codex execution;
- structured errors and redaction;
- process-group timeout cleanup;
- systemd hardening template;
- deterministic Python tests.

## Explicit non-goals

This is not yet a complete multi-agent operating system, hosted service, or
endorsement of the upstream OpenBot project. Runtime identity binding, per-run
workspace authorization, durable execution integration, native Linux E2E, and
production deployment integration remain host-level responsibilities or future
work.

See [README.md](README.md) for installation and security boundaries.

