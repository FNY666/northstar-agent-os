# Northstar Agent OS — initial public component

## Unreleased (seventeenth batch) — streaming that cannot disagree with the record

The blueprint's last user-visible gap. Every serious agent tool streams; Northstar
could not have claimed the "governed" position while its output arrived only at the end
of a turn. The interesting part was never the printing.

- **The provider contract gained a second entry point.** `Provider.stream()` yields text
  chunks then exactly one `Generation`; `generate()` is unchanged, so every existing
  adapter, test and embedding keeps working, and the default `stream()` (whole turn, no
  chunks) is a safe fallback for a *direct* caller - but not for a run: `streams = True`
  without real chunks is caught, so the flag cannot be a marketing claim.
- **Fidelity is enforced by the runtime, not promised by the provider.** `"".join(deltas)`
  must equal the text of the **assembled** message - deliberately compared against the
  record rather than against the provider's own object, since the record is what a
  checkpoint digest and a later reader are verified against. Disagreement in either
  direction (`the stream carried N char(s) the turn does not contain`, `the stream stopped
  N char(s) short`) fails the turn as `error_during_execution` and writes **no
  `AssistantMessage`**: a run cannot end with a verdict on a turn nobody can describe.
- **What the client caps, the client admits.** Per-turn ceilings (200 000 chars, 4 000
  events - "one event per character" is legal at the protocol level and would otherwise let
  a provider size this process's event stream), oversized chunks are re-split rather than
  dropped, and when text is withheld the live view is required to be a *prefix* of the
  record plus an `informational` event saying how much was held back. Shorter is allowed;
  different is not.
- **The transcript is untouched, on purpose.** Deltas are events, not records: `RECORD_TYPES`
  stays at 13, so checkpoint digests, `--resume-from` and the session panel mean exactly
  what they meant before streaming existed, and a resumed run has nothing to replay. A test
  asserts the records are byte-identical with and without `--stream`, with the single
  tolerated difference being the `stream` declaration in the init record.
- **What never streams:** partial `tool_use` arguments (a half-received
  `{"path": "/etc/pass` must not be displayable, executable, or hashable), `thinking` /
  `reasoning_content` (an unsigned Anthropic block is not yet legitimate text, and chat-side
  reasoning has no place in the transcript), and delegated turns - streaming is a property of
  the operator's terminal, not of the delegation chain, so a subagent on a provider that
  cannot stream still runs.
- **Adapters**: `anthropic` forwards `messages.stream`'s text deltas and normalises from
  `get_final_message()`; `openai` reassembles SSE `delta.content` into the *same*
  `choices[0].message` shape a non-streaming call would have carried and then reuses
  `normalise()`, so truncated `arguments` still fail closed instead of becoming an empty
  write, and `stream_options.include_usage` keeps cost attached to the turn (with
  `stream_usage=False` as the operator's explicit opt-out for gateways that reject the
  field, because a run reporting `$0.000000` silently is worse than one that says so).
- `scripted` gained `"stream": ["chunk", …]` so chunking is under test rather than incidental,
  and `RunOptions.stream` keeps the SDK at parity: `stream_run()` yields the extra
  `stream_delta` dicts, `run()` reports the same numbers either way.

45 new tests (855 in the runtime, 1149 in the repository), all offline and
credential-free. Honest limits: both live adapters are verified against injected fakes,
not against a network; a gateway that accepts `stream` but never sets `finish_reason`, or
that puts text in a field we do not model, will fail the fidelity check rather than
silently under-report - that is the intended direction of failure, but it is a direction
nobody has exercised against a real vendor.

## Unreleased (sixteenth batch) — MCP grows a second generation, and a remote question becomes an approval

The blueprint's first P1 row. The 2026-07-28 Model Context Protocol revision deleted the
handshake: there is no session id any more, version and capabilities ride in
`params._meta` on every request, servers may no longer initiate JSON-RPC requests, and
`elicitation/create` / `sampling/createMessage` / `roots/list` became **Multi Round-Trip
Requests** — a server answers a tool call with `resultType: "input_required"` and waits
for the client to retry. That last part is the one that matters here: it is a permission
request arriving over a socket, and every other agent tool on the market treats it as a UI
detail. Northstar treats it as a gate.

- **`mcp_negotiate.py`: the generation rules as pure functions.** `server/discover` is
  probed first; a reply means modern, a `-32022` means modern *and* names the versions to
  adopt (only a modern server can produce that code), and anything else — method-not-found,
  garbage, a dead process — falls back to the `initialize` handshake. Never a guessed
  version: with nothing mutual in common the client reports the server's own list instead
  of trying a favourite date. `auto` is the default; `--mcp-protocol legacy|modern` pins it,
  and the reason is printed to stderr so a CI log records which dialect was used. Era is a
  property of the server process, decided once.
- **`_meta` everywhere on modern, nowhere on legacy.** The probe carries it too — a client
  that asked "are you modern?" without declaring a version would be asking in a language
  only modern servers read. Legacy payloads get no extra keys, because unknown keys are how
  a strict 2024 server ends a conversation.
- **`mcp_elicitation.py`: what may be answered.** `elicitation` is advertised as a
  capability **only when an approver is attached**, so an unattended run is never asked
  (per spec a server must not send what the client did not declare) rather than asked and
  defaulted. `sampling/createMessage` is always declined — a remote tool does not get to
  run our model on a prompt we did not write. `roots/list` is declined unless
  `--mcp-allow-roots`, and then answered with exactly one root, the workspace. A field named
  like a credential is refused before a human sees it, unless `--mcp-allow-sensitive-input`.
  Schemas are bounded (16 fields, depth 3, 8 KB), and an answer that includes a field the
  server never asked for is rejected: volunteering data to a remote process is not a client's
  job.
- **The retry is a real retry.** `--mcp-elicit-answers '{"approved": true}'` is an approval
  granted *in advance*, and coverage is strict: a server that adds a required field gets a
  refusal, not a guess. `--mcp-elicit` without it prompts on a terminal and refuses to start
  when stdin is not a tty. The retry is a **new JSON-RPC request** carrying `inputResponses`
  plus the server's opaque `requestState` verbatim — the client never inspects it — and
  `--mcp-max-rounds` (default 3) bounds how long a server may re-ask. When a round contains
  nothing but refusals the in-flight call is cancelled with `notifications/cancelled`:
  declining is final, not a negotiation.
- **Audited, values excluded.** Each verdict is
  `{kind, server, tool, method, action, reason, answered_fields}` in
  `client.elicitation_log` and the `audit=` callback, and a `[governance] …` line rides
  inside the tool result so the model and the transcript both see that a server tried to ask
  and what became of it. Answer *values* are never recorded.
- **A new fixture speaks only the modern generation** (`mcp_mrtr_server.py`), with
  switchable modes for the `-32022` retry, method-not-found, an `input_required` with nothing
  to answer, and a server that re-asks forever — and it logs every inbound byte so tests
  assert on the wire, not on the client's self-report. 67 new tests; the legacy fixture is
  unchanged and still passes, which is the point of the fallback.
- **Docs debt closed**: `docbuild` now covers `checkpoints`, `postconditions`,
  `contract_bridge`, `command_hooks`, `skill_audit`, `skill_check`, the two new MCP modules,
  `providers.openai_compat` and `tools.verify_invariants` — modules that shipped in earlier
  batches without ever reaching the generated API page.

Honest limits: "conformant" here means matching the published grammar, verified against our
own fixture — **no vendor MCP server has been exercised in this sandbox**. There is no HTTP
transport (the era rules and MRTR are transport-agnostic; only framing differs), no
prompts/resources UI, and no task extension.

## Unreleased (fifteenth batch) — the skill supply chain gets a gate

`skills check`, the highest-leverage row left in the blueprint's debt table: the Agent
Skills standard fixed the file format and left review out, and 2026's surveys of
third-party skill collections found instruction-override phrasing and
install-the-world instructions widely.

- **`skill_audit.py`: rules as pure functions of the bytes.** No model call, no
  network, no classifier - so it cannot be prompted out of existence by the file under
  review, and the suite proves it. Rule families: instruction override, concealment
  ("do not tell the user"), role hijack, **policy self-edit / disabling controls**
  (CBSE), remote script piped to a shell, host privilege, instance-metadata
  endpoints, credential stores, environment-value exfiltration (both word orders),
  installers, inline `eval`/`python -c`, tunnelling, outbound POSTs, invisible
  unicode (zero-width, bidi, tag chars), and the context-bloat limits the spec
  implies (description length, body lines, body size). `RULES_VERSION` is recorded in
  every lockfile, because "no findings" under an older rule set is not a pass.
- **One deliberate demotion.** A command inside a fenced code block is an example,
  not an instruction, so it is reported one level lower with a note - which is what
  keeps the tool usable on real documentation instead of drowning in `pip install`.
  Invisible-character findings never demote: invisibility is identical inside code.
- **Reviewed means pinned.** `--write-lock` writes `.northstar/skills.lock` (content
  digest per skill path + name + size + finding count); `check_lock` reports
  `stale`/`added`/`removed`, and `run --require-skill-lock` refuses to start on any of
  them (exit 64). Pins bind the path *and* the bytes, so a rename cannot borrow
  another skill's review. `doctor` gained a `skills-review` check (warn, never fails
  a host).
- **The gate is outside the model's reach.** `skills.lock` sits under `.northstar`,
  which the tool layer already refuses to write, so a run cannot mark its own skills
  reviewed - tested end to end, including that the refusal is a tool error rather
  than a permission denial.
- **Foreign trees are auditable before adoption**: `--root DIR` reads
  `.northstar/skills`, `.claude/skills` and `.agents/skills`, since the standard does
  not fix an install path.
- **Scaffold closes the loop**: `cli new` now writes `.northstar/skills/README.md`
  (where skills go, what the frontmatter may say, how trust is earned) and the CI
  recipe runs `skills check` before the reviewer, so a fresh project gates skill
  drift by default. `[[verify]]` is documented in the generated config too.

Runtime 686 → 734 tests, repository 1028, all offline and credential-free. **No
release**: version stays `0.1.0.dev0`, no tag, no index upload.

## Unreleased (fourteenth batch, continued) — resumable turn boundaries (F3)

- **`checkpoints.py` + `--checkpoint-turns` / `--resume-from`.** A turn boundary can
  now be recorded (transcript length, digest of that exact prefix, consumed
  turns/tool calls/cost) and resumed from. This closed a real hole, not just an
  inconvenience: ceilings were per-run and `--resume` started a new run, so resuming
  a session that had spent $4.90 of a $5 budget handed it $5 again — resume was an
  escape hatch around `max_budget_usd`. A resumed run now *inherits* the spend, the
  turn number (so `max_turns` bounds the lineage, not the process) and the tool-call
  count; an embedder who forgets to seed the `Budget` gets a configuration error
  instead of a wider ceiling.
- **Fork-on-read, never rewind-in-place.** `--resume-from` writes a new session file
  whose `session_start` names the parent and the checkpoint; the parent transcript is
  never modified, and a digest mismatch at the cut refuses the run rather than
  attributing numbers to the wrong history. `--resume` keeps the old append-in-place
  behaviour, and the two flags are mutually exclusive because they disagree about the
  parent file. A `--checkpoint-turns` value that could never fire is refused: a
  cadence that writes no records would leave the operator believing the run was
  resumable.
- Protocol addition: 13th session record type `checkpoint` (panel renders it), still
  opt-in so no transcript changes shape unless asked. SDK parity via
  `RunOptions.checkpoint_turns` / `resume_from`. Runtime 660 → 683 tests; repository
  977, all offline.

## Unreleased (fourteenth batch) — many models, and a verdict that is not the model's

Continued the blueprint's non-conflicting debt (`docs/next-gen-agent-blueprint.zh-CN.md`
§6). Three changes, still offline and credential-free; **no release is made**, no tag
is pushed, the version stays `0.1.0.dev0`.

- **P1-2 multi-model, one door.** New `providers/openai_compat.py` speaks the Chat
  Completions wire, so a single adapter brings the OpenAI / Azure / vLLM / SGLang /
  Ollama / LM Studio / LiteLLM / OpenRouter universe into the governed loop instead
  of requiring a per-vendor harness. It translates both directions per call
  (`tool_use` -> `tool_calls` with JSON-encoded `arguments`, `tool_result` ->
  `role: "tool"` + `tool_call_id`, `finish_reason` -> the runtime's stop
  vocabulary, `prompt_tokens_details.cached_tokens` -> `cache_read_input_tokens`),
  drops `thinking` from the *request* while keeping it in the transcript, picks
  `max_completion_tokens` for reasoning-era model ids, fails the turn on
  non-JSON `arguments` rather than running a truncated call as a real write, and
  never invents a price: unknown ids stay on the conservative tier with
  `pricing_estimated: true`. `--provider openai` reads `OPENAI_API_KEY` /
  `OPENAI_BASE_URL` from the environment only (a flag would leak via `ps` and CI
  logs), and `--model` is validated against `--provider` before a credential is
  touched, so an impossible pair exits `64` instead of 400-ing at a server.
  `doctor` now reports the SDK the *selected* provider needs, not every SDK that
  exists.
- **Independent completion verification (blueprint §4 #4).** New
  `postconditions.py`: `--verify KIND:PATH[:TEXT]` and `[[verify]]` declare claims
  about the workspace (`exists`, `absent`, `changed`, `unchanged`, `contains`) that
  the runtime checks after the run, so *the agent saying it finished* stops being
  the evidence that it did. The design constraints that make it governance: the
  conditions are **never injected into the prompt** (a model told what is checked
  optimises the check, and `contains` is the easiest string to write), digests are
  snapshotted before the first event, evaluation only reads, symlinks and paths
  that resolve outside the workspace are refused at configuration time, and a
  repository may add a check but can never remove or weaken the operator's. Two
  protocol additions, each with its own tests: result subtype
  `error_postconditions_failed` (exit `6`) and session record type
  `postconditions`, so the verdict is a first-class audit record that
  `examples/session-panel` renders rather than a line of prose.
- **Drift guards.** `tests/test_module_layout.py` now asserts every top-level
  module is listed in `pyproject.toml`'s `py-modules` (an unpackaged module works in
  the checkout and vanishes after `pip install .`), and the session-panel record
  vocabulary test caught the new `RECORD_TYPES` entry the way it is meant to.

Runtime tests 596 -> 660; repository total 890 -> 954, all offline, no API key.
Verified by hand: the same claim ("全部检查通过") with `report.md` absent exits `6`,
and exits `0` once a `Write` actually creates it, with `unchanged:keep.txt` still
holding across the run.

**Not in this batch**: turn-boundary checkpoints and fork-on-read resume (blueprint
F3) remain open — the transcript is append-only and resumable, but a run still
restarts from the beginning rather than from a checkpoint.

## Unreleased (thirteenth batch) — closing the governance seams (P0)

Acted on the 2026-09-08 capability audit (`docs/benchmark-top-agents-2026-09.zh-CN.md`
F1/F2, plus the new `docs/next-gen-agent-blueprint.zh-CN.md` decision on absorbing
top-tier features only in a governed form). Four changes, all offline-testable,
none of which loosens a guardrail; **no release is made** and no tag is pushed.

- **P0-1 the Run Contract is now on the execution path.** New
  `contract_bridge.py` is the single definition of the runtime -> sidecar wire
  format (the runtime previously kept a second copy), `--run-id` becomes the
  sidecar `request_id` so the runtime transcript and the sidecar log share one
  correlation key, and `policy_revision`/`run_id`/`protected_prefixes` are
  recorded in the `init` event (so the transcript and the `sessions export` audit
  feed carry them). When a host injects `NORTHSTAR_RUN_BINDING` +
  `NORTHSTAR_HOST_KEY` + `NORTHSTAR_RUN_REQUEST`, the client re-derives its own
  request through `validate_run_request -> verify_binding -> to_sidecar_request`
  and **refuses the call** on any mismatch, expiry, or inability to verify - fail
  closed, never a silent downgrade. With no binding configured the bridge is
  inert, so the runtime keeps its zero-dependency, bare-interpreter property.
  The sidecar itself still authenticates by Unix permissions only: putting the
  binding on the wire means changing its strict request allowlist, which is left
  as an explicit protocol decision rather than taken here.
- **P0-2 an agent can no longer rewrite its own governance.** `ToolLimits.protected_prefixes`
  defaults to `(".git", ".northstar")`: `Write`/`Edit` refuse the policy file, the
  repository agent definitions, and the skill packages. Measured before the change:
  a run under `--permission-mode acceptEdits` replaced its own
  `.northstar/config.toml` (and the next run inherited it). Escalation was bounded -
  a policy file may only tighten, so `bypassPermissions` fails closed - so this is
  about silent policy drift, poisoned instructions, and self-DoS, not privilege gain.
  `--allow-policy-writes` opens the tree for one run when a human means it, and the
  effective set is auditable in the `init` event.
- **P0-3 repository-declared lifecycle hooks** (`[[hooks]]` in the policy file),
  the governed subset of a "command hook": veto-capable events only, no `command`
  key and no shell at all, workspace-contained script resolved symlink-first,
  interpreter allowlist, bounded output and a TERM->KILL process-group cleanup,
  a scrubbed child environment (model credentials never cross into hook code), and
  **off unless `--enable-workspace-hooks` is passed** - cloning a repository must
  not mean executing it. A timeout, crash, or unparseable verdict on a veto event
  is a denial.
- **P0-4 drift is visible before the run.** `doctor` gains `policy-drift` (disk
  policy digest vs `git HEAD`, warn, never blocking) and a warn for declared-but-
  disabled hooks; `--dry-run` prints `run_id`, `policy_revision`, and the
  effective `protected_prefixes`.

Tests 830 -> **890** (runtime 536 -> 596: `test_contract_bridge` 18 including the
three-way runtime/adapter/sidecar field agreement, `test_governance_writes` 12,
`test_command_hooks` 30). The three real-subprocess hook tests were mutation-checked:
leaking the API key into the child environment turns one red, removing the timeout
turns another slow-and-red. `pyproject.toml` ships both new modules; the generated
API pages were regenerated for the doc-freshness test. `0.1.0.dev0` unchanged.

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

