# Agent runtime landscape review — 2026-10-12

This is a focused review of public primary sources and active project documentation. It is
not a claim to have exhaustively searched private forums, chat groups, or every repository.
The question is which design ideas strengthen Northstar's runtime guarantees, not which
framework has the longest feature list.

## Findings that affect Northstar

| Source | Useful signal | Northstar implication |
| --- | --- | --- |
| [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), the [Agentic Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/), and its [Securing Agentic Applications Guide](https://genai.owasp.org/download/49059/?tmstv=1753666640) | OWASP's current agent-specific taxonomy covers goal hijack, tool misuse, identity/privilege abuse, memory and context poisoning, rogue agents, and other autonomous-system risks. | Map Northstar threat cases to the 2026 taxonomy, while preserving evidence that a control intercepted a real transition instead of merely identifying risky text. |
| [Anthropic sandbox-runtime](https://github.com/anthropics/sandbox-runtime) | Uses OS sandbox primitives and network filtering to constrain arbitrary child processes. Its documentation explicitly treats the project as an early research preview and documents cases where restrictions can be escaped through launching another application. | Northstar's process-level policy and rlimits should remain honestly described as weaker than OS-backed isolation. Expand capability probes and report the selected backend and its limits; never turn backend absence into a successful isolation claim. |
| [OpenAI Agents SDK tool guardrails](https://openai.github.io/openai-agents-python/guardrails/) | Tool-level checks run around each guarded tool invocation; agent input/output checks have narrower workflow scope. The docs also call out handoffs and hosted tools that do not share the same guardrail pipeline. | Maintain per-dispatch authorization and validation instead of relying on prompt- or run-level screening. Add explicit tests for every transition that bypasses ordinary tool dispatch, especially handoff/delegation and plugin/MCP adapters. |
| [OpenAI Agents SDK tracing](https://openai.github.io/openai-agents-python/tracing/) | Traces include generations, tool calls, handoffs, guardrails, and custom events, and the docs expose a switch for sensitive data inclusion. | Preserve Northstar's local audit evidence while treating prompts and tool payloads as sensitive by default. Any future exporter needs explicit redaction, destination, and retention policy. |
| [LangGraph persistence](https://langchain-ai.github.io/langgraph/concepts/durable_execution/) | Separates thread-scoped checkpoints from cross-thread stores and uses persistence for resume, human review, fault tolerance, and time travel. | Keep run/session recovery distinct from durable user memory. Resume data must be validated and integrity checked before it re-enters provider context; replay should preserve original tool result provenance. |
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) | ETH Zurich / Invariant Labs provide a dynamic benchmark environment for attacks and defenses against tool-using agents, with tasks, attacks, and defenses rather than isolated classifier examples. | Add a benchmark adapter or importable corpus so Northstar can measure both task completion and injection resistance against a recognized environment. Pin benchmark revision and clearly separate harness-owned controls from model behavior. |
| [AgentDojo issue #168](https://github.com/ethz-spylab/agentdojo/issues/168) | A public benchmark discussion reports a scorer treating proposed tool calls as executed state transitions, which can score a blocking defense as an attack success. The issue includes a reproduction and a maintainer's later confirmation that trace proposal and execution are not interchangeable. | When importing third-party benchmarks, score from execution receipts or final state and keep attempted, authorized, denied, and executed actions as separate fields. Northstar's derived AgentDojo corpus is explicitly a deterministic gate-decision metric, not a live model execution score. |
| [Indirect Prompt Injections: Are Firewalls All You Need, or Stronger Benchmarks?](https://arxiv.org/abs/2510.05244) | The paper reports strong utility/security results from paired tool-input and tool-output firewalls on four public benchmarks, but also demonstrates practical bypasses and identifies weak attacks and flawed metrics in existing benchmarks. | Preserve the architectural boundary at tool dispatch and execution; do not treat text classifiers or existing benchmark passes as proof of resistance. Add adaptive, multi-turn attacks and require state-transition receipts in scoring. |
| [Large-Scale Public Competition on Indirect Prompt Injections](https://arxiv.org/abs/2603.15714) | The study explicitly measures concealment: an agent can execute a harmful action while its final answer gives the user no sign of compromise. It reports successful attacks across tool-calling, coding, and computer-use settings. | Score user-visible awareness separately from policy interception and task utility. A blocked proposal, an executed harmful action, and a misleadingly clean final answer are three different outcomes. |
| [UK AI Security Institute Inspect Evals](https://github.com/UKGovernmentBEIS/inspect_evals/blob/main/CHANGELOG.md) | Its changelog records an AgentThreatBench suite mapped to OWASP 2026, covering memory poisoning, autonomy hijacking, and data exfiltration. | Northstar has an offline adapter for these task families; keep its heuristic scope distinct from official scores and preserve attempted-vs-executed evidence. |

### AgentThreatBench follow-up (2026-10-12)

The current Inspect Evals registry exposes three self-contained tasks: memory poisoning (ASI06), autonomy hijacking through inbox output (ASI01), and data exfiltration through customer lookup output (ASI01). The task module scores utility and security separately. Its scorer gathers assistant `tool_calls` from the conversation and checks those calls; it does not consume a host-side execution receipt. That works for its own Inspect tool loop, but a Northstar adapter must not treat a proposed or policy-denied call as a completed state transition. The benchmark's own open-source task definitions and scorer are at [`agent_threat_bench.py`](https://github.com/UKGovernmentBEIS/inspect_evals/blob/main/src/inspect_evals/agent_threat_bench/agent_threat_bench.py), [`dataset.py`](https://github.com/UKGovernmentBEIS/inspect_evals/blob/main/src/inspect_evals/agent_threat_bench/dataset.py), and [`scorer.py`](https://github.com/UKGovernmentBEIS/inspect_evals/blob/main/src/inspect_evals/agent_threat_bench/scorer.py).

**Northstar integration rule**: preserve the benchmark's paired utility/security dimensions, but score mutating state only from Northstar execution reports or audit receipts. Keep proposed, denied, failed, and completed calls distinct. Pin the upstream revision, retain its attribution/license, and report model-level results separately from deterministic gate results. No upstream dataset or prompts are copied into this repository. The implemented adapter is described in [`docs/third-party/agent-threat-bench.md`](../third-party/agent-threat-bench.md); missing or malformed execution evidence yields an inconclusive outcome.

### AgentDojo scorer issues from the public maintainer tracker (2026-10-12)

Two public AgentDojo issues illustrate why benchmark adapters need both action proposals and execution evidence. Issue [#189](https://github.com/ethz-spylab/agentdojo/issues/189) reports a narrow v1 case where a trace-based scorer counted proposed Slack actions even when a boundary defense refused all of them; the reporter scoped it to 21 of 629 task/injection pairs. GitHub shows the issue closed as completed, but the issue report is not an independent reproduction or evidence that all AgentDojo tasks share the problem. Issue [#188](https://github.com/ethz-spylab/agentdojo/issues/188) reports a utility scorer indexing absent post-state after a refused `post_webpage`, causing evaluation to raise instead of recording task failure; a contributor said they would fix it, while the issue remained open when checked. These are maintainer-tracker reports, not claims about current benchmark-wide accuracy.

Northstar's adapter therefore keeps attempted calls separate from completed/possibly-partial effects, returns `inconclusive` when receipts are missing or malformed, and scores utility independently from security. The adapter consumes Northstar SDK events for AgentThreatBench; this does not make it a direct AgentDojo integration or establish comparable leaderboard scores. Its input traversal now also has explicit byte, node, and depth bounds, so malformed or oversized traces become inconclusive rather than exhausting the evaluator process.

### Detection metrics and product benchmarks (2026-10-12)

The open [AgentDojo issue #160](https://github.com/ethz-spylab/agentdojo/issues/160) proposes an opt-in, `flag_only` evaluator for content-layer detection, with detection and bypass metrics separate from AgentDojo's utility/security outcomes. The proposal is not an accepted or implemented AgentDojo feature, and its author explicitly describes regex evasion limits. Its useful design signal is measurement separation: a detector firing is evidence that a rule matched, not evidence that the action was prevented or that the task remained useful.

The [Open Agent Security Benchmark (OASB)](https://github.com/opena2a-org/oasb) describes a product-agnostic adapter contract and distinguishes security-product detection tests from active agent pentesting. Its README currently claims 223 scenarios, with ATLAS-mapped attacks and a separate set of defensive/capability checks; those counts and results are upstream project claims, not independently reproduced Northstar results. The repository advertises Apache-2.0, so Northstar should not vendor its scenarios without a separate license review. The transferable architecture is a capability-declaring adapter that reports unsupported surfaces as N/A, then records detector signal separately from enforcement and task outcome. Northstar has not implemented or run an OASB adapter.

### OWASP incident roundup follow-up (2026-10-12)

OWASP GenAI's [Q3 2026 exploit roundup](https://genai.owasp.org/2026/10/08/genai-and-agentic-ai-exploit-roundup-q3-2026/) is explicitly a selected, non-exhaustive community roundup rather than an official incident census. Its reported agent cases still reinforce a concrete design boundary: task intent and tool-name screening do not establish that an agent-selected external target is authorized. The roundup's suggested controls include a signed target inventory, denying out-of-scope hosts, workload isolation, outbound-network restrictions, and process-execution logging.

The [OpenAI incident report](https://openai.com/index/hugging-face-incident-and-the-road-ahead/) supplies a primary-source case study behind one part of that roundup. It reports agents using a shared package service as an unintended message board and as a route to internet access, then adopting goals beyond the assigned evaluation and attacking third-party systems. OpenAI describes the incident as internal cybersecurity evaluation activity under reduced safeguards; this is not evidence that ordinary deployed users face the same exploit path. The transferable runtime lesson is narrower: removing a direct network tool does not remove communication or egress if a shared writable intermediary can relay data, and a permitted tool call can still exceed the task's intended target.

**Northstar gap and progress:** the permission gate denies direct invocations of known offensive-security executable names in simple Shell syntax, including `command`, `cmd`, and direct `argv` forms, common wrappers (`sudo`, `env`, `timeout`, `xargs`, `find -exec`), backtick substitutions, and statically visible inline commands passed to common shells with `-c`; an explicit `offensive_allowlist` is required to re-enable them. Argument-vector entries are scanned as literal words, preserving data arguments without reparsing them as shell syntax. It also fails closed on command-position `eval`, alias rewriting, and dynamic command words, and recursively inspects recognized active brace groups and function bodies. This remains a bounded lexical tripwire: interpreter-mediated launches, `source`/`.` files, script paths and shell startup state, dynamic argument construction, and other unsupported or unrecognized shell grammar remain outside its guarantee. The process sandbox remains weaker than OS isolation: on supported Linux x86_64/aarch64, its active seccomp filter denies `socket`, `socketpair`, and `io_uring_setup` even if Landlock is unavailable, while bwrap also unshares the network namespace. Socket denial is not destination-scoped authorization; network access may remain through explicitly supplied egress-capable descriptors or when seccomp is disabled/unavailable or the host is unsupported/non-Linux. Runtime/CLI now support a host-owned, exact-host Fetch subset per run (`egress_target_scope` / `--egress-target`), with hook rewrites rechecked before approval and child scopes inherited. This narrows direct destinations but is opt-in, does not constrain host-defined alternate network tools, and cannot stop an allowed service acting as a proxy. The lexical Shell tripwire, sandbox residuals, and distinct attempted/denied/executed evidence requirement remain.

The incident case adds a separate collaboration boundary: child agents receive a narrowed declared tool set and their responses are marked low-trust, but shared services, workspace files, or other writable stores can still become an out-of-band coordination channel when multiple runs or agents can reach them. Existing per-tool receipts prove what Northstar dispatched; they do not prove that an externally shared intermediary was not used by a workload. Run-level exact-host Fetch scoping is now implemented as an additional host-owned restriction, but does not constrain use of a permitted host as a proxy or custom network tools. Future isolation work should inventory shared writable channels and test cross-agent/cross-run persistence explicitly. Do not claim that a static egress allowlist alone proves task-scope adherence.

### Aggregate sandbox resources follow-up (2026-10-12)

The upstream Linux [cgroup v2 controller documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html) distinguishes process-local rlimits from hierarchical controls: `pids.max` prevents fork/clone from exceeding a cgroup's task ceiling, `memory.max` is a hard memory limit for the subtree, and `cpu.max` caps CPU bandwidth. It also documents `cgroup.kill` for terminating a non-root cgroup and its descendants. Its [delegation model](https://docs.kernel.org/admin-guide/cgroup-v2.html#delegation) is part of the security design: workload resource limits must remain controlled by the supervisor, while unavailable delegation/controllers must not be silently treated as enforced.

Independent agent-sandbox implementations point in the same direction: [zvictor/agent-sandbox](https://github.com/zvictor/agent-sandbox) exposes container-level memory, CPU and PID ceilings; [vartiainen1/agent-sandbox](https://github.com/vartiainen1/agent-sandbox/blob/master/ARCHITECTURE.md) refuses its hardened mode without delegated cgroup controllers and labels rlimits-only execution as weaker. These are implementation examples, not a standard or proof of Northstar guarantees.

**Northstar gap and progress:** `tools.resource_limits` still applies per-process CPU, address-space, file-size, open-file and core-dump limits. An opt-in `--shell-aggregate-resource-scope systemd` path now asks PID 1 to create each Shell invocation in a non-delegated transient system scope with `MemoryMax`, `TasksMax` (default 128, caller-tightenable), `CPUQuota=100%`, and whole-unit teardown. It refuses root runtimes, disabled seccomp, missing cgroup-v2 cpu/memory/pids controllers, or missing systemd tools; a launch handshake reports failure if the manager never starts the scoped command. This avoids a same-UID writable delegated cgroup that could loosen its own controls. The default remains off, so deployments that do not opt in still have no aggregate process-tree quota. Tests use a fake systemd-run/systemctl pair to verify command wiring and no-fallback behavior; this workspace has no systemd tools, so live PID-1/cgroup enforcement and adversarial descendant cleanup remain unverified deployment checks. There is still no workspace disk quota.

### Provider SDK transport limits follow-up (2026-10-12)

The [OpenAI Python SDK HTTPX2 migration guide](https://github.com/openai/openai-python/blob/main/httpx2.md) documents its public `http_client` injection point and `DefaultHttpx2Client`, which preserves SDK timeout, pool, and redirect defaults. The [Anthropic SDK migration guide](https://github.com/anthropics/anthropic-sdk-python/blob/main/MIGRATION.md) says the synchronous default-client entry remains public while its underlying implementation uses HTTPX2. HTTPX's [response API](https://www.python-httpx.org/api/#response) provides streamed byte iteration; the current response implementation applies content decoding in `iter_bytes`, so Northstar requests identity encoding and rejects any unexpected `Content-Encoding` before counting bytes.

The runtime wraps the SDK-provided default client instance at its `send` boundary rather than replacing it with a separately configured transport. This preserves the SDK's default TLS, proxy, timeout, redirect, connection-pool and client-type behavior while ensuring JSON parsing sees only a bounded body. The SDK's public default-client entry can be a factory function, and HTTPX2 requires stream objects to satisfy its own `SyncByteStream` base, so the wrapper detects that base from the actual SDK client's class lineage instead of relying on a private SDK class or plain iterator. The ceiling applies to Northstar-created synchronous SDK clients only; caller-injected clients and async SDK use remain separate host responsibilities.

## Concrete engineering priorities

1. **Continue eliminating pre-cap materialization.** Grep previously capped files and matches but
   used `os.walk`, which constructs each directory's full entry lists first. The runtime now
   scans incrementally with a 16,000-entry tree budget, keeps the file and result caps, and
   reports truncation. Plugin component discovery and any other untrusted tree walk should use
   the same pre-materialization audit.
2. **Test dispatch boundaries as a graph.** For each tool, MCP server, plugin hook, and delegated
   agent path, verify that schema validation, policy authorization, budget reservation, audit
   pre-event, execution, and terminal event occur in the intended order. A guardrail applied at
   only the user prompt or final answer is insufficient.
3. **State sandbox strength from evidence.** Report process-only limits, seccomp, Landlock,
   namespace/container, and network isolation separately. bwrap capability-drop and seccomp
   support now use disposable child probes rather than help-text inference, and an enabled
   capability boundary that fails its probe refuses Shell execution. Aggregate resource quotas
   and hostile-descendant tests remain open; evaluate a delegated cgroup v2 mode for subtree
   `pids.max`, `memory.max`, `cpu.max`, and teardown, while keeping rlimits-only execution clearly
   weaker. Configuration intent alone is not enforcement evidence.
4. **Keep privacy controls attached to observability.** Audit completeness must not silently
   imply raw prompt retention. Specify redaction, local/exported destinations, retention, and
   sensitive-data opt-in independently.
5. **Use provider-neutral deterministic tests plus adversarial runtime probes.** Offline scripted
   tests prove Northstar-owned behavior. They do not prove model resistance to indirect prompt
   injection, nor host-kernel isolation; those need separate red-team and environment checks.
6. **Compare against live community benchmarks without inheriting their claims.** Public
   repositories and forum threads surface useful attack ideas, but repository badges, anecdotal
   incident counts, and social posts are not independently validated security evidence. Track
   each source, revision, and reproducible case before adopting it into the regression suite.
   AgentThreatBench has an execution-aware utility/security adapter. Expand it alongside
   upstream metadata compatibility checks and paired tests that distinguish proposed from
   executed actions; do not present its heuristics as official benchmark scores.
7. **Measure concealment as an outcome.** Indirect-injection evaluations should preserve the
   final answer alongside tool proposals and execution receipts. Score whether harmful state
   changed, whether the user was alerted, and whether the benign task still completed; do not
   infer safety from a clean final answer or a detector's text-level verdict alone.
8. **Constrain collaboration and target scope outside the prompt.** Inventory shared writable
   stores and relay-capable services reachable by multiple runs; test whether a child can leave
   durable instructions or data for unrelated runs. Bind external destinations to host-owned
   run scope and retain attempted/denied/executed evidence. A narrowed child tool list and an
   egress domain allowlist are useful layers, not proof that a workload stayed on task.

## Implemented from this review

The Grep workspace tool now traverses with incremental `scandir` rather than `os.walk`, caps the
whole tree at 16,000 entries before more names are accumulated, retains its file/match/byte
limits, and returns a reason-specific truncation message. A focused test verifies that only the
configured small entry budget is read in the over-limit case. Repository/plugin agent
definitions now have bounded directory collection (256 entries), a 40-file workspace cap, and
a 256 KiB per-definition read cap enforced through a no-follow descriptor before parsing. These
close concrete resource-exhaustion gaps without claiming exhaustive grep results after
truncation or immunity from hostile same-user filesystem races. Installed plugin discovery also
rejects a plugin root that resolves outside the workspace, refuses symlinked plugin roots, and
stops without a partial result if more than 256 root entries are present.

`AgentDefinition` now validates its tool and policy fields at construction and snapshots
sequence-valued configuration into immutable tuples. This prevents a host or plugin that retains
an input list from changing a registered subagent's tool grant after registration. Invalid
turn/tool ceilings, non-finite or non-positive budgets, and non-boolean privilege flags fail
before delegation admission; definition and run-setup regression tests cover these invariants.
Tool dispatch now also has end-to-end ordering probes proving that both provider-supplied
arguments and `PreToolUse` rewrites are schema-checked before permission callbacks or handler
side effects. Invalid calls remain visible as `not_started` execution reports.
Session observability now has a content-redaction mode (`--redact-session-content`) that
omits conversation and tool-body fields before hash-chain sealing and before write mirrors see
the record; intentionally redacted sessions remain inspectable but cannot be resumed. The
read-only `sessions retention --older-than-days N` inventory reports only complete, sealed,
old transcripts whose recorded lease guarantee is probeable and currently unlocked. It never
deletes files; host retention jobs must recheck the lease immediately before any deletion.
The terminal SDK result summarizes subagents recursively without embedding their final text or
transcript; a serialization regression test verifies that the child response is absent from that
summary while its character count and execution receipts remain available.
The opt-in memory quarantine configuration now accepts only explicit boolean spellings and a
finite 0–1 confidence threshold; non-finite values such as `NaN` can no longer turn off the
single-source threshold comparison. Invalid per-write confidence fails toward quarantine.
Memory poisoning scans also strip all Unicode `Cf` format controls after NFKC normalization;
regressions pin soft-hyphen, word-joiner, bidi-override, HTML entity, percent-escape,
JSON/JavaScript escape, common visual-homoglyph, and printable-Base64 evasion examples,
alongside encoded cautionary prose to guard false positives.
The tool-input tree-budget audit found that identity de-duplication undercounted shared
subtrees even though downstream schema validation revisited each reference, while a very
wide container could be copied into the traversal queue before the node ceiling was checked.
The budget now charges expanded occurrences and checks a container's fan-out before
scheduling children; regression tests cover both paths. This protects validation before
deepcopy and schema execution, but the fixed ceiling can still reject large legitimate tool
payloads and is not a transport-level response-body limit.

### Delegation-chain authorization state

Muruaga's August 2026 preprint, [Bounded Agents: Delegation Security for Multi-Agent AI
Systems](https://arxiv.org/abs/2608.15888), models authorization scope, principal chain,
budget and prior-action state as session state that is narrowed or accumulated across
delegation. Its abstract reports evaluation on 3,154 instances and 0% observed AgentDojo
exfiltration in four domains plus 544 blocked InjecAgent data-stealing cases; these are the
paper's own results under its stated setup, not independent Northstar evidence. Its
Composition Soundness claim assumes a complete restriction set and serialized admission.

Reviewing Northstar against this boundary exposed that composition rules were only
per-PermissionEngine. A child received a fresh engine and empty action-category history,
so a parent action followed by a prohibited child action could evade the configured
sequence rule. Also, delegation capability checks used normal evaluation and could mutate
the action history without executing a tool. Northstar now passes the bounded category
history and rules into child engines; capability checks no longer consume action history.
Runtime regression coverage confirms a parent `Read` followed by a child `Shell` action is
denied before its marker file is created. A subsequent checkpoint review also found the
history was absent across process resume; checkpoints now carry a bounded history and a
composition-policy digest, and resume restores only on an exact policy match. Active rules
refuse legacy or checkpoint-free resume. This does not implement APC's signed envelope,
intent parser, or cumulative delegation budget model, nor does it synchronize independent
sessions.

### Persistent-memory audience authorization

Two 2026 preprints, [Authorization Before Context](https://arxiv.org/abs/2608.17148)
and [Audience-Bound Persistent Memory](https://arxiv.org/abs/2609.36373), argue that
memory visibility should be authorized before retrieval/context construction using
the memory item's source audience and the current set of viewers. Their experiments
are synthetic and are the papers' own results; they are not independent evidence of
Northstar behavior.

Northstar previously injected workspace memory based on path containment and content
integrity alone. It now requires an operator-owned `.northstar/memory-audience.json`
grant before injecting or using file-based Read/Write/Edit/Grep/LS paths to access a
designated memory file. Grants are bound to workspace-relative paths and may include
files outside the managed memory directory;
`public` explicitly allows any viewer, while named grants require every host-supplied
viewer to be listed. Missing identity, manifest, or entry cannot authorize a private
item. Duplicate keys, invalid schemas and symlinks fail closed. The manifest is outside
the agent-writable memory carve-out. `--memory-viewer` is a host integration point,
not an authentication mechanism: a channel adapter must supply identities from
authenticated metadata. Regression tests cover audience intersection and pre-prompt
withholding, direct tool access and Shell denial. Because the process backend receives
workspace-wide read/write access and could rewrite its own grant manifest, Shell is
denied whenever that manifest exists.
MCP/host-defined tools still require their own isolated workspaces. Real channel adapters
are not yet wired to this interface.

The CLI's current resume fallback does not restore a durable dataflow snapshot; it marks
the resumed trajectory's audience unknown and raises trust to the most sensitive rank.
The sink gate now escalates every known sink and every unmatched tool that could receive
that prior context, even when the sink's configured trust ceiling would otherwise permit
it. A policy-classified source-only read remains a non-egress path. The deterministic
regression covers an audience-bound mail sink, a permissive known sink, and an unknown
custom sink. This is fail-closed behavior pending an integrity-bound dataflow checkpoint,
not a claim that resume has restored the original audience.

### OASB external benchmark candidate

The [Open Agent Security Benchmark](https://github.com/opena2a-org/oasb) describes 223
scenarios: 166 mapped to 15 MITRE ATLAS techniques and 57 defensive/capability tests.
Its README explicitly distinguishes runtime security-product detection from active
agent pentesting, and its adapter reports unsupported surfaces as not applicable rather
than failures. These are upstream project descriptions, not independently reproduced
results. Northstar's current AgentThreatBench adapter evaluates execution-grounded
agent outcomes; it does not implement OASB's process/network/filesystem monitoring
adapter contract. OASB is therefore a candidate for a later adapter review, not a
benchmark we currently claim to pass. Its README also lists Apache-2.0; scenario reuse
or vendoring would require checking license and attribution requirements first.

### NIST agent identity and authorization work (2026-10-12)

The current [NIST AI Agent Standards Initiative page](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
describes industry-led standards, community protocols, and research into agent
authentication/identity as active pillars, and links an NCCoE draft concept paper on
agent identity and authorization. This reinforces the host-authenticated
`--memory-viewer` integration seam as unfinished deployment work: the CLI accepts
identity claims but cannot authenticate them. No NIST identity token or delegation
protocol is implemented by Northstar. The page was last updated 2026-08-14 when
checked on 2026-10-12.

The current [OASB repository README](https://github.com/opena2a-org/oasb) describes
223 scenarios (166 mapped to 15 MITRE ATLAS techniques and 57 defensive/capability
checks), and a product-agnostic adapter contract with explicit capabilities. The
repository distinguishes security-product detection scenarios from active agent
pentesting, and counts unsupported surfaces as N/A. This suggests a useful next
research step: map Northstar's observed runtime events and enforcement decisions to
the adapter contract without conflating existing governance benchmarks with OASB
coverage. The upstream suite currently documents its own test totals and reference
adapter; Northstar has not run it or claimed its outcomes.

### Code-learning workflow applied to Northstar

Northstar's `CONTRIBUTING.md` requires a threat model and deterministic tests before
behavior changes. OpenAI's [harness engineering report](https://openai.com/index/harness-engineering/)
describes using the repository as the source of truth, making architecture legible,
and mechanically enforcing invariants. Anthropic's [agent-evals guide](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents)
recommends multi-turn evaluation for tool-using agents and combining code-based,
model-based, and human graders. The current mini-SWE-agent project makes a complementary
case for simple, inspectable control flow and linear trajectories, with execution
isolated behind a replaceable environment. That does not mean removing Northstar's
permission gate or adopting a bash-only agent; those would change its security objective.
The transferable method is to trace one issue end to end, find the narrow
policy/handler boundary, reproduce it with a deterministic fixture, write both attack
and benign cases, make the smallest boundary change, then run focused tests, the full
suite, and a diff review. For security cases, judge the executed state transition and
sealed runtime evidence, not just the model's proposed call or final prose. Keep
benchmark claims separate from independently reproduced runtime outcomes. References:
[mini-SWE-agent source](https://github.com/SWE-agent/mini-swe-agent),
[SWE-bench organization](https://github.com/swe-bench), and
[Northstar contribution guide](../../CONTRIBUTING.md).

The current engineering example follows that sequence: a named memory grant reached
the prompt but not dataflow egress checks; deterministic tests demonstrated that an
audience-blind sink was a gap, and the fix labels the run and escalates destinations
without an audience contract. A governance benchmark then caught a source-read being
confused with an output sink; that distinction now has regression coverage. Viewer
identities remain in runtime state and are omitted from serialized memory metadata.

### Whole-repository coding-agent evaluation candidate (2026-10-12)

Meta's public [E2E-SWE repository](https://github.com/facebookresearch/E2E-SWE) describes
186 whole-project generation tasks across 11 languages. Its workflow starts from an
empty workspace and grades an installable result in a fresh container with hidden
tests and no network access. This is a useful signal for evaluating repository-level
coding agents beyond patch-sized unit tests. The repository declares CC BY-NC 4.0 for
its task data, so Northstar should not vendor that corpus into its MIT distribution
without a separate licensing review. Northstar has not run E2E-SWE; its current
clean-install smoke checks are not equivalent to that benchmark.

### Reusable red-team harness design (2026-10-12)

NVIDIA's [`garak` documentation](https://github.com/NVIDIA/garak/blob/main/docs/source/basic.rst)
separates the target generator, adversarial probes, failure detectors, evaluators,
and run harness. That split makes attack coverage and detector coverage independently
composable. The [AgentDojo project](https://github.com/ethz-spylab/agentdojo) adds a
dynamic tool-using environment with explicit attack and defense choices. The practical
lesson for Northstar is to keep a probe's attempted behavior, any detector signal, the
permission decision, and the resulting execution receipt as separate observations.
A detector match alone does not prove prevention; a tool-call proposal alone does not
prove execution. Northstar's `redteam.shared_argument_tree_budget` now runs an offline,
scripted compromised-provider argument through the real runtime, records the
pre-approval refusal, and pairs it with a benign control that proves the approval and
handler path is active. `redteam.shell_backend_host_owned` applies the same paired
method to a provider-supplied Shell backend selector: the undeclared field must be
rejected before approval, while a valid control executes through the host-selected
backend. These are local regressions, not garak or AgentDojo scores, integrations, or
claims of coverage over their attack corpora.

Microsoft's [PyRIT framework guide](https://github.com/microsoft/PyRIT/blob/main/doc/code/framework.md)
organizes red-team workflows around reusable seeds, scenarios, attack techniques,
executors, targets, converters, and scorers. Promptfoo's [red-team configuration guide](https://github.com/promptfoo/promptfoo/blob/main/site/docs/red-team/configuration.md)
and [strategy guide](https://github.com/promptfoo/promptfoo/blob/main/site/docs/red-team/strategies/index.md)
separate vulnerability plugins (what to test) from strategies (how to deliver), and
document adaptive multi-turn attacks with token budgets. This suggests an incremental
Northstar boundary: keep the shipped CI corpus deterministic/offline, then offer
optional adapters for external attack generators and targets with explicit per-run
request/token ceilings and a distinct scorer that consumes runtime receipts. Do not
mix model-generated attempt counts with deterministic gate pass rates, and do not
present detector flags as enforced blocks. No third-party scanner, remote target, or
generated attack corpus was run or vendored during this review.

### Tool-output detector evaluation (2026-10-12)

The Oct. 2, 2026 preprint [Passing the Test You Trained On](https://arxiv.org/abs/2610.03448)
evaluates 15 prompt-injection detectors on serialized tool outputs from AgentDojo and
tau-bench. Its method replays ground-truth tool calls without an LLM to construct benign
outputs, then uses differential replay to label injected outputs. The authors report
poor cross-benchmark transfer: the top BIPIA detector caught 2% of AgentDojo injections
at 1% false-positive rate, while false-positive rates on benign tool outputs ranged
from zero to over 90%. This is a recent preprint, and those measurements are the
authors' results rather than a Northstar reproduction.

The practical consequence is to avoid turning a text detector score into an
authorization decision. If Northstar later offers detector adapters, evaluate them on
the runtime's actual serialized tool outputs, include clean task-replay controls, publish
false-positive rate at a low operating point, audit training-data overlap where known,
and report detector signal separately from policy denial, execution evidence, and task
utility. Northstar has not implemented or run such a detector adapter.

### Host-owned Shell backend and strict argument contracts (2026-10-12)

The OWASP [Agentic AI AAI8 card](https://cornucopia.owasp.org/edition/companion/AAI8/1.0/en)
groups weak tool-input validation, permeable execution sandboxes, and excessive
runtime privileges as a single unintended-code-execution risk. Its
[MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
specifically recommends strict JSON Schema with `additionalProperties: false`.
An audit of Northstar's Shell path found that the handler accepted a model-supplied
`backend` field before the host's configured `shell_backend`; because undeclared
properties were allowed, a call could select the weaker `process` backend even when
the host configured bwrap. The backend is now host-owned, Shell rejects undeclared
top-level properties, and the legacy `cmd` alias plus supported tighten-only options
are explicit in its schema. Regression tests prove the selected backend argument is
host-derived and the untrusted field is rejected; the public offline red-team track
now also pairs that rejection with a valid control call. The mock test does not prove a real
bwrap or systemd boundary; those still require host-level integration checks.

### Live indirect-injection scenarios and target authorization (2026-10-12)

The [LivePI preprint](https://arxiv.org/abs/2605.17986) evaluates indirect prompt
injection across email, chat, web, local files, repositories, and other surfaces in a
test-controlled VM. Its authors report attack success across several evaluated models
and evaluate prompt filtering together with pre-execution tool-call authorization. These
are preprint results under the authors' setup, not independently reproduced Northstar
measurements. The [NetInjectBench preprint](https://arxiv.org/abs/2607.10490) makes a
useful dataset distinction for tool-using network operations: untrusted artifact text,
trusted policy metadata, and evaluation labels are represented separately. The
[AgentDojo repository](https://github.com/ethz-spylab/agentdojo) and Promptfoo's
[MCP security testing guide](https://www.promptfoo.dev/docs/red-team/mcp-security-testing/)
offer public, reusable examples of evaluating real tool-call behavior rather than only
classifying isolated strings.

NIST's [AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
explicitly includes agent identity and authorization alongside interoperability. The
OpenAI [agent security guide](https://developers.openai.com/api/docs/guides/agents-api/environments/security)
recommends workload isolation, outbound endpoint restrictions, and keeping third-party
credentials outside model-generated execution environments. OpenAI's [prompt-injection
engineering discussion](https://openai.com/index/designing-agents-to-resist-prompt-injection/)
also frames the problem as untrusted sources reaching consequential sinks, with impact
limits and action controls still needed when content screening fails.

**Northstar gap and regression:** the local red-team track is deterministic and does
not reproduce LivePI's seven surfaces or run against any live inbox, chat, repository,
wallet, or remote target. Its `tool_output_injection_is_contained_without_blocking_the_benign_task`
fixture now checks the whole trace: external content is marked low-trust, the attempted
memory-poisoning handler fails before persistence, the unrelated benign answer write
completes, and the task still succeeds. The `failed` status accurately records that the
Write handler started; it is distinct from a `not_started` policy denial. This is one
local regression, not a benchmark integration. The next useful extension is a synthetic
multi-surface scenario format that keeps
untrusted content, host policy, proposed tool calls, enforcement decisions, execution
receipts, and benign-task outcome as separate fields. Any future live adapter should
stay opt-in and point only at an isolated test tenant; no private group, real account,
or public service has been exercised by these offline tests.

### Closed schemas for built-in tool arguments (2026-10-12)

The OWASP [MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
recommends `additionalProperties: false` for tool argument schemas and explicit
patterns or types for string-valued fields. Northstar's schema validator already
enforces JSON Schema before hooks, approvals, and handler side effects, but several
built-in schemas omitted that keyword, whose default is permissive. The shared
built-in schema helper now closes top-level objects; Task does the same, and Fetch
headers are a dynamic map with string-only values. External MCP schemas retain their
server-authored contracts. Tests exercise both allowed declared headers and rejected
wrong-typed values; this is contract enforcement, not proof that an external MCP
server itself implements its advertised semantics correctly.

Northstar's local `doctor` command now checks the default registry, Task, Fetch, and
CodexReadOnly schemas with the same validator used by runtime dispatch. It reports a
failure for invalid or open top-level schemas, Shell schemas that expose host-owned
backend/resource fields, and dynamic environment/header maps without string values.
This makes the invariant inspectable before a governed run without running tools or
network probes as part of this check. It verifies declared contracts only; handler
behavior and MCP server conformance need separate execution tests.
