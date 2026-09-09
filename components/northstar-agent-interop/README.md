# Northstar Agent Interop

This is a local, backend-neutral interoperability boundary for combining
multiple Agent engines such as coding agents, browser/workflow agents, and
future OpenBot-compatible adapters. It does not call or impersonate any
vendor product.

## What is standardized

The component defines four distinct concepts:

1. `AgentProfile` — an untrusted capability declaration for a registered
   backend. A profile says what an adapter claims to support; it grants
   nothing.
2. `AgentAttestation` — a host-signed, expiring statement binding one source
   Agent to a specific task/run/thread/actor/workspace/step and input digest.
3. `HandoffRequest` — a typed request to delegate a bounded step to a target
   Agent with an exact capability set, deadline, postconditions and
   idempotency key.
4. `HandoffGrant` — a host-issued signed grant that binds the request to its
   source and target. Nested delegation must narrow capabilities and advance
   delegation depth exactly one level.

The grant path is:

```text
verified Host Authorization
  + verified source Agent Attestation
  + current policy revision
  + registered target profile
  + narrowed request
  → signed Handoff Grant
```

Grant verification does not mean the backend finished the task. The separate
`interop_adapter.py` boundary then verifies target, policy revision, expiry,
context digest and postconditions before invoking a backend-specific executor.
The executor receives an opaque `context_ref`, not a raw prompt or arbitrary
context. It must return a typed execution result; only a verified result may
be reported as `finished`.

## Security properties

- Unknown fields, invalid IDs, malformed digests, duplicate capabilities,
  wildcard capabilities, expired credentials and bad signatures are rejected.
- `task_id`, `thread_id`, `run_id`, `actor_id`, `workspace_id`,
  `policy_revision`, `step_id`, `trace_id` and `input_digest` are checked
  across the handoff chain.
- A target profile cannot authorize itself. Parent authorization and source
  attestation remain the authority; target capability declarations only limit
  compatibility.
- Child capabilities are a subset of the parent and source capabilities.
  Child expiry is no later than parent expiry, attestation expiry, request
  deadline and host TTL.
- Handoff depth cannot jump or be widened. Handoff and adapter calls require
  the current policy revision, not merely the revision embedded in an old
  token.
- Handoff tokens and context envelopes contain claims and digests only. Do
  not place passwords, API keys, cookies, prompts, raw tool output or vendor
  login state in them.
- Adapter execution is idempotent for a handoff key and rejects a conflicting
  reuse. Backend output cannot mutate the registry, grant or authorization.

## Backend scope

This component intentionally does not contain Codex, Claude Code, Hermes,
Cursor or OpenBot integrations. Those products have different APIs, process
models, licenses, authentication boundaries and execution environments. Each
future adapter must be independently reviewed and tested behind this contract;
connecting a name to the registry is not proof of integration.

The current adapter calls a caller-provided fake/local executor only. The
canary demonstrates a three-backend handoff chain using fake executors and an
independent artifact verifier. No network, server, vendor account, browser
session or production environment is used by the tests.

## Current ceiling

This is a local contract candidate, not a complete Agent OS, distributed
broker, sandbox, identity provider, secret manager, queue or team workflow
platform. It does not prove cross-process fencing, native Linux isolation,
provider reliability, prompt-injection resistance of a backend, or task-level
success across real engines. Those require separate canaries, fixed tasks,
independent verifiers, rollback plans and explicit deployment authorization.

## Local CLI process adapter candidate

`process_adapter.py` is a backend-neutral process boundary for a future
version-pinned Codex, Claude Code, or Cursor CLI mapping. It is **not** a
vendor integration and is disabled until a caller explicitly supplies an
enabled `ProcessBackendSpec` with an absolute executable and fixed argv
Template.

The boundary enforces:

- no shell invocation and no arbitrary command/template tokens;
- host-resolved private `0700` workspace;
- explicit `supported_capabilities` checked against every Handoff Grant;
- current policy revision and target Agent verification;
- opaque context reference resolved by the host, bounded before stdin;
- environment allowlist that rejects credential-like names;
- bounded output, timeout and process-group termination;
- strict one-object JSON execution result;
- structured failed/unknown Receipt instead of false success;
- idempotent replay by Handoff idempotency key.

The three helper specs (`codex_cli_spec`, `claude_code_cli_spec`,
`cursor_cli_spec`) are disabled by default and intentionally use placeholder
absolute paths. No CLI is installed, authenticated or executed by this
repository. Before enabling one, pin and audit the actual binary/version,
verify its documented non-interactive flags, authentication mode, output
schema, session/resume semantics, cancellation behavior and workspace policy.

## Local deterministic backend router candidate

`backend_router.py` is a local-only selection layer above backend-specific
adapters. It is not an authorization layer: a `RouteDecision` contains no
secret or grant and cannot authorize a tool call by itself. The caller must
still create and verify a narrowed Handoff Grant before execution.

A `RouteRequest` carries only bounded task/run identity, policy revision,
input digest, capability requirements and routing preferences. The router
selects among explicitly registered profiles/adapters using capability support,
enabled state, health, cooldown, priority and stable agent-id ordering.
Preferences are soft: an unavailable preferred backend falls back to another
healthy compatible backend. Cooldown expiry is handled consistently by both
selection and adapter lookup.

The selected backend profile/version and route identity are checked again when
the adapter is looked up. `assert_route_matches_handoff()` permits only
further deadline narrowing; all other identity, policy, target, digest and
capability fields must match exactly. No real backend or network service is
used by the local tests.

## Local tamper-evident Route Lineage v2

`route_lineage.py` is a local-only persistence layer above the bounded v1
`RouteEvent` contract. It wraps each event in a versioned v2 envelope with a
canonical SHA-256 event digest and a predecessor digest. Recovery verifies
field schemas, event digests, contiguous sequence numbers and the complete
predecessor chain before returning a `verified` result.

A hash chain cannot detect deletion of its final row by itself. Callers that
need rollback detection must retain and pass the returned `LineageCursor`;
recovery fails closed when the current head differs. The v1-to-v2 migration
reads the source JSONL without writing it, validates the complete route state
machine, writes and verifies a separate temporary target, and refuses to
overwrite an existing target. The migrated target remains appendable.

This is evidence and recovery plumbing, not authorization, sandboxing or
backend execution. It contains no credentials, prompts, raw provider errors,
network calls or real Codex/Claude Code/Hermes/Cursor/OpenBot integration.

## Independent route state and causal replay

`route_state.py` contains the public, pure `RouteStateMachine` used to validate
selected/started/failed/retry/succeeded/cancelled transitions. It re-parses
route events before replay and does not depend on private RouteLedger methods.
`RouteLineage.replay_verdict()` classifies verified history as `replayable`, a
head mismatch against a caller cursor as `stale`, and malformed or tampered
history as `unverifiable`.

`route_causality.py` derives typed `receipt` and retry edges. A graph may be
built from multiple independently verified route segments; explicit
`HandoffLink` edges connect a terminal parent route to a child decision while
requiring shared task/run/workspace/policy identity and correct source/target
agents. These links are bounded evidence only, not signed authorization; the
actual Handoff grant remains verified by `handoff.py`.

`causal_store.py` provides a separate append-only evidence index for these
validated edges. It uses a versioned envelope, canonical record digest,
predecessor chain, `fsync`, and an external `EvidenceCursor` for suffix
rollback detection after restart. The store persists evidence only; it is not
an authorization database and cannot authorize tools, agents, or providers.

`CausalGraph.from_events()` is intentionally limited to one route segment:
its route identity and target agent remain fixed. Cross-agent delegation must
use `CausalGraph.from_segments()` with separate verified segments and an
explicit terminal-parent to child-decision `HandoffLink`; the API rejects
unknown/duplicate event digests, non-terminal parents, wrong agents and
identity drift.
