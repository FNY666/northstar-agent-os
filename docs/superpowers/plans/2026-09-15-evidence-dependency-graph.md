# Evidence Dependency Graph Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Model claim-to-claim evidence prerequisites and conservatively propagate supported, blocked, and unknown state through a deterministic acyclic dependency graph.

**Architecture:** `EvidenceDependencyGraph` contains canonical `ClaimDependency(claim_digest, requires)` nodes. `project_dependencies` takes direct `ClaimProjection` values and derives a graph-aware projection per declared claim in topological order. Direct conflict/insufficient/unverifiable states dominate; any blocked prerequisite produces `blocked`, any unknown prerequisite produces `unknown`, and cycles or undeclared dependencies fail closed. The graph is descriptive evidence structure, not truth resolution or action authorization.

**Tech Stack:** Python 3.10+, standard library, existing `evidence_state_projection`, `unittest`. No network and no new dependency.

## Global Constraints

- Research worktree only; no local-only, main, integration-next, arena, runtime, merge, cherry-pick, or remote push changes.
- A dependency edge means evidence precondition only; it grants no capability and triggers no action.
- Graph nodes and requirements are digest-only; no prompt, event body, secret, output, command, or policy action is serialized.
- Cycles, self-dependencies, duplicate nodes, duplicate edges, and missing dependencies fail closed.
- Direct `conflicted`, `insufficient`, or `unverifiable` states dominate every dependent result; no dependency can turn them into supported.
- `supported` in a graph remains an evidence-state conclusion, not execution authorization.

---

### Task 1: Strict canonical dependency graph (RED first)

**Files:**
- Create: `components/northstar-agent-interop/evidence_dependency_graph.py`
- Create: `components/northstar-agent-interop/tests/test_evidence_dependency_graph.py`

**Interfaces:**
- `ClaimDependency.to_dict()/from_dict()`
- `EvidenceDependencyGraph.to_dict()/from_dict()`
- `make_dependency_graph(nodes) -> EvidenceDependencyGraph`

- [x] Test canonical node/edge ordering and deterministic graph digest.
- [x] Reject duplicate nodes, duplicate edges, self-dependencies, cycles, and malformed digests.
- [x] Run focused tests RED before implementation.

### Task 2: Transitive evidence-state projection

**Files:**
- Modify: `components/northstar-agent-interop/evidence_dependency_graph.py`
- Modify: `components/northstar-agent-interop/tests/test_evidence_dependency_graph.py`

**Interfaces:**
- `DependencyProjection.to_dict()/from_dict()`
- `project_dependencies(graph, direct_projections) -> dict[str, DependencyProjection]`

- [x] Supported direct claims with supported prerequisites remain supported.
- [x] Blocked prerequisites propagate blocked; unknown prerequisites propagate unknown.
- [x] Direct conflicted/insufficient/unverifiable states dominate dependencies.
- [x] Missing direct projections fail closed as unknown; provenance contains direct/dependency state and reasons.

### Task 3: Replay verification and local regression

**Files:**
- Modify: `components/northstar-agent-interop/evidence_dependency_graph.py`
- Modify: `components/northstar-agent-interop/tests/test_evidence_dependency_graph.py`
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Create: `docs/superpowers/plans/2026-09-15-evidence-dependency-graph.md`

**Interfaces:**
- `DependencyGraphWitness.to_dict()/from_dict()`
- `make_graph_witness(graph, direct_projections) -> DependencyGraphWitness`
- `verify_graph_witness(witness, graph, direct_projections, *, expected_digest=None) -> GraphWitnessVerdict`

- [x] Bind the complete graph, direct source projection wires, derived projections, and a domain-separated witness digest.
- [x] Reject graph/projection/state/order/digest substitution.
- [x] Preserve unresolved boundaries; `actionable=False` for every dependency projection and witness verdict.
- [x] Run focused tests, full Interop regression, `py_compile`, `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not notify other sessions or push.
