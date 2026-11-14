# Graph Admission and Atomic Batch Evidence Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `test-driven-development` task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Admit only fully verified `CausalGraph` objects into a graph-level evidence index and persist each admitted graph as one restart-verifiable atomic record.

**Architecture:** `route_causality.py` exposes a canonical graph commitment over verified lineage-event digests, segment boundaries, typed edge dictionaries, and typed handoff links. `graph_store.py` stores one graph commitment per record, including node digests and edges but not duplicate full `LineageEvent` bodies. Admission re-parses and verifies the graph before any write. A locked transactional rewrite (temporary file + fsync + atomic replace) publishes the old records plus one complete new record, so validation failures and interrupted preparation do not publish partial batches. Recovery validates record/schema/digest/chain/endpoint/handoff invariants and an external cursor detects suffix rollback.

**Tech Stack:** Python 3.12 stdlib (`dataclasses`, `hashlib`, `json`, `fcntl`, `tempfile`, `os`, `pathlib`, `unittest`); no network, subprocess, credentials, or remote writes.

## Global Constraints

- Modify only `/var/minis/workspace/northstar-agent-os-local-only`.
- Do not modify public checkout, integration, arena branches, research-route-journal, remotes, or servers.
- Do not copy or cherry-pick research source.
- Existing `CausalEvidenceStore`, `CausalGraph`, and 119 Interop tests remain compatible.
- Current graph admission adds 17 focused graph tests; standard discovery currently reports 136 tests in total.
- Persist only event digests and bounded typed edges; never prompts, credentials, raw provider output, or signed tokens.
- Malformed, forged, duplicate, unknown-endpoint, sequence-gap, digest-mismatch, and cursor-mismatch data fails closed.
- Atomicity claim is for the store's validated batch publication protocol; crash consistency still depends on the filesystem's atomic rename contract and fsync behavior.

## Public Interfaces

```python
@dataclass(frozen=True)
class GraphEvidenceCursor:
    sequence: int
    record_digest: str

@dataclass(frozen=True)
class GraphEvidenceRecord:
    schema_version: str  # exactly "northstar.graph-evidence.v2"
    sequence: int
    prev_record_digest: str | None
    record_digest: str
    graph_digest: str
    segment_lengths: tuple[int, ...]
    event_digests: tuple[str, ...]
    edges: tuple[CausalEdge, ...]
    handoffs: tuple[HandoffLink, ...]

@dataclass(frozen=True)
class GraphEvidenceRecovery:
    verdict: str  # verified
    records: tuple[GraphEvidenceRecord, ...]
    cursor: GraphEvidenceCursor | None

class GraphEvidenceStore:
    def __init__(self, path: str | Path): ...
    def admit(self, graph: CausalGraph) -> GraphEvidenceRecord: ...
    def recover(self, *, expected_cursor: GraphEvidenceCursor | None = None) -> GraphEvidenceRecovery: ...
```

`CausalGraph.graph_digest` is the SHA-256 of canonical:

```json
{
  "schema_version": "northstar.causal-graph.v1",
  "segment_lengths": [3],
  "event_digests": ["..."],
  "edges": [{"relation": "...", "parent_event_digest": "...", "child_event_digest": "...", "edge_digest": "...", "handoff_id": null}],
  "handoffs": []
}
```

The order of verified events and edges is significant and preserved.

### Task 1: Canonical graph commitment and strict admission

- [x] Write RED tests for `graph_digest`, forged event/edge rejection, and unknown edge endpoint rejection.
- [x] Run focused tests and confirm expected RED.
- [x] Implement canonical commitment and make `CausalGraph.verify()` reparse objects instead of merely inspecting their fields.
- [x] Confirm focused GREEN.

### Task 2: Atomic graph record store and restart recovery

- [x] Write RED tests for one-record graph admission, idempotent re-admission, restart recovery, and cursor rollback.
- [x] Run focused tests and confirm expected RED.
- [x] Implement strict graph evidence records, lock-protected temp-file publication, fsync, no partial publication on admission failure, and recovery checks.
- [x] Confirm focused GREEN.

### Task 3: Regression, documentation, and local-only commit

- [x] Document graph-index boundaries and atomic publication limitations.
- [x] Run focused graph tests, py_compile, standard full Interop regression, documentation tests, diff check, sensitive scan, and public checkout status check.
- [x] Create one local-only commit after fresh verification; never push.

## Execution notes

- The initial RED exposed the missing graph commitment; subsequent tests exposed and fixed handoff-edge inclusion, graph-record digest recomputation, segment coverage, handoff declaration/edge consistency, and relation/ID type closure.
- The index deliberately stores bounded event digests and typed edges rather than full LineageEvent bodies; source LineageStore verification remains required for full event semantics.
- Final standard-order verification before this note: Interop 136/136 PASS, py_compile PASS, documentation 3/3 PASS, diff check and sensitive scan PASS.

## Known boundaries

- The graph index commits node digests rather than duplicating full LineageEvents; validating event contents still requires the source LineageStore.
- A graph digest authenticates internal consistency only; it does not authenticate an external Handoff grant or authorize an action.
- A caller-held cursor remains necessary to detect deletion of the final graph record.
