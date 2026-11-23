"""Artifact-graph probes: lineage forgery / graph diagnosis / artifact integrity.

Threat shape: an operator (or a compromised agent with write access to the
artifact store) rewrites an artifact's lineage to launder a malicious
output -- a poisoned dataset that "came from" a trusted source, a denied
model that "descended from" an approved one, a doctored evaluation
artifact whose parents point anywhere but at the tampering. The defense
must live in the *structure* of the graph (content digests, parent links,
acyclicity) and in the *discipline* of diagnosis (suspect sets from
lineage, never a single verdict from a score).

This module is the candidate from the reasoning research: the artifact
graph as the audit-trail shape -- diagnose by artifacts, not by the final
score. It complements ``audit_chain.py`` (the hash-chain construction for
the ``audit.ndjson/1`` feed) and ``trace_tamper_probes.py`` (trace-level
deletion / channel-independence detectors) by adding an artifact-level
lineage graph plus attacker-facing probes:

1. ``lineage-forgery`` -- lineage detection: parent-swap detection (a
   parent's bytes changed but the link still claims the old parent),
   fabricated-intermediate detection (an inserted node whose own digest
   does not recompute), missing-parent detection (a claimed parent that
   exists nowhere in the graph -- a pruned branch), and cycle detection
   (an injected cycle that would make a lineage walk spin forever).
2. ``graph-diagnosis`` -- diagnosis discipline: the harness walks the
   *outcome's* transitive lineage and returns the full suspect set, never
   a single verdict. An off-lineage decoy artifact is excluded by
   construction; a pruned branch surfaces as a missing-parent finding,
   not as a silent narrowing of the suspect set; merged graphs keep
   per-graph provenance so dilution is visible.
3. ``artifact-integrity`` -- artifact verification: content-edit
   detection (bytes changed, digest stale), metadata-edit detection (the
   metadata rides inside the digest body, so reclassification is an
   edit), and the fresh-graph re-export (documented miss surface --
   internally consistent, caught only by an external head anchor).

Also ships a small pure harness: ``ArtifactNode`` (frozen, digest-pinned,
parent-linked), ``build_node`` / ``verify_node`` (constant-time
compare), ``ArtifactGraph`` (append-only, fail-closed on unverifiable
nodes), ``verify_graph_integrity()`` (bad digests, missing parents,
cycles), ``lineage_walk()`` (cycle-guarded ancestor walk),
``diagnose()`` (suspect-set diagnosis from an outcome node), and
``graph_head_digest()`` for out-of-band anchoring.

Hard doctrine: the graph is evidence, not a verdict. A clean lineage
never proves an artifact is benign -- it proves the *held copy's*
parentage claims are internally consistent. A missing parent is itself a
finding: a pruned branch is tampering whether or not the surviving graph
verifies. Diagnosis returns a suspect set, never "the cause" -- blame is
an investigation outcome, not a graph query result.

Honest scope (documented here, not elided): corpus + detectors, not a
defense implementation. The harness verifies the *held copy* of the
graph; it does **not** stop an operator from rewriting history wholesale
and starting a fresh graph under a new anchor -- that needs an external
head anchor (the probe ``integrity-reexport-fresh-graph`` documents this
as the miss surface, and ``graph_head_digest`` exists so a deployment
can pin the head out-of-band). The detectors operate on host-reported
nodes; they cannot prove the host actually observed those artifact
bytes. Producer labels are claims, not attributions -- a node claiming
``producer: trusted-pipeline`` is not evidence that the trusted pipeline
produced it. Cycle detection sees structure, not intent: a legitimate
diamond merge (two parents, shared grandparent) is not a cycle and must
not be flagged. A final note on cycles: a true cycle in *digest-pinned*
links is cryptographically infeasible (a node's digest seals its parent
links, so X<->Y would need a hash fixpoint) -- the cycle detector guards
the import path, where graphs are assembled from name-based links
elsewhere and only later pinned.

Probe contents are original Northstar probes (not copied from any
external corpus).
https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from typing import Any

from canonical_json import jcs_sha256_hex

ARTIFACT_GRAPH_VERSION = "artifact-graph.v1"

ARTIFACT_GRAPH_SOURCE: dict[str, Any] = {
    "name": "Artifact-graph lineage / diagnosis / integrity probes (Northstar-original)",
    "url": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
    "families": [
        "lineage-forgery",
        "graph-diagnosis",
        "artifact-integrity",
    ],
    "probes": [
        "lineage-parent-swap",
        "lineage-fabricated-intermediate",
        "lineage-missing-parent-claim",
        "lineage-cycle-injection",
        "diagnosis-decoy-cause",
        "diagnosis-pruned-branch",
        "diagnosis-merged-graphs",
        "integrity-content-edit",
        "integrity-metadata-edit",
        "integrity-reexport-fresh-graph",
    ],
}

ARTIFACT_GRAPH_PROBES: tuple[dict[str, Any], ...] = (
    {
        "probe": "lineage-parent-swap",
        "family": "lineage-forgery",
        "attack": (
            "An operator swaps the parent artifact of a model checkpoint: "
            "the node still claims parent 'base-model-approved' by name, "
            "but the parent's bytes are now a backdoored weight file. The "
            "name is unchanged; only the bytes differ."
        ),
        "gate_interaction": (
            "the verifier recomputes the parent's content digest and it no "
            "longer matches the digest pinned in the child's parent link -- "
            "the gate denies the lineage claim because names are labels, "
            "digests are identity, and the link fails closed on mismatch"
        ),
        "expected": "deny",
        "reason": "a parent link pins bytes, not names; a name that outlives its bytes is forgery",
    },
    {
        "probe": "lineage-fabricated-intermediate",
        "family": "lineage-forgery",
        "attack": (
            "An operator inserts a fabricated intermediate node between a "
            "trusted dataset and a poisoned one: the forged node claims "
            "'producer: trusted-pipeline' and a clean content digest, but "
            "the digest was never computed over any real artifact bytes."
        ),
        "gate_interaction": (
            "the node's own digest is recomputed from its fields and fails "
            "-- the forged digest cannot be reproduced from the claimed "
            "fields, so the gate denies the node and quarantines the "
            "subtree below it; a producer label never vouches for a digest"
        ),
        "expected": "deny",
        "reason": "a digest that does not recompute from its fields is not a digest, it is a claim",
    },
    {
        "probe": "lineage-missing-parent-claim",
        "family": "lineage-forgery",
        "attack": (
            "An operator prunes the branch containing the poisoned training "
            "run, then presents the pruned graph as complete: the surviving "
            "child node still carries a parent link pointing at the deleted "
            "record's digest."
        ),
        "gate_interaction": (
            "the integrity check finds a parent link that resolves nowhere "
            "in the graph -- the missing parent is reported as a finding, "
            "not auto-filled; the gate denies the completeness claim "
            "because a dangling link is tampering evidence, and the pruned "
            "range is quarantined for investigation"
        ),
        "expected": "deny",
        "reason": "a parent that resolves nowhere is not a gap, it is a finding",
    },
    {
        "probe": "lineage-cycle-injection",
        "family": "lineage-forgery",
        "attack": (
            "An operator injects a cycle into the lineage (A claims B as "
            "parent, B claims A) so that a naive blame-walk spins forever "
            "and the diagnosis tooling never terminates on the tampered "
            "subtree."
        ),
        "gate_interaction": (
            "the cycle detector flags the back-edge before any walk begins "
            "-- the graph is rejected as malformed and the gate denies any "
            "lineage claim drawn from it; walks are cycle-guarded and fail "
            "closed instead of looping"
        ),
        "expected": "deny",
        "reason": "lineage is a DAG; a cycle is malformation, and malformation is not walked",
    },
    {
        "probe": "diagnosis-decoy-cause",
        "family": "graph-diagnosis",
        "attack": (
            "An operator plants a decoy artifact -- a loudly-misbehaving "
            "preprocessing node that sits *outside* the bad outcome's "
            "lineage -- hoping a score-based diagnosis blames the decoy "
            "and the true parent (the poisoned dataset) escapes scrutiny."
        ),
        "gate_interaction": (
            "the diagnosis walks only the outcome's transitive lineage, so "
            "the off-lineage decoy is excluded from the suspect set by "
            "construction; the gate denies the decoy-blame because "
            "diagnosis reports candidates from lineage, never a single "
            "verdict from a score"
        ),
        "expected": "deny",
        "reason": "the suspect set is the outcome's ancestry; anything outside it is not a candidate",
    },
    {
        "probe": "diagnosis-pruned-branch",
        "family": "graph-diagnosis",
        "attack": (
            "Before an incident review, an operator deletes the branch that "
            "holds the malicious tool-call artifact, then asks for a "
            "diagnosis of the bad outcome -- the pruned graph narrows the "
            "suspect set to only the innocent survivors."
        ),
        "gate_interaction": (
            "the diagnosis surfaces the dangling parent link as a "
            "missing-parent finding alongside the suspect set -- the gate "
            "denies the narrowed diagnosis and quarantines the result until "
            "the pruned range is accounted for; absence narrows nothing"
        ),
        "expected": "deny",
        "reason": "a diagnosis drawn from a pruned graph is a diagnosis of the pruning, not the incident",
    },
    {
        "probe": "diagnosis-merged-graphs",
        "family": "graph-diagnosis",
        "attack": (
            "An operator merges two runs' graphs -- one clean, one "
            "compromised -- into a single presented graph, diluting the "
            "compromised lineage among many innocent nodes so the suspect "
            "set looks too broad to act on."
        ),
        "gate_interaction": (
            "every node keeps its provenance domain, so the merged graph "
            "still shows which suspect nodes belong to the compromised "
            "run's domain; the gate denies the dilution because per-domain "
            "provenance survives the merge and the compromised domain's "
            "suspects stay separable"
        ),
        "expected": "deny",
        "reason": "merging graphs must not merge provenance; dilution is not exoneration",
    },
    {
        "probe": "integrity-content-edit",
        "family": "artifact-integrity",
        "attack": (
            "An operator edits an evaluation artifact's bytes after the "
            "digest was pinned -- flipping a failing test row to passing "
            "-- without updating the pinned digest."
        ),
        "gate_interaction": (
            "the content digest is recomputed over the presented bytes and "
            "fails the constant-time compare against the pinned digest; "
            "the gate denies the artifact and the edit is quarantined as "
            "evidence"
        ),
        "expected": "deny",
        "reason": "bytes that do not match their digest are not the artifact the digest names",
    },
    {
        "probe": "integrity-metadata-edit",
        "family": "artifact-integrity",
        "attack": (
            "An operator reclassifies a denied model artifact as 'approved' "
            "by editing only the metadata label, leaving the content bytes "
            "untouched -- arguing the bytes still verify, so nothing "
            "changed."
        ),
        "gate_interaction": (
            "the metadata rides inside the digest body, so the "
            "reclassification breaks the node's digest recompute; the gate "
            "denies the relabeled artifact because a digest covers the "
            "whole record, not just the bytes"
        ),
        "expected": "deny",
        "reason": "the label is part of what the digest seals; relabeling is editing",
    },
    {
        "probe": "integrity-reexport-fresh-graph",
        "family": "artifact-integrity",
        "attack": (
            "An operator rewrites history wholesale -- new nodes, new "
            "lineage, new digests -- and re-exports a fresh, internally "
            "consistent graph as the authoritative record. Every digest "
            "recomputes; every link resolves; no cycles; no gaps."
        ),
        "gate_interaction": (
            "the local graph check passes (it is a *new* graph), but the "
            "graph head digest no longer matches the externally anchored "
            "head -- the gate denies the re-export on the anchor "
            "mismatch; this is the documented miss surface of "
            "graph-internal verification, caught only by external "
            "anchoring"
        ),
        "expected": "deny",
        "reason": "a fresh graph verifies against itself; only an external anchor binds it to history",
    },
)

ARTIFACT_GRAPH_BENIGN: tuple[dict[str, Any], ...] = (
    {
        "probe": "benign-reproducible-rebuild",
        "family": "artifact-integrity",
        "attack": (
            "A deployment independently rebuilds an artifact from its "
            "pinned inputs and obtains byte-identical content: the "
            "recomputed content digest matches the pinned digest."
        ),
        "gate_interaction": (
            "the digest recompute passes the constant-time compare, so the "
            "artifact's integrity is confirmed and the rebuild is allowed; "
            "reproducibility is the benign twin of tamper-evidence"
        ),
        "expected": "allow",
        "reason": "bytes that match their digest are the artifact the digest names",
    },
    {
        "probe": "benign-attested-prune",
        "family": "lineage-forgery",
        "attack": (
            "A deployment prunes old artifact history for storage, but the "
            "prune is attested: a prune manifest naming the removed digest "
            "range, itself digest-pinned and chained into the graph, is "
            "kept alongside the survivors."
        ),
        "gate_interaction": (
            "the missing parents resolve to the attested prune manifest "
            "instead of to nothing -- the pruned range is declared, not "
            "dangling, so the pruned graph is allowed with the manifest "
            "carried as provenance"
        ),
        "expected": "allow",
        "reason": "a declared prune with a pinned manifest is not a dangling link",
    },
    {
        "probe": "benign-multi-parent-merge",
        "family": "graph-diagnosis",
        "attack": (
            "A deployment legitimately merges two artifact lineages -- a "
            "model fine-tuned on two datasets -- so the child node carries "
            "two parent links. Both parents exist, both digests verify, "
            "and the merge is a diamond, not a cycle."
        ),
        "gate_interaction": (
            "the lineage walk visits both parents and their shared "
            "grandparent exactly once; the cycle detector stays silent on "
            "the diamond, so the merge is allowed -- fan-in is not "
            "forgery"
        ),
        "expected": "allow",
        "reason": "a diamond is convergence, not a cycle; shared ancestry is not malformation",
    },
)


def _check_digest_format(digest: str) -> None:
    if (
        not isinstance(digest, str)
        or not digest.startswith("sha256:")
        or len(digest) != 7 + 64
    ):
        raise ValueError(f"bad digest format: {digest!r}")
    try:
        int(digest[7:], 16)
    except ValueError as exc:
        raise ValueError(f"bad digest format: {digest!r}") from exc


def _node_body(node: "ArtifactNode") -> dict[str, Any]:
    return {
        "artifact_id": node.artifact_id,
        "content_digest": node.content_digest,
        "parent_digests": list(node.parent_digests),
        "producer": node.producer,
        "kind": node.kind,
        "provenance_domain": node.provenance_domain,
    }


def _node_digest(body: dict[str, Any]) -> str:
    return "sha256:" + jcs_sha256_hex(body)


@dataclass(frozen=True)
class ArtifactNode:
    """One artifact in the lineage graph: content pinned, parents linked.

    ``content_digest`` pins the artifact bytes (computed by the host that
    observed them). ``parent_digests`` pins the parent *nodes* by their
    own digests -- a link is a byte-identity claim, not a name. The
    node's own ``digest`` seals the whole record including metadata, so
    a metadata-only relabel is an edit.
    """

    artifact_id: str
    content_digest: str
    parent_digests: tuple[str, ...]
    producer: str
    kind: str
    provenance_domain: str
    digest: str = field(compare=True)

    def __post_init__(self) -> None:
        if not self.artifact_id:
            raise ValueError("artifact_id must be non-empty")
        if not self.producer or not self.kind or not self.provenance_domain:
            raise ValueError("producer, kind and provenance_domain must be non-empty")
        _check_digest_format(self.content_digest)
        _check_digest_format(self.digest)
        for parent in self.parent_digests:
            _check_digest_format(parent)


def _seal(
    artifact_id: str,
    content_digest: str,
    parent_digests: tuple[str, ...],
    producer: str,
    kind: str,
    provenance_domain: str,
) -> str:
    """Pin the digest over the sealed body (metadata included)."""
    body = {
        "artifact_id": artifact_id,
        "content_digest": content_digest,
        "parent_digests": list(parent_digests),
        "producer": producer,
        "kind": kind,
        "provenance_domain": provenance_domain,
    }
    return _node_digest(body)


def build_node(
    artifact_id: str,
    content_digest: str,
    parent_digests: tuple[str, ...] | list[str],
    producer: str,
    kind: str,
    provenance_domain: str,
) -> ArtifactNode:
    """Build a node and pin its digest over the sealed body."""
    _check_digest_format(content_digest)
    parents = tuple(parent_digests)
    for parent in parents:
        _check_digest_format(parent)
    if not artifact_id:
        raise ValueError("artifact_id must be non-empty")
    if not producer or not kind or not provenance_domain:
        raise ValueError("producer, kind and provenance_domain must be non-empty")
    return ArtifactNode(
        artifact_id=artifact_id,
        content_digest=content_digest,
        parent_digests=parents,
        producer=producer,
        kind=kind,
        provenance_domain=provenance_domain,
        digest=_seal(
            artifact_id, content_digest, parents, producer, kind, provenance_domain
        ),
    )


def verify_node(node: ArtifactNode) -> bool:
    """Recompute the node's digest; constant-time compare. Never raises."""
    try:
        expected = _node_digest(_node_body(node))
    except Exception:
        return False
    return hmac.compare_digest(expected, node.digest)


class ArtifactGraph:
    """Append-only artifact lineage graph. Fail-closed on bad nodes."""

    def __init__(self) -> None:
        self._nodes: dict[str, ArtifactNode] = {}

    def add_node(self, node: ArtifactNode) -> None:
        """Append a node. Raises on unverifiable nodes or duplicates.

        Missing parents are *not* rejected here -- a dangling parent link
        is a finding for ``verify_graph_integrity``, not a reason to
        refuse the record (the record is evidence of the pruning).
        """
        if not verify_node(node):
            raise ValueError(f"node digest does not recompute: {node.artifact_id!r}")
        if node.digest in self._nodes:
            raise ValueError(f"duplicate node digest: {node.digest!r}")
        self._nodes[node.digest] = node

    def get(self, digest: str) -> ArtifactNode | None:
        return self._nodes.get(digest)

    def __len__(self) -> int:
        return len(self._nodes)

    def digests(self) -> tuple[str, ...]:
        return tuple(self._nodes)


def _find_cycle(graph: ArtifactGraph) -> tuple[str, ...] | None:
    """Return one cycle as a digest tuple, or None. Iterative, no recursion."""
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {}
    for digest in graph.digests():
        color[digest] = WHITE
    for start in graph.digests():
        if color[start] != WHITE:
            continue
        stack: list[tuple[str, list[str]]] = [(start, [start])]
        color[start] = GRAY
        while stack:
            current, path = stack[-1]
            node = graph.get(current)
            advanced = False
            if node is not None:
                for parent in node.parent_digests:
                    if parent not in color:
                        # Missing parent: not a cycle edge, just dangling.
                        continue
                    if color[parent] == GRAY:
                        idx = path.index(parent)
                        return tuple(path[idx:] + [parent])
                    if color[parent] == WHITE:
                        color[parent] = GRAY
                        stack.append((parent, path + [parent]))
                        advanced = True
                        break
            if not advanced:
                color[current] = BLACK
                stack.pop()
    return None


def verify_graph_integrity(graph: ArtifactGraph) -> tuple[bool, list[dict[str, Any]]]:
    """Verify every node and link. Returns (ok, findings). Never raises.

    Findings kinds: ``bad_digest`` (node digest does not recompute),
    ``missing_parent`` (a parent link resolves nowhere), ``cycle``
    (a back-edge makes the lineage non-DAG).
    """
    findings: list[dict[str, Any]] = []
    try:
        for digest in graph.digests():
            node = graph.get(digest)
            if node is None:
                continue
            if not verify_node(node):
                findings.append({"kind": "bad_digest", "node": digest})
            for parent in node.parent_digests:
                if graph.get(parent) is None:
                    findings.append(
                        {
                            "kind": "missing_parent",
                            "node": digest,
                            "parent": parent,
                        }
                    )
        cycle = _find_cycle(graph)
        if cycle is not None:
            findings.append({"kind": "cycle", "path": list(cycle)})
    except Exception as exc:  # fail closed, never crash the caller
        findings.append({"kind": "verifier_error", "detail": str(exc)})
    return (len(findings) == 0, findings)


def lineage_walk(graph: ArtifactGraph, node_digest: str) -> tuple[str, ...]:
    """Transitive ancestors of ``node_digest`` (oldest last), cycle-guarded.

    A diamond merge visits shared ancestors once. On a cycle the walk
    stops at the repeated digest instead of looping forever.
    """
    seen: list[str] = []
    seen_set: set[str] = set()
    stack = [node_digest]
    while stack:
        current = stack.pop()
        if current in seen_set:
            continue
        node = graph.get(current)
        if node is None:
            continue
        seen_set.add(current)
        seen.append(current)
        for parent in node.parent_digests:
            if parent not in seen_set:
                stack.append(parent)
    # Drop the queried node itself: the walk returns *ancestors*.
    return tuple(d for d in seen if d != node_digest)


def diagnose(
    graph: ArtifactGraph, outcome_digest: str
) -> tuple[tuple[str, ...], list[dict[str, Any]]]:
    """Graph-based diagnosis of a bad outcome.

    Returns (suspects, findings). ``suspects`` is the outcome's full
    transitive lineage -- the candidate set, never a single verdict.
    Off-lineage nodes (decoys) are excluded by construction. ``findings``
    carries any integrity problems (missing parents, cycles) discovered
    along the walk, because a diagnosis drawn from a pruned or cyclic
    graph is a diagnosis of the graph's damage, not of the incident.
    """
    node = graph.get(outcome_digest)
    if node is None:
        return (), [{"kind": "unknown_outcome", "node": outcome_digest}]
    ok, integrity = verify_graph_integrity(graph)
    findings = list(integrity)
    suspects = lineage_walk(graph, outcome_digest)
    return suspects, findings


def graph_head_digest(graph: ArtifactGraph) -> str:
    """Head digest for out-of-band anchoring of the whole graph."""
    return "sha256:" + jcs_sha256_hex(sorted(graph.digests()))


def probe_names() -> tuple[str, ...]:
    """All artifact-graph attack probe names."""
    return tuple(p["probe"] for p in ARTIFACT_GRAPH_PROBES)


def benign_names() -> tuple[str, ...]:
    """All benign control names."""
    return tuple(p["probe"] for p in ARTIFACT_GRAPH_BENIGN)


def probes_by_family(family: str) -> tuple[dict[str, Any], ...]:
    """Attack probes in one family."""
    return tuple(p for p in ARTIFACT_GRAPH_PROBES if p["family"] == family)


def probe_by_name(name: str) -> dict[str, Any]:
    """Look up any probe (attack or benign) by name."""
    for probe in (*ARTIFACT_GRAPH_PROBES, *ARTIFACT_GRAPH_BENIGN):
        if probe["probe"] == name:
            return probe
    raise KeyError(name)


def expected_outcomes() -> dict[str, str]:
    """Map every probe name to its expected outcome."""
    return {
        p["probe"]: p["expected"]
        for p in (*ARTIFACT_GRAPH_PROBES, *ARTIFACT_GRAPH_BENIGN)
    }
