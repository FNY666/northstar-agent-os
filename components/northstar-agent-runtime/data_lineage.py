"""Provenance DAG for ML data: which datasets derived from which sources.

A data lineage tracker answers "where did this dataset come from?" -- the
question every ML audit, data-deletion request, and contamination review
starts with. :meth:`DataLineage.track` records one derivation edge:
``data_id`` was produced from one or more parent sources through an
optional named transform (``"filter"``, ``"join"``, ``"train"``,
``"tokenize"``). External origins (a bucket prefix, a vendor dump, a
crawl snapshot) are declared up front with
:meth:`DataLineage.register_source`; every parent of a tracked dataset
must be a registered source or an already-tracked dataset, so the graph
is closed under its own claims.

Each record carries a ``sha256:`` digest pin over its canonical body
(data id, sorted parents, transform, seq), so a verifier can re-derive
every pin from the claimed fields. :meth:`DataLineage.lineage` returns
the full ancestor closure of a dataset in deterministic topological
order (root sources first), and :meth:`DataLineage.verify` re-checks
digest pins, parent resolution, acyclicity, and temporal causality
(a child's ``seq`` must be strictly greater than every parent's --
a dataset cannot be derived before its inputs existed).

House style: frozen dataclasses, no wall-clock (all caller-supplied int
seqs), fail-closed validation, stdlib-only, deterministic, version pin
``data-lineage.v1``, schema pin ``northstar.data-lineage.v1``.

Honest scope: this module pins *reported* provenance, nothing else. It
cannot observe an unreported copy, an unreported transform, or a
dataset that was never tracked -- the host chooses what to record. A
registered source is a *claim* ("this came from s3://bucket/raw"), not
a verified fact; the digest pins bind record identity, not data truth.
``verify() == True`` means "the recorded graph is internally
consistent", never "the data really came from these sources". State is
in-memory; persistence is the host's job.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple


#: Version pin for this module's record shape.
DATA_LINEAGE_VERSION = "data-lineage.v1"

#: Schema pin carried on audit records.
DATA_LINEAGE_SCHEMA = "northstar.data-lineage.v1"

#: Digest domain prefix (binds pins to this module).
_DIGEST_DOMAIN = b"northstar.data-lineage.v1/record\x00"


class DataLineageError(Exception):
    """Base error for data-lineage failures."""


class UnknownParentError(DataLineageError):
    """A track() parent is neither a registered source nor a tracked dataset."""


class DuplicateIdError(DataLineageError):
    """A data id or source name is already registered/tracked."""


class SeqCausalityError(DataLineageError):
    """A track() seq does not strictly follow every parent's seq."""


class LineageVerificationError(DataLineageError):
    """Raised by verify_strict() on the first inconsistent record."""

    def __init__(self, reason: str, data_id: Optional[str] = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.data_id = data_id


def _check_seq(seq: object, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"{what} must be an int")
    if seq < 0:
        raise ValueError(f"{what} must be non-negative")
    return seq


def _check_name(name: object, what: str) -> str:
    if not isinstance(name, str):
        raise TypeError(f"{what} must be a str")
    if not name:
        raise ValueError(f"{what} must be non-empty")
    return name


def _check_parents(parents: object) -> Tuple[str, ...]:
    if isinstance(parents, (str, bytes)) or not isinstance(parents, Iterable):
        raise TypeError("sources must be a non-empty iterable of str")
    items = tuple(parents)
    if not items:
        raise ValueError("sources must be non-empty")
    for p in items:
        _check_name(p, "source")
    if len(set(items)) != len(items):
        raise ValueError("duplicate sources are not allowed")
    return items


def _record_digest(data_id: str, parents: Tuple[str, ...], transform: Optional[str], seq: int) -> str:
    body = json.dumps(
        {
            "data_id": data_id,
            "parents": sorted(parents),
            "transform": transform,
            "seq": seq,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(_DIGEST_DOMAIN + body).hexdigest()


def _source_digest(name: str, seq: int) -> str:
    body = json.dumps(
        {"source": name, "seq": seq},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(_DIGEST_DOMAIN + b"source\x00" + body).hexdigest()


@dataclass(frozen=True)
class ExternalSource:
    """A declared external origin (bucket prefix, vendor dump, crawl snapshot)."""

    name: str
    seq: int
    digest: str
    schema: str = field(default=DATA_LINEAGE_SCHEMA)

    def __post_init__(self) -> None:
        _check_name(self.name, "name")
        _check_seq(self.seq)
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise ValueError("digest must be a sha256: pin")
        if self.schema != DATA_LINEAGE_SCHEMA:
            raise ValueError("schema pin mismatch")

    def as_dict(self) -> dict:
        return {"name": self.name, "seq": self.seq, "digest": self.digest, "schema": self.schema}


@dataclass(frozen=True)
class LineageRecord:
    """One derivation edge: data_id was produced from parents via transform."""

    data_id: str
    parents: Tuple[str, ...]
    transform: Optional[str]
    seq: int
    digest: str
    schema: str = field(default=DATA_LINEAGE_SCHEMA)

    def __post_init__(self) -> None:
        _check_name(self.data_id, "data_id")
        _check_parents(self.parents)
        if self.transform is not None:
            _check_name(self.transform, "transform")
        _check_seq(self.seq)
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise ValueError("digest must be a sha256: pin")
        if self.schema != DATA_LINEAGE_SCHEMA:
            raise ValueError("schema pin mismatch")

    def verify_digest(self) -> bool:
        """Recompute the digest pin from the claimed fields."""
        import hmac

        expected = _record_digest(self.data_id, self.parents, self.transform, self.seq)
        return hmac.compare_digest(expected, self.digest)

    def as_dict(self) -> dict:
        return {
            "data_id": self.data_id,
            "parents": list(self.parents),
            "transform": self.transform,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class LineageNode:
    """One node of a lineage path: id, its direct parents, depth from a root."""

    data_id: str
    parents: Tuple[str, ...]
    depth: int

    def as_dict(self) -> dict:
        return {"data_id": self.data_id, "parents": list(self.parents), "depth": self.depth}


@dataclass(frozen=True)
class LineagePath:
    """Full ancestor closure of a dataset, root sources first."""

    data_id: str
    nodes: Tuple[LineageNode, ...]
    schema: str = field(default=DATA_LINEAGE_SCHEMA)

    def ids(self) -> Tuple[str, ...]:
        return tuple(n.data_id for n in self.nodes)

    def as_dict(self) -> dict:
        return {
            "data_id": self.data_id,
            "nodes": [n.as_dict() for n in self.nodes],
            "schema": self.schema,
        }


@dataclass(frozen=True)
class LineageVerification:
    """Outcome of verify(): internal consistency of the recorded graph."""

    ok: bool
    records_checked: int
    issues: Tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "records_checked": self.records_checked,
            "issues": list(self.issues),
        }


class DataLineage:
    """Provenance DAG: register external sources, track derivations, verify."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sources: Dict[str, ExternalSource] = {}
        self._records: Dict[str, LineageRecord] = {}
        self._seqs: Dict[str, int] = {}  # every known id -> its registration seq

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    def register_source(self, name: str, seq: int) -> ExternalSource:
        """Declare an external origin. Names share one namespace with data ids."""
        _check_name(name, "name")
        _check_seq(seq)
        with self._lock:
            if name in self._seqs:
                raise DuplicateIdError(f"id already known: {name!r}")
            src = ExternalSource(name=name, seq=seq, digest=_source_digest(name, seq))
            self._sources[name] = src
            self._seqs[name] = seq
            return src

    def track(
        self,
        data_id: str,
        sources: Iterable[str],
        seq: int,
        transform: Optional[str] = None,
    ) -> LineageRecord:
        """Record that ``data_id`` was derived from ``sources`` via ``transform``."""
        _check_name(data_id, "data_id")
        parents = _check_parents(sources)
        _check_seq(seq)
        if transform is not None:
            _check_name(transform, "transform")
        with self._lock:
            if data_id in self._seqs:
                raise DuplicateIdError(f"id already known: {data_id!r}")
            for p in parents:
                if p == data_id:
                    raise DataLineageError("a dataset cannot derive from itself")
                if p not in self._seqs:
                    raise UnknownParentError(f"unknown parent: {p!r}")
                if self._seqs[p] >= seq:
                    raise SeqCausalityError(
                        f"parent {p!r} seq {self._seqs[p]} is not before child seq {seq}"
                    )
            rec = LineageRecord(
                data_id=data_id,
                parents=parents,
                transform=transform,
                seq=seq,
                digest=_record_digest(data_id, parents, transform, seq),
            )
            self._records[data_id] = rec
            self._seqs[data_id] = seq
            return rec

    def sources(self) -> Tuple[str, ...]:
        """Registered external source names, in registration order."""
        with self._lock:
            return tuple(self._sources)

    def datasets(self) -> Tuple[str, ...]:
        """Tracked dataset ids, in track order."""
        with self._lock:
            return tuple(self._records)

    def record(self, data_id: str) -> Optional[LineageRecord]:
        with self._lock:
            return self._records.get(data_id)

    def children(self, data_id: str) -> Tuple[str, ...]:
        """Directly derived datasets of ``data_id``, sorted for determinism."""
        _check_name(data_id, "data_id")
        with self._lock:
            return tuple(sorted(d for d, r in self._records.items() if data_id in r.parents))

    def lineage(self, data_id: str) -> LineagePath:
        """Full ancestor closure of ``data_id``, root sources first.

        Multi-parent graphs are emitted in deterministic topological
        order (Kahn's algorithm, ties broken by ``(seq, id)``); each
        node carries its longest-path depth from a root source.
        """
        _check_name(data_id, "data_id")
        with self._lock:
            if data_id not in self._records and data_id not in self._sources:
                raise DataLineageError(f"unknown id: {data_id!r}")
            # Ancestor closure (tracked records only; sources are roots).
            closure: Dict[str, LineageRecord] = {}
            stack = [data_id]
            while stack:
                cur = stack.pop()
                rec = self._records.get(cur)
                if rec is None or cur in closure:
                    continue
                closure[cur] = rec
                stack.extend(p for p in rec.parents if p in self._records)
            # Deterministic topological order over the closure.
            indeg: Dict[str, int] = {d: 0 for d in closure}
            dependents: Dict[str, List[str]] = {d: [] for d in closure}
            for d, rec in closure.items():
                for p in rec.parents:
                    if p in closure:
                        indeg[d] += 1
                        dependents[p].append(d)
            ready = sorted(
                (d for d, n in indeg.items() if n == 0),
                key=lambda d: (self._seqs[d], d),
            )
            order: List[str] = []
            while ready:
                cur = ready.pop(0)
                order.append(cur)
                for dep in dependents[cur]:
                    indeg[dep] -= 1
                    if indeg[dep] == 0:
                        ready.append(dep)
                ready.sort(key=lambda d: (self._seqs[d], d))
            # Depth = longest path from a root source.
            depth: Dict[str, int] = {}
            for d in order:
                rec = closure[d]
                parent_depths = [depth[p] for p in rec.parents if p in depth]
                depth[d] = (max(parent_depths) + 1) if parent_depths else 1
            # Root sources that feed the closure, registration order.
            root_names = sorted(
                {p for rec in closure.values() for p in rec.parents if p in self._sources}
                | ({data_id} if data_id in self._sources else set()),
                key=lambda n: (self._seqs[n], n),
            )
            nodes = [LineageNode(data_id=n, parents=(), depth=0) for n in root_names]
            nodes.extend(
                LineageNode(data_id=d, parents=closure[d].parents, depth=depth[d]) for d in order
            )
            return LineagePath(data_id=data_id, nodes=tuple(nodes))

    def verify(self) -> LineageVerification:
        """Re-check internal consistency; returns a report (never raises)."""
        issues: List[str] = []
        with self._lock:
            records = list(self._records.values())
            seqs = dict(self._seqs)
        for rec in records:
            if not rec.verify_digest():
                issues.append(f"digest mismatch: {rec.data_id!r}")
            for p in rec.parents:
                if p not in seqs:
                    issues.append(f"dangling parent {p!r} of {rec.data_id!r}")
                elif seqs[p] >= rec.seq:
                    issues.append(f"seq causality violated: {p!r} -> {rec.data_id!r}")
        # Acyclicity over tracked records.
        color: Dict[str, int] = {}  # 0=unvisited, 1=in-stack, 2=done
        rec_map = {r.data_id: r for r in records}

        def visit(node: str, path: List[str]) -> None:
            color[node] = 1
            path.append(node)
            for p in rec_map[node].parents:
                if p not in rec_map:
                    continue
                c = color.get(p, 0)
                if c == 1:
                    issues.append(
                        "cycle: " + " -> ".join(path[path.index(p):] + [p])
                    )
                elif c == 0:
                    visit(p, path)
            path.pop()
            color[node] = 2

        for r in records:
            if color.get(r.data_id, 0) == 0:
                visit(r.data_id, [])
        return LineageVerification(
            ok=not issues,
            records_checked=len(records),
            issues=tuple(issues),
        )

    def verify_strict(self) -> None:
        """Like verify(), but raises LineageVerificationError on the first issue."""
        report = self.verify()
        if not report.ok:
            first = report.issues[0]
            raise LineageVerificationError(first)


def data_lineage_audit_event(kind: str, lineage: DataLineage, seq: int) -> dict:
    """Shape a data-lineage lifecycle event as an ``audit.ndjson/1`` record."""
    valid = ("source-registered", "tracked", "verified", "verification-failed")
    if kind not in valid:
        raise ValueError(f"unknown audit kind {kind!r}")
    if not isinstance(lineage, DataLineage):
        raise TypeError("lineage must be a DataLineage")
    _check_seq(seq)
    return {
        "schema": "audit.ndjson/1",
        "kind": f"data-lineage.{kind}",
        "module": DATA_LINEAGE_SCHEMA,
        "version": DATA_LINEAGE_VERSION,
        "seq": seq,
        "sources": len(lineage.sources()),
        "datasets": len(lineage.datasets()),
    }


def main() -> None:
    lin = DataLineage()
    lin.register_source("s3://bucket/raw-2026-10", 0)
    lin.register_source("vendor-acme-v3", 1)
    a = lin.track("cleaned", ("s3://bucket/raw-2026-10",), 2, transform="filter")
    b = lin.track("features", ("cleaned", "vendor-acme-v3"), 3, transform="join")
    assert a.verify_digest() is True
    assert b.parents == ("cleaned", "vendor-acme-v3")
    path = lin.lineage("features")
    assert path.ids() == (
        "s3://bucket/raw-2026-10",
        "vendor-acme-v3",
        "cleaned",
        "features",
    ), path.ids()
    assert [n.depth for n in path.nodes] == [0, 0, 1, 2]
    assert lin.children("cleaned") == ("features",)
    assert lin.verify().ok is True
    lin.verify_strict()
    ev = data_lineage_audit_event("tracked", lin, 4)
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["datasets"] == 2
    print("data-lineage OK: register, track, lineage, verify")


if __name__ == "__main__":
    main()
