"""Forensic collection: mock artifact collection, Simulated.

Collector kinds: memory, disk, logs, network, config.
A job targets one endpoint; artifacts are host-supplied bytes (or
deterministic mock bytes from mock_artifact). Each artifact gets a
sha256; manifest() emits the artifact list plus a manifest hash for
chain-of-custody handoff.

What this IS: collection bookkeeping + manifest hashing.

What this IS NOT:
* Not real acquisition -- no live capture.
"""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List

#: Module version.
MONITOR_27_VERSION = "monitor-27.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-27.v1"

_COLLECTORS = frozenset({"memory", "disk", "logs", "network", "config"})


class ForensicError(Exception):
    """Fail-closed."""


def mock_artifact(name: str, size: int, seed: str = "northstar") -> bytes:
    """Deterministic mock artifact bytes (for tests/demos)."""
    if size < 0:
        raise ForensicError("size must be >= 0")
    out = bytearray()
    counter = 0
    while len(out) < size:
        out.extend(hashlib.sha256(f"{seed}:{name}:{counter}".encode()).digest())
        counter += 1
    return bytes(out[:size])


@dataclass(frozen=True)
class Artifact:
    name: str
    collector: str
    size: int
    sha256: str


@dataclass
class CollectionJob:
    job_id: str
    target: str
    collectors: frozenset
    artifacts: List[Artifact] = field(default_factory=list)

    def add_artifact(self, name: str, collector: str, data: bytes) -> Artifact:
        if not name or "/" in name or "\\" in name or ".." in name:
            raise ForensicError(f"unsafe artifact name {name!r}")
        if collector not in self.collectors:
            raise ForensicError(f"collector {collector!r} not in job")
        if not isinstance(data, (bytes, bytearray)):
            raise ForensicError("data must be bytes")
        art = Artifact(
            name, collector, len(data),
            "sha256:" + hashlib.sha256(bytes(data)).hexdigest(),
        )
        self.artifacts.append(art)
        return art

    def manifest(self) -> Dict[str, object]:
        items = [
            {"name": a.name, "collector": a.collector,
             "size": a.size, "sha256": a.sha256}
            for a in self.artifacts
        ]
        canonical = json.dumps(
            {"job_id": self.job_id, "target": self.target, "artifacts": items},
            sort_keys=True, separators=(",", ":"),
        )
        return {
            "job_id": self.job_id,
            "target": self.target,
            "artifacts": items,
            "manifest_hash": "sha256:" + hashlib.sha256(canonical.encode()).hexdigest(),
        }


class ForensicCollector:
    """Mock forensic collection coordinator."""

    def __init__(self) -> None:
        self._jobs: Dict[str, CollectionJob] = {}
        self._next = 1

    def start_job(self, target: str, collectors: List[str]) -> str:
        if not target:
            raise ForensicError("target required")
        unknown = set(collectors) - _COLLECTORS
        if unknown:
            raise ForensicError(f"unknown collectors {sorted(unknown)}")
        if not collectors:
            raise ForensicError("at least one collector required")
        job_id = f"FC-{self._next:04d}"
        self._next += 1
        self._jobs[job_id] = CollectionJob(job_id, target, frozenset(collectors))
        return job_id

    def job(self, job_id: str) -> CollectionJob:
        job = self._jobs.get(job_id)
        if job is None:
            raise ForensicError(f"unknown job {job_id!r}")
        return job


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "hashlib", "json", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    fc = ForensicCollector()
    jid = fc.start_job("WS-01", ["memory", "logs"])
    job = fc.job(jid)
    a1 = job.add_artifact("mem.dmp", "memory", mock_artifact("mem.dmp", 64))
    a2 = job.add_artifact("syslog", "logs", b"log-bytes")
    assert a1.size == 64 and a1.sha256.startswith("sha256:")
    assert mock_artifact("mem.dmp", 64) == mock_artifact("mem.dmp", 64)
    m = job.manifest()
    assert m["manifest_hash"].startswith("sha256:")
    assert len(m["artifacts"]) == 2  # type: ignore
    for bad in (
        lambda: fc.start_job("", ["logs"]),
        lambda: fc.start_job("WS-02", []),
        lambda: fc.start_job("WS-02", ["xray"]),
        lambda: fc.job("FC-9999"),
        lambda: job.add_artifact("../evil", "logs", b"x"),
        lambda: job.add_artifact("ok", "disk", b"x"),  # disk not in job
        lambda: job.add_artifact("ok", "logs", "not-bytes"),  # type: ignore
        lambda: mock_artifact("x", -1),
    ):
        try:
            bad()
            raise AssertionError("should raise")
        except ForensicError:
            pass
    assert stdlib_only()
    print("monitor-27 OK: jobs, artifacts, manifest hash, fail-closed, stdlib")


if __name__ == "__main__":
    main()
