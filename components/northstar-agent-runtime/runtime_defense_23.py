"""Runtime defense 23: Audit logging (mock), Simulated.

Append-only in-memory audit log for security events.  Records are
hash-chained (each entry commits to the previous) so tampering is
detectable.  This is a mock: production sinks to WORM storage.

What this IS: hash-chained event ledger for runtime defenses.

What this IS NOT:
* Not durable -- memory only; host persists to WORM.
"""

from __future__ import annotations

import ast
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

#: Module version.
RUNTIME_DEFENSE_23_VERSION = "runtime-defense-23.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-23.v1"


class AuditError(Exception):
    """Fail-closed: bad records raise."""


@dataclass(frozen=True)
class AuditRecord:
    """One audit record."""

    seq: int
    ts: float
    event: str
    details: Dict[str, Any]
    prev_hash: str
    record_hash: str


def _hash_record(seq: int, ts: float, event: str, details: Dict[str, Any],
                 prev_hash: str) -> str:
    canonical = json.dumps(
        {"seq": seq, "ts": ts, "event": event,
         "details": details, "prev_hash": prev_hash},
        sort_keys=True, separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


@dataclass
class AuditLog:
    """Append-only mock audit log."""

    records: List[AuditRecord] = field(default_factory=list)

    def append(self, event: str, details: Optional[Dict[str, Any]] = None) -> AuditRecord:
        """Append an event; returns the sealed record."""
        if not event or not event.strip():
            raise AuditError("event required")
        details = dict(details or {})
        seq = len(self.records)
        prev_hash = self.records[-1].record_hash if self.records else "sha256:GENESIS"
        ts = time.time()
        record_hash = _hash_record(seq, ts, event, details, prev_hash)
        record = AuditRecord(seq, ts, event, details, prev_hash, record_hash)
        self.records.append(record)
        return record

    def verify_chain(self) -> bool:
        """Verify the hash chain.  True if intact."""
        prev = "sha256:GENESIS"
        for record in self.records:
            if record.prev_hash != prev:
                return False
            expected = _hash_record(
                record.seq, record.ts, record.event, record.details,
                record.prev_hash,
            )
            if record.record_hash != expected:
                return False
            prev = record.record_hash
        return True


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "hashlib", "json", "pathlib", "time", "typing"}
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
    log = AuditLog()
    r1 = log.append("gate.deny", {"tool": "exec"})
    r2 = log.append("kill.switch", {"scope": "task"})
    assert r1.seq == 0
    assert r2.prev_hash == r1.record_hash
    assert log.verify_chain() is True
    try:
        log.append("")
        raise AssertionError("should raise")
    except AuditError:
        pass
    assert stdlib_only()
    print("runtime-defense-23 OK: audit log, hash chain, fail-closed")


if __name__ == "__main__":
    main()
