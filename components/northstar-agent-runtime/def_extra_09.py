"""Audit trail verification, Simulated.

Verifies a sequence of audit entries: sequence numbers must be
monotonic with no gaps, and each entry's prev_hash must link to the
previous entry's hash.

What this IS: structural integrity check for audit logs.

What this IS NOT:
* Not cryptographic provenance -- hashes are computed by the host;
  this only checks the chain structure.
* First bad entry reported; verification FAILS CLOSED on any break.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import List, Tuple

#: Module version.
DEF_EXTRA_09_VERSION = "def-extra-09.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.def-extra-09.v1"


class AuditTrailError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class AuditEntry:
    """One audit record."""

    seq: int
    prev_hash: str
    entry_hash: str
    action: str


def verify_trail(entries: List[AuditEntry]) -> Tuple[bool, str]:
    """Verify seq continuity and hash linkage.

    Returns (ok, detail).  Empty trail is ok ("empty trail").
    """
    if not entries:
        return True, "empty trail"
    expected_seq = entries[0].seq
    prev_hash = entries[0].prev_hash
    for entry in entries:
        if entry.seq != expected_seq:
            return False, f"seq gap at {entry.seq}, expected {expected_seq}"
        if entry.seq != entries[0].seq and entry.prev_hash != prev_hash:
            return False, f"hash link broken at seq {entry.seq}"
        if not entry.entry_hash:
            return False, f"missing hash at seq {entry.seq}"
        expected_seq += 1
        prev_hash = entry.entry_hash
    return True, "trail ok"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
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
    trail = [
        AuditEntry(1, "genesis", "h1", "start"),
        AuditEntry(2, "h1", "h2", "allow"),
        AuditEntry(3, "h2", "h3", "deny"),
    ]
    ok, detail = verify_trail(trail)
    assert ok is True, detail
    # Seq gap.
    bad = trail[:2] + [AuditEntry(4, "h2", "h4", "allow")]
    ok, detail = verify_trail(bad)
    assert ok is False and "gap" in detail
    # Broken link.
    bad2 = trail[:2] + [AuditEntry(3, "WRONG", "h3", "deny")]
    ok, detail = verify_trail(bad2)
    assert ok is False and "link" in detail
    # Empty ok.
    ok, _ = verify_trail([])
    assert ok is True
    assert stdlib_only()
    print("def-extra-09 OK: chain, gaps, broken links")


if __name__ == "__main__":
    main()
