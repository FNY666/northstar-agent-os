"""Runtime defense 24: Integrity monitoring (mock), Simulated.

Tracks expected content hashes for guarded files.  Re-hashing and
comparing detects unauthorized modification.  Mock: hashes are
registered by the host, not read from a manifest.

What this IS: expected-hash registry + drift check.

What this IS NOT:
* Not a file watcher -- host triggers re-checks.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

#: Module version.
RUNTIME_DEFENSE_24_VERSION = "runtime-defense-24.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-24.v1"


class IntegrityError(Exception):
    """Fail-closed: bad registrations raise."""


def sha256_text(text: str) -> str:
    """Hash helper."""
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class IntegrityMonitor:
    """Registry of expected hashes."""

    expected: Dict[str, str] = field(default_factory=dict)

    def register(self, path: str, content_hash: str) -> None:
        """Register the expected hash for a path."""
        if not path:
            raise IntegrityError("path required")
        if not content_hash.startswith("sha256:"):
            raise IntegrityError("content_hash must be sha256:-pinned")
        self.expected[path] = content_hash

    def check(self, path: str, current_hash: str) -> Tuple[bool, str]:
        """Check current hash against expected.  (ok, reason)."""
        if path not in self.expected:
            return False, f"unregistered path '{path}'"
        if current_hash != self.expected[path]:
            return False, f"drift detected on '{path}'"
        return True, "integrity ok"

    def drifted(self, current: Dict[str, str]) -> List[str]:
        """Return paths whose current hash differs from expected."""
        bad = []
        for path, expected in self.expected.items():
            if current.get(path) != expected:
                bad.append(path)
        return bad


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "hashlib", "pathlib", "typing"}
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
    mon = IntegrityMonitor()
    mon.register("/etc/policy.yaml", sha256_text("v1"))
    ok, _ = mon.check("/etc/policy.yaml", sha256_text("v1"))
    assert ok is True
    ok, reason = mon.check("/etc/policy.yaml", sha256_text("v2"))
    assert ok is False
    assert "drift" in reason
    ok, _ = mon.check("/unknown", sha256_text("x"))
    assert ok is False
    assert mon.drifted({"/etc/policy.yaml": sha256_text("v9")}) == ["/etc/policy.yaml"]
    try:
        mon.register("", sha256_text("x"))
        raise AssertionError("should raise")
    except IntegrityError:
        pass
    assert stdlib_only()
    print("runtime-defense-24 OK: integrity monitor, drift, fail-closed")


if __name__ == "__main__":
    main()
