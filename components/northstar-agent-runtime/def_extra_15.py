"""Certificate Transparency enforcement (mock), Simulated.

Requires a quorum of Signed Certificate Timestamps (SCTs) from
distinct KNOWN logs before a certificate is accepted.  SCTs from
unknown logs do not count.

What this IS: multi-log quorum policy for cert acceptance.

What this IS NOT:
* Not real CT -- SCTs are HMAC stand-ins, no Merkle proofs.
* Quorum not met or unknown log -> FAIL CLOSED (reject).
"""

from __future__ import annotations

import ast
import hashlib
import hmac
from dataclasses import dataclass
from typing import Dict, List, Tuple

#: Module version.
DEF_EXTRA_15_VERSION = "def-extra-15.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.def-extra-15.v1"


class CTError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class SCT:
    """Signed Certificate Timestamp (mock)."""

    log_id: str
    cert_hash: str
    mac: str


class CTEnforcer:
    """Enforce SCT quorum from known logs."""

    def __init__(self, log_keys: Dict[str, bytes], *, quorum: int = 2) -> None:
        if quorum < 1:
            raise CTError("quorum must be >= 1")
        if not log_keys:
            raise CTError("at least one known log required")
        self._log_keys = dict(log_keys)
        self._quorum = quorum

    def issue_sct(self, log_id: str, cert_hash: str) -> SCT:
        """Test helper: a known log issues an SCT."""
        key = self._log_keys.get(log_id)
        if key is None:
            raise CTError(f"unknown log: {log_id}")
        mac = hmac.new(
            key, f"{log_id}:{cert_hash}".encode(), hashlib.sha256
        ).hexdigest()
        return SCT(log_id, cert_hash, mac)

    def verify_quorum(self, cert_hash: str, scts: List[SCT]) -> Tuple[bool, str]:
        """Require >= quorum valid SCTs from distinct known logs."""
        if not cert_hash:
            return False, "cert_hash required"
        valid_logs = set()
        for sct in scts:
            if sct.cert_hash != cert_hash:
                continue
            key = self._log_keys.get(sct.log_id)
            if key is None:
                continue  # unknown log: does not count
            expected = hmac.new(
                key, f"{sct.log_id}:{sct.cert_hash}".encode(), hashlib.sha256
            ).hexdigest()
            if hmac.compare_digest(expected, sct.mac):
                valid_logs.add(sct.log_id)
        if len(valid_logs) >= self._quorum:
            return True, f"quorum met ({len(valid_logs)}/{self._quorum})"
        return False, f"quorum not met ({len(valid_logs)}/{self._quorum})"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "hashlib", "hmac", "pathlib", "typing"}
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
    enforcer = CTEnforcer({"log-a": b"ka", "log-b": b"kb", "log-c": b"kc"}, quorum=2)
    cert = "sha256:cert123"
    sct_a = enforcer.issue_sct("log-a", cert)
    sct_b = enforcer.issue_sct("log-b", cert)
    ok, reason = enforcer.verify_quorum(cert, [sct_a, sct_b])
    assert ok is True, reason
    # Single SCT below quorum -> reject.
    ok, _ = enforcer.verify_quorum(cert, [sct_a])
    assert ok is False
    # SCT from unknown log does not count.
    rogue = SCT("log-evil", cert, "deadbeef")
    ok, _ = enforcer.verify_quorum(cert, [sct_a, rogue])
    assert ok is False
    # SCT for a different cert does not count.
    other = enforcer.issue_sct("log-b", "sha256:other")
    ok, _ = enforcer.verify_quorum(cert, [sct_a, other])
    assert ok is False
    assert stdlib_only()
    print("def-extra-15 OK: quorum, unknown logs, binding")


if __name__ == "__main__":
    main()
