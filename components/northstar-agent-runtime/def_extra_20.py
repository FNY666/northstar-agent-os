"""Protocol version enforcement, Simulated.

Hard floor/ceiling on negotiable protocol versions: anything below
the minimum (e.g. TLS 1.0/1.1, SSL3) or above the maximum is
rejected before negotiation.

What this IS: version allowlist at the handshake boundary.

What this IS NOT:
* Not a TLS stack -- the host enforces the decision.
* Unknown or out-of-range versions FAIL CLOSED.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import List, Tuple

#: Module version.
DEF_EXTRA_20_VERSION = "def-extra-20.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.def-extra-20.v1"


class VersionPolicyError(Exception):
    """Fail-closed."""


#: Ordered versions, oldest to newest.
ORDERED_VERSIONS: List[str] = ["SSL3", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"]


@dataclass(frozen=True)
class VersionPolicy:
    """Allowed protocol version range [min_version, max_version]."""

    min_version: str = "TLS1.2"
    max_version: str = "TLS1.3"

    def __post_init__(self) -> None:
        if self.min_version not in ORDERED_VERSIONS:
            raise VersionPolicyError(f"unknown min_version: {self.min_version}")
        if self.max_version not in ORDERED_VERSIONS:
            raise VersionPolicyError(f"unknown max_version: {self.max_version}")
        if ORDERED_VERSIONS.index(self.min_version) > ORDERED_VERSIONS.index(
            self.max_version
        ):
            raise VersionPolicyError("min_version above max_version")


def enforce(version: str, policy: VersionPolicy) -> Tuple[bool, str]:
    """Check a version against the policy.  Fail closed."""
    if version not in ORDERED_VERSIONS:
        return False, f"unknown version: {version}"
    idx = ORDERED_VERSIONS.index(version)
    lo = ORDERED_VERSIONS.index(policy.min_version)
    hi = ORDERED_VERSIONS.index(policy.max_version)
    if idx < lo:
        return False, f"{version} below minimum {policy.min_version}"
    if idx > hi:
        return False, f"{version} above maximum {policy.max_version}"
    return True, "allowed"


def negotiate(
    offered: List[str], policy: VersionPolicy
) -> Tuple[bool, str, str]:
    """Pick the highest mutually acceptable version.

    Returns (ok, version, detail).  No overlap -> fail closed.
    """
    best = None
    for version in offered:
        ok, _ = enforce(version, policy)
        if ok and (best is None or ORDERED_VERSIONS.index(version) > ORDERED_VERSIONS.index(best)):
            best = version
    if best is None:
        return False, "", "no mutually acceptable version"
    return True, best, "negotiated"


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
    policy = VersionPolicy("TLS1.2", "TLS1.3")
    ok, _ = enforce("TLS1.3", policy)
    assert ok is True
    ok, detail = enforce("TLS1.0", policy)
    assert ok is False and "below minimum" in detail
    ok, _ = enforce("SSL3", policy)
    assert ok is False
    ok, _ = enforce("QUICv99", policy)
    assert ok is False
    ok, version, _ = negotiate(["TLS1.0", "TLS1.2", "TLS1.3"], policy)
    assert ok is True and version == "TLS1.3"
    ok, _, detail = negotiate(["TLS1.0", "TLS1.1"], policy)
    assert ok is False and "no mutually acceptable" in detail
    try:
        VersionPolicy("TLS1.3", "TLS1.2")
    except VersionPolicyError:
        pass
    else:
        raise AssertionError("expected VersionPolicyError")
    assert stdlib_only()
    print("def-extra-20 OK: floor, ceiling, negotiate")


if __name__ == "__main__":
    main()
