"""Runtime defense 09: network policies (egress rules), Simulated.

Egress rule engine: ordered rules matching (destination IP/port) with
first-match allow/deny.  Default-deny at the end.  Policy check only;
actual enforcement is via iptables/nftables/eBPF.

What this IS: ordered egress rule policy + matcher.
What this IS NOT: packet filtering.
"""

from __future__ import annotations

import ast
import ipaddress
from dataclasses import dataclass
from typing import List, Optional, Tuple

#: Module version.
RUNTIME_DEFENSE_09_VERSION = "runtime-defense-09.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-09.v1"


class NetPolicyError(Exception):
    """Fail-closed: bad rules raise."""


@dataclass(frozen=True)
class EgressRule:
    """One egress rule.  First match wins."""

    action: str  # "allow" or "deny"
    cidr: str  # destination network, e.g. "10.0.0.0/8" or "0.0.0.0/0"
    ports: Tuple[int, ...] = ()  # empty = any port
    description: str = ""

    def __post_init__(self):
        if self.action not in ("allow", "deny"):
            raise NetPolicyError(f"bad action {self.action!r}")
        try:
            ipaddress.ip_network(self.cidr)
        except ValueError:
            raise NetPolicyError(f"bad cidr {self.cidr!r}")
        for p in self.ports:
            if not 0 < p <= 65535:
                raise NetPolicyError(f"bad port {p}")

    def matches(self, ip: str, port: int) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        net = ipaddress.ip_network(self.cidr)
        if addr not in net:
            return False
        if self.ports and port not in self.ports:
            return False
        return True


@dataclass
class NetworkPolicy:
    """Ordered egress rules; default-deny."""

    rules: List[EgressRule]

    def check(self, ip: str, port: int) -> Tuple[bool, str]:
        """First-match.  Returns (allowed, reason).  No match -> deny."""
        for rule in self.rules:
            if rule.matches(ip, port):
                return (rule.action == "allow",
                        f"{rule.action} by rule: {rule.description or rule.cidr}")
        return False, "default deny: no rule matched"


def default_policy() -> NetworkPolicy:
    """Default: allow DNS + HTTPS to anywhere, deny the rest."""
    return NetworkPolicy(rules=[
        EgressRule("allow", "0.0.0.0/0", (53,), "dns"),
        EgressRule("allow", "0.0.0.0/0", (443,), "https"),
        EgressRule("deny", "10.0.0.0/8", (), "no rfc1918"),
        EgressRule("deny", "172.16.0.0/12", (), "no rfc1918"),
        EgressRule("deny", "192.168.0.0/16", (), "no rfc1918"),
        EgressRule("deny", "169.254.0.0/16", (), "no link-local/metadata"),
    ])


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "ipaddress", "pathlib", "typing"}
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
    pol = default_policy()
    ok, _ = pol.check("8.8.8.8", 443)
    assert ok is True
    ok, _ = pol.check("8.8.8.8", 53)
    assert ok is True
    ok, _ = pol.check("8.8.8.8", 80)
    assert ok is False  # http not allowed
    ok, reason = pol.check("10.1.2.3", 443)
    assert ok is False  # rfc1918 denied even on 443
    ok, _ = pol.check("169.254.169.254", 80)
    assert ok is False  # metadata endpoint blocked

    try:
        EgressRule("maybe", "0.0.0.0/0")
        raise AssertionError("should raise")
    except NetPolicyError:
        pass

    assert stdlib_only()
    print("runtime-defense-09 OK: egress rules, default-deny, stdlib")


if __name__ == "__main__":
    main()
