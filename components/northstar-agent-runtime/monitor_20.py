"""Honeypots: mock honeypot services, Simulated.

Honeypot services: ssh, http, smb, ftp, telnet. The host feeds
connection events: connect, auth_attempt, auth_success, command.
Per-source-IP attempt counting; auto-ban after N attempts; critical
alert on auth_success; alert on banned-IP retry.

What this IS: interaction logging + auto-ban bookkeeping.

What this IS NOT:
* Not a network listener -- events are host-supplied.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Set

#: Module version.
MONITOR_20_VERSION = "monitor-20.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-20.v1"

_SERVICES = frozenset({"ssh", "http", "smb", "ftp", "telnet"})
_EVENTS = frozenset({"connect", "auth_attempt", "auth_success", "command"})


class HoneypotError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class Honeypot:
    service: str
    endpoint_id: str
    port: int


@dataclass(frozen=True)
class HoneypotAlert:
    kind: str  # auth_success, banned, banned_ip_retry
    endpoint_id: str
    src_ip: str
    severity: int
    detail: str
    ts: float


class Honeynet:
    """Mock honeynet."""

    def __init__(self, *, ban_threshold: int = 5) -> None:
        if ban_threshold <= 0:
            raise HoneypotError("ban_threshold must be positive")
        self._ban_n = ban_threshold
        self._pots: Dict[str, Honeypot] = {}
        self._attempts: Dict[str, int] = {}
        self._banned: Set[str] = set()
        self._alerts: List[HoneypotAlert] = []
        self._log: List[Dict[str, object]] = []

    def deploy(self, service: str, endpoint_id: str, port: int) -> None:
        if service not in _SERVICES:
            raise HoneypotError(f"unknown service {service!r}")
        if not endpoint_id:
            raise HoneypotError("endpoint_id required")
        if not 1 <= port <= 65535:
            raise HoneypotError("port must be 1-65535")
        if endpoint_id in self._pots:
            raise HoneypotError(f"endpoint {endpoint_id!r} already deployed")
        self._pots[endpoint_id] = Honeypot(service, endpoint_id, port)

    def connection(
        self, endpoint_id: str, src_ip: str, event: str, ts: float = 0.0,
        detail: str = "",
    ) -> None:
        pot = self._pots.get(endpoint_id)
        if pot is None:
            raise HoneypotError(f"unknown endpoint {endpoint_id!r}")
        if not src_ip:
            raise HoneypotError("src_ip required")
        if event not in _EVENTS:
            raise HoneypotError(f"unknown event {event!r}")
        if ts < 0:
            raise HoneypotError("ts must be >= 0")
        self._log.append(
            {"endpoint": endpoint_id, "src": src_ip, "event": event, "ts": ts}
        )
        if src_ip in self._banned:
            self._alerts.append(HoneypotAlert(
                "banned_ip_retry", endpoint_id, src_ip, 60,
                "banned IP reconnected", ts,
            ))
            return
        if event in ("auth_attempt", "auth_success", "command"):
            self._attempts[src_ip] = self._attempts.get(src_ip, 0) + 1
            if self._attempts[src_ip] >= self._ban_n and src_ip not in self._banned:
                self._banned.add(src_ip)
                self._alerts.append(HoneypotAlert(
                    "banned", endpoint_id, src_ip, 75,
                    f"{self._attempts[src_ip]} attempts", ts,
                ))
        if event == "auth_success":
            self._alerts.append(HoneypotAlert(
                "auth_success", endpoint_id, src_ip, 95,
                detail or "attacker authenticated", ts,
            ))

    def is_banned(self, src_ip: str) -> bool:
        return src_ip in self._banned

    def alerts(self) -> List[HoneypotAlert]:
        return list(self._alerts)

    def stats(self) -> Dict[str, int]:
        return {
            "honeypots": len(self._pots),
            "events": len(self._log),
            "banned_ips": len(self._banned),
            "alerts": len(self._alerts),
        }


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
    hn = Honeynet(ban_threshold=3)
    hn.deploy("ssh", "hp-ssh-1", 2222)
    hn.deploy("http", "hp-web-1", 8080)
    hn.connection("hp-ssh-1", "9.9.9.9", "connect", ts=1.0)
    hn.connection("hp-ssh-1", "9.9.9.9", "auth_attempt", ts=2.0)
    hn.connection("hp-ssh-1", "9.9.9.9", "auth_attempt", ts=3.0)
    assert hn.is_banned("9.9.9.9") is False
    hn.connection("hp-ssh-1", "9.9.9.9", "auth_attempt", ts=4.0)
    assert hn.is_banned("9.9.9.9") is True
    assert any(a.kind == "banned" for a in hn.alerts())
    hn.connection("hp-ssh-1", "9.9.9.9", "connect", ts=5.0)
    assert any(a.kind == "banned_ip_retry" for a in hn.alerts())
    hn.connection("hp-web-1", "8.8.8.8", "auth_success", ts=6.0, detail="admin/admin")
    assert any(a.kind == "auth_success" and a.severity == 95 for a in hn.alerts())
    s = hn.stats()
    assert s["honeypots"] == 2 and s["banned_ips"] == 1
    for bad in (
        lambda: hn.deploy("irc", "x", 80),
        lambda: hn.deploy("ssh", "hp-ssh-1", 2223),
        lambda: hn.deploy("ssh", "x", 99999),
        lambda: hn.connection("nope", "1.1.1.1", "connect"),
        lambda: hn.connection("hp-ssh-1", "1.1.1.1", "bogus"),
        lambda: hn.connection("hp-ssh-1", "", "connect"),
        lambda: Honeynet(ban_threshold=0),
    ):
        try:
            bad()
            raise AssertionError("should raise")
        except HoneypotError:
            pass
    assert stdlib_only()
    print("monitor-20 OK: deploy, attempts, ban, auth_success, fail-closed, stdlib")


if __name__ == "__main__":
    main()
