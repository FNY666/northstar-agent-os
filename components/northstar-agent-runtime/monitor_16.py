"""NDR: mock network detection & response, Simulated.

Analyzes host-supplied flow records:
- port_scan: src touches >= N distinct ports on one dst within window
- exfil: egress bytes from src to external dst >= threshold in window
- beaconing: >= M flows src->dst with low interval jitter
- lateral: internal src -> >= K distinct internal dsts on admin ports

What this IS: flow-metadata heuristics feeding an alert queue.

What this IS NOT:
* Not packet inspection -- flow records only.
* Mock: no live capture; RFC1918 treated as internal.
"""

from __future__ import annotations

import ast
import statistics
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

#: Module version.
MONITOR_16_VERSION = "monitor-16.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-16.v1"

_ADMIN_PORTS = frozenset({22, 445, 3389, 5985, 5900})
_PROTOS = frozenset({"tcp", "udp", "icmp"})


class NdrError(Exception):
    """Fail-closed."""


def is_internal(ip: str) -> bool:
    """RFC1918 check."""
    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
        except (IndexError, ValueError):
            return False
        return 16 <= second <= 31
    return False


@dataclass(frozen=True)
class Flow:
    src: str
    dst: str
    dst_port: int
    proto: str
    bytes_out: int
    ts: float

    def __post_init__(self) -> None:
        if not self.src or not self.dst:
            raise NdrError("src/dst required")
        if not 1 <= self.dst_port <= 65535:
            raise NdrError("dst_port must be 1-65535")
        if self.proto not in _PROTOS:
            raise NdrError(f"unknown proto {self.proto!r}")
        if self.bytes_out < 0:
            raise NdrError("bytes_out must be >= 0")
        if self.ts < 0:
            raise NdrError("ts must be >= 0")


@dataclass(frozen=True)
class NdrAlert:
    kind: str
    src: str
    dst: str
    severity: int
    detail: str
    ts: float


class Ndr:
    """Flow-based network detection (mock)."""

    def __init__(
        self,
        *,
        window_s: float = 300.0,
        port_scan_ports: int = 10,
        exfil_bytes: int = 100_000_000,
        beacon_min_conns: int = 5,
        beacon_max_jitter: float = 0.25,
        lateral_hosts: int = 5,
    ) -> None:
        for name, val in (
            ("window_s", window_s),
            ("port_scan_ports", port_scan_ports),
            ("exfil_bytes", exfil_bytes),
            ("beacon_min_conns", beacon_min_conns),
            ("beacon_max_jitter", beacon_max_jitter),
            ("lateral_hosts", lateral_hosts),
        ):
            if val <= 0:
                raise NdrError(f"{name} must be positive")
        self._window = window_s
        self._scan_n = port_scan_ports
        self._exfil_b = exfil_bytes
        self._beacon_n = beacon_min_conns
        self._beacon_j = beacon_max_jitter
        self._lat_n = lateral_hosts
        self._ports: Dict[Tuple[str, str], Dict[int, float]] = {}
        self._egress: Dict[Tuple[str, str], List[float]] = {}  # [bytes, first_ts]
        self._conns: Dict[Tuple[str, str], List[float]] = {}
        self._admin: Dict[str, Dict[str, float]] = {}
        self._fired: Set[Tuple[str, str, str]] = set()
        self._alerts: List[NdrAlert] = []

    def _prune(self, now: float) -> None:
        cutoff = now - self._window
        for key in list(self._ports):
            kept = {p: t for p, t in self._ports[key].items() if t >= cutoff}
            if kept:
                self._ports[key] = kept
            else:
                del self._ports[key]
        for key in list(self._conns):
            kept = [t for t in self._conns[key] if t >= cutoff]
            if kept:
                self._conns[key] = kept
            else:
                del self._conns[key]
        for src in list(self._admin):
            kept = {d: t for d, t in self._admin[src].items() if t >= cutoff}
            if kept:
                self._admin[src] = kept
            else:
                del self._admin[src]

    def _fire(
        self, kind: str, src: str, dst: str, severity: int, detail: str, ts: float
    ) -> None:
        key = (kind, src, dst)
        if key in self._fired:
            return
        self._fired.add(key)
        self._alerts.append(NdrAlert(kind, src, dst, severity, detail, ts))

    def ingest(self, flow: Flow) -> List[NdrAlert]:
        """Ingest one flow; returns alerts fired by this flow."""
        if not isinstance(flow, Flow):
            raise NdrError("flow must be Flow")
        before = len(self._alerts)
        self._prune(flow.ts)
        key = (flow.src, flow.dst)

        # Port scan.
        ports = self._ports.setdefault(key, {})
        ports.setdefault(flow.dst_port, flow.ts)
        if len(ports) >= self._scan_n:
            self._fire(
                "port_scan", flow.src, flow.dst, 70,
                f"{len(ports)} ports in window", flow.ts,
            )

        # Exfiltration (egress to external).
        if not is_internal(flow.dst):
            entry = self._egress.get(key)
            if entry is None or flow.ts - entry[1] > self._window:
                entry = [0.0, flow.ts]
            entry[0] += flow.bytes_out
            self._egress[key] = entry
            if entry[0] >= self._exfil_b:
                self._fire(
                    "exfil", flow.src, flow.dst, 85,
                    f"{int(entry[0])} bytes egress", flow.ts,
                )

        # Beaconing.
        conns = self._conns.setdefault(key, [])
        conns.append(flow.ts)
        if len(conns) >= self._beacon_n and ("beaconing", flow.src, flow.dst) not in self._fired:
            ordered = sorted(conns)
            gaps = [b - a for a, b in zip(ordered, ordered[1:])]
            mean = statistics.fmean(gaps)
            if mean > 0 and len(gaps) >= 2:
                jitter = statistics.stdev(gaps) / mean
                if jitter <= self._beacon_j:
                    self._fire(
                        "beaconing", flow.src, flow.dst, 80,
                        f"jitter {jitter:.3f} over {len(conns)} conns", flow.ts,
                    )
            elif mean > 0 and len(gaps) == 1:
                self._fire(
                    "beaconing", flow.src, flow.dst, 80,
                    f"regular interval {mean:.1f}s", flow.ts,
                )

        # Lateral movement.
        if (
            is_internal(flow.src)
            and is_internal(flow.dst)
            and flow.dst_port in _ADMIN_PORTS
        ):
            dsts = self._admin.setdefault(flow.src, {})
            dsts.setdefault(flow.dst, flow.ts)
            if len(dsts) >= self._lat_n:
                self._fire(
                    "lateral_movement", flow.src, "multiple", 75,
                    f"{len(dsts)} internal hosts on admin ports", flow.ts,
                )

        return self._alerts[before:]

    def alerts(self) -> List[NdrAlert]:
        return list(self._alerts)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__", "ast", "dataclasses", "pathlib", "statistics", "typing",
    }
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
    ndr = Ndr(
        window_s=300.0, port_scan_ports=10, exfil_bytes=1000,
        beacon_min_conns=5, beacon_max_jitter=0.25, lateral_hosts=5,
    )
    # Port scan: 12 ports on one dst.
    for p in range(20, 32):
        ndr.ingest(Flow("10.0.0.5", "8.8.8.8", p, "tcp", 60, float(p)))
    assert any(a.kind == "port_scan" for a in ndr.alerts())

    # Exfil: 2KB to external.
    ndr.ingest(Flow("10.0.0.5", "1.2.3.4", 443, "tcp", 2000, 400.0))
    assert any(a.kind == "exfil" for a in ndr.alerts())

    # Beaconing: 6 flows, 60s apart.
    for i in range(6):
        ndr.ingest(Flow("10.0.0.6", "9.9.9.9", 443, "tcp", 100, 1000.0 + i * 60))
    assert any(a.kind == "beaconing" for a in ndr.alerts())

    # Lateral: 6 internal hosts on 445.
    for i in range(6):
        ndr.ingest(
            Flow("10.0.0.7", f"192.168.1.{i + 1}", 445, "tcp", 100, 2000.0 + i)
        )
    assert any(a.kind == "lateral_movement" for a in ndr.alerts())

    # Benign: fresh NDR, single flow -> no alerts.
    ndr2 = Ndr()
    assert ndr2.ingest(Flow("10.0.0.1", "10.0.0.2", 80, "tcp", 100, 1.0)) == []

    # Fail-closed.
    for bad in (
        lambda: Flow("", "1.1.1.1", 80, "tcp", 1, 1.0),
        lambda: Flow("a", "b", 0, "tcp", 1, 1.0),
        lambda: Flow("a", "b", 80, "gre", 1, 1.0),
        lambda: Flow("a", "b", 80, "tcp", -1, 1.0),
    ):
        try:
            bad()
            raise AssertionError("should raise")
        except NdrError:
            pass
    try:
        ndr.ingest("not-a-flow")  # type: ignore
        raise AssertionError("should raise")
    except NdrError:
        pass
    assert is_internal("10.1.2.3") and is_internal("172.20.5.4")
    assert is_internal("192.168.0.1") and not is_internal("8.8.8.8")
    assert not is_internal("172.15.0.1") and not is_internal("172.32.0.1")
    assert stdlib_only()
    print("monitor-16 OK: port_scan, exfil, beaconing, lateral, fail-closed, stdlib")


if __name__ == "__main__":
    main()
