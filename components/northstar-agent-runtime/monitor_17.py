"""EDR integration: mock endpoint telemetry, Simulated.

Registers endpoints; ingests host-supplied events:
- process: image, parent, signed, pid
- file: path, op (write/delete)
- registry: key, op (set/delete)
- net: dst_ip, dst_port

Detections:
- suspicious_parent: office/reader parent -> script interpreter child
- unsigned_exec: unsigned process image (unless allowlisted)
- ransomware: >= N writes with ransom suffixes in window
- c2: net connection to intel-listed IP
- persistence: Run-key registry set

Mock actions: isolate_endpoint(), kill_process() -> action log.

What this IS: telemetry normalization + heuristic detections.

What this IS NOT:
* Not a real EDR sensor -- no live collection, events in.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

#: Module version.
MONITOR_17_VERSION = "monitor-17.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-17.v1"

_SUSP_PARENTS = frozenset({
    "winword.exe", "excel.exe", "powerpoint.exe", "outlook.exe", "acrord32.exe",
})
_SUSP_CHILDREN = frozenset({
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe",
})
_RANSOM_SUFFIXES = frozenset({".locked", ".enc", ".crypt", ".crypted", ".encrypted"})
_EVENT_KINDS = frozenset({"process", "file", "registry", "net"})


class EdrError(Exception):
    """Fail-closed."""


def _base(name: str) -> str:
    return name.replace("\\", "/").split("/")[-1].lower()


@dataclass(frozen=True)
class Endpoint:
    endpoint_id: str
    hostname: str
    isolated: bool = False


@dataclass(frozen=True)
class EdrEvent:
    endpoint_id: str
    kind: str
    ts: float
    fields: Dict[str, object]

    def __post_init__(self) -> None:
        if not self.endpoint_id:
            raise EdrError("endpoint_id required")
        if self.kind not in _EVENT_KINDS:
            raise EdrError(f"unknown event kind {self.kind!r}")
        if self.ts < 0:
            raise EdrError("ts must be >= 0")
        if not isinstance(self.fields, dict):
            raise EdrError("fields must be dict")


@dataclass(frozen=True)
class EdrAlert:
    kind: str
    endpoint_id: str
    severity: int
    detail: str
    ts: float


@dataclass(frozen=True)
class EdrAction:
    action: str
    endpoint_id: str
    detail: str
    ts: float


class Edr:
    """Mock EDR integration."""

    def __init__(
        self,
        *,
        bad_ips: Optional[Set[str]] = None,
        ransom_threshold: int = 5,
        window_s: float = 300.0,
        allowlist_images: Optional[Set[str]] = None,
    ) -> None:
        if ransom_threshold <= 0 or window_s <= 0:
            raise EdrError("threshold/window must be positive")
        self._bad_ips = set(bad_ips or set())
        self._ransom_n = ransom_threshold
        self._window = window_s
        self._allowlist = {_base(i) for i in (allowlist_images or set())}
        self._endpoints: Dict[str, Endpoint] = {}
        self._alerts: List[EdrAlert] = []
        self._actions: List[EdrAction] = []
        self._file_writes: Dict[str, List[float]] = {}
        self._fired_ransom: Set[str] = set()

    def register_endpoint(self, endpoint_id: str, hostname: str) -> None:
        if not endpoint_id or not hostname:
            raise EdrError("endpoint_id/hostname required")
        self._endpoints[endpoint_id] = Endpoint(endpoint_id, hostname)

    def _alert(self, kind: str, eid: str, severity: int, detail: str, ts: float) -> None:
        self._alerts.append(EdrAlert(kind, eid, severity, detail, ts))

    def ingest(self, event: EdrEvent) -> List[EdrAlert]:
        if not isinstance(event, EdrEvent):
            raise EdrError("event must be EdrEvent")
        if event.endpoint_id not in self._endpoints:
            raise EdrError(f"unknown endpoint {event.endpoint_id!r}")
        before = len(self._alerts)
        f = event.fields
        eid = event.endpoint_id

        if event.kind == "process":
            image = _base(str(f.get("image", "")))
            parent = _base(str(f.get("parent", "")))
            signed = f.get("signed", True)
            if not image:
                raise EdrError("process image required")
            if parent in _SUSP_PARENTS and image in _SUSP_CHILDREN:
                self._alert("suspicious_parent", eid, 90,
                            f"{parent} -> {image}", event.ts)
            if signed is False and image not in self._allowlist:
                self._alert("unsigned_exec", eid, 60,
                            f"unsigned {image}", event.ts)
        elif event.kind == "file":
            path = str(f.get("path", ""))
            op = str(f.get("op", ""))
            if not path or op not in ("write", "delete"):
                raise EdrError("file path and op write/delete required")
            if op == "write" and any(path.lower().endswith(s) for s in _RANSOM_SUFFIXES):
                writes = self._file_writes.setdefault(eid, [])
                writes.append(event.ts)
                cutoff = event.ts - self._window
                writes[:] = [t for t in writes if t >= cutoff]
                if len(writes) >= self._ransom_n and eid not in self._fired_ransom:
                    self._fired_ransom.add(eid)
                    self._alert("ransomware", eid, 95,
                                f"{len(writes)} ransom-suffix writes", event.ts)
        elif event.kind == "registry":
            key = str(f.get("key", ""))
            op = str(f.get("op", ""))
            if not key or op not in ("set", "delete"):
                raise EdrError("registry key and op set/delete required")
            if op == "set" and "\\run" in key.lower():
                self._alert("persistence", eid, 70, f"Run key set: {key}", event.ts)
        elif event.kind == "net":
            dst = str(f.get("dst_ip", ""))
            if not dst:
                raise EdrError("net dst_ip required")
            if dst in self._bad_ips:
                self._alert("c2", eid, 85, f"connection to {dst}", event.ts)

        return self._alerts[before:]

    def isolate_endpoint(self, endpoint_id: str, ts: float = 0.0) -> None:
        ep = self._endpoints.get(endpoint_id)
        if ep is None:
            raise EdrError(f"unknown endpoint {endpoint_id!r}")
        self._endpoints[endpoint_id] = Endpoint(ep.endpoint_id, ep.hostname, True)
        self._actions.append(EdrAction("isolate", endpoint_id, "isolated", ts))

    def kill_process(self, endpoint_id: str, pid: int, ts: float = 0.0) -> None:
        if endpoint_id not in self._endpoints:
            raise EdrError(f"unknown endpoint {endpoint_id!r}")
        if pid <= 0:
            raise EdrError("pid must be positive")
        self._actions.append(EdrAction("kill_process", endpoint_id, f"pid {pid}", ts))

    def alerts(self) -> List[EdrAlert]:
        return list(self._alerts)

    def actions(self) -> List[EdrAction]:
        return list(self._actions)

    def is_isolated(self, endpoint_id: str) -> bool:
        ep = self._endpoints.get(endpoint_id)
        if ep is None:
            raise EdrError(f"unknown endpoint {endpoint_id!r}")
        return ep.isolated


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
    edr = Edr(bad_ips={"6.6.6.6"}, ransom_threshold=5, window_s=300.0)
    edr.register_endpoint("ep1", "WS-01")

    got = edr.ingest(edr_event := EdrEvent(
        "ep1", "process", 1.0,
        {"image": "powershell.exe", "parent": "winword.exe", "signed": True, "pid": 42},
    ))
    assert any(a.kind == "suspicious_parent" for a in got)

    got = edr.ingest(EdrEvent(
        "ep1", "process", 2.0,
        {"image": "evil.exe", "parent": "explorer.exe", "signed": False, "pid": 43},
    ))
    assert any(a.kind == "unsigned_exec" for a in got)

    for i in range(5):
        edr.ingest(EdrEvent(
            "ep1", "file", 10.0 + i,
            {"path": f"C:\\docs\\f{i}.locked", "op": "write"},
        ))
    assert any(a.kind == "ransomware" for a in edr.alerts())

    got = edr.ingest(EdrEvent("ep1", "net", 20.0, {"dst_ip": "6.6.6.6", "dst_port": 443}))
    assert any(a.kind == "c2" for a in got)

    got = edr.ingest(EdrEvent(
        "ep1", "registry", 21.0,
        {"key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "op": "set"},
    ))
    assert any(a.kind == "persistence" for a in got)

    edr.isolate_endpoint("ep1")
    assert edr.is_isolated("ep1") is True
    edr.kill_process("ep1", 42)
    assert len(edr.actions()) == 2

    for bad in (
        lambda: edr.ingest(EdrEvent("nope", "process", 1.0, {"image": "a.exe"})),
        lambda: edr.ingest(EdrEvent("ep1", "bogus", 1.0, {})),
        lambda: edr.isolate_endpoint("nope"),
        lambda: edr.ingest("nope"),  # type: ignore
    ):
        try:
            bad()
            raise AssertionError("should raise")
        except EdrError:
            pass
    assert stdlib_only()
    print("monitor-17 OK: parent/unsigned/ransomware/c2/persistence, actions, fail-closed")


if __name__ == "__main__":
    main()
