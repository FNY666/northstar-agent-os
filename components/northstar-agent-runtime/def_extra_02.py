"""Device fingerprinting gate (mock), Simulated.

Builds a stable device fingerprint from declared device attributes
(OS, screen, fonts, timezone, ...) and detects drift when a known
device presents changed attributes.

What this IS: signal for "same device?" decisions.

What this IS NOT:
* Not real hardware attestation -- attributes are self-declared.
* Unknown device FAILS CLOSED (deny) by default.
"""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from typing import Dict, List, Tuple

#: Module version.
DEF_EXTRA_02_VERSION = "def-extra-02.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.def-extra-02.v1"


class FingerprintError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class DeviceRecord:
    """Registered device."""

    device_id: str
    fingerprint: str
    attributes: Dict[str, str]


def fingerprint(attrs: Dict[str, str]) -> str:
    """Stable fingerprint: sha256 of canonical JSON."""
    if not attrs:
        raise FingerprintError("attributes required")
    canonical = json.dumps(attrs, sort_keys=True, separators=(",", ":"))
    return "fp:" + hashlib.sha256(canonical.encode()).hexdigest()


class DeviceRegistry:
    """Register devices, detect attribute drift."""

    def __init__(self, *, max_changed_keys: int = 1) -> None:
        if max_changed_keys < 0:
            raise FingerprintError("max_changed_keys must be >= 0")
        self._max_changed = max_changed_keys
        self._devices: Dict[str, DeviceRecord] = {}

    def register(self, device_id: str, attrs: Dict[str, str]) -> DeviceRecord:
        """Register (or re-register) a device."""
        if not device_id:
            raise FingerprintError("device_id required")
        record = DeviceRecord(device_id, fingerprint(attrs), dict(attrs))
        self._devices[device_id] = record
        return record

    def verify(
        self, device_id: str, attrs: Dict[str, str]
    ) -> Tuple[bool, List[str]]:
        """Verify presented attributes against the registered device.

        Returns (ok, changed_keys).  Unknown device -> (False, []).
        """
        record = self._devices.get(device_id)
        if record is None or not attrs:
            return False, []
        changed = [
            key
            for key in set(record.attributes) | set(attrs)
            if record.attributes.get(key) != attrs.get(key)
        ]
        ok = len(changed) <= self._max_changed
        return ok, sorted(changed)


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
    registry = DeviceRegistry(max_changed_keys=1)
    attrs = {"os": "linux", "screen": "1920x1080", "tz": "UTC"}
    record = registry.register("dev-1", attrs)
    assert record.fingerprint.startswith("fp:")
    # Identical attributes verify.
    ok, changed = registry.verify("dev-1", dict(attrs))
    assert ok is True and changed == []
    # One changed key within tolerance.
    attrs2 = dict(attrs)
    attrs2["tz"] = "Asia/Shanghai"
    ok, changed = registry.verify("dev-1", attrs2)
    assert ok is True and changed == ["tz"]
    # Two changed keys exceed tolerance.
    attrs3 = dict(attrs2)
    attrs3["os"] = "windows"
    ok, _ = registry.verify("dev-1", attrs3)
    assert ok is False
    # Unknown device fails closed.
    ok, _ = registry.verify("dev-9", attrs)
    assert ok is False
    assert stdlib_only()
    print("def-extra-02 OK: fingerprint, drift, fail-closed")


if __name__ == "__main__":
    main()
