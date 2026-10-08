"""Crypto Defense 18: Measured boot (mock), Simulated.

PCR-style registers: extend(i, data) sets pcr[i] = sha256(pcr[i] || data).
A boot measurement extends PCRs in order over the boot components and
keeps an event log.  Verification compares against golden values.

What this IS: hash-chain boot measurement API.
What this IS NOT: real UEFI/TPM measured boot or secure boot signatures.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

#: Module version.
CRYPTO_DEFENSE_18_VERSION = "crypto-defense-18.v1"
SCHEMA_PIN = "northstar.crypto-defense-18.v1"


class BootError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class BootEvent:
    """One measured component."""

    pcr_index: int
    component: str
    digest: str  # sha256 of the component data


class MeasuredBoot:
    """Mock measured-boot with PCR registers."""

    def __init__(self, n_pcrs: int = 8) -> None:
        if n_pcrs <= 0:
            raise BootError("n_pcrs must be positive")
        self._pcrs: List[str] = ["00" * 32 for _ in range(n_pcrs)]
        self._log: List[BootEvent] = []

    def extend(self, index: int, data: bytes) -> str:
        """Extend a PCR: pcr = sha256(pcr || data)."""
        if not 0 <= index < len(self._pcrs):
            raise BootError("PCR index out of range")
        if not isinstance(data, bytes):
            raise BootError("data must be bytes")
        raw = bytes.fromhex(self._pcrs[index]) + data
        self._pcrs[index] = hashlib.sha256(raw).hexdigest()
        return self._pcrs[index]

    def measure_boot(self, components: List[Tuple[int, str, bytes]]) -> List[BootEvent]:
        """Measure boot components: (pcr_index, name, data)."""
        events = []
        for index, name, data in components:
            digest = hashlib.sha256(data).hexdigest()
            self.extend(index, data)
            event = BootEvent(index, name, digest)
            events.append(event)
            self._log.append(event)
        return events

    def pcr(self, index: int) -> str:
        if not 0 <= index < len(self._pcrs):
            raise BootError("PCR index out of range")
        return self._pcrs[index]

    def pcr_state(self) -> Dict[int, str]:
        return {i: v for i, v in enumerate(self._pcrs)}

    def event_log(self) -> List[BootEvent]:
        return list(self._log)

    def verify(self, expected: Dict[int, str]) -> bool:
        """Compare current PCR state to golden values."""
        for index, value in expected.items():
            if not 0 <= index < len(self._pcrs):
                return False
            if self._pcrs[index] != value:
                return False
        return True


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
    comps = [(0, "firmware", b"fw v1"), (1, "bootloader", b"bl v2"), (2, "kernel", b"k v3")]
    a = MeasuredBoot()
    a.measure_boot(comps)
    golden = a.pcr_state()
    # Same boot reproduces.
    b = MeasuredBoot()
    b.measure_boot(comps)
    assert b.verify(golden) is True
    # Tampered component changes measurement.
    c = MeasuredBoot()
    c.measure_boot([(0, "firmware", b"fw EVIL"), (1, "bootloader", b"bl v2"), (2, "kernel", b"k v3")])
    assert c.verify(golden) is False
    # Direct extend chains.
    d = MeasuredBoot()
    d.extend(0, b"x")
    assert d.pcr(0) != "00" * 32
    assert stdlib_only()
    print("crypto-defense-18 OK")


if __name__ == "__main__":
    main()
