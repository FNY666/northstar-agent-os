"""ICMP exfiltration detection (icmp-exfil), Simulated.

Detects data smuggled in ICMP echo payloads. Flags oversized payloads and high-entropy content in ping packets.

What this IS: an ICMP payload shape detector.

What this IS NOT:
* Not a packet sniffer -- inspects provided type/payload.
* Cannot see encrypted or fragmented exfil.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List
import math
import os

#: Module version.
EXFIL_02_VERSION = "exfil-02.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.exfil-02.v1"


class Exfil02Error(Exception):
    """Fail-closed."""


def _byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def detect_icmp_exfil(icmp_type: int, payload: bytes) -> tuple:
    """Detect ICMP exfiltration. Returns (suspicious, reason)."""
    if not isinstance(payload, (bytes, bytearray)):
        raise Exfil02Error("payload must be bytes")
    if icmp_type == 8:  # echo request
        if len(payload) > 64:
            return True, "oversized echo payload: %d bytes" % len(payload)
        if len(payload) >= 16:
            max_ent = math.log2(len(payload))
            if _byte_entropy(bytes(payload)) > 0.92 * max_ent:
                return True, "high-entropy echo payload"
    elif icmp_type == 0:  # echo reply
        if len(payload) > 64:
            return True, "oversized echo-reply payload: %d bytes" % len(payload)
    return False, "ok"

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "math", "os"}
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
    ok, _ = detect_icmp_exfil(8, b"\x00" * 32)
    assert ok is False
    ok, _ = detect_icmp_exfil(8, b"A" * 200)
    assert ok is True
    import os
    ok, _ = detect_icmp_exfil(8, os.urandom(48))
    assert ok is True
    assert stdlib_only()
    print("exfil-02 OK: icmp shapes, fail-closed")


if __name__ == "__main__":
    main()
