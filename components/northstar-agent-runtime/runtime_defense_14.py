"""Runtime defense 14: certificate pinning (SPKI hashes), Simulated.

Pin store: host -> set of allowed SPKI SHA-256 hashes
(base64, as in HPKP / OkHttp CertificatePinner).  Verification compares
the presented SPKI hash against the pin set; unknown host or mismatch ->
deny (fail-closed).

What this IS: pin store + verification logic (policy).
What this IS NOT: actual TLS handshake cert extraction.
"""

from __future__ import annotations

import ast
import base64
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Tuple

#: Module version.
RUNTIME_DEFENSE_14_VERSION = "runtime-defense-14.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-14.v1"


class PinningError(Exception):
    """Fail-closed: bad pins raise."""


def _valid_pin(pin: str) -> bool:
    """A valid pin is base64 of 32 bytes (SHA-256)."""
    try:
        raw = base64.b64decode(pin, validate=True)
    except Exception:
        return False
    return len(raw) == 32


@dataclass(frozen=True)
class PinStore:
    """Host -> SPKI pin sets."""

    pins: Dict[str, FrozenSet[str]]

    def verify(self, host: str, spki_b64: str) -> Tuple[bool, str]:
        """Verify a presented SPKI hash.  Fail-closed."""
        h = host.strip().lower().rstrip(".")
        if h not in self.pins:
            return False, f"no pins for host {h}: deny"
        if not _valid_pin(spki_b64):
            return False, "malformed presented pin: deny"
        if spki_b64 in self.pins[h]:
            return True, f"pin matched for {h}"
        return False, f"pin mismatch for {h}: deny"


def build_store(entries: Dict[str, List[str]]) -> PinStore:
    """Build pin store.  Empty store -> fail-closed (deny everything)."""
    pins: Dict[str, FrozenSet[str]] = {}
    for host, pin_list in entries.items():
        h = host.strip().lower().rstrip(".")
        if not h:
            raise PinningError("empty host")
        if not pin_list:
            raise PinningError(f"no pins for {h}: fail-closed")
        for pin in pin_list:
            if not _valid_pin(pin):
                raise PinningError(f"bad pin for {h}: {pin[:16]}...")
        pins[h] = frozenset(pin_list)
    # NOTE: empty entries dict is allowed (deny-all store), but callers
    # should be aware verify() then denies everything.
    return PinStore(pins=pins)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "base64", "dataclasses", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


# Example 32-byte pins (base64).  Test values only.
_PIN_A = base64.b64encode(b"A" * 32).decode()
_PIN_B = base64.b64encode(b"B" * 32).decode()


def main() -> None:
    """Self-check."""
    store = build_store({"api.example.com": [_PIN_A, _PIN_B]})
    ok, _ = store.verify("api.example.com", _PIN_A)
    assert ok is True
    ok, reason = store.verify("api.example.com", base64.b64encode(b"C" * 32).decode())
    assert ok is False and "mismatch" in reason
    ok, _ = store.verify("unknown.example.com", _PIN_A)
    assert ok is False  # no pins: deny
    ok, _ = store.verify("api.example.com", "not-base64!!")
    assert ok is False

    empty = build_store({})
    ok, _ = empty.verify("anything.example", _PIN_A)
    assert ok is False  # deny-all

    try:
        build_store({"h.example": ["short"]})
        raise AssertionError("should raise")
    except PinningError:
        pass

    assert stdlib_only()
    print("runtime-defense-14 OK: pin store, verify, fail-closed, stdlib")


if __name__ == "__main__":
    main()
