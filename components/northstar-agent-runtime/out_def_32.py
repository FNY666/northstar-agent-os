"""LSB steganography detection, Simulated.

Examines the least-significant-bit plane of byte data for statistical
anomalies that suggest a hidden (e.g. encrypted) payload: a
suspiciously uniform bit distribution (chi-square test) or long
repeating byte patterns in the packed LSB stream.

What this IS:
* A heuristic triage signal returning (ok, reason); ok=False means the
  LSB plane looks anomalous and the data should be quarantined.
* stdlib-only statistics; deterministic.

What this IS NOT:
* Not proof of a hidden message -- some natural data triggers it.
* Not a decoder -- it cannot extract embedded content.
* Simulated: works on synthetic bytes, not a real media-forensics tool.
"""

from __future__ import annotations

import ast

#: Module version.
OUT_DEF_32_VERSION = "out-def-32.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.out-def-32.v1"

#: chi^2 (df=1) floor: below this the bit mix is so close to 50/50 that
#: it is suspicious (P(uniformity | natural) < ~0.05), suggesting
#: whitened/encrypted embedded data.
_CHI2_UNIFORM_FLOOR = 0.004

#: Longest identical-byte run in the packed LSB stream that is flagged.
_MAX_RUN_FLAG = 16


class OutDef32Error(Exception):
    """Fail-closed."""


def lsb_plane(data: bytes) -> bytes:
    """Extract the LSB of each byte in *data*, packed MSB-first."""
    bits = [b & 1 for b in data]
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i : i + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)


def _chi2_uniform(bits: list[int]) -> float:
    """Chi-square statistic vs the hypothesis of a 50/50 bit mix."""
    n = len(bits)
    expected = n / 2
    if expected == 0:
        return 0.0
    ones = sum(bits)
    return ((ones - expected) ** 2 + (n - ones - expected) ** 2) / expected


def detect_lsb_stego(data: bytes, *, min_bytes: int = 64) -> tuple[bool, str]:
    """Check the LSB plane for stego-like anomalies.

    Returns (ok, reason); ok=False flags a suspicious LSB plane.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise OutDef32Error("data must be bytes")
    if len(data) < min_bytes:
        return True, f"insufficient data ({len(data)} < {min_bytes} bytes)"
    bits = [b & 1 for b in data]
    chi2 = _chi2_uniform(bits)
    if chi2 < _CHI2_UNIFORM_FLOOR:
        return False, (
            f"lsb plane suspiciously uniform: chi2={chi2:.4f} over "
            f"{len(bits)} bits (possible encrypted embed)"
        )
    packed = lsb_plane(data)
    max_run = 1
    run = 1
    for prev, cur in zip(packed, packed[1:]):
        if cur == prev:
            run += 1
            if run > max_run:
                max_run = run
        else:
            run = 1
    if max_run >= _MAX_RUN_FLAG:
        return False, f"lsb plane has repeating byte run of length {max_run}"
    return True, f"lsb plane clean (chi2={chi2:.2f})"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "random"}
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
    import random

    # Perfectly uniform LSB plane (exactly 50/50) -> flagged.
    ok, reason = detect_lsb_stego(bytes([0x00, 0x01] * 64))
    assert ok is False
    assert "uniform" in reason

    # Non-uniform but repeating packed pattern (0xF8 x 16) -> flagged.
    data = bytes([0x01] * 5 + [0x00] * 3) * 16
    ok, reason = detect_lsb_stego(data)
    assert ok is False
    assert "run" in reason

    # Random noise -> clean.
    rnd = random.Random(20261009)
    ok, _ = detect_lsb_stego(bytes(rnd.randrange(256) for _ in range(512)))
    assert ok is True

    # Too short -> insufficient data, passes.
    ok, _ = detect_lsb_stego(b"\x00\x01")
    assert ok is True

    # Non-bytes fails closed.
    try:
        detect_lsb_stego("not bytes")  # type: ignore[arg-type]
    except OutDef32Error:
        pass
    else:
        raise AssertionError("non-bytes input should fail closed")

    assert stdlib_only()
    print("out-def-32 OK: uniformity flag, pattern flag, clean noise, stdlib")


if __name__ == "__main__":
    main()
