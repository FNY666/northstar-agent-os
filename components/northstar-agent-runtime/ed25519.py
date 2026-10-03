"""Minimal pure-Python Ed25519 (RFC 8032), vendored.

The runtime is deliberately dependency-free, so instead of depending on
``cryptography`` or ``PyNaCl`` this module ships a small, self-contained
Ed25519 implementation (~120 lines) used only for audit-feed signatures
(``audit_chain.sign_record``). It is NOT a general-purpose crypto library:

* signing is variable-time (fine for offline audit signing; not for an
  online oracle);
* only the pure Ed25519 variant (no prehash, no context) is implemented;
* ``verify`` returns ``False`` (never raises) on any malformed input.

Correctness is pinned by the RFC 8032 §7.1 test vectors in
``tests/test_audit_chain.py`` (TEST 1-3, plus tamper rejection). If you
replace this file, re-run those tests: a wrong constant here silently
breaks every signature the feed ever carries.
"""
from __future__ import annotations

import hashlib

_Q = (1 << 255) - 19
_L = (1 << 252) + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)

# Base point, extended coordinates (X, Y, Z, T).


def _inv(x: int) -> int:
    return pow(x, _Q - 2, _Q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x & 1:
        x = _Q - x
    return x


_BY = (4 * _inv(5)) % _Q
_BX = _xrecover(_BY)
_G = (_BX, _BY, 1, (_BX * _BY) % _Q)
_IDENTITY = (0, 1, 1, 0)


def _edwards_add(p: tuple[int, int, int, int], q: tuple[int, int, int, int]):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _Q
    b = ((y1 + x1) * (y2 + x2)) % _Q
    c = (t1 * 2 * _D * t2) % _Q
    d = (z1 * 2 * z2) % _Q
    e = (b - a) % _Q
    f = (d - c) % _Q
    g = (d + c) % _Q
    h = (b + a) % _Q
    return ((e * f) % _Q, (g * h) % _Q, (f * g) % _Q, (e * h) % _Q)


def _scalarmult(p: tuple[int, int, int, int], e: int):
    result = _IDENTITY
    while e > 0:
        if e & 1:
            result = _edwards_add(result, p)
        p = _edwards_add(p, p)
        e >>= 1
    return result


def _encodepoint(p: tuple[int, int, int, int]) -> bytes:
    x, y, z, _t = p
    zi = _inv(z)
    x = (x * zi) % _Q
    y = (y * zi) % _Q
    return (((y & ((1 << 255) - 1)) | ((x & 1) << 255))).to_bytes(32, "little")


def _decodepoint(s: bytes):
    if len(s) != 32:
        return None
    raw = int.from_bytes(s, "little")
    y = raw & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != (raw >> 255):
        x = _Q - x
    p = (x, y, 1, (x * y) % _Q)
    # On-curve check: -x^2 + y^2 = 1 + d*x^2*y^2.
    if (-(x * x) + y * y - 1 - _D * x * x % _Q * y * y % _Q) % _Q != 0:
        return None
    return p


def _hint(m: bytes) -> int:
    return int.from_bytes(hashlib.sha512(m).digest(), "little") % _L


def _clamp(digest32: bytes) -> int:
    a = int.from_bytes(digest32, "little")
    a &= (1 << 254) - 8  # clear bits 0, 1, 2 and everything above 253
    a |= 1 << 254  # set bit 254
    return a


def public_key(secret_key: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte secret seed."""
    if len(secret_key) != 32:
        raise ValueError("Ed25519 secret key must be 32 bytes")
    a = _clamp(hashlib.sha512(secret_key).digest()[:32])
    return _encodepoint(_scalarmult(_G, a))


def sign(secret_key: bytes, message: bytes) -> bytes:
    """Sign a message; returns the 64-byte signature."""
    if len(secret_key) != 32:
        raise ValueError("Ed25519 secret key must be 32 bytes")
    h = hashlib.sha512(secret_key).digest()
    a = _clamp(h[:32])
    r = _hint(h[32:] + message)
    big_r = _encodepoint(_scalarmult(_G, r))
    big_a = public_key(secret_key)
    s = (_hint(big_r + big_a + message) * a + r) % _L
    return big_r + s.to_bytes(32, "little")


def verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a signature; False on any malformed input, never raises."""
    if len(public_key_bytes) != 32 or len(signature) != 64:
        return False
    a_point = _decodepoint(public_key_bytes)
    if a_point is None:
        return False
    r_point = _decodepoint(signature[:32])
    if r_point is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = _hint(signature[:32] + public_key_bytes + message)
    s_b = _scalarmult(_G, s)
    h_a = _scalarmult(a_point, h)
    return _encodepoint(s_b) == _encodepoint(_edwards_add(r_point, h_a))
