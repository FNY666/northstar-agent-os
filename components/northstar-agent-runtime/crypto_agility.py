"""Crypto-agility seam for digital signatures.

NIST's PQC migration guidance centers on *crypto agility*: systems must be
able to swap signature algorithms without retrofitting every call site.
Northstar signs delegation tokens, audit-chain records, and (via
``message_signing``) inter-agent messages -- today all with Ed25519, all by
calling the ``ed25519`` module directly.

This module is the seam every signing call site should program against:

* ``Signer`` / ``Verifier`` -- abstract interfaces. ``sign`` takes bytes and
  returns bytes; ``verify`` takes bytes and returns ``False`` (never raises)
  on any defect. Each carries an ``algorithm`` identifier string so signed
  artifacts stay self-describing.
* ``Ed25519Signer`` / ``Ed25519Verifier`` -- the current concrete
  implementation, wrapping the vendored RFC 8032 ``ed25519`` module.
* Registry -- ``register_algorithm`` / ``get_signer`` / ``get_verifier`` /
  ``supported_algorithms``. When ML-DSA-65 (FIPS 204) lands, the hybrid
  implementation registers here and every call site picks it up without
  code changes.

Deliberately NOT in v1: actual PQC implementations. ``ALGORITHM_ML_DSA_65``
is a reserved identifier that raises ``NotImplementedError`` when looked up,
so a silent string-match typo cannot pretend to give post-quantum security.

Design rules:
* The module stays dependency-free at import time; the ``ed25519``
  primitive is imported lazily inside the Ed25519 classes, exactly like
  ``message_signing`` does. Missing primitives raise ``RuntimeError`` at
  construction/sign time, and ``verify`` still fails closed.
* Construction validates key material (raises ``ValueError`` on bad input).
* ``Verifier.verify`` never raises: any defect is ``False``.
* Verification is fail-closed even when the algorithm is unknown: there is
  no default and no fallback, only ``UnknownAlgorithmError``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass

ALGORITHM_ED25519 = "ed25519"

#: Reserved identifier for ML-DSA-65 (FIPS 204). Not implemented yet;
#: looking it up raises NotImplementedError rather than silently
#: falling back to Ed25519.
ALGORITHM_ML_DSA_65 = "ml-dsa-65"


class UnknownAlgorithmError(KeyError):
    """Raised when no Signer/Verifier is registered for an algorithm id."""


class Signer(ABC):
    """Abstract digital-signature producer. Binds bytes to key holder."""

    @property
    @abstractmethod
    def algorithm(self) -> str:
        """Algorithm identifier, e.g. ``"ed25519"``."""

    @abstractmethod
    def public_key_bytes(self) -> bytes:
        """The public key counterpart of the signing key, as bytes."""

    @abstractmethod
    def sign(self, message: bytes) -> bytes:
        """Sign ``message``. Raises on bad input (not fail-closed)."""


class Verifier(ABC):
    """Abstract signature checker. Fail-closed: never raises."""

    @property
    @abstractmethod
    def algorithm(self) -> str:
        """Algorithm identifier, e.g. ``"ed25519"``."""

    @abstractmethod
    def verify(self, message: bytes, signature: bytes) -> bool:
        """``True`` iff ``signature`` is valid for ``message`` under this key.

        ``False`` on any defect (bad signature, bad key, malformed input,
        missing primitive). Never raises.
        """


def _load_ed25519():
    try:
        import ed25519 as _ed
    except ImportError as e:
        raise RuntimeError("ed25519 primitive unavailable") from e
    return _ed


class Ed25519Signer(Signer):
    """Ed25519 (RFC 8032, pure variant) signer. ``seed`` is 32 bytes."""

    def __init__(self, seed: bytes) -> None:
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            raise ValueError("Ed25519 seed must be exactly 32 bytes")
        _ed = _load_ed25519()
        self._seed = bytes(seed)
        self._public_key = _ed.public_key(self._seed)

    @property
    def algorithm(self) -> str:
        return ALGORITHM_ED25519

    def public_key_bytes(self) -> bytes:
        return self._public_key

    def sign(self, message: bytes) -> bytes:
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError("message must be bytes")
        return _load_ed25519().sign(self._seed, bytes(message))


class Ed25519Verifier(Verifier):
    """Ed25519 (RFC 8032, pure variant) verifier. ``public_key`` is 32 bytes."""

    def __init__(self, public_key: bytes) -> None:
        if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
            raise ValueError("Ed25519 public key must be exactly 32 bytes")
        self._public_key = bytes(public_key)

    @property
    def algorithm(self) -> str:
        return ALGORITHM_ED25519

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            if not isinstance(message, (bytes, bytearray)):
                return False
            if not isinstance(signature, (bytes, bytearray)):
                return False
            if len(signature) != 64:
                return False
            return bool(
                _load_ed25519().verify(self._public_key, bytes(message), bytes(signature))
            )
        except Exception:
            return False


@dataclass(frozen=True)
class _AlgorithmEntry:
    signer_factory: Callable[[bytes], Signer]
    verifier_factory: Callable[[bytes], Verifier]


_REGISTRY: dict[str, _AlgorithmEntry] = {}


def register_algorithm(
    name: str,
    signer_factory: Callable[[bytes], Signer],
    verifier_factory: Callable[[bytes], Verifier],
) -> None:
    """Register ``name`` -> (signer factory, verifier factory).

    Factories take raw key bytes (seed for signers, public key for
    verifiers) and return the concrete instance. Re-registering a name
    replaces it; use that only in tests or deliberate migration shims.
    """
    if not name or not isinstance(name, str):
        raise ValueError("algorithm name must be a non-empty string")
    _REGISTRY[name] = _AlgorithmEntry(signer_factory, verifier_factory)


def supported_algorithms() -> tuple[str, ...]:
    """Algorithm identifiers currently registered, sorted."""
    return tuple(sorted(_REGISTRY))


def get_signer(algorithm: str, key_material: bytes) -> Signer:
    """Build a ``Signer`` for ``algorithm`` from raw key bytes (seed).

    Raises ``UnknownAlgorithmError`` for an unregistered id and
    ``NotImplementedError`` for the reserved ``ml-dsa-65`` id.
    """
    if algorithm == ALGORITHM_ML_DSA_65:
        raise NotImplementedError(
            "ml-dsa-65 is reserved for the future FIPS 204 hybrid; "
            "no implementation is registered yet"
        )
    entry = _REGISTRY.get(algorithm)
    if entry is None:
        raise UnknownAlgorithmError(algorithm)
    return entry.signer_factory(key_material)


def get_verifier(algorithm: str, key_material: bytes) -> Verifier:
    """Build a ``Verifier`` for ``algorithm`` from raw key bytes (public key).

    Raises ``UnknownAlgorithmError`` for an unregistered id and
    ``NotImplementedError`` for the reserved ``ml-dsa-65`` id.
    """
    if algorithm == ALGORITHM_ML_DSA_65:
        raise NotImplementedError(
            "ml-dsa-65 is reserved for the future FIPS 204 hybrid; "
            "no implementation is registered yet"
        )
    entry = _REGISTRY.get(algorithm)
    if entry is None:
        raise UnknownAlgorithmError(algorithm)
    return entry.verifier_factory(key_material)


register_algorithm(ALGORITHM_ED25519, Ed25519Signer, Ed25519Verifier)
