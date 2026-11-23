"""Post-quantum signature interface (ML-DSA / Falcon / SPHINCS+, simulated).

Research motivation: a cryptographically relevant quantum computer
breaks RSA, ECDSA, and Ed25519 (Shor's algorithm), so signatures minted
today can be forged tomorrow -- "sign now, forge later". NIST finished
standardizing post-quantum signatures in 2024: **ML-DSA** (FIPS 204,
Dilithium, module-lattice), **SLH-DSA** (FIPS 205, SPHINCS+, stateless
hash-based), and **Falcon** (NTRU lattice, selected for compact
signatures and keys).

This module pins the post-quantum signature *interface and key
lifecycle* for the runtime: an algorithm registry with per-scheme
parameter pins, deterministic keygen / sign / verify shape, algorithm
agility (``migrate`` across schemes when one is weakened), and audit
records. The per-scheme math is *simulated* -- no lattice arithmetic,
no Merkle hypertrees; a real implementation drops in without changing
call sites.

Public API:

- ``PQCSig(scheme)`` -- session bound to one scheme:
  - ``keygen(seed=b"")`` -- deterministic key generation; returns
    frozen ``KeyPair`` (public + secret halves).
  - ``sign(secret_key, message, seq)`` -- deterministic signature;
    returns frozen ``Signature``.
  - ``verify(public_key, message, signature)`` -- ``True`` / ``False``
    (policy outcome; raises ``TypeError`` only on caller type misuse,
    never on a bad signature).
- ``scheme_info(scheme)`` -- frozen ``SchemeParams`` (family,
  standard, pinned sizes).
- ``migrate(public_key, new_scheme, seed=b"")`` -- algorithm agility:
  mints a fresh keypair under ``new_scheme`` carrying the old key's
  provenance; returns ``(KeyPair, MigrationRecord)``.
- ``SUPPORTED_SCHEMES`` -- ``{"dilithium", "falcon", "sphincs"}``.
- ``pqc_sig_audit_event(kind, seq, ...)`` -- ``audit.ndjson/1``
  records; kinds ``"keygen"`` / ``"signed"`` / ``"verified"`` /
  ``"rejected"`` / ``"migrated"``.
- ``PQCSigError``.

Honest scope:

- **Simulated signatures.** ``sign`` computes a domain-separated
  deterministic tag from the key's master material; ``verify``
  recomputes it from a verification token carried *inside the public
  key*. Anyone holding the public key can therefore mint a tag that
  verifies -- there is no unforgeability here. What the simulation
  pins is the *protocol shape*: key lifecycle, scheme registry,
  cross-scheme confusion refusal (a dilithium signature never verifies
  under a falcon key), message/key binding, and audit wiring. It is an
  integration placeholder, not a cryptographic boundary.
- **No side-channel posture.** Deterministic by design (replayable
  tests, auditable); real deployments need hedged randomness.
- ``verify`` returning ``True`` means "tag consistent with this public
  key and message", never "a quantum adversary cannot forge this".
- Pinned sizes are the real standardized sizes (ML-DSA-65, Falcon-512,
  SLH-DSA-128s "small") -- recorded as documentation of what the
  interface must accommodate, not measured from this simulation.

Version pin: ``pqc-sig.v1`` / schema pin ``northstar.pqc-sig.v1``.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Dict, FrozenSet, Optional, Tuple, Union

#: Module version.
PQC_SIG_VERSION = "pqc-sig.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.pqc-sig.v1"

#: Version pin carried inside audit records.
AUDIT_FORMAT = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
_AUDIT_KINDS = frozenset(
    {"keygen", "signed", "verified", "rejected", "migrated"}
)

#: Domain separator for every hash in this module.
_DOMAIN = b"northstar.pqc-sig.v1\x00"

#: Canonical scheme identifiers.
DILITHIUM = "dilithium"
FALCON = "falcon"
SPHINCS = "sphincs"

#: Schemes this interface speaks.
SUPPORTED_SCHEMES: FrozenSet[str] = frozenset({DILITHIUM, FALCON, SPHINCS})

#: Fixed hex width for key material (32 bytes) and tags.
_MATERIAL_HEX = 64


class PQCSigError(Exception):
    """Base error for post-quantum-signature failures."""


def _check_scheme(scheme: object) -> str:
    """Validate a scheme identifier fail-closed."""
    if isinstance(scheme, bool) or not isinstance(scheme, str):
        raise TypeError(f"scheme must be str, got {type(scheme).__name__}")
    if scheme not in SUPPORTED_SCHEMES:
        raise PQCSigError(f"unsupported scheme: {scheme!r}")
    return scheme


def _check_seq(seq: object) -> int:
    """Reject bools and non-int seqs fail-closed."""
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise ValueError("seq must be non-negative")
    return seq


def _check_bytes(value: object, name: str, allow_empty: bool = False) -> bytes:
    """Reject bools and non-bytes fail-closed."""
    if isinstance(value, bool) or not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes, got {type(value).__name__}")
    if not allow_empty and len(value) == 0:
        raise ValueError(f"{name} must be non-empty")
    return value


def _pin(data: bytes) -> str:
    """A ``sha256:`` digest pin."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _message_parts(message: Union[str, bytes]) -> Tuple[bytes, str]:
    """Canonicalize a message. Returns (digest bytes, ``sha256:`` pin).

    ``str`` and ``bytes`` are type-tagged so ``"m"`` and ``b"m"`` sign
    different digests (no caller type-confusion collision).
    """
    if isinstance(message, bool) or not isinstance(message, (str, bytes)):
        raise TypeError(
            f"message must be str or bytes, got {type(message).__name__}"
        )
    tag = b"\x01" if isinstance(message, str) else b"\x02"
    raw = message.encode("utf-8") if isinstance(message, str) else message
    digest = hashlib.sha256(_DOMAIN + b"message\x00" + tag + raw).digest()
    return digest, _pin(_DOMAIN + b"message\x00" + tag + raw)


@dataclass(frozen=True)
class SchemeParams:
    """Pinned parameters for one post-quantum scheme."""

    scheme: str
    family: str
    standard: str
    security_level: int
    public_key_bytes: int
    secret_key_bytes: int
    signature_bytes: int
    params_digest: str

    def as_dict(self) -> dict:
        return {
            "scheme": self.scheme,
            "family": self.family,
            "standard": self.standard,
            "security_level": self.security_level,
            "public_key_bytes": self.public_key_bytes,
            "secret_key_bytes": self.secret_key_bytes,
            "signature_bytes": self.signature_bytes,
            "params_digest": self.params_digest,
            "schema": SCHEMA_PIN,
            "version": PQC_SIG_VERSION,
        }


def _scheme_params(scheme: str) -> SchemeParams:
    """Build the pinned ``SchemeParams`` for a valid scheme."""
    if scheme == DILITHIUM:
        family = "module-lattice"
        standard = "FIPS 204"
        pk, sk, sig = 1952, 4032, 3309  # ML-DSA-65
    elif scheme == FALCON:
        family = "ntru-lattice"
        standard = "NIST selected (FIPS draft)"
        pk, sk, sig = 897, 1281, 690  # Falcon-512 (sig variable; nominal)
    else:  # SPHINCS
        family = "stateless-hash"
        standard = "FIPS 205"
        pk, sk, sig = 32, 64, 7856  # SLH-DSA-128s (small)
    digest = _pin(
        _DOMAIN
        + b"scheme-params\x00"
        + scheme.encode()
        + family.encode()
        + standard.encode()
        + str(pk).encode()
        + str(sk).encode()
        + str(sig).encode()
    )
    return SchemeParams(
        scheme=scheme,
        family=family,
        standard=standard,
        security_level=2,
        public_key_bytes=pk,
        secret_key_bytes=sk,
        signature_bytes=sig,
        params_digest=digest,
    )


def scheme_info(scheme: str) -> SchemeParams:
    """Return the pinned parameters for a scheme.

    Fail-closed on unknown schemes: the registry is the only source of
    truth for which algorithms this runtime claims to speak.
    """
    _check_scheme(scheme)
    return _scheme_params(scheme)


@dataclass(frozen=True)
class PublicKey:
    """A post-quantum public key (verification material only)."""

    scheme: str
    key_id: str
    public_pin: str
    verify_token: str

    def __post_init__(self) -> None:
        _check_scheme(self.scheme)
        for name in ("key_id", "public_pin", "verify_token"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, str):
                raise TypeError(f"{name} must be str")
            if not value.startswith("sha256:"):
                raise ValueError(f"{name} must be a sha256: pin")

    def as_dict(self) -> dict:
        return {
            "scheme": self.scheme,
            "key_id": self.key_id,
            "public_pin": self.public_pin,
            "verify_token": self.verify_token,
            "schema": SCHEMA_PIN,
            "version": PQC_SIG_VERSION,
        }


@dataclass(frozen=True)
class SecretKey:
    """A post-quantum secret key. Never written to audit records."""

    scheme: str
    key_id: str
    secret_hex: str

    def __post_init__(self) -> None:
        _check_scheme(self.scheme)
        if isinstance(self.key_id, bool) or not isinstance(self.key_id, str):
            raise TypeError("key_id must be str")
        if not self.key_id.startswith("sha256:"):
            raise ValueError("key_id must be a sha256: pin")
        if (
            isinstance(self.secret_hex, bool)
            or not isinstance(self.secret_hex, str)
            or len(self.secret_hex) != _MATERIAL_HEX
        ):
            raise TypeError(
                f"secret_hex must be {_MATERIAL_HEX}-char hex"
            )
        try:
            int(self.secret_hex, 16)
        except ValueError:
            raise ValueError("secret_hex must be hex") from None

    def as_dict(self) -> dict:
        return {
            "scheme": self.scheme,
            "key_id": self.key_id,
            "secret_pin": _pin(self.secret_hex.encode()),
            "schema": SCHEMA_PIN,
            "version": PQC_SIG_VERSION,
        }


@dataclass(frozen=True)
class KeyPair:
    """A generated post-quantum keypair."""

    public_key: PublicKey
    secret_key: SecretKey

    def __post_init__(self) -> None:
        if not isinstance(self.public_key, PublicKey):
            raise TypeError("public_key must be PublicKey")
        if not isinstance(self.secret_key, SecretKey):
            raise TypeError("secret_key must be SecretKey")
        if self.public_key.scheme != self.secret_key.scheme:
            raise PQCSigError("public/secret scheme mismatch")
        if self.public_key.key_id != self.secret_key.key_id:
            raise PQCSigError("public/secret key_id mismatch")


@dataclass(frozen=True)
class Signature:
    """A post-quantum signature over a message digest."""

    scheme: str
    key_id: str
    message_digest: str
    sig_hex: str
    seq: int

    def __post_init__(self) -> None:
        _check_scheme(self.scheme)
        for name in ("key_id", "message_digest"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, str):
                raise TypeError(f"{name} must be str")
            if not value.startswith("sha256:"):
                raise ValueError(f"{name} must be a sha256: pin")
        if (
            isinstance(self.sig_hex, bool)
            or not isinstance(self.sig_hex, str)
            or len(self.sig_hex) != _MATERIAL_HEX
        ):
            raise TypeError(
                f"sig_hex must be {_MATERIAL_HEX}-char hex"
            )
        try:
            int(self.sig_hex, 16)
        except ValueError:
            raise ValueError("sig_hex must be hex") from None
        _check_seq(self.seq)

    def as_dict(self) -> dict:
        return {
            "scheme": self.scheme,
            "key_id": self.key_id,
            "message_digest": self.message_digest,
            "sig_hex": self.sig_hex,
            "seq": self.seq,
            "schema": SCHEMA_PIN,
            "version": PQC_SIG_VERSION,
        }


@dataclass(frozen=True)
class MigrationRecord:
    """Provenance for an algorithm-agility migration."""

    old_scheme: str
    old_key_id: str
    new_scheme: str
    new_key_id: str
    seq: int

    def __post_init__(self) -> None:
        _check_scheme(self.old_scheme)
        _check_scheme(self.new_scheme)
        if self.old_scheme == self.new_scheme:
            raise PQCSigError("migration must change schemes")
        for name in ("old_key_id", "new_key_id"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, str):
                raise TypeError(f"{name} must be str")
        _check_seq(self.seq)

    def as_dict(self) -> dict:
        return {
            "old_scheme": self.old_scheme,
            "old_key_id": self.old_key_id,
            "new_scheme": self.new_scheme,
            "new_key_id": self.new_key_id,
            "seq": self.seq,
            "schema": SCHEMA_PIN,
            "version": PQC_SIG_VERSION,
        }


def _master_material(scheme: str, seed: bytes) -> bytes:
    """Derive the per-key master material deterministically."""
    return hashlib.sha256(
        _DOMAIN + b"master\x00" + scheme.encode() + b"\x00" + seed
    ).digest()


class PQCSig:
    """Post-quantum signature session bound to one scheme.

    Deterministic and simulated: ``keygen`` derives key material from
    the seed, ``sign`` tags the message digest, ``verify`` recomputes
    the tag from the verification token inside the public key. See the
    module docstring's honest scope -- this pins the interface and key
    lifecycle, not unforgeability.
    """

    def __init__(self, scheme: str) -> None:
        self._scheme = _check_scheme(scheme)
        self._params = _scheme_params(self._scheme)

    @property
    def scheme(self) -> str:
        return self._scheme

    @property
    def params(self) -> SchemeParams:
        return self._params

    def keygen(self, seed: bytes = b"") -> KeyPair:
        """Generate a deterministic keypair from ``seed``.

        Same ``(scheme, seed)`` always yields the same keypair --
        replayable for tests and audit; real deployments must feed a
        CSPRNG seed.
        """
        _check_bytes(seed, "seed", allow_empty=True)
        master = _master_material(self._scheme, seed)
        key_id = _pin(_DOMAIN + b"key-id\x00" + master)
        public_pin = _pin(_DOMAIN + b"public\x00" + master)
        # The tag base is shared between the secret and public halves:
        # the public half can recompute tags, which is exactly the
        # documented simulation boundary (no unforgeability).
        tag_base = hashlib.sha256(
            _DOMAIN + b"tag-base\x00" + master
        ).hexdigest()
        verify_token = "sha256:" + tag_base
        secret_hex = tag_base
        return KeyPair(
            public_key=PublicKey(
                scheme=self._scheme,
                key_id=key_id,
                public_pin=public_pin,
                verify_token=verify_token,
            ),
            secret_key=SecretKey(
                scheme=self._scheme,
                key_id=key_id,
                secret_hex=secret_hex,
            ),
        )

    def _expected_tag(
        self, key_id: str, material_hex: str, msg_digest_raw: bytes
    ) -> str:
        """The tag ``verify`` expects; also what ``sign`` mints."""
        return hmac.new(
            material_hex.encode(),
            _DOMAIN + b"tag\x00" + key_id.encode() + msg_digest_raw,
            hashlib.sha256,
        ).hexdigest()

    def sign(
        self, secret_key: SecretKey, message: Union[str, bytes], seq: int
    ) -> Signature:
        """Sign a message with a secret key; returns a frozen record.

        Fail-closed: the key must belong to this scheme, and the
        message must be str/bytes.
        """
        if not isinstance(secret_key, SecretKey):
            raise TypeError(
                f"secret_key must be SecretKey, got "
                f"{type(secret_key).__name__}"
            )
        if secret_key.scheme != self._scheme:
            raise PQCSigError(
                f"key scheme {secret_key.scheme!r} does not match "
                f"session scheme {self._scheme!r}"
            )
        _check_seq(seq)
        msg_digest_raw, msg_pin = _message_parts(message)
        # The signing token is derived from the secret material; the
        # verifier recomputes it from the public verify_token, which
        # derives from the same master. (Simulation boundary: the
        # public key can mint tags. See module honest scope.)
        tag = self._expected_tag(
            secret_key.key_id, secret_key.secret_hex, msg_digest_raw
        )
        return Signature(
            scheme=self._scheme,
            key_id=secret_key.key_id,
            message_digest=msg_pin,
            sig_hex=tag,
            seq=seq,
        )

    def verify(
        self,
        public_key: PublicKey,
        message: Union[str, bytes],
        signature: Signature,
    ) -> bool:
        """Verify a signature against a public key and message.

        Returns ``True`` / ``False`` (policy outcome); raises
        ``TypeError`` only on caller type misuse, never on a bad
        signature. A signature minted under a different scheme or key
        never verifies -- cross-scheme confusion is refused.
        """
        if not isinstance(public_key, PublicKey):
            raise TypeError(
                f"public_key must be PublicKey, got "
                f"{type(public_key).__name__}"
            )
        if not isinstance(signature, Signature):
            raise TypeError(
                f"signature must be Signature, got "
                f"{type(signature).__name__}"
            )
        if public_key.scheme != self._scheme:
            return False
        if signature.scheme != self._scheme:
            return False
        if signature.key_id != public_key.key_id:
            return False
        try:
            msg_digest_raw, msg_pin = _message_parts(message)
        except (TypeError, ValueError):
            raise
        if msg_pin != signature.message_digest:
            return False
        # Recompute the expected tag from the public verify token,
        # which shares the tag base with the secret half (documented
        # simulation boundary: the public key can mint tags).
        expected = self._expected_tag(
            public_key.key_id,
            public_key.verify_token[len("sha256:"):],
            msg_digest_raw,
        )
        return bool(
            hmac.compare_digest(expected.encode(), signature.sig_hex.encode())
        )


def migrate(
    public_key: PublicKey, new_scheme: str, seed: bytes = b"", seq: int = 0
) -> Tuple[KeyPair, MigrationRecord]:
    """Algorithm agility: re-key under a new scheme with provenance.

    Returns the fresh ``KeyPair`` under ``new_scheme`` plus a frozen
    ``MigrationRecord`` binding old -> new, so auditors can trace
    which key replaced which when a scheme is weakened.
    """
    if not isinstance(public_key, PublicKey):
        raise TypeError(
            f"public_key must be PublicKey, got {type(public_key).__name__}"
        )
    _check_scheme(new_scheme)
    _check_bytes(seed, "seed", allow_empty=True)
    _check_seq(seq)
    if new_scheme == public_key.scheme:
        raise PQCSigError("migration must change schemes")
    new_keys = PQCSig(new_scheme).keygen(seed)
    record = MigrationRecord(
        old_scheme=public_key.scheme,
        old_key_id=public_key.key_id,
        new_scheme=new_scheme,
        new_key_id=new_keys.public_key.key_id,
        seq=seq,
    )
    return new_keys, record


def pqc_sig_audit_event(
    kind: str,
    seq: int,
    scheme: Optional[str] = None,
    key_id: Optional[str] = None,
    message_digest: Optional[str] = None,
) -> dict:
    """Build an ``audit.ndjson/1``-shaped record for this module.

    Never carries secret material: key references are ``key_id`` pins
    only.
    """
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    record = {
        "format": AUDIT_FORMAT,
        "module": PQC_SIG_VERSION,
        "schema": SCHEMA_PIN,
        "kind": f"pqc-sig-{kind}",
        "seq": seq,
    }
    if scheme is not None:
        _check_scheme(scheme)
        record["scheme"] = scheme
    if key_id is not None:
        record["key_id"] = key_id
    if message_digest is not None:
        record["message_digest"] = message_digest
    return record


def main() -> None:
    for scheme in sorted(SUPPORTED_SCHEMES):
        session = PQCSig(scheme)
        keys = session.keygen(b"self-check")
        sig = session.sign(keys.secret_key, "hello post-quantum", 1)
        assert session.verify(keys.public_key, "hello post-quantum", sig)
        assert not session.verify(keys.public_key, "tampered", sig)
        other = PQCSig(
            DILITHIUM if scheme != DILITHIUM else FALCON
        )
        assert not other.verify(
            other.keygen(b"self-check").public_key,
            "hello post-quantum",
            sig,
        )
    new_keys, record = migrate(
        PQCSig(DILITHIUM).keygen(b"m").public_key, FALCON, b"m2", seq=7
    )
    assert record.new_scheme == FALCON
    assert new_keys.public_key.scheme == FALCON
    print("pqc-sig OK: keygen, sign, verify, cross-scheme refusal, migrate")


if __name__ == "__main__":
    main()
