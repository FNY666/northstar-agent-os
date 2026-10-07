"""Hardware security module interface: keys never leave the module.

A simulated HSM boundary for the runtime: key material is generated,
stored, and used *inside* an ``HSM`` instance, and the only things that
ever cross the boundary are:

- ``KeyHandle`` (frozen): ``key_id`` + algorithm + digest pins - identity,
  not material.
- ``PublicKey`` (frozen): for asymmetric algorithms, an exportable
  public half that can encrypt and verify but never sign or decrypt.
- Ciphertexts and signatures.

``generate_key()`` mints material into the module's internal vault;
``sign()`` and ``decrypt()`` execute inside the module and return only
the operation result. There is deliberately **no** ``export_private``
path - requesting private material is a fail-closed ``HSMError``.

Design (simulated cryptography, deterministic):
1. One ``HSM`` instance owns one vault: a plain in-memory mapping
   ``key_id -> key material`` guarded by an ``RLock``. A fresh instance
   has a fresh vault, so tests and tenants never share keys.
2. Algorithms are pinned by name: ``ed25519-sim`` (signing),
   ``hmac-sha256`` (symmetric MAC), ``rsa-oaep-sim`` (asymmetric
   encryption), ``aes-256-gcm-sim`` (symmetric encryption). Key
   material derives deterministically from
   ``sha256(domain || hsm_label || key_id || purpose)`` so the module
   is fully deterministic and audit-replayable (real HSMs use a
   hardware TRNG; determinism here is pinned, not a feature).
3. Signatures/MACs are ``HMAC-SHA256(material, domain || key_id ||
   message)`` - deterministic, and the signer's public half verifies
   them via a verification token derived from the same material.
4. Encryption is a SHA-256 counter-mode keystream XOR plus a 16-byte
   integrity tag bound to ``key_id``; ``decrypt`` verifies the tag
   with ``hmac.compare_digest`` before opening, so tampering is a
   fail-closed ``IntegrityError``, never silent garbage.
5. Cross-key operations are refused: ``decrypt`` with a signing key,
   ``sign`` with an encryption key, and cross-instance handles all
   raise ``HSMError`` (a ``KeyHandle`` is bound to its ``HSM`` via the
   instance id in the handle).

Honest scope: interface pin, not a security boundary. This is a
bookkeeping simulation of the HSM API shape (generate/sign/decrypt/
public-export/audit) so production code can be written against it and
later dropped onto a real PKCS#11 / cloud-HSM driver without changing
call sites. The vault lives in process memory - anyone with a memory
dump reads the keys - and "private key never leaves" is enforced by the
API, not by hardware. Deterministic key derivation means two
deployments with the same label mint the same keys; do not use as a
cryptographic module.

No wall-clock anywhere. All caller-supplied int seqs.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

HSM_INTERFACE_VERSION = "hsm-interface.v1"
SCHEMA_PIN = "northstar.hsm-interface.v1"

_DOMAIN = b"northstar.hsm-interface.v1"
_TAG_LEN = 16
_KEY_ID_BYTES = 16

_SIGNING_ALGORITHMS = ("ed25519-sim", "hmac-sha256")
_ENCRYPTION_ALGORITHMS = ("rsa-oaep-sim", "aes-256-gcm-sim")
_ALGORITHMS = _SIGNING_ALGORITHMS + _ENCRYPTION_ALGORITHMS
_ASYMMETRIC = ("ed25519-sim", "rsa-oaep-sim")


class HSMError(Exception):
    """Fail-closed HSM boundary error: unknown handle, wrong algorithm,
    export refusal, integrity failure."""


class IntegrityError(HSMError):
    """A ciphertext or signature tag did not verify - tampering or
    wrong key. Fail-closed: nothing is returned."""


def _check_seq(seq: int) -> None:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise HSMError("seq must be a non-negative int")


def _check_bytes(value: bytes, name: str, allow_empty: bool = False) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes, not {type(value).__name__}")
    if not allow_empty and len(value) == 0:
        raise HSMError(f"{name} must not be empty")


def _derive(label: str, key_id: str, purpose: str) -> bytes:
    return hashlib.sha256(
        _DOMAIN + b"|" + label.encode() + b"|" + key_id.encode() + b"|" + purpose.encode()
    ).digest()


def _pin(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class KeyHandle:
    """Identity of a key that lives inside an ``HSM`` vault.

    Carries no key material - only ``key_id``, the algorithm name, the
    owning instance id, and digest pins. Frozen and opaque to callers.
    """

    key_id: str
    algorithm: str
    instance_id: str
    material_pin: str
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.key_id, str) or not self.key_id:
            raise HSMError("key_id must be a non-empty str")
        if self.algorithm not in _ALGORITHMS:
            raise HSMError(f"unknown algorithm {self.algorithm!r}")
        if not isinstance(self.instance_id, str) or not self.instance_id:
            raise HSMError("instance_id must be a non-empty str")
        if not self.material_pin.startswith("sha256:"):
            raise HSMError("material_pin must be a sha256: pin")

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "instance_id": self.instance_id,
            "material_pin": self.material_pin,
        }


@dataclass(frozen=True)
class PublicKey:
    """Exportable public half of an asymmetric key.

    Can encrypt (``rsa-oaep-sim``) and verify signatures
    (``ed25519-sim``); can never sign or decrypt. ``verify_token`` is a
    digest bound to the private material, not the material itself.
    """

    key_id: str
    algorithm: str
    instance_id: str
    verify_token: str
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if self.algorithm not in _ASYMMETRIC:
            raise HSMError(f"algorithm {self.algorithm!r} has no public half")
        if not self.verify_token.startswith("sha256:"):
            raise HSMError("verify_token must be a sha256: pin")

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "instance_id": self.instance_id,
            "verify_token": self.verify_token,
        }


@dataclass(frozen=True)
class Signature:
    """A signature minted inside the module: binding, not material."""

    key_id: str
    algorithm: str
    instance_id: str
    message_pin: str
    sig: bytes
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.sig, bytes) or len(self.sig) != 32:
            raise HSMError("sig must be 32 bytes")
        if not isinstance(self.instance_id, str) or not self.instance_id:
            raise HSMError("instance_id must be a non-empty str")
        if not self.message_pin.startswith("sha256:"):
            raise HSMError("message_pin must be a sha256: pin")

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "instance_id": self.instance_id,
            "message_pin": self.message_pin,
            "sig": self.sig.hex(),
        }


@dataclass(frozen=True)
class Ciphertext:
    """A ciphertext minted inside (or via a public half of) the module."""

    key_id: str
    algorithm: str
    nonce: int
    body: bytes
    tag: bytes
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.body, bytes) or len(self.body) == 0:
            raise HSMError("body must be non-empty bytes")
        if not isinstance(self.tag, bytes) or len(self.tag) != _TAG_LEN:
            raise HSMError(f"tag must be {_TAG_LEN} bytes")
        if isinstance(self.nonce, bool) or not isinstance(self.nonce, int) or self.nonce < 0:
            raise HSMError("nonce must be a non-negative int")

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "nonce": self.nonce,
            "body": self.body.hex(),
            "tag": self.tag.hex(),
        }


class HSM:
    """One simulated HSM slot: generates, stores, and uses key material.

    The vault is instance-local and RLock-guarded. Key material is a
    per-key 32-byte secret derived deterministically at generation; it
    is stored only in ``self._vault`` and never leaves through any
    public method.
    """

    def __init__(self, label: str = "default") -> None:
        if not isinstance(label, str) or not label:
            raise HSMError("label must be a non-empty str")
        self._label = label
        self._lock = threading.RLock()
        self._vault: Dict[str, bytes] = {}
        self._counter = 0
        self._nonce: Dict[str, int] = {}
        self._instance_id = hashlib.sha256(
            _DOMAIN + b"|instance|" + label.encode()
        ).hexdigest()[:32]

    # -- internals ----------------------------------------------------

    def _get_material(self, handle: KeyHandle) -> bytes:
        if not isinstance(handle, KeyHandle):
            raise TypeError("handle must be a KeyHandle")
        if handle.instance_id != self._instance_id:
            raise HSMError("KeyHandle belongs to a different HSM instance")
        with self._lock:
            try:
                return self._vault[handle.key_id]
            except KeyError:
                raise HSMError(f"unknown key_id {handle.key_id!r}") from None

    def _keystream(self, material: bytes, nonce: int, length: int) -> bytes:
        out = b""
        block = 0
        while len(out) < length:
            out += hashlib.sha256(
                material
                + b"|ks|"
                + nonce.to_bytes(8, "big")
                + block.to_bytes(8, "big")
            ).digest()
            block += 1
        return out[:length]

    # -- public API ----------------------------------------------------

    def generate_key(self, algorithm: str, seq: int) -> KeyHandle:
        """Mint key material inside the vault; return only the handle."""
        _check_seq(seq)
        if algorithm not in _ALGORITHMS:
            raise HSMError(f"unknown algorithm {algorithm!r}")
        with self._lock:
            self._counter += 1
            key_id = "key-%d-%s" % (
                self._counter,
                hashlib.sha256(
                    _DOMAIN
                    + b"|kid|"
                    + self._instance_id.encode()
                    + b"|"
                    + str(self._counter).encode()
                    + b"|"
                    + str(seq).encode()
                ).hexdigest()[: _KEY_ID_BYTES * 2],
            )
            material = _derive(self._label, key_id, "material")
            self._vault[key_id] = material
            self._nonce[key_id] = 0
        return KeyHandle(
            key_id=key_id,
            algorithm=algorithm,
            instance_id=self._instance_id,
            material_pin=_pin(material),
        )

    def key_count(self) -> int:
        """Number of keys currently in the vault (no material exposed)."""
        with self._lock:
            return len(self._vault)

    def export_public(self, handle: KeyHandle, seq: int) -> PublicKey:
        """Export the public half of an asymmetric key.

        Symmetric keys and signing-only material have no public half -
        requesting one is a fail-closed refusal, never a leak.
        """
        _check_seq(seq)
        material = self._get_material(handle)
        if handle.algorithm not in _ASYMMETRIC:
            raise HSMError(
                f"algorithm {handle.algorithm!r} has no exportable public half"
            )
        return PublicKey(
            key_id=handle.key_id,
            algorithm=handle.algorithm,
            instance_id=self._instance_id,
            verify_token=_pin(_DOMAIN + b"|verify|" + material),
        )

    def sign(self, handle: KeyHandle, message: bytes, seq: int) -> Signature:
        """Sign ``message`` inside the module; return the signature."""
        _check_seq(seq)
        _check_bytes(message, "message")
        if handle.algorithm not in _SIGNING_ALGORITHMS:
            raise HSMError(
                f"algorithm {handle.algorithm!r} cannot sign; "
                f"signing algorithms: {_SIGNING_ALGORITHMS}"
            )
        material = self._get_material(handle)
        sig = hmac.new(
            material,
            _DOMAIN + b"|sign|" + handle.key_id.encode() + b"|" + message,
            hashlib.sha256,
        ).digest()
        return Signature(
            key_id=handle.key_id,
            algorithm=handle.algorithm,
            instance_id=self._instance_id,
            message_pin=_pin(message),
            sig=sig,
        )

    def verify_signature(
        self, public: PublicKey, message: bytes, signature: Signature
    ) -> bool:
        """Verify with a public half: True/False, never raises on policy.

        Cross-instance and cross-key inputs verify False. Malformed
        argument *types* raise TypeError; anything else that does not
        check out is a False verdict.
        """
        if not isinstance(public, PublicKey):
            raise TypeError("public must be a PublicKey")
        if not isinstance(signature, Signature):
            raise TypeError("signature must be a Signature")
        if not isinstance(message, bytes):
            raise TypeError("message must be bytes")
        if (
            public.key_id != signature.key_id
            or public.algorithm != signature.algorithm
            or public.instance_id != signature.instance_id
            or public.algorithm not in _SIGNING_ALGORITHMS
        ):
            return False
        material = self._vault.get(public.key_id)
        if material is None:
            return False
        expected_token = _pin(_DOMAIN + b"|verify|" + material)
        if not hmac.compare_digest(expected_token, public.verify_token):
            return False
        expected = hmac.new(
            material,
            _DOMAIN + b"|sign|" + public.key_id.encode() + b"|" + message,
            hashlib.sha256,
        ).digest()
        return hmac.compare_digest(expected, signature.sig)

    def encrypt(
        self,
        key: object,
        data: bytes,
        seq: int,
    ) -> Ciphertext:
        """Encrypt ``data``. Accepts a ``KeyHandle`` (symmetric) or a
        ``PublicKey`` (asymmetric) - the private half never encrypts
        outside the module."""
        _check_seq(seq)
        _check_bytes(data, "data")
        if isinstance(key, PublicKey):
            if key.algorithm != "rsa-oaep-sim":
                raise HSMError(
                    f"public key algorithm {key.algorithm!r} cannot encrypt"
                )
            material = self._vault.get(key.key_id)
            if material is None or key.instance_id != self._instance_id:
                raise HSMError("unknown public key")
            key_id, algorithm = key.key_id, key.algorithm
        elif isinstance(key, KeyHandle):
            if key.algorithm != "aes-256-gcm-sim":
                raise HSMError(
                    f"algorithm {key.algorithm!r} cannot encrypt; "
                    "encryption algorithms: "
                    f"{_ENCRYPTION_ALGORITHMS}"
                )
            material = self._get_material(key)
            key_id, algorithm = key.key_id, key.algorithm
        else:
            raise TypeError("key must be a KeyHandle or PublicKey")
        with self._lock:
            self._nonce[key_id] += 1
            nonce = self._nonce[key_id]
        body = bytes(
            b ^ k for b, k in zip(data, self._keystream(material, nonce, len(data)))
        )
        tag = hmac.new(
            material,
            _DOMAIN + b"|enc|" + key_id.encode() + nonce.to_bytes(8, "big") + body,
            hashlib.sha256,
        ).digest()[:_TAG_LEN]
        return Ciphertext(
            key_id=key_id, algorithm=algorithm, nonce=nonce, body=body, tag=tag
        )

    def decrypt(self, handle: KeyHandle, ciphertext: Ciphertext, seq: int) -> bytes:
        """Decrypt inside the module. Tag failure is fail-closed."""
        _check_seq(seq)
        if not isinstance(ciphertext, Ciphertext):
            raise TypeError("ciphertext must be a Ciphertext")
        if handle.algorithm not in _ENCRYPTION_ALGORITHMS:
            raise HSMError(
                f"algorithm {handle.algorithm!r} cannot decrypt; "
                f"encryption algorithms: {_ENCRYPTION_ALGORITHMS}"
            )
        if ciphertext.key_id != handle.key_id:
            raise HSMError("ciphertext was not minted for this key")
        if ciphertext.algorithm != handle.algorithm:
            raise HSMError("ciphertext algorithm does not match key algorithm")
        material = self._get_material(handle)
        expected = hmac.new(
            material,
            _DOMAIN
            + b"|enc|"
            + handle.key_id.encode()
            + ciphertext.nonce.to_bytes(8, "big")
            + ciphertext.body,
            hashlib.sha256,
        ).digest()[:_TAG_LEN]
        if not hmac.compare_digest(expected, ciphertext.tag):
            raise IntegrityError("ciphertext integrity check failed")
        keystream = self._keystream(material, ciphertext.nonce, len(ciphertext.body))
        return bytes(b ^ k for b, k in zip(ciphertext.body, keystream))


def hsm_audit_event(kind: str, seq: int, key_id: Optional[str] = None) -> dict:
    """Shape an HSM lifecycle event as an ``audit.ndjson/1`` record.

    Only key ids and kinds cross into the audit trail - never key
    material, never plaintext.
    """
    valid = (
        "key-generated",
        "public-exported",
        "signed",
        "verified",
        "encrypted",
        "decrypted",
        "rejected",
    )
    if kind not in valid:
        raise ValueError(f"unknown audit kind {kind!r}")
    _check_seq(seq)
    if key_id is not None and (not isinstance(key_id, str) or not key_id):
        raise ValueError("key_id must be a non-empty str or None")
    record = {
        "schema": "audit.ndjson/1",
        "kind": f"hsm-interface.{kind}",
        "module": SCHEMA_PIN,
        "version": HSM_INTERFACE_VERSION,
        "seq": seq,
    }
    if key_id is not None:
        record["key_id"] = key_id
    return record


def main() -> None:
    hsm = HSM("self-check")
    # Signing path: keys never leave, public half verifies.
    signing = hsm.generate_key("ed25519-sim", 1)
    sig = hsm.sign(signing, b"approve:budget=100", 2)
    pub = hsm.export_public(signing, 3)
    assert hsm.verify_signature(pub, b"approve:budget=100", sig) is True
    assert hsm.verify_signature(pub, b"approve:budget=101", sig) is False
    # Symmetric MAC path.
    mac_key = hsm.generate_key("hmac-sha256", 4)
    tag = hsm.sign(mac_key, b"heartbeat", 5)
    assert tag.sig != sig.sig
    # Asymmetric encryption: encrypt with public half, decrypt inside.
    enc_key = hsm.generate_key("rsa-oaep-sim", 6)
    enc_pub = hsm.export_public(enc_key, 7)
    ct = hsm.encrypt(enc_pub, b"payload", 8)
    assert hsm.decrypt(enc_key, ct, 9) == b"payload"
    # Symmetric encryption stays inside the module entirely.
    sym = hsm.generate_key("aes-256-gcm-sim", 10)
    ct2 = hsm.encrypt(sym, b"secret", 11)
    assert hsm.decrypt(sym, ct2, 12) == b"secret"
    # Boundary refusals.
    try:
        hsm.export_public(sym, 13)
        raise AssertionError("symmetric key must not export")
    except HSMError:
        pass
    try:
        hsm.sign(enc_key, b"x", 14)
        raise AssertionError("encryption key must not sign")
    except HSMError:
        pass
    print("hsm-interface OK: keygen, sign, verify, encrypt, decrypt, refusals")


if __name__ == "__main__":
    main()
