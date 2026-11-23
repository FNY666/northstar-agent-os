"""Key management service (KMS) interface: key lifecycle as a state machine.

Research motivation: every real key-management system (AWS KMS, GCP Cloud
KMS, HashiCorp Vault's transit engine, PKCS #11 token APIs) separates *key
lifecycle* from *crypto use*. The load-bearing rules are:

- A key alias has exactly one **current** version; older versions are kept
  readable only so old ciphertexts can be re-encrypted during rotation.
- Encryption always uses the current version; decrypt accepts any
  non-revoked version (data encrypted years ago must stay readable).
- Revocation is terminal and immediate: a revoked key decrypts nothing.

This module pins that shape as a deterministic, network-free state
machine. It is *not* a crypto library: key material is derived from
SHA-256 KDF chains (deterministic, no entropy source), and sealing is a
SHA-256 keystream under an HMAC integrity tag. The *policy* -
who may encrypt, which version, what happens after rotation/revocation -
is the part the runtime depends on, and it is pinned here.

Public API:

- ``KMS()`` -- in-memory key store; all operations take caller-supplied
  int seqs (no wall-clock).
- ``create_key(alias, purpose, seq) -> Key`` -- mints version 1 in state
  ``active``. Duplicate aliases fail closed.
- ``rotate_key(alias, seq) -> Key`` -- mints version n+1 ``active``;
  the old version becomes ``superseded`` (decrypt-only).
- ``revoke_key(alias, seq)`` -- marks *all* versions ``revoked``;
  both directions refuse afterwards.
- ``encrypt(alias, plaintext, seq) -> Envelope`` -- only the current
  ``active`` version may encrypt.
- ``decrypt(envelope, seq) -> bytes`` -- verifies the integrity tag,
  then unseals; revoked keys fail closed.
- ``Key`` / ``Envelope`` / ``RotationRecord`` / ``RevocationRecord`` --
  frozen records with ``as_dict()`` and ``sha256:`` digest pins.
- ``kms_audit_event(kind, seq, ...)`` -- ``audit.ndjson/1`` shaped
  records with fixed vocabulary (``key-created`` / ``key-rotated`` /
  ``key-revoked`` / ``encrypted`` / ``decrypted`` / ``encrypt-refused`` /
  ``decrypt-refused``).

Honest scope: simulated - the keystream is SHA-256, key material is
KDF-derived and visible to the host (there is no HSM, no secure
channel, no access policy beyond the state machine); confidentiality
against the host operator is not claimed. Deterministic on purpose:
same inputs give bit-identical envelopes, which keeps audit snapshots
reproducible. This pins the *interface shape*; real HSM backends drop
in without changing call sites.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Tuple, Dict, Optional

__version__ = "kms-interface.v1"
__schema__ = "northstar.kms-interface.v1"

_DOMAIN = b"northstar.kms-interface.v1"
_MAX_KEY_BYTES = 1 << 20  # 1 MiB per envelope; DoS guardrail.

_STATE_ACTIVE = "active"
_STATE_SUPERSEDED = "superseded"
_STATE_REVOKED = "revoked"


class KMSError(Exception):
    """Base error for the KMS interface."""


class DuplicateAliasError(KMSError):
    """Alias already exists; key creation refused."""


class UnknownAliasError(KMSError):
    """Alias has no registered key."""


class KMSDeniedError(KMSError):
    """Operation denied by key state (wrong state, revoked, ...)."""


class EnvelopeIntegrityError(KMSError):
    """Envelope tag mismatch; never silently decrypted."""


def _fail_closed_str(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise KMSError(f"{name} must be a non-empty str")
    return value


def _fail_closed_seq(seq: object, name: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise KMSError(f"{name} must be a non-negative int")
    return seq


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _pin(data: bytes) -> str:
    return "sha256:" + _sha256(data).hex()


def _kdf(context: bytes, *parts: bytes) -> bytes:
    """Domain-separated deterministic key derivation."""
    acc = _DOMAIN + b"/" + context
    for part in parts:
        acc += b"/" + _sha256(part)
    return _sha256(acc)


def _key_material(alias: str, version: int) -> bytes:
    return _kdf(b"key", alias.encode("utf-8"), version.to_bytes(8, "big"))


def _keystream(material: bytes, nonce: bytes, length: int) -> bytes:
    """SHA-256 counter-mode keystream (simulated, deterministic)."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += _sha256(material + b"/stream/" + nonce +
                       counter.to_bytes(8, "big"))
        counter += 1
    return bytes(out[:length])


@dataclass(frozen=True)
class Key:
    """A single key version; immutable snapshot of one lifecycle state."""
    alias: str
    version: int
    state: str
    public_pin: str
    created_seq: int
    schema: str = field(default=__schema__, repr=False)

    def __post_init__(self) -> None:
        _fail_closed_str(self.alias, "alias")
        if (isinstance(self.version, bool) or not isinstance(self.version, int)
                or self.version < 1):
            raise KMSError("version must be a positive int")
        if self.state not in (_STATE_ACTIVE, _STATE_SUPERSEDED, _STATE_REVOKED):
            raise KMSError("unknown key state")
        if not isinstance(self.public_pin, str) or not self.public_pin.startswith("sha256:"):
            raise KMSError("public_pin must be a sha256: pin")
        _fail_closed_seq(self.created_seq, "created_seq")
        if self.schema != __schema__:
            raise KMSError("schema pin mismatch")

    def as_dict(self) -> dict:
        return {
            "alias": self.alias,
            "version": self.version,
            "state": self.state,
            "public_pin": self.public_pin,
            "created_seq": self.created_seq,
            "module": __version__,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class Envelope:
    """Sealed plaintext bound to one key version."""
    alias: str
    version: int
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    seq: int
    schema: str = field(default=__schema__, repr=False)

    def __post_init__(self) -> None:
        _fail_closed_str(self.alias, "alias")
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version < 1:
            raise KMSError("version must be a positive int")
        for name, val in (("nonce", self.nonce), ("ciphertext", self.ciphertext),
                          ("tag", self.tag)):
            if not isinstance(val, bytes) or not val:
                raise KMSError(f"{name} must be non-empty bytes")
        _fail_closed_seq(self.seq, "seq")
        if self.schema != __schema__:
            raise KMSError("schema pin mismatch")

    def as_dict(self) -> dict:
        return {
            "alias": self.alias,
            "version": self.version,
            "digest": _pin(self.nonce + self.ciphertext),
            "seq": self.seq,
            "module": __version__,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class RotationRecord:
    """Evidence that alias moved from version old to new."""
    alias: str
    old_version: int
    new_version: int
    seq: int
    schema: str = field(default=__schema__, repr=False)

    def __post_init__(self) -> None:
        _fail_closed_str(self.alias, "alias")
        for name, val in (("old_version", self.old_version), ("new_version", self.new_version)):
            if isinstance(val, bool) or not isinstance(val, int) or val < 1:
                raise KMSError(f"{name} must be a positive int")
        if self.new_version != self.old_version + 1:
            raise KMSError("rotation must advance exactly one version")
        _fail_closed_seq(self.seq, "seq")
        if self.schema != __schema__:
            raise KMSError("schema pin mismatch")

    def as_dict(self) -> dict:
        return {
            "alias": self.alias,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "seq": self.seq,
            "module": __version__,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class RevocationRecord:
    """Terminal evidence: alias revoked at a seq."""
    alias: str
    seq: int
    schema: str = field(default=__schema__, repr=False)

    def __post_init__(self) -> None:
        _fail_closed_str(self.alias, "alias")
        _fail_closed_seq(self.seq, "seq")
        if self.schema != __schema__:
            raise KMSError("schema pin mismatch")

    def as_dict(self) -> dict:
        return {
            "alias": self.alias,
            "seq": self.seq,
            "module": __version__,
            "schema": self.schema,
        }


class KMS:
    """In-memory key store enforcing the lifecycle state machine.

    All methods are fail-closed and take caller-supplied int seqs;
    there is no wall-clock. No randomness: key material is KDF-derived,
    so the whole history is reproducible from the alias/version inputs.
    """

    def __init__(self) -> None:
        # alias -> list of per-version dicts (state, pin), index = version-1
        self._keys: Dict[str, list] = {}
        self._seal_counter = 0

    def _versions(self, alias: str) -> list:
        if alias not in self._keys:
            raise UnknownAliasError(f"unknown alias: {alias!r}")
        return self._keys[alias]

    def _current_version(self, alias: str) -> int:
        return len(self._versions(alias))

    def create_key(self, alias: str, purpose: str, seq: int) -> Key:
        """Mint version 1 of ``alias`` in state active."""
        _fail_closed_str(alias, "alias")
        _fail_closed_str(purpose, "purpose")
        _fail_closed_seq(seq)
        if alias in self._keys:
            raise DuplicateAliasError(f"alias already exists: {alias!r}")
        material = _key_material(alias, 1)
        pin = _pin(b"public/" + alias.encode() + b"/1/" + _sha256(material))
        self._keys[alias] = [{"state": _STATE_ACTIVE, "pin": pin,
                              "created_seq": seq, "purpose": purpose}]
        return Key(alias=alias, version=1, state=_STATE_ACTIVE,
                   public_pin=pin, created_seq=seq)

    def rotate_key(self, alias: str, seq: int) -> RotationRecord:
        """Mint version n+1 as active; old current becomes superseded."""
        _fail_closed_str(alias, "alias")
        _fail_closed_seq(seq)
        versions = self._versions(alias)
        if versions[-1]["state"] == _STATE_REVOKED:
            raise KMSDeniedError("cannot rotate a revoked key")
        versions[-1]["state"] = _STATE_SUPERSEDED
        new_version = len(versions) + 1
        material = _key_material(alias, new_version)
        pin = _pin(b"public/" + alias.encode()
                   + b"/" + str(new_version).encode() + b"/" + _sha256(material))
        versions.append({"state": _STATE_ACTIVE, "pin": pin,
                         "created_seq": seq, "purpose": versions[0]["purpose"]})
        return RotationRecord(alias=alias, old_version=new_version - 1,
                              new_version=new_version, seq=seq)

    def revoke_key(self, alias: str, seq: int) -> RevocationRecord:
        """Mark every version of ``alias`` revoked; terminal."""
        _fail_closed_str(alias, "alias")
        _fail_closed_seq(seq)
        versions = self._versions(alias)
        for entry in versions:
            entry["state"] = _STATE_REVOKED
        return RevocationRecord(alias=alias, seq=seq)

    def describe(self, alias: str) -> Tuple[Key, ...]:
        """All versions of ``alias``, oldest first (current snapshot)."""
        _fail_closed_str(alias, "alias")
        return tuple(
            Key(alias=alias, version=i + 1, state=entry["state"],
                public_pin=entry["pin"], created_seq=entry["created_seq"])
            for i, entry in enumerate(self._versions(alias))
        )

    def current_key(self, alias: str) -> Key:
        """Snapshot of the current (latest) version of ``alias``."""
        versions = self.describe(alias)
        return versions[-1]

    def encrypt(self, alias: str, plaintext: bytes, seq: int) -> Envelope:
        """Seal ``plaintext`` under the current active version of ``alias``.

        Only an ``active`` (current, non-revoked) key may encrypt.
        """
        _fail_closed_str(alias, "alias")
        if isinstance(plaintext, bool) or not isinstance(plaintext, bytes):
            raise KMSError("plaintext must be bytes")
        if len(plaintext) > _MAX_KEY_BYTES:
            raise KMSError("plaintext exceeds envelope guardrail")
        _fail_closed_seq(seq)
        versions = self._versions(alias)
        entry = versions[-1]
        if entry["state"] != _STATE_ACTIVE:
            raise KMSDeniedError(
                f"encrypt denied: alias {alias!r} is {entry['state']}")
        version = len(versions)
        material = _key_material(alias, version)
        nonce = _sha256(b"nonce/" + alias.encode() + b"/" + str(version).encode()
                        + b"/" + str(self._seal_counter).encode())
        self._seal_counter += 1
        keystream = _keystream(material, nonce, len(plaintext))
        ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
        tag = _kdf(b"tag", material, nonce, ciphertext)
        return Envelope(alias=alias, version=version, nonce=nonce,
                        ciphertext=ciphertext, tag=tag, seq=seq)

    def decrypt(self, envelope: Envelope, seq: int) -> bytes:
        """Verify the tag, then unseal.

        Accepts any non-revoked version (superseded keys still decrypt
        their old ciphertexts so rotation can migrate data). Fails closed
        on revoked keys and on tag mismatch.
        """
        if not isinstance(envelope, Envelope):
            raise KMSError("envelope must be an Envelope")
        _fail_closed_seq(seq)
        versions = self._versions(envelope.alias)
        if not (1 <= envelope.version <= len(versions)):
            raise KMSDeniedError("envelope names a version that does not exist")
        entry = versions[envelope.version - 1]
        if entry["state"] == _STATE_REVOKED:
            raise KMSDeniedError(
                f"decrypt denied: alias {envelope.alias!r} v{envelope.version} is revoked")
        material = _key_material(envelope.alias, envelope.version)
        expected = _kdf(b"tag", material, envelope.nonce, envelope.ciphertext)
        if not hmac.compare_digest(expected, envelope.tag):
            raise EnvelopeIntegrityError("envelope tag mismatch")
        keystream = _keystream(material, envelope.nonce, len(envelope.ciphertext))
        return bytes(c ^ k for c, k in zip(envelope.ciphertext, keystream))


_KMS_EVENT_KINDS = (
    "key-created",
    "key-rotated",
    "key-revoked",
    "encrypted",
    "decrypted",
    "encrypt-refused",
    "decrypt-refused",
)


def kms_audit_event(kind: str, seq: int, **fields: object) -> dict:
    """Audit-shaped record for a KMS observation."""
    if kind not in _KMS_EVENT_KINDS:
        raise ValueError("unknown kind")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    record = {
        "event": "kms-interface",
        "kind": kind,
        "audit_seq": seq,
        "schema": "audit.ndjson/1",
    }
    record.update(fields)
    return record


def main() -> None:
    kms = KMS()
    key = kms.create_key("agent-signing", "signing", 1)
    assert key.state == "active" and key.version == 1, "created active v1"
    env = kms.encrypt("agent-signing", b"hello", 2)
    assert kms.decrypt(env, 3) == b"hello", "roundtrip"
    rec = kms.rotate_key("agent-signing", 4)
    assert rec.new_version == 2, "rotation advanced"
    assert kms.decrypt(env, 5) == b"hello", "old ciphertext still decrypts"
    new_env = kms.encrypt("agent-signing", b"world", 6)
    assert new_env.version == 2, "encryption uses current version"
    kms.revoke_key("agent-signing", 7)
    try:
        kms.encrypt("agent-signing", b"x", 8)
    except KMSDeniedError:
        pass
    else:
        raise AssertionError("encrypt after revoke must refuse")
    try:
        kms.decrypt(env, 9)
    except KMSDeniedError:
        pass
    else:
        raise AssertionError("decrypt after revoke must refuse")
    print("kms-interface OK: create, encrypt, rotate, decrypt-old, revoke-deny")


if __name__ == "__main__":
    main()
