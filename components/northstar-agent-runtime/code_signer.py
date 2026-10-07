"""Code signing interface (Sigstore / Fulcio / Cosign shaped, simulated).

Research motivation: supply-chain security stands on *signing artifacts at
the point of creation* — a build attests what it produced, and a consumer
verifies before it trusts. Sigstore's load-bearing ideas are: (1) *keyed
signing* — a persistent key (e.g. an Ed25519 key in a KMS) signs the artifact
digest; (2) *keyless signing* — the signer proves an OIDC identity (a
human's GitHub login, a workload's service account) to Fulcio, which issues
a short-lived certificate binding the *identity* to an *ephemeral key*, so
there is no long-lived key to steal; (3) *verify before trust* — a verifier
checks the signature against the pinned public key (keyed) or the identity
+ OIDC issuer (keyless), and *tamper is data*, not an exception — the caller
acts on the verdict.

This module implements that shape as a deterministic, single-host ledger:

* **Key registry** — :meth:`CodeSigner.register_key` pins a public key for a
  ``key_id`` (duplicate ids refused fail-closed).
* **Keyed signing** — :meth:`CodeSigner.sign` books a frozen
  :class:`SignatureRecord` (``sig-N`` monotonic ids) binding (artifact id,
  artifact digest, key id) with a ``sha256:`` digest pin. The "signature" is
  an HMAC over the canonical signing statement with a host-supplied secret
  standing in for the real private key — simulated, stated in the
  honest-scope docstring below.
* **Keyless signing** — :meth:`CodeSigner.keyless` books a frozen
  :class:`KeylessSignature` binding (identity, OIDC issuer, artifact digest);
  the identity is the attestation *subject*, exactly as Fulcio's certificate
  subject is the signer. No persistent key material exists.
* **Verification** — :meth:`CodeSigner.verify` and
  :meth:`CodeSigner.verify_keyless` return frozen
  :class:`VerificationReport` records (``valid`` + reason); a bad signature,
  wrong digest, unknown key, or issuer mismatch is verdict *data*, never an
  exception (fail-closed observation).

House style: frozen dataclasses, caller-supplied int seqs (strictly
increasing per signer, no wall-clock, no RNG), RLock-guarded, fail-closed
(unknown keys, duplicate ids, tampered payloads, issuer mismatch, bool/
negative/non-increasing seqs all raise or verdict-refuse via a subclass of
:class:`CodeSignerError`), stdlib-only, type-tagged canonical digest
encoding (bool != int; NaN/inf and integral floats with magnitude >= 2**53
refused at digest-pin time — the batch-5 JCS float-loss caveat), audit
events shaped for ``audit.ndjson/1``, ``main()`` self-check.

Honest scope: this is a *signature bookkeeping* interface, not a crypto
implementation. It runs no Ed25519, no X.509, no Fulcio/Rekor: the HMAC
stands in for the signature scheme, the identity field stands in for the
OIDC token, and the digest pins stand in for the certificate chain. A
``valid=True`` verdict means "this ledger's bookkeeping checks out for the
pinned key/identity", never "the artifact is trustworthy" — a lying host
gets a consistent ledger of lies (GIGO, same boundary as every other
bookkeeping module). Pair with ``remote_attestation`` and
``transparency_log`` for production trust roots.

Version pin: code-signer.v1
Schema pin: northstar.code-signer.v1
"""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

    def _pin(obj: Any) -> str:  # type: ignore[no-redef]
        return "sha256:" + hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Module version pin.
CODE_SIGNER_VERSION = "code-signer.v1"

#: Schema pin for records produced by this module.
CODE_SIGNER_SCHEMA = "northstar.code-signer.v1"

#: Audit event schema pin.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Hard cap on artifact-digest string length (guardrail).
MAX_DIGEST_LEN = 256

#: OIDC issuers this module recognizes for keyless signing (pinned
#: vocabulary — an unknown issuer is refused fail-closed).
KNOWN_ISSUERS = frozenset(
    {
        "https://token.actions.githubusercontent.com",
        "https://accounts.google.com",
        "https://gitlab.com",
    }
)

#: Audit event kinds.
_AUDIT_KINDS = (
    "key-registered",
    "signed",
    "keyless-signed",
    "verified",
    "keyless-verified",
    "revoked",
    "rejected",
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CodeSignerError(ValueError):
    """Base fail-closed code-signer error."""


class UnknownKeyError(CodeSignerError):
    """No registered key for this key_id (or it was revoked)."""


class DuplicateKeyError(CodeSignerError):
    """A key_id is already registered (ids are never recycled)."""


class RevokedKeyError(CodeSignerError):
    """The key was revoked; it signs/verifies no more."""


class UnknownSignatureError(CodeSignerError):
    """No such signature in the ledger."""


class UnknownIssuerError(CodeSignerError):
    """The OIDC issuer is not in the pinned vocabulary."""


class ValidationError(CodeSignerError):
    """Malformed input (bad id, bad digest, empty identity, ...)."""


class SeqOrderError(CodeSignerError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: Any, last: int) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise CodeSignerError("seq must be an int, got %r" % (type(seq).__name__,))
    if seq < 0:
        raise CodeSignerError("seq must be non-negative")
    if seq <= last:
        raise SeqOrderError("seq must strictly increase (last=%d, got=%d)" % (last, seq))
    return seq


def _check_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("%s must be a non-empty str" % name)
    if len(value) > 128:
        raise ValidationError("%s too long (max 128 chars)" % name)
    return value


def _check_digest(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError("artifact_digest must be a non-empty str")
    if len(value) > MAX_DIGEST_LEN:
        raise ValidationError("artifact_digest too long (max %d)" % MAX_DIGEST_LEN)
    return value


def _hmac_sig(secret: bytes, statement: Mapping[str, Any]) -> str:
    """Simulated signature: HMAC-SHA256 over the JCS canonical statement."""
    mac = hmac.new(secret, jcs_canonical_json(dict(statement)), hashlib.sha256)
    return "hmac-sha256:" + mac.hexdigest()


def _pin(obj: Any) -> str:
    """Digest pin: sibling convention is a raw hex from jcs_sha256_hex,
    wrapped with the ``sha256:`` scheme prefix."""
    raw = jcs_sha256_hex(obj)
    return raw if raw.startswith("sha256:") else "sha256:" + raw


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class KeyRecord:
    """A pinned public key (the stand-in for a real Ed25519/KMS key)."""

    key_id: str
    public_key: str
    pin: str
    seq: int
    version: str = CODE_SIGNER_VERSION
    schema: str = CODE_SIGNER_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "key_id": self.key_id,
            "public_key": self.public_key,
            "pin": self.pin,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class SignatureRecord:
    """One booked keyed signature over an artifact digest."""

    signature_id: str
    artifact_id: str
    artifact_digest: str
    key_id: str
    signature: str
    pin: str
    seq: int
    version: str = CODE_SIGNER_VERSION
    schema: str = CODE_SIGNER_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "signature_id": self.signature_id,
            "artifact_id": self.artifact_id,
            "artifact_digest": self.artifact_digest,
            "key_id": self.key_id,
            "signature": self.signature,
            "pin": self.pin,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class KeylessSignature:
    """One booked keyless signature bound to an OIDC identity + issuer."""

    signature_id: str
    artifact_id: str
    artifact_digest: str
    identity: str
    issuer: str
    ephemeral_key_id: str
    signature: str
    pin: str
    seq: int
    version: str = CODE_SIGNER_VERSION
    schema: str = CODE_SIGNER_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "signature_id": self.signature_id,
            "artifact_id": self.artifact_id,
            "artifact_digest": self.artifact_digest,
            "identity": self.identity,
            "issuer": self.issuer,
            "ephemeral_key_id": self.ephemeral_key_id,
            "signature": self.signature,
            "pin": self.pin,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class VerificationReport:
    """A frozen verify verdict — tamper is data, never raised."""

    signature_id: str
    artifact_digest: str
    valid: bool
    reason: str
    pin: str
    seq: int
    version: str = CODE_SIGNER_VERSION
    schema: str = CODE_SIGNER_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "signature_id": self.signature_id,
            "artifact_digest": self.artifact_digest,
            "valid": self.valid,
            "reason": self.reason,
            "pin": self.pin,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class RevocationRecord:
    """Terminal revocation of a signing key."""

    key_id: str
    pin: str
    seq: int
    version: str = CODE_SIGNER_VERSION
    schema: str = CODE_SIGNER_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "key_id": self.key_id,
            "pin": self.pin,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


# ---------------------------------------------------------------------------
# The signer
# ---------------------------------------------------------------------------


class CodeSigner:
    """Deterministic, single-host code-signing bookkeeping.

    ``register_key(key_id, public_key_hex, secret_hex, seq)`` pins a key
    (the secret stands in for the private key half, simulated). ``sign``
    books a keyed signature, ``verify`` checks it. ``keyless(identity,
    artifact_id, artifact_digest, issuer, seq)`` books an OIDC-identity-
    bound signature with no persistent key, ``verify_keyless`` checks it.
    ``revoke(key_id, seq)`` is terminal.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._keys: Dict[str, KeyRecord] = {}
        self._secrets: Dict[str, bytes] = {}
        self._revoked: set[str] = set()
        self._sigs: Dict[str, SignatureRecord] = {}
        self._keyless: Dict[str, KeylessSignature] = {}
        self._sig_counter = 0
        self._last_seq = -1
        self._audit: list[Dict[str, Any]] = []

    # -- internals ------------------------------------------------------

    def _monotonic(self, seq: Any) -> int:
        seq = _check_seq(seq, self._last_seq)
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(code_signer_audit_event(kind, seq, **detail))

    def _next_sig_id(self) -> str:
        self._sig_counter += 1
        return "sig-%d" % self._sig_counter

    # -- key lifecycle --------------------------------------------------

    def register_key(
        self, key_id: Any, public_key_hex: Any, secret_hex: Any, seq: Any
    ) -> KeyRecord:
        """Pin a signing key (public half + simulated private secret)."""
        with self._lock:
            seq = self._monotonic(seq)
            key_id = _check_id(key_id, "key_id")
            if key_id in self._keys:
                raise DuplicateKeyError("key_id %r already registered" % key_id)
            for name, value in (("public_key_hex", public_key_hex), ("secret_hex", secret_hex)):
                if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]+", value):
                    raise ValidationError("%s must be hex" % name)
                if len(value) < 32:
                    raise ValidationError("%s too short (min 32 hex chars)" % name)
            pin = _pin(
                {"key_id": key_id, "public_key": public_key_hex.lower()}
            )
            record = KeyRecord(
                key_id=key_id,
                public_key=public_key_hex.lower(),
                pin=pin,
                seq=seq,
            )
            self._keys[key_id] = record
            self._secrets[key_id] = bytes.fromhex(secret_hex)
            self._emit("key-registered", seq, key_id=key_id, pin=pin)
            return record

    def revoke(self, key_id: Any, seq: Any) -> RevocationRecord:
        """Revoke a key: terminal, no further sign/verify on it."""
        with self._lock:
            seq = self._monotonic(seq)
            key_id = _check_id(key_id, "key_id")
            if key_id not in self._keys:
                raise UnknownKeyError("unknown key_id %r" % key_id)
            if key_id in self._revoked:
                raise CodeSignerError("key_id %r already revoked" % key_id)
            self._revoked.add(key_id)
            record = RevocationRecord(
                key_id=key_id,
                pin=_pin({"key_id": key_id, "revoked": True}),
                seq=seq,
            )
            self._emit("revoked", seq, key_id=key_id, pin=record.pin)
            return record

    # -- keyed signing --------------------------------------------------

    def sign(
        self, artifact_id: Any, artifact_digest: Any, key_id: Any, seq: Any
    ) -> SignatureRecord:
        """Book a keyed signature over an artifact digest."""
        with self._lock:
            seq = self._monotonic(seq)
            artifact_id = _check_id(artifact_id, "artifact_id")
            artifact_digest = _check_digest(artifact_digest)
            key_id = _check_id(key_id, "key_id")
            if key_id not in self._keys:
                raise UnknownKeyError("unknown key_id %r" % key_id)
            if key_id in self._revoked:
                raise RevokedKeyError("key_id %r is revoked" % key_id)
            signature_id = self._next_sig_id()
            statement = {
                "signature_id": signature_id,
                "artifact_id": artifact_id,
                "artifact_digest": artifact_digest,
                "key_id": key_id,
            }
            signature = _hmac_sig(self._secrets[key_id], statement)
            pin = _pin({**statement, "signature": signature})
            record = SignatureRecord(
                signature_id=signature_id,
                artifact_id=artifact_id,
                artifact_digest=artifact_digest,
                key_id=key_id,
                signature=signature,
                pin=pin,
                seq=seq,
            )
            self._sigs[signature_id] = record
            self._emit(
                "signed", seq, signature_id=signature_id, key_id=key_id, pin=pin
            )
            return record

    def verify(
        self, signature_id: Any, artifact_digest: Any, seq: Any
    ) -> VerificationReport:
        """Verify a keyed signature — verdict data, never raises on tamper."""
        with self._lock:
            seq = self._monotonic(seq)
            if not isinstance(signature_id, str) or not signature_id:
                raise ValidationError("signature_id must be a non-empty str")
            artifact_digest = _check_digest(artifact_digest)
            record = self._sigs.get(signature_id)
            if record is None:
                return self._report(
                    signature_id, artifact_digest, False, "unknown-signature", seq
                )
            if record.artifact_digest != artifact_digest:
                return self._report(
                    signature_id, artifact_digest, False, "digest-mismatch", seq
                )
            if record.key_id in self._revoked:
                return self._report(
                    signature_id, artifact_digest, False, "key-revoked", seq
                )
            statement = {
                "signature_id": record.signature_id,
                "artifact_id": record.artifact_id,
                "artifact_digest": record.artifact_digest,
                "key_id": record.key_id,
            }
            expected = _hmac_sig(self._secrets[record.key_id], statement)
            if not hmac.compare_digest(expected, record.signature):
                return self._report(
                    signature_id, artifact_digest, False, "bad-signature", seq
                )
            return self._report(signature_id, artifact_digest, True, "ok", seq)

    def _report(
        self,
        signature_id: str,
        artifact_digest: str,
        valid: bool,
        reason: str,
        seq: int,
    ) -> VerificationReport:
        kind = "verified" if reason != "keyless" else "keyless-verified"
        report = VerificationReport(
            signature_id=signature_id,
            artifact_digest=artifact_digest,
            valid=valid,
            reason=reason,
            pin=_pin(
                {
                    "signature_id": signature_id,
                    "artifact_digest": artifact_digest,
                    "valid": valid,
                    "reason": reason,
                }
            ),
            seq=seq,
        )
        self._emit(kind, seq, signature_id=signature_id, valid=valid, reason=reason)
        return report

    # -- keyless signing -------------------------------------------------

    def keyless(
        self,
        identity: Any,
        artifact_id: Any,
        artifact_digest: Any,
        issuer: Any,
        seq: Any,
    ) -> KeylessSignature:
        """Book a keyless signature bound to an OIDC identity + issuer.

        The identity (e.g. ``alice@example.com`` or
        ``https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main``)
        is the attestation subject; ``issuer`` must be in the pinned
        vocabulary. The ephemeral key id is derived from the binding —
        no persistent key material exists.
        """
        with self._lock:
            seq = self._monotonic(seq)
            identity = _check_id(identity, "identity")
            artifact_id = _check_id(artifact_id, "artifact_id")
            artifact_digest = _check_digest(artifact_digest)
            if not isinstance(issuer, str) or issuer not in KNOWN_ISSUERS:
                raise UnknownIssuerError("unknown OIDC issuer %r" % (issuer,))
            signature_id = self._next_sig_id()
            ephemeral_key_id = "eph-" + hashlib.sha256(
                jcs_canonical_json(
                    {"identity": identity, "issuer": issuer, "id": signature_id}
                )
            ).hexdigest()[:16]
            statement = {
                "signature_id": signature_id,
                "artifact_id": artifact_id,
                "artifact_digest": artifact_digest,
                "identity": identity,
                "issuer": issuer,
                "ephemeral_key_id": ephemeral_key_id,
            }
            signature = _hmac_sig(b"keyless-ephemeral-binding", statement)
            pin = _pin({**statement, "signature": signature})
            record = KeylessSignature(
                signature_id=signature_id,
                artifact_id=artifact_id,
                artifact_digest=artifact_digest,
                identity=identity,
                issuer=issuer,
                ephemeral_key_id=ephemeral_key_id,
                signature=signature,
                pin=pin,
                seq=seq,
            )
            self._keyless[signature_id] = record
            self._emit(
                "keyless-signed",
                seq,
                signature_id=signature_id,
                identity=identity,
                issuer=issuer,
                pin=pin,
            )
            return record

    def verify_keyless(
        self, signature_id: Any, artifact_digest: Any, seq: Any
    ) -> VerificationReport:
        """Verify a keyless signature — verdict data, never raises on tamper."""
        with self._lock:
            seq = self._monotonic(seq)
            if not isinstance(signature_id, str) or not signature_id:
                raise ValidationError("signature_id must be a non-empty str")
            artifact_digest = _check_digest(artifact_digest)
            record = self._keyless.get(signature_id)
            if record is None:
                return self._report(
                    signature_id, artifact_digest, False, "unknown-signature", seq
                )
            if record.artifact_digest != artifact_digest:
                return self._report(
                    signature_id, artifact_digest, False, "digest-mismatch", seq
                )
            statement = {
                "signature_id": record.signature_id,
                "artifact_id": record.artifact_id,
                "artifact_digest": record.artifact_digest,
                "identity": record.identity,
                "issuer": record.issuer,
                "ephemeral_key_id": record.ephemeral_key_id,
            }
            expected = _hmac_sig(b"keyless-ephemeral-binding", statement)
            if not hmac.compare_digest(expected, record.signature):
                return self._report(
                    signature_id, artifact_digest, False, "bad-signature", seq
                )
            return self._report(signature_id, artifact_digest, True, "ok", seq)

    # -- views -----------------------------------------------------------

    def key_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._keys))

    def is_revoked(self, key_id: str) -> bool:
        with self._lock:
            return key_id in self._revoked

    def signature(self, signature_id: str) -> Optional[SignatureRecord]:
        with self._lock:
            return self._sigs.get(signature_id)

    def keyless_signature(self, signature_id: str) -> Optional[KeylessSignature]:
        with self._lock:
            return self._keyless.get(signature_id)

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def code_signer_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for code-signer activity."""
    if kind not in _AUDIT_KINDS:
        raise CodeSignerError("unknown audit kind %r" % (kind,))
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise CodeSignerError("seq must be a non-negative int")
    event: Dict[str, Any] = {
        "schema": AUDIT_SCHEMA,
        "event": kind,
        "audit_seq": seq,
        "module_version": CODE_SIGNER_VERSION,
        "module_schema": CODE_SIGNER_SCHEMA,
    }
    for key, value in detail.items():
        if key in ("secret_hex", "secret", "private_key"):
            raise CodeSignerError("audit boundary must never carry key material")
        event[key] = value
    return event


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """Self-check: register, sign, verify, tamper, keyless, revoke, refusals."""
    signer = CodeSigner()
    key = signer.register_key(
        "k1", "ab" * 32, "cd" * 32, 0
    )
    assert key.pin.startswith("sha256:")
    sig = signer.sign("app-v1.2.3", "sha256:deadbeef", "k1", 1)
    assert sig.signature_id == "sig-1"
    assert sig.pin.startswith("sha256:")

    ok = signer.verify("sig-1", "sha256:deadbeef", 2)
    assert ok.valid and ok.reason == "ok", ok.as_dict()

    bad = signer.verify("sig-1", "sha256:00", 3)
    assert not bad.valid and bad.reason == "digest-mismatch"

    unknown = signer.verify("sig-99", "sha256:deadbeef", 4)
    assert not unknown.valid and unknown.reason == "unknown-signature"

    kls = signer.keyless(
        "alice@example.com",
        "app-v1.2.3",
        "sha256:deadbeef",
        "https://accounts.google.com",
        5,
    )
    assert kls.ephemeral_key_id.startswith("eph-")
    vok = signer.verify_keyless(kls.signature_id, "sha256:deadbeef", 6)
    assert vok.valid and vok.reason == "ok"

    rev = signer.revoke("k1", 7)
    assert signer.is_revoked("k1")
    stale = signer.verify("sig-1", "sha256:deadbeef", 8)
    assert not stale.valid and stale.reason == "key-revoked"

    try:
        signer.sign("app-v2", "sha256:11", "k1", 9)
    except RevokedKeyError:
        pass
    else:
        raise AssertionError("signing with revoked key must fail")

    try:
        signer.keyless("b", "a", "d", "https://evil.example.com", 10)
    except UnknownIssuerError:
        pass
    else:
        raise AssertionError("unknown issuer must fail")

    print("code-signer OK: register, sign, verify, tamper, keyless, revoke")


if __name__ == "__main__":
    main()
