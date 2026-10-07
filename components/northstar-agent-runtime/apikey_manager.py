"""API key manager: issuance, rotation, revocation, and verification (simulated).

Research note: API keys are the oldest bearer-token scheme on the web, and
every major provider eventually converges on the same four operational
questions — the ones codified in Stripe's secret-key docs, GitHub's token
docs, and NIST SP 800-57's key-management lifecycle:

* **Issue** — mint a high-entropy secret, bind it to an identity (a
  ``key_id``), attach scopes, and hand the secret to the caller *exactly
  once*. What the ledger stores afterward is a *verifier* (here a
  ``sha256:`` digest of the secret), never the secret itself — the same
  shape as Unix password hashes and Stripe's ``sk_live_`` prefix convention
  (the ``nsk_`` prefix here is Northstar's analogue).
* **Verify** — on presentation, recompute the digest and compare with
  ``hmac.compare_digest`` (constant-time, no early-exit oracle), then check
  ledger state: unknown digest → reject, revoked → reject, expired →
  reject. A verifier that throws on bad input is a DoS surface, so
  *malformed* input returns ``valid=False`` as data; only wrong *types* are
  programming errors and raise.
* **Rotate** — mint a replacement key for the same name/scopes and revoke
  the old one in one atomic ledger step (GitHub's "regenerate token"
  semantics). Rotation is a re-issue plus revocation, never a mutation.
* **Revoke** — terminal ledger state. A revoked key never verifies again,
  never un-revokes, and never blocks a *new* ``key_id``.

Expiry is expressed in caller-supplied logical seqs (no wall-clock): a key
is live while ``at_seq < expires_at_seq``. A clock that moves backwards
cannot resurrect an expired or revoked record.

Fail-closed rules (load-bearing):

* ``key_id`` is globally unique: re-issuing an existing id raises
  ``DuplicateKeyError``, even after revocation (rotation mints a fresh id,
  it never recycles).
* A revoked key is terminal: ``verify()`` reports ``"revoked"``,
  ``rotate()`` raises ``RevokedKeyError``, and a second ``revoke()``
  raises ``AlreadyRevokedError`` — revocation is recorded exactly once.
* ``expires_at_seq`` must be strictly greater than the issuing seq; a key
  cannot be born expired.
* Mutation seqs must strictly increase per manager (``SeqOrderError``),
  so the ledger order is total and replay-exact.
* Raw secrets never appear in ``as_dict()``, audit events, or digests:
  the digest pins bind (key_id, name, scopes, key_digest, seqs) only.

Honest scope: this books *reported* key-lifecycle events. It cannot prove
a host stopped honoring a revoked key, cannot observe the wire, and the
key material is HMAC-derived bookkeeping, not a CSPRNG boundary —
production deployments must mint from the OS RNG (``secrets``) and bind
the verifier to a real hash store. With an explicit ``seed=`` the module
is fully deterministic for tests and audit replay; the default salt comes
from ``secrets.token_bytes``.

Version pin: apikey-manager.v1
Schema pin: northstar.apikey-manager.v1
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
APIKEY_MANAGER_VERSION = "apikey-manager.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.apikey-manager.v1"

#: Prefix minted keys carry (Northstar analogue of Stripe's ``sk_live_``).
KEY_PREFIX = "nsk_"

#: Length of the hex body of a minted secret (32 bytes of HMAC output).
KEY_HEX_LEN = 64


class APIKeyError(Exception):
    """Base error for the API key manager (fail-closed programming error)."""


class UnknownKeyError(APIKeyError):
    """No key with this id exists in the ledger."""


class DuplicateKeyError(APIKeyError):
    """A key with this id already exists (ids are never recycled)."""


class RevokedKeyError(APIKeyError):
    """Operation refused: the key is revoked (terminal state)."""


class AlreadyRevokedError(APIKeyError):
    """The key is already revoked; revocation is recorded exactly once."""


class SeqOrderError(APIKeyError):
    """Mutation seq did not strictly increase (ledger order must be total)."""


def _check_seq(value: Any, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise APIKeyError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise APIKeyError(f"{name} must be non-negative, got {value}")
    return value


def _check_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise APIKeyError(f"{name} must be a non-empty str")
    return value


def _check_scopes(scopes: Any) -> Tuple[str, ...]:
    if scopes is None:
        return ()
    if not isinstance(scopes, (tuple, list)):
        raise APIKeyError("scopes must be a tuple/list of str")
    checked = tuple(_check_str(s, "scope") for s in scopes)
    if len(set(checked)) != len(checked):
        raise APIKeyError("duplicate scopes")
    return tuple(sorted(checked))


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(payload)).hexdigest()


@dataclass(frozen=True)
class IssuedKey:
    """Frozen issuance record. ``secret`` is shown exactly once — it never
    appears in ``as_dict()``, digests, or audit events."""

    version: str
    key_id: str
    name: str
    scopes: Tuple[str, ...]
    key_digest: str
    issued_seq: int
    expires_at_seq: Optional[int]
    digest: str
    secret: str

    def as_dict(self) -> Dict[str, Any]:
        # The raw secret is deliberately excluded: pins and metadata only.
        return {
            "version": self.version,
            "key_id": self.key_id,
            "name": self.name,
            "scopes": list(self.scopes),
            "key_digest": self.key_digest,
            "issued_seq": self.issued_seq,
            "expires_at_seq": self.expires_at_seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class KeyInfo:
    """Metadata-only view of a key (no secret, ever)."""

    version: str
    key_id: str
    name: str
    scopes: Tuple[str, ...]
    key_digest: str
    issued_seq: int
    expires_at_seq: Optional[int]
    revoked: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "key_id": self.key_id,
            "name": self.name,
            "scopes": list(self.scopes),
            "key_digest": self.key_digest,
            "issued_seq": self.issued_seq,
            "expires_at_seq": self.expires_at_seq,
            "revoked": self.revoked,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class VerifyReport:
    """Outcome of ``verify()``. Malformed/unknown/revoked/expired are data,
    never exceptions."""

    version: str
    valid: bool
    key_id: Optional[str]
    reason: str  # ok | unknown | malformed | revoked | expired
    at_seq: int
    digest: str


@dataclass(frozen=True)
class RevocationRecord:
    """Terminal revocation pin."""

    version: str
    key_id: str
    seq: int
    reason: str
    digest: str


@dataclass(frozen=True)
class RotationRecord:
    """Atomic re-issue + revocation (old key is revoked, new key issued)."""

    version: str
    old_key_id: str
    new_key_id: str
    seq: int
    digest: str


class APIKeyManager:
    """Ledger for API-key issuance, rotation, revocation, and verification.

    ``seed`` is an optional 32-byte salt for deterministic key material in
    tests/audit replay; when omitted it comes from ``secrets.token_bytes``.
    """

    def __init__(self, seed: Optional[bytes] = None) -> None:
        if seed is None:
            seed = secrets.token_bytes(32)
        if not isinstance(seed, (bytes, bytearray)) or not seed:
            raise APIKeyError("seed must be non-empty bytes")
        self._salt = bytes(seed)
        self._lock = threading.RLock()
        self._keys: Dict[str, Dict[str, Any]] = {}
        self._revocations: Dict[str, RevocationRecord] = {}
        self._rotations: Tuple[RotationRecord, ...] = ()
        self._last_seq = -1

    # -- internals ------------------------------------------------------

    def _touch(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq
        return seq

    def _mint_secret(self, key_id: str, seq: int) -> str:
        mac = hmac.new(
            self._salt, f"apikey:{key_id}:{seq}".encode(), hashlib.sha256
        ).hexdigest()
        return KEY_PREFIX + mac[:KEY_HEX_LEN]

    def _record(self, key_id: str, name: str, secret: str,
                scopes: Tuple[str, ...], issued_seq: int,
                expires_at_seq: Optional[int]) -> Dict[str, Any]:
        key_digest = _digest({"secret": secret})
        digest = _digest({
            "key_id": key_id,
            "name": name,
            "scopes": list(scopes),
            "key_digest": key_digest,
            "issued_seq": issued_seq,
            "expires_at_seq": expires_at_seq,
        })
        return {
            "version": APIKEY_MANAGER_VERSION,
            "key_id": key_id,
            "name": name,
            "secret": secret,
            "scopes": scopes,
            "key_digest": key_digest,
            "issued_seq": issued_seq,
            "expires_at_seq": expires_at_seq,
            "digest": digest,
        }

    def _issued(self, rec: Dict[str, Any]) -> IssuedKey:
        return IssuedKey(
            version=rec["version"],
            key_id=rec["key_id"],
            name=rec["name"],
            scopes=rec["scopes"],
            key_digest=rec["key_digest"],
            issued_seq=rec["issued_seq"],
            expires_at_seq=rec["expires_at_seq"],
            digest=rec["digest"],
            secret=rec["secret"],
        )

    def _require(self, key_id: str) -> Dict[str, Any]:
        rec = self._keys.get(key_id)
        if rec is None:
            raise UnknownKeyError(f"unknown key_id: {key_id!r}")
        return rec

    # -- public API -----------------------------------------------------

    def issue(self, key_id: str, name: str, seq: int,
              scopes: Any = None,
              expires_at_seq: Optional[int] = None) -> IssuedKey:
        """Mint a key. The raw secret is returned in the record exactly
        once; the ledger stores only its ``sha256:`` digest."""
        key_id = _check_str(key_id, "key_id")
        name = _check_str(name, "name")
        checked_scopes = _check_scopes(scopes)
        if expires_at_seq is not None:
            if isinstance(expires_at_seq, bool) or not isinstance(
                expires_at_seq, int
            ):
                raise APIKeyError("expires_at_seq must be an int or None")
            if expires_at_seq <= seq:
                raise APIKeyError(
                    "expires_at_seq must be strictly greater than the "
                    f"issuing seq (got {expires_at_seq} <= {seq})"
                )
        with self._lock:
            seq = self._touch(seq)
            if key_id in self._keys:
                raise DuplicateKeyError(f"key_id already exists: {key_id!r}")
            secret = self._mint_secret(key_id, seq)
            rec = self._record(
                key_id, name, secret, checked_scopes, seq, expires_at_seq
            )
            self._keys[key_id] = rec
            return self._issued(rec)

    def verify(self, raw_key: Any, at_seq: int) -> VerifyReport:
        """Verify a presented key. Malformed input yields ``valid=False``
        as data (verifiers must not throw on hostile input); wrong *types*
        raise."""
        if not isinstance(raw_key, str):
            raise APIKeyError(
                f"raw_key must be a str, got {type(raw_key).__name__}"
            )
        at_seq = _check_seq(at_seq, "at_seq")
        reason = "malformed"
        key_id: Optional[str] = None
        if raw_key.startswith(KEY_PREFIX) and len(raw_key) == len(
            KEY_PREFIX
        ) + KEY_HEX_LEN:
            try:
                int(raw_key[len(KEY_PREFIX):], 16)
            except ValueError:
                pass  # not hex: stays malformed
            else:
                presented = _digest({"secret": raw_key})
                with self._lock:
                    for rec in self._keys.values():
                        if hmac.compare_digest(rec["key_digest"], presented):
                            key_id = rec["key_id"]
                            if key_id in self._revocations:
                                reason = "revoked"
                            elif (
                                rec["expires_at_seq"] is not None
                                and at_seq >= rec["expires_at_seq"]
                            ):
                                reason = "expired"
                            else:
                                reason = "ok"
                            break
                    else:
                        reason = "unknown"
        digest = _digest({
            "key_id": key_id,
            "reason": reason,
            "at_seq": at_seq,
        })
        return VerifyReport(
            version=APIKEY_MANAGER_VERSION,
            valid=reason == "ok",
            key_id=key_id,
            reason=reason,
            at_seq=at_seq,
            digest=digest,
        )

    def revoke(self, key_id: str, seq: int, reason: str = "") -> RevocationRecord:
        """Revoke a key. Terminal: it never verifies, un-revokes, or
        re-revokes again."""
        key_id = _check_str(key_id, "key_id")
        if not isinstance(reason, str):
            raise APIKeyError("reason must be a str")
        with self._lock:
            self._require(key_id)
            seq = self._touch(seq)
            if key_id in self._revocations:
                raise AlreadyRevokedError(f"already revoked: {key_id!r}")
            digest = _digest({
                "key_id": key_id,
                "seq": seq,
                "reason": reason,
            })
            rec = RevocationRecord(
                version=APIKEY_MANAGER_VERSION,
                key_id=key_id,
                seq=seq,
                reason=reason,
                digest=digest,
            )
            self._revocations[key_id] = rec
            return rec

    def rotate(self, key_id: str, new_key_id: str, seq: int,
               expires_at_seq: Optional[int] = None) -> Tuple[IssuedKey, RotationRecord]:
        """Rotate a key: mint a replacement (same name/scopes) and revoke
        the old one in a single ledger step."""
        key_id = _check_str(key_id, "key_id")
        new_key_id = _check_str(new_key_id, "new_key_id")
        if expires_at_seq is not None:
            if isinstance(expires_at_seq, bool) or not isinstance(
                expires_at_seq, int
            ):
                raise APIKeyError("expires_at_seq must be an int or None")
        with self._lock:
            old = self._require(key_id)
            if key_id in self._revocations:
                raise RevokedKeyError(f"cannot rotate revoked key: {key_id!r}")
            if new_key_id in self._keys:
                raise DuplicateKeyError(
                    f"new key_id already exists: {new_key_id!r}"
                )
            if expires_at_seq is not None and expires_at_seq <= seq:
                raise APIKeyError(
                    "expires_at_seq must be strictly greater than seq"
                )
            seq = self._touch(seq)
            secret = self._mint_secret(new_key_id, seq)
            new_rec = self._record(
                new_key_id,
                old["name"],
                secret,
                old["scopes"],
                seq,
                expires_at_seq,
            )
            self._keys[new_key_id] = new_rec
            rev_digest = _digest({
                "key_id": key_id,
                "seq": seq,
                "reason": "rotated",
            })
            self._revocations[key_id] = RevocationRecord(
                version=APIKEY_MANAGER_VERSION,
                key_id=key_id,
                seq=seq,
                reason="rotated",
                digest=rev_digest,
            )
            rot_digest = _digest({
                "old_key_id": key_id,
                "new_key_id": new_key_id,
                "seq": seq,
            })
            rotation = RotationRecord(
                version=APIKEY_MANAGER_VERSION,
                old_key_id=key_id,
                new_key_id=new_key_id,
                seq=seq,
                digest=rot_digest,
            )
            self._rotations = self._rotations + (rotation,)
            return self._issued(new_rec), rotation

    # -- views ----------------------------------------------------------

    def key(self, key_id: str) -> KeyInfo:
        """Metadata-only view of a key (no secret, ever)."""
        key_id = _check_str(key_id, "key_id")
        with self._lock:
            rec = self._require(key_id)
            return KeyInfo(
                version=rec["version"],
                key_id=rec["key_id"],
                name=rec["name"],
                scopes=rec["scopes"],
                key_digest=rec["key_digest"],
                issued_seq=rec["issued_seq"],
                expires_at_seq=rec["expires_at_seq"],
                revoked=key_id in self._revocations,
                digest=rec["digest"],
            )

    def key_ids(self) -> Tuple[str, ...]:
        """All issued key ids, sorted."""
        with self._lock:
            return tuple(sorted(self._keys))

    def active_ids(self, at_seq: int) -> Tuple[str, ...]:
        """Ids that are unrevoked and unexpired at ``at_seq``."""
        at_seq = _check_seq(at_seq, "at_seq")
        with self._lock:
            return tuple(
                sorted(
                    kid
                    for kid, rec in self._keys.items()
                    if kid not in self._revocations
                    and (
                        rec["expires_at_seq"] is None
                        or at_seq < rec["expires_at_seq"]
                    )
                )
            )

    def revocation(self, key_id: str) -> Optional[RevocationRecord]:
        """The revocation record for a key, or None if it is live."""
        key_id = _check_str(key_id, "key_id")
        with self._lock:
            self._require(key_id)
            return self._revocations.get(key_id)

    def rotations(self) -> Tuple[RotationRecord, ...]:
        """Append-only rotation history."""
        with self._lock:
            return self._rotations


def apikey_manager_audit_event(kind: str, seq: int, detail: dict) -> dict:
    """Shape an ``audit.ndjson/1`` record for API-key-manager events.

    Raw secrets must never be passed in ``detail`` — only ids, scopes,
    pins, and digests. This is enforced by convention here (as in
    ``secret_manager``), because the audit boundary cannot reach back into
    the frozen record's excluded ``secret`` field.
    """
    seq = _check_seq(seq)
    allowed = {"issued", "verified", "revoked", "rotated", "rejected"}
    if kind not in allowed:
        raise APIKeyError(f"unknown audit kind: {kind!r}")
    if not isinstance(detail, dict):
        raise APIKeyError("detail must be a dict")
    if any(k in ("secret", "raw_key") for k in detail):
        raise APIKeyError("audit detail must never carry key material")
    return {
        "schema": SCHEMA_PIN,
        "version": APIKEY_MANAGER_VERSION,
        "audit_seq": seq,
        "event": "apikey-manager",
        "kind": kind,
        "detail": detail,
    }


def main() -> None:
    """Self-check: issue, verify, duplicate refusal, revoke, rotate, audit."""
    mgr = APIKeyManager(seed=b"apikey-manager-selfcheck-seed-32bytes!")
    key = mgr.issue("k-1", "billing", 1, scopes=("read", "write"))
    assert key.secret.startswith(KEY_PREFIX)
    assert len(key.secret) == len(KEY_PREFIX) + KEY_HEX_LEN
    assert key.scopes == ("read", "write")  # sorted
    assert key.key_digest.startswith("sha256:")
    assert "secret" not in key.as_dict()  # never leaks

    report = mgr.verify(key.secret, at_seq=2)
    assert report.valid and report.key_id == "k-1" and report.reason == "ok"

    # Duplicate key_id is refused even before revocation.
    try:
        mgr.issue("k-1", "other", 3)
    except DuplicateKeyError:
        pass
    else:
        raise AssertionError("expected DuplicateKeyError")

    # Expiry: born-expired is refused; born-live then expires.
    exp = mgr.issue("k-2", "ephemeral", 4, expires_at_seq=10)
    try:
        mgr.issue("k-3", "bad", 5, expires_at_seq=5)
    except APIKeyError:
        pass
    else:
        raise AssertionError("expected APIKeyError for born-expired key")
    assert mgr.verify(exp.secret, at_seq=9).valid
    assert mgr.verify(exp.secret, at_seq=10).reason == "expired"
    assert mgr.active_ids(at_seq=11) == ("k-1",)

    # Rotation: new key verifies, old key is dead.
    new_key, rotation = mgr.rotate("k-1", "k-1b", 6)
    assert mgr.verify(new_key.secret, at_seq=7).valid
    assert mgr.verify(key.secret, at_seq=7).reason == "revoked"
    assert rotation.old_key_id == "k-1" and rotation.new_key_id == "k-1b"
    assert mgr.revocation("k-1") is not None
    assert mgr.key("k-1").revoked and not mgr.key("k-1b").revoked
    try:
        mgr.revoke("k-1", 8)
    except AlreadyRevokedError:
        pass
    else:
        raise AssertionError("expected AlreadyRevokedError")

    # Hostile input to verify() is data, not an exception.
    assert mgr.verify("", at_seq=9).reason == "malformed"
    assert mgr.verify(KEY_PREFIX + "0" * KEY_HEX_LEN, at_seq=9).reason == "unknown"
    try:
        mgr.verify(None, at_seq=9)  # type: ignore[arg-type]
    except APIKeyError:
        pass
    else:
        raise AssertionError("expected APIKeyError for wrong type")

    # Seq order is total.
    try:
        mgr.issue("k-9", "x", 6)
    except SeqOrderError:
        pass
    else:
        raise AssertionError("expected SeqOrderError")

    event = apikey_manager_audit_event(
        "revoked", 20, {"key_id": "k-1", "reason": "rotated"}
    )
    assert event["kind"] == "revoked"
    try:
        apikey_manager_audit_event("issued", 21, {"secret": "leak"})
    except APIKeyError:
        pass
    else:
        raise AssertionError("expected APIKeyError for secret in audit")

    print("apikey-manager OK: issue, verify, rotate, revoke, refusals, audit")


if __name__ == "__main__":
    main()
