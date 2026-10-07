"""Device manager: trusted-device enrollment, verification, and revocation (simulated).

Research note: trusted-device registries are the enrollment side of every
step-up-authentication and fleet story — the same four operational questions
show up in WebAuthn's credential registry, TOTP enrollment bindings, MDM
device-trust lists, and SSH ``authorized_keys`` management:

* **Trust (enroll)** — bind a ``device_id`` to an owner identity, a human
  label, and a *device attestation fingerprint* (a verifier pin for the
  device's public key, e.g. a ``sha256:`` digest of its attestation
  certificate). ``device_id`` is globally unique: enrollment of an existing
  id raises, and revocation never frees the id for recycling — a new id is
  issued for a re-enrolled device, so the ledger cannot alias two physical
  devices under one row.
* **Verify** — on every authentication event the caller asks
  ``is_trusted(device_id)``. ``True`` means enrolled *and* not revoked;
  ``False`` is returned as data for unknown ids, never thrown, because a
  verifier that throws on hostile input is a DoS surface. Only wrong
  *types* are programming errors and raise.
* **Revoke** — terminal ledger state (lost/stolen/decommissioned device).
  A revoked device never verifies again, never un-revokes, and a second
  ``revoke()`` raises ``AlreadyRevokedError`` — revocation is recorded
  exactly once.
* **List** — the whole registry as metadata-only views, sorted by
  ``device_id`` for replay-exact diffs; raw fingerprints stay as pins
  (digests), never as private key material.

Ordering is expressed in caller-supplied logical seqs (no wall-clock):
mutation seqs must strictly increase per manager (``SeqOrderError``), so
the ledger order is total and replay-exact. A clock that moves backwards
cannot resurrect a revoked device.

Fail-closed rules (load-bearing):

* ``device_id`` is globally unique: re-trusting an existing id raises
  ``DuplicateDeviceError``, even after revocation.
* A revoked device is terminal: ``is_trusted()`` reports ``False``,
  ``revocation()`` returns its pin, and a second ``revoke()`` raises
  ``AlreadyRevokedError``.
* Mutation seqs must strictly increase per manager (``SeqOrderError``).
* The ledger stores verifier pins only: enrollment records bind
  (device_id, owner, label, fingerprint, scopes, seq), and trust digests
  pin the same tuple — there is no private key material to leak.

Honest scope: this books *reported* device-trust events. It cannot prove
a device that presents this id is the enrolled hardware (that is the
job of the attestation verifier on the wire), cannot observe the
transport, and cannot confirm a revoked device stopped being honored —
production deployments must check revocation on the auth path, not just
in this ledger. With an explicit ``seed=`` the digests are deterministic
for tests and audit replay; the default salt comes from
``secrets.token_bytes``.

Version pin: device-manager.v1
Schema pin: northstar.device-manager.v1
"""

from __future__ import annotations

import hashlib
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
DEVICE_MANAGER_VERSION = "device-manager.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.device-manager.v1"


class DeviceError(Exception):
    """Base error for the device manager (fail-closed programming error)."""


class UnknownDeviceError(DeviceError):
    """No device with this id exists in the ledger."""


class DuplicateDeviceError(DeviceError):
    """A device with this id is already enrolled (ids are never recycled)."""


class AlreadyRevokedError(DeviceError):
    """The device is already revoked; revocation is recorded exactly once."""


class SeqOrderError(DeviceError):
    """Mutation seq did not strictly increase (ledger order must be total)."""


def _check_seq(value: Any, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise DeviceError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise DeviceError(f"{name} must be non-negative, got {value}")
    return value


def _check_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise DeviceError(f"{name} must be a non-empty str")
    return value


def _check_optional_str(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise DeviceError(f"{name} must be a str")
    return value


def _check_scopes(scopes: Any) -> Tuple[str, ...]:
    if scopes is None:
        return ()
    if not isinstance(scopes, (tuple, list)):
        raise DeviceError("scopes must be a tuple/list of str")
    checked = tuple(_check_str(s, "scope") for s in scopes)
    if len(set(checked)) != len(checked):
        raise DeviceError("duplicate scopes")
    return tuple(sorted(checked))


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(payload)).hexdigest()


@dataclass(frozen=True)
class TrustRecord:
    """Frozen enrollment record. ``fingerprint`` is a verifier pin (a digest
    of the device's attestation material), never private key material."""

    version: str
    device_id: str
    owner: str
    label: str
    fingerprint: str
    scopes: Tuple[str, ...]
    trusted_seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "device_id": self.device_id,
            "owner": self.owner,
            "label": self.label,
            "fingerprint": self.fingerprint,
            "scopes": list(self.scopes),
            "trusted_seq": self.trusted_seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class DeviceInfo:
    """Metadata-only view of a device (pins and flags, never secrets)."""

    version: str
    device_id: str
    owner: str
    label: str
    fingerprint: str
    scopes: Tuple[str, ...]
    trusted_seq: int
    revoked: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "device_id": self.device_id,
            "owner": self.owner,
            "label": self.label,
            "fingerprint": self.fingerprint,
            "scopes": list(self.scopes),
            "trusted_seq": self.trusted_seq,
            "revoked": self.revoked,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class RevocationRecord:
    """Terminal revocation pin."""

    version: str
    device_id: str
    seq: int
    reason: str
    digest: str


class DeviceManager:
    """Ledger for trusted-device enrollment, verification, and revocation.

    ``seed`` is an optional salt for deterministic digests in tests/audit
    replay; when omitted it comes from ``secrets.token_bytes``.
    """

    def __init__(self, seed: Optional[bytes] = None) -> None:
        if seed is None:
            seed = secrets.token_bytes(32)
        if not isinstance(seed, (bytes, bytearray)) or not seed:
            raise DeviceError("seed must be non-empty bytes")
        self._salt = bytes(seed)
        self._lock = threading.RLock()
        self._devices: Dict[str, Dict[str, Any]] = {}
        self._revocations: Dict[str, RevocationRecord] = {}
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

    def _pin(self, device_id: str, owner: str, label: str, fingerprint: str,
             scopes: Tuple[str, ...], trusted_seq: int) -> str:
        return _digest({
            "salt": self._salt.hex(),
            "device_id": device_id,
            "owner": owner,
            "label": label,
            "fingerprint": fingerprint,
            "scopes": list(scopes),
            "trusted_seq": trusted_seq,
        })

    def _record(self, device_id: str, owner: str, label: str,
                fingerprint: str, scopes: Tuple[str, ...],
                trusted_seq: int) -> Dict[str, Any]:
        return {
            "version": DEVICE_MANAGER_VERSION,
            "device_id": device_id,
            "owner": owner,
            "label": label,
            "fingerprint": fingerprint,
            "scopes": scopes,
            "trusted_seq": trusted_seq,
            "digest": self._pin(
                device_id, owner, label, fingerprint, scopes, trusted_seq
            ),
        }

    def _view(self, rec: Dict[str, Any]) -> DeviceInfo:
        device_id = rec["device_id"]
        return DeviceInfo(
            version=rec["version"],
            device_id=device_id,
            owner=rec["owner"],
            label=rec["label"],
            fingerprint=rec["fingerprint"],
            scopes=rec["scopes"],
            trusted_seq=rec["trusted_seq"],
            revoked=device_id in self._revocations,
            digest=rec["digest"],
        )

    def _require(self, device_id: str) -> Dict[str, Any]:
        rec = self._devices.get(device_id)
        if rec is None:
            raise UnknownDeviceError(f"unknown device_id: {device_id!r}")
        return rec

    # -- public API -----------------------------------------------------

    def trust(self, device_id: str, seq: int, owner: str = "",
              label: str = "", fingerprint: str = "",
              scopes: Any = None) -> TrustRecord:
        """Enroll a device as trusted. ``device_id`` is globally unique:
        re-trusting an existing id raises ``DuplicateDeviceError`` even
        after revocation (a re-enrolled device gets a fresh id)."""
        device_id = _check_str(device_id, "device_id")
        owner = _check_optional_str(owner, "owner")
        label = _check_optional_str(label, "label")
        fingerprint = _check_optional_str(fingerprint, "fingerprint")
        checked_scopes = _check_scopes(scopes)
        with self._lock:
            seq = self._touch(seq)
            if device_id in self._devices:
                raise DuplicateDeviceError(
                    f"device_id already enrolled: {device_id!r}"
                )
            rec = self._record(
                device_id, owner, label, fingerprint, checked_scopes, seq
            )
            self._devices[device_id] = rec
            return TrustRecord(
                version=rec["version"],
                device_id=device_id,
                owner=owner,
                label=label,
                fingerprint=fingerprint,
                scopes=checked_scopes,
                trusted_seq=seq,
                digest=rec["digest"],
            )

    def is_trusted(self, device_id: Any) -> bool:
        """Whether the device is enrolled and not revoked. Unknown ids
        return ``False`` as data (a verifier must not throw on hostile
        input); wrong *types* raise."""
        if not isinstance(device_id, str):
            raise DeviceError(
                f"device_id must be a str, got {type(device_id).__name__}"
            )
        with self._lock:
            return device_id in self._devices and device_id not in self._revocations

    def revoke(self, device_id: str, seq: int,
               reason: str = "") -> RevocationRecord:
        """Revoke a device. Terminal: it never verifies again, never
        un-revokes, and never re-revokes."""
        device_id = _check_str(device_id, "device_id")
        if not isinstance(reason, str):
            raise DeviceError("reason must be a str")
        with self._lock:
            self._require(device_id)
            seq = self._touch(seq)
            if device_id in self._revocations:
                raise AlreadyRevokedError(
                    f"already revoked: {device_id!r}"
                )
            digest = _digest({
                "salt": self._salt.hex(),
                "device_id": device_id,
                "seq": seq,
                "reason": reason,
            })
            rec = RevocationRecord(
                version=DEVICE_MANAGER_VERSION,
                device_id=device_id,
                seq=seq,
                reason=reason,
                digest=digest,
            )
            self._revocations[device_id] = rec
            return rec

    def list(self) -> Tuple[DeviceInfo, ...]:
        """All enrolled devices, sorted by ``device_id``."""
        with self._lock:
            return tuple(
                self._view(self._devices[kid]) for kid in sorted(self._devices)
            )

    def device(self, device_id: str) -> DeviceInfo:
        """Metadata-only view of one device."""
        device_id = _check_str(device_id, "device_id")
        with self._lock:
            return self._view(self._require(device_id))

    def device_ids(self) -> Tuple[str, ...]:
        """All enrolled device ids, sorted."""
        with self._lock:
            return tuple(sorted(self._devices))

    def trusted_ids(self) -> Tuple[str, ...]:
        """Enrolled and unrevoked ids, sorted."""
        with self._lock:
            return tuple(
                sorted(
                    kid
                    for kid in self._devices
                    if kid not in self._revocations
                )
            )

    def revoked_ids(self) -> Tuple[str, ...]:
        """Revoked ids, sorted."""
        with self._lock:
            return tuple(sorted(self._revocations))

    def revocation(self, device_id: str) -> Optional[RevocationRecord]:
        """The revocation record for a device, or None if it is trusted."""
        device_id = _check_str(device_id, "device_id")
        with self._lock:
            self._require(device_id)
            return self._revocations.get(device_id)


def device_manager_audit_event(kind: str, seq: int, detail: dict) -> dict:
    """Shape an ``audit.ndjson/1`` record for device-manager events.

    Private key material must never be passed in ``detail`` — only ids,
    owners, labels, pins, and digests. ``fingerprint`` pins (digests) are
    allowed; raw attestation secrets are not. This is enforced by
    convention here (as in ``secret_manager`` and ``apikey_manager``),
    because the audit boundary cannot reach back into any excluded field.
    """
    seq = _check_seq(seq)
    allowed = {"trusted", "revoked", "verified", "rejected"}
    if kind not in allowed:
        raise DeviceError(f"unknown audit kind: {kind!r}")
    if not isinstance(detail, dict):
        raise DeviceError("detail must be a dict")
    if any(k in ("private_key", "attestation_secret") for k in detail):
        raise DeviceError("audit detail must never carry device key material")
    return {
        "schema": SCHEMA_PIN,
        "version": DEVICE_MANAGER_VERSION,
        "audit_seq": seq,
        "event": "device-manager",
        "kind": kind,
        "detail": detail,
    }


def main() -> None:
    """Self-check: trust, verify, duplicate refusal, revoke, list, audit."""
    mgr = DeviceManager(seed=b"device-manager-selfcheck-seed-32bytes!")

    rec = mgr.trust(
        "dev-1", 1, owner="alice", label="laptop",
        fingerprint="sha256:" + "ab" * 32, scopes=("ssh", "vpn"),
    )
    assert rec.device_id == "dev-1"
    assert rec.owner == "alice"
    assert rec.scopes == ("ssh", "vpn")  # sorted
    assert rec.fingerprint.startswith("sha256:")
    assert rec.digest.startswith("sha256:")
    assert mgr.is_trusted("dev-1")
    assert not mgr.is_trusted("dev-unknown")  # unknown is data, not an error

    # Duplicate enrollment is refused, even after revocation.
    try:
        mgr.trust("dev-1", 2)
    except DuplicateDeviceError:
        pass
    else:
        raise AssertionError("expected DuplicateDeviceError")

    mgr.revoke("dev-1", 3, reason="lost")
    assert not mgr.is_trusted("dev-1")
    assert mgr.revocation("dev-1") is not None
    assert mgr.revocation("dev-1").reason == "lost"
    assert mgr.device("dev-1").revoked
    assert mgr.trusted_ids() == ()
    assert mgr.revoked_ids() == ("dev-1",)
    try:
        mgr.revoke("dev-1", 4)
    except AlreadyRevokedError:
        pass
    else:
        raise AssertionError("expected AlreadyRevokedError")
    try:
        mgr.trust("dev-1", 5)
    except DuplicateDeviceError:
        pass
    else:
        raise AssertionError("expected DuplicateDeviceError after revocation")

    # A re-enrolled device gets a fresh id.
    rec2 = mgr.trust("dev-1b", 6, owner="alice", label="laptop-replacement")
    assert mgr.is_trusted("dev-1b")
    infos = mgr.list()
    assert [i.device_id for i in infos] == ["dev-1", "dev-1b"]  # sorted
    assert [i.revoked for i in infos] == [True, False]
    assert rec2.as_dict()["digest"].startswith("sha256:")

    # Audit helper: kinds pass, key material and unknown kinds are refused.
    evt = device_manager_audit_event(
        "revoked", 7, {"device_id": "dev-1", "reason": "lost"}
    )
    assert evt["schema"] == SCHEMA_PIN and evt["event"] == "device-manager"
    for bad_kind in ("enrolled", "trust"):
        try:
            device_manager_audit_event(bad_kind, 8, {})
        except DeviceError:
            pass
        else:
            raise AssertionError(f"expected DeviceError for {bad_kind!r}")
    try:
        device_manager_audit_event("trusted", 9, {"private_key": "x"})
    except DeviceError:
        pass
    else:
        raise AssertionError("expected DeviceError for key material in detail")

    # Seq order: non-increasing mutation seq is refused.
    try:
        mgr.trust("dev-2", 6)
    except SeqOrderError:
        pass
    else:
        raise AssertionError("expected SeqOrderError")

    print("device_manager self-check OK")


if __name__ == "__main__":
    main()
