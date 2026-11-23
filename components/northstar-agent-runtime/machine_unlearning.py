"""Machine unlearning interface (certified unlearning mechanics, simulated).

House rules: frozen dataclasses, no wall-clock, fail-closed, stdlib-only.

HONEST SCOPE
------------
This module is the *registry bookkeeping* half of certified unlearning: it
records which training items were added, which were forgotten, and mints a
`UnlearningCertificate` binding the forgotten and retained sets by digest.

It does NOT retrain a model, it cannot inspect model weights, and it cannot
prove that a model's parameters no longer carry influence from a forgotten
item. `verify_forgotten()` returns True when the registry holds no digest
for any forgotten item -- a record claim, never a proof about weights. Real
certified unlearning (Ginart et al. 2019; Thudi et al. 2022) replaces the
bookkeeping with retraining, and must be audited by retraining pipelines,
not by this module.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
from dataclasses import dataclass, field, asdict

VERSION = "machine-unlearning.v1"
SCHEMA = "northstar.machine-unlearning.v1"
SCHEMA_MAJOR = "northstar.machine-unlearning"

# --- canonical encoding (stdlib-only; immune to the JCS >2^53 caveat) --------


def _canon(value):
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return {"$int": "%+d" % value}
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise UnlearningError("non-finite float not canonicalizable")
        return {"$float": repr(value)}
    if isinstance(value, str):
        return {"$str": value}
    if isinstance(value, (bytes, bytearray)):
        return {"$bytes": "hex:" + bytes(value).hex()}
    if isinstance(value, (list, tuple)):
        return [_canon(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _canon(value[k]) for k in sorted(value, key=str)}
    raise UnlearningError("value of type %s not canonicalizable" % type(value).__name__)


def _pin(value) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(_canon(value), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _check_seq(seq, *, name="seq"):
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise UnlearningError("%s must be a non-negative int" % name)
    return seq


def _check_id(data_id: str) -> str:
    if not isinstance(data_id, str) or not data_id:
        raise UnlearningError("data_id must be a non-empty str")
    return data_id


class UnlearningError(Exception):
    """Fail-closed error for every invalid unlearning operation."""


# --- frozen records -----------------------------------------------------------


@dataclass(frozen=True)
class TrainingRecord:
    data_id: str
    data_pin: str
    added_seq: int
    version_pin: str = VERSION
    schema_pin: str = SCHEMA

    def __post_init__(self):
        if self.version_pin != VERSION or self.schema_pin != SCHEMA:
            raise UnlearningError("version/schema pin mismatch")

    def as_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class ForgetRequest:
    data_id: str
    requested_seq: int
    version_pin: str = VERSION
    schema_pin: str = SCHEMA

    def __post_init__(self):
        if self.version_pin != VERSION or self.schema_pin != SCHEMA:
            raise UnlearningError("version/schema pin mismatch")

    def as_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class UnlearningCertificate:
    forgotten: tuple
    retained: tuple
    certificate_pin: str
    certified_seq: int
    all_requests_honored: bool
    version_pin: str = VERSION
    schema_pin: str = SCHEMA

    def __post_init__(self):
        if self.version_pin != VERSION or self.schema_pin != SCHEMA:
            raise UnlearningError("version/schema pin mismatch")

    def as_dict(self):
        return asdict(self)


# --- the registry --------------------------------------------------------------


class MachineUnlearning:
    """Forget/verify registry for machine unlearning (simulated)."""

    def __init__(self):
        self._lock = threading.RLock()
        self._training: dict[str, TrainingRecord] = {}
        self._forgotten: dict[str, ForgetRequest] = {}
        self._events: list[dict] = []

    # -- mutation ------------------------------------------------------------

    def add_training(self, data_id: str, data, seq: int) -> TrainingRecord:
        _check_id(data_id)
        _check_seq(seq)
        with self._lock:
            if data_id in self._training:
                raise UnlearningError("data_id already recorded: %r" % data_id)
            if data_id in self._forgotten:
                raise UnlearningError(
                    "data_id was forgotten; re-adding requires an explicit re-train record"
                )
            rec = TrainingRecord(data_id=data_id, data_pin=_pin(data), added_seq=seq)
            self._training[data_id] = rec
            self._events.append({"kind": "training-added", "data_id": data_id, "seq": seq})
            return rec

    def forget(self, data_id: str, seq: int) -> ForgetRequest:
        _check_id(data_id)
        _check_seq(seq)
        with self._lock:
            if data_id in self._forgotten:
                # Idempotent: return the recorded request, no second event.
                return self._forgotten[data_id]
            if data_id not in self._training:
                raise UnlearningError("unknown data_id: %r" % data_id)
            req = ForgetRequest(data_id=data_id, requested_seq=seq)
            self._forgotten[data_id] = req
            del self._training[data_id]
            self._events.append({"kind": "forgotten", "data_id": data_id, "seq": seq})
            return req

    # -- verification --------------------------------------------------------

    def verify_forgotten(self) -> bool:
        """True iff no forgotten item's digest remains in the training registry."""
        with self._lock:
            forgotten_ids = set(self._forgotten)
            retained_ids = set(self._training)
            return forgotten_ids.isdisjoint(retained_ids)

    def certify(self, seq: int) -> UnlearningCertificate:
        _check_seq(seq)
        with self._lock:
            forgotten = tuple(sorted(self._forgotten))
            retained = tuple(sorted(self._training))
            honored = self.verify_forgotten()
            pin = _pin(
                {"forgotten": list(forgotten), "retained": list(retained), "honored": honored}
            )
            cert = UnlearningCertificate(
                forgotten=forgotten,
                retained=retained,
                certificate_pin=pin,
                certified_seq=seq,
                all_requests_honored=honored,
            )
            self._events.append({"kind": "certified", "seq": seq, "pin": pin})
            return cert

    # -- views ---------------------------------------------------------------

    def forgotten_ids(self):
        with self._lock:
            return tuple(sorted(self._forgotten))

    def retained_ids(self):
        with self._lock:
            return tuple(sorted(self._training))

    def events(self):
        with self._lock:
            return tuple(self._events)

    def registry_digest(self) -> str:
        with self._lock:
            return _pin(
                {
                    "training": {k: v.data_pin for k, v in sorted(self._training.items())},
                    "forgotten": sorted(self._forgotten),
                }
            )


# --- audit events ------------------------------------------------------------


AUDIT_KINDS = frozenset({"training-added", "forgotten", "certified", "rejected"})


def machine_unlearning_audit_event(kind: str, seq: int, **kwargs) -> dict:
    if kind not in AUDIT_KINDS:
        raise UnlearningError("unknown audit kind: %r" % kind)
    _check_seq(seq)
    body = {"kind": kind, "seq": seq}
    body.update(kwargs)
    return {
        "audit": "audit.ndjson/1",
        "schema": SCHEMA,
        "version": VERSION,
        "event": body,
        "event_pin": _pin(body),
    }


def main() -> None:
    mu = MachineUnlearning()
    mu.add_training("d1", {"x": 1}, 0)
    mu.add_training("d2", {"x": 2}, 1)
    mu.forget("d1", 2)
    assert mu.verify_forgotten()
    cert = mu.certify(3)
    assert cert.all_requests_honored and cert.forgotten == ("d1",)
    print("machine-unlearning OK: forget, verify, certify")


if __name__ == "__main__":
    main()
