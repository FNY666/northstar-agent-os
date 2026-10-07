"""Trojan defense: trojan remediation lifecycle ledger for models, Simulated.

Research note: trojans in ML (BadNets / TrojanNN / sleeper-agent models) embed
malicious behavior *in the weights* - a trigger switches on misbehavior at
runtime. Detection methods from the literature - activation clustering,
trigger inversion (Neural Cleanse), fine-pruning, spectral signatures, weight
analysis, behavioral probing - can flag *suspect* models; remediation ranges
from fine-pruning through retraining to full removal. A reported "clean" scan
is never proof a model is trojan-free: it is proof a declared method ran and
a declared verdict was booked.

This module is the *remediation lifecycle* ledger for that practice,
deliberately distinct from its siblings:

- ``backdoor_detector.py`` - runtime *text* tripwire for known trigger shapes
  (regex over input text); neither scans models nor remediates.
- ``backdoor_detection.py`` - declared trigger-detection decision ledger.

This module owns the model lifecycle instead:

* **register_model()** - declare one model under trojan-defense watch.
* **scan()** - book one declared trojan scan (pinned method vocabulary,
  pinned verdict vocabulary). The verdict is data, never proof of infection
  or cleanliness.
* **quarantine()** - book isolation of an infected/suspect model.
* **remove()** - book one declared remediation (pinned technique vocabulary)
  against a model with an un-remediated infected/suspect verdict.
* **verify()** - pure read view: re-walks digest pins and reports the model's
  remediation state as data.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``trojan-defense.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: this module runs no scans, repairs no weights, and cannot
prove a model is clean or infected. All verdicts are host-declared GIGO
booked under digest pins; raw weights, triggers, and model bytes never
cross the module boundary.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps, jcs_sha256_hex as _jcs_hash  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _jcs_hash(obj: Any) -> str:  # type: ignore
        return "sha256:" + hashlib.sha256(_jcs_dumps(obj)).hexdigest()


#: Module version pin.
TROJAN_DEFENSE_VERSION = "trojan-defense.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.trojan-defense.v1"

#: Pinned scan-method vocabulary (declared, never executed).
METHODS = (
    "activation-clustering",
    "trigger-inversion",
    "fine-pruning",
    "spectral",
    "weight-analysis",
    "behavioral",
)

#: Pinned scan-verdict vocabulary. Verdicts are data, never proof.
VERDICTS = ("clean", "suspect", "infected")

#: Pinned remediation-technique vocabulary (declared, never executed).
TECHNIQUES = (
    "fine-pruning",
    "retrain",
    "weight-repair",
    "rollback",
    "deletion",
)

#: Pinned quarantine-reason vocabulary.
QUARANTINE_REASONS = ("manual", "infected-verdict", "suspect-verdict", "precaution")

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "model-registered",
    "scan-recorded",
    "quarantined",
    "removed",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "weights",
        "weight",
        "trigger",
        "trigger_bytes",
        "payload",
        "model",
        "model_bytes",
        "checkpoint",
        "params",
        "activations",
        "secret",
        "raw",
        "text",
        "content",
        "data",
        "value",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class TrojanDefenseError(Exception):
    """Base error for trojan-defense ledger misuse."""


class BadModelError(TrojanDefenseError):
    """Malformed model id."""


class DuplicateModelError(TrojanDefenseError):
    """Model id already registered."""


class RetiredModelError(TrojanDefenseError):
    """Model id retired via deletion; never recycled."""


class UnknownModelError(TrojanDefenseError):
    """Model id not registered."""


class BadDigestError(TrojanDefenseError):
    """Malformed sha256: digest pin."""


class BadMethodError(TrojanDefenseError):
    """Unknown scan method."""


class BadVerdictError(TrojanDefenseError):
    """Unknown scan verdict."""


class BadTechniqueError(TrojanDefenseError):
    """Unknown remediation technique."""


class BadReasonError(TrojanDefenseError):
    """Unknown quarantine reason."""


class UnknownScanError(TrojanDefenseError):
    """Scan id not booked."""


class UnknownRemovalError(TrojanDefenseError):
    """Removal id not booked."""


class QuarantineStateError(TrojanDefenseError):
    """Model already quarantined (or not quarantined where required)."""


class RemovalStateError(TrojanDefenseError):
    """Removal preconditions not met (no infected/suspect verdict pending)."""


class SeqOrderError(TrojanDefenseError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(TrojanDefenseError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Records (all frozen)
# ---------------------------------------------------------------------------


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadModelError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: str, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


@dataclass(frozen=True)
class ModelRecord:
    model_id: str
    model_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "model_id": self.model_id,
            "model_digest": self.model_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {"schema": SCHEMA_PIN, "model_id": self.model_id,
             "model_digest": self.model_digest}
        )


@dataclass(frozen=True)
class ScanRecord:
    scan_id: str
    model_id: str
    method: str
    verdict: str
    findings_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "scan_id": self.scan_id,
            "model_id": self.model_id,
            "method": self.method,
            "verdict": self.verdict,
            "findings_digest": self.findings_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "scan_id": self.scan_id,
                "model_id": self.model_id,
                "method": self.method,
                "verdict": self.verdict,
                "findings_digest": self.findings_digest,
            }
        )


@dataclass(frozen=True)
class QuarantineRecord:
    quarantine_id: str
    model_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "quarantine_id": self.quarantine_id,
            "model_id": self.model_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "quarantine_id": self.quarantine_id,
                "model_id": self.model_id,
                "reason": self.reason,
            }
        )


@dataclass(frozen=True)
class RemovalRecord:
    removal_id: str
    model_id: str
    scan_id: str
    technique: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "removal_id": self.removal_id,
            "model_id": self.model_id,
            "scan_id": self.scan_id,
            "technique": self.technique,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "removal_id": self.removal_id,
                "model_id": self.model_id,
                "scan_id": self.scan_id,
                "technique": self.technique,
            }
        )


@dataclass(frozen=True)
class VerifyReport:
    model_id: str
    n_scans: int
    latest_verdict: str
    quarantined: bool
    remediated: bool
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "model_id": self.model_id,
            "n_scans": self.n_scans,
            "latest_verdict": self.latest_verdict,
            "quarantined": self.quarantined,
            "remediated": self.remediated,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "model_id": self.model_id,
                "n_scans": self.n_scans,
                "latest_verdict": self.latest_verdict,
                "quarantined": self.quarantined,
                "remediated": self.remediated,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def trojan_defense_audit_event(
    kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the trojan-defense ledger."""
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class TrojanDefense:
    """Trojan remediation lifecycle ledger (Simulated).

    ``register_model()`` / ``scan()`` / ``quarantine()`` / ``remove()``
    mutate the ledger and consume caller seqs; ``verify()`` and all views
    are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._models: Dict[str, ModelRecord] = {}
        self._scans: Dict[str, ScanRecord] = {}
        self._model_scans: Dict[str, List[str]] = {}
        self._quarantines: Dict[str, QuarantineRecord] = {}
        self._removals: Dict[str, RemovalRecord] = {}
        self._remediation_of_scan: Dict[str, str] = {}
        self._retired: set = set()
        self._audit: List[Dict[str, Any]] = []
        self._seq = 0
        self._scn_counter = 0
        self._qtn_counter = 0
        self._rmv_counter = 0

    # -- seq discipline ----------------------------------------------------

    def _check_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._check_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = trojan_defense_audit_event("rejected", seq,
                                            rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(trojan_defense_audit_event(audit_kind, seq, **details))

    # -- register_model ------------------------------------------------------

    def register_model(
        self, model_id: str, seq: int, model_digest: str = ""
    ) -> ModelRecord:
        """Declare one model under trojan-defense watch."""
        with self._lock:
            try:
                self._claim(seq)
            except TrojanDefenseError:
                raise
            try:
                _require_id(model_id, "model_id")
                if model_digest:
                    _require_digest(model_digest, "model_digest")
                else:
                    model_digest = "sha256:" + "00" * 32
                if model_id in self._retired:
                    raise RetiredModelError(
                        f"model id retired, never recycled: {model_id!r}")
                if model_id in self._models:
                    raise DuplicateModelError(
                        f"model already registered: {model_id!r}")
                digest = _digest_pin(
                    {"schema": SCHEMA_PIN, "model_id": model_id,
                     "model_digest": model_digest}
                )
                record = ModelRecord(
                    model_id=model_id, model_digest=model_digest, digest=digest
                )
                self._models[model_id] = record
                self._model_scans[model_id] = []
                self._emit("model-registered", seq, model_id=model_id)
                return record
            except TrojanDefenseError:
                self._burn(seq, "register_model")
                raise

    # -- scan ----------------------------------------------------------------

    def scan(
        self,
        model_id: str,
        seq: int,
        method: str = "weight-analysis",
        verdict: str = "clean",
        findings_digest: str = "",
    ) -> ScanRecord:
        """Book one declared trojan scan. The verdict is data, never proof."""
        with self._lock:
            try:
                self._claim(seq)
            except TrojanDefenseError:
                raise
            try:
                if model_id not in self._models:
                    raise UnknownModelError(f"unknown model: {model_id!r}")
                if method not in METHODS:
                    raise BadMethodError(f"method must be one of {METHODS}")
                if verdict not in VERDICTS:
                    raise BadVerdictError(f"verdict must be one of {VERDICTS}")
                if findings_digest:
                    _require_digest(findings_digest, "findings_digest")
                else:
                    findings_digest = "sha256:" + "00" * 32
                self._scn_counter += 1
                scan_id = f"scn-{self._scn_counter}"
                if scan_id in self._scans:
                    raise TrojanDefenseError(
                        f"scan id collision: {scan_id!r}")
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "scan_id": scan_id,
                        "model_id": model_id,
                        "method": method,
                        "verdict": verdict,
                        "findings_digest": findings_digest,
                    }
                )
                record = ScanRecord(
                    scan_id=scan_id,
                    model_id=model_id,
                    method=method,
                    verdict=verdict,
                    findings_digest=findings_digest,
                    digest=digest,
                )
                self._scans[scan_id] = record
                self._model_scans[model_id].append(scan_id)
                self._emit(
                    "scan-recorded", seq, scan_id=scan_id,
                    model_id=model_id, verdict=verdict,
                )
                return record
            except TrojanDefenseError:
                self._burn(seq, "scan")
                raise

    # -- quarantine ----------------------------------------------------------

    def quarantine(
        self, model_id: str, seq: int, reason: str = "manual"
    ) -> QuarantineRecord:
        """Book isolation of a model (infected/suspect or precautionary)."""
        with self._lock:
            try:
                self._claim(seq)
            except TrojanDefenseError:
                raise
            try:
                if model_id not in self._models:
                    raise UnknownModelError(f"unknown model: {model_id!r}")
                if reason not in QUARANTINE_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {QUARANTINE_REASONS}")
                if model_id in self._quarantines:
                    raise QuarantineStateError(
                        f"model already quarantined: {model_id!r}")
                self._qtn_counter += 1
                quarantine_id = f"qtn-{self._qtn_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "quarantine_id": quarantine_id,
                        "model_id": model_id,
                        "reason": reason,
                    }
                )
                record = QuarantineRecord(
                    quarantine_id=quarantine_id, model_id=model_id,
                    reason=reason, digest=digest,
                )
                self._quarantines[model_id] = record
                self._emit(
                    "quarantined", seq, quarantine_id=quarantine_id,
                    model_id=model_id, reason=reason,
                )
                return record
            except TrojanDefenseError:
                self._burn(seq, "quarantine")
                raise

    # -- remove --------------------------------------------------------------

    def remove(
        self,
        model_id: str,
        scan_id: str,
        seq: int,
        technique: str = "fine-pruning",
    ) -> RemovalRecord:
        """Book one declared remediation against an infected/suspect scan.

        The removal must reference a scan with verdict ``infected`` or
        ``suspect`` that has not already been remediated. Technique
        ``deletion`` retires the model id forever.
        """
        with self._lock:
            try:
                self._claim(seq)
            except TrojanDefenseError:
                raise
            try:
                if model_id not in self._models:
                    raise UnknownModelError(f"unknown model: {model_id!r}")
                record = self._scans.get(scan_id)
                if record is None:
                    raise UnknownScanError(f"unknown scan: {scan_id!r}")
                if record.model_id != model_id:
                    raise UnknownScanError(
                        f"scan {scan_id!r} belongs to another model")
                if record.verdict not in ("infected", "suspect"):
                    raise RemovalStateError(
                        f"scan verdict {record.verdict!r} needs no removal")
                if scan_id in self._remediation_of_scan:
                    raise RemovalStateError(
                        f"scan already remediated: {scan_id!r}")
                if technique not in TECHNIQUES:
                    raise BadTechniqueError(
                        f"technique must be one of {TECHNIQUES}")
                self._rmv_counter += 1
                removal_id = f"rmv-{self._rmv_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "removal_id": removal_id,
                        "model_id": model_id,
                        "scan_id": scan_id,
                        "technique": technique,
                    }
                )
                removal = RemovalRecord(
                    removal_id=removal_id, model_id=model_id,
                    scan_id=scan_id, technique=technique, digest=digest,
                )
                self._removals[removal_id] = removal
                self._remediation_of_scan[scan_id] = removal_id
                if technique == "deletion":
                    self._retired.add(model_id)
                self._emit(
                    "removed", seq, removal_id=removal_id,
                    model_id=model_id, scan_id=scan_id, technique=technique,
                )
                return removal
            except TrojanDefenseError:
                self._burn(seq, "remove")
                raise

    # -- verify (pure read) --------------------------------------------------

    def verify(self, model_id: str, seq: int) -> VerifyReport:
        """Pure read: re-walk digest pins, report remediation state as data."""
        with self._lock:
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                raise SeqOrderError("verify seq must be a non-negative int")
            record = self._models.get(model_id)
            if record is None:
                raise UnknownModelError(f"unknown model: {model_id!r}")
            integrity_ok = record.verify()
            scan_ids = self._model_scans.get(model_id, [])
            scans = [self._scans[sid] for sid in scan_ids]
            for scan in scans:
                if not scan.verify():
                    integrity_ok = False
            latest_verdict = scans[-1].verdict if scans else "unknown"
            quarantined = model_id in self._quarantines
            remediated = all(
                scan.scan_id in self._remediation_of_scan
                for scan in scans
                if scan.verdict in ("infected", "suspect")
            )
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "model_id": model_id,
                    "n_scans": len(scans),
                    "latest_verdict": latest_verdict,
                    "quarantined": quarantined,
                    "remediated": remediated,
                    "integrity_ok": integrity_ok,
                }
            )
            return VerifyReport(
                model_id=model_id,
                n_scans=len(scans),
                latest_verdict=latest_verdict,
                quarantined=quarantined,
                remediated=remediated,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- pure-read views -------------------------------------------------------

    def _view_seq_ok(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("view seq must be a non-negative int")

    def model_record(self, model_id: str, seq: int) -> ModelRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._models.get(model_id)
            if record is None:
                raise UnknownModelError(f"unknown model: {model_id!r}")
            return record

    def scan_record(self, scan_id: str, seq: int) -> ScanRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._scans.get(scan_id)
            if record is None:
                raise UnknownScanError(f"unknown scan: {scan_id!r}")
            return record

    def removal_record(self, removal_id: str, seq: int) -> RemovalRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._removals.get(removal_id)
            if record is None:
                raise UnknownRemovalError(f"unknown removal: {removal_id!r}")
            return record

    def model_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._models))

    def scan_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._scans))

    def scans_for(self, model_id: str, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            if model_id not in self._models:
                raise UnknownModelError(f"unknown model: {model_id!r}")
            return tuple(self._model_scans.get(model_id, ()))

    def quarantined_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._quarantines))

    def is_quarantined(self, model_id: str, seq: int) -> bool:
        with self._lock:
            self._view_seq_ok(seq)
            if model_id not in self._models:
                raise UnknownModelError(f"unknown model: {model_id!r}")
            return model_id in self._quarantines

    def is_retired(self, model_id: str, seq: int) -> bool:
        with self._lock:
            self._view_seq_ok(seq)
            return model_id in self._retired

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._audit)

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._view_seq_ok(seq)
            return {
                "models": len(self._models),
                "scans": len(self._scans),
                "quarantined": len(self._quarantines),
                "removals": len(self._removals),
                "retired": len(self._retired),
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }


def main() -> None:
    td = TrojanDefense()
    rec = td.register_model("model-1", 1)
    scan = td.scan("model-1", 2, method="trigger-inversion", verdict="infected")
    td.quarantine("model-1", 3, reason="infected-verdict")
    removal = td.remove("model-1", scan.scan_id, 4, technique="fine-pruning")
    report = td.verify("model-1", 0)
    assert rec.verify() and scan.verify() and removal.verify()
    assert report.verify() and report.remediated and report.quarantined
    assert report.integrity_ok
    print(
        "trojan-defense OK: register, scan, quarantine, remove, verify, "
        "pins, audit"
    )


if __name__ == "__main__":
    main()
