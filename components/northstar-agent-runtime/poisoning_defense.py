"""Training-data poisoning defense lifecycle ledger.

Research note: data poisoning is the attack shape where the adversary
touches the *data*, not the model — a handful of poisoned samples (label
flips, outlier clusters, implanted trigger patterns, clean-label
adversarials) get averaged into the gradient update and the backdoor
survives training while the eval suite stays green. Defense therefore
splits into three disciplines this module books as an explicit,
deterministic lifecycle:

* **detect** — record which poison shapes were declared against a
  dataset (``detect()``);
* **clean** — record what remediation was declared (quarantine, drop,
  relabel, reweight, or abort the training run) (``clean()``);
* **verify** — re-walk the ledger and report the defense posture as
  *data* (``verify()``).

This module is deliberately distinct from its siblings: ``
data_poisoning_detector.py`` *analyzes* feature vectors and scores
statistical shapes; this module books the *decisions* a host made in
response — who called what dirty, what was done about it, and whether
the ledger still checks out. It runs no analysis and no training; all
values are host-declared GIGO booked under ``sha256:`` digest pins.

House rules: frozen dataclasses, caller int seqs strictly increasing
(claim-then-burn — failed mutations consume their seq and book a
``rejected`` row; rewinds raise bare without consuming), no wall-clock,
RLock-guarded, fail-closed taxonomy, stdlib-only plus a
``canonical_json`` try/except fallback, and ``audit.ndjson/1`` events.
Raw samples, labels, features, or trigger payloads never cross the
module boundary — digests only.

Honest scope: a booked ``cleaned=True`` means the host *declared* a
cleaning action; the module saw no data and cannot prove the poison is
gone. A ``verify()`` report with ``integrity_ok=True`` means the
ledger's own digest pins recompute, never that the dataset is safe to
train on. Pair with real detection (the sibling analyzer), provenance
tracking (who contributed what), and held-out canary evaluation for
the full picture.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:  # pragma: no cover - exercised when canonical_json is importable
    from canonical_json import jcs_dumps as _jcs_dumps, jcs_sha256_hex as _jcs_hash  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _jcs_hash(obj: Any) -> str:  # type: ignore
        return "sha256:" + hashlib.sha256(_jcs_dumps(obj)).hexdigest()


#: Module version pin.
POISONING_DEFENSE_VERSION = "poisoning-defense.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.poisoning-defense.v1"

#: Pinned threat vocabulary booked by ``detect()``.
THREAT_KINDS = (
    "label-flip",
    "outlier-cluster",
    "trigger-pattern",
    "clean-label",
    "data-pipeline",
)

#: Pinned remediation vocabulary booked by ``clean()``.
CLEAN_ACTIONS = (
    "quarantine",
    "drop-samples",
    "relabel",
    "reweight",
    "abort-training",
)

#: Audit row kinds this module emits.
AUDIT_KINDS = (
    "dataset-registered",
    "detection-booked",
    "cleaning-booked",
    "rejected",
)

#: Raw-material keys banned from the audit boundary.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "samples",
        "sample",
        "data",
        "features",
        "label",
        "labels",
        "payload",
        "trigger",
        "content",
        "raw",
        "text",
        "value",
        "values",
        "secret",
        "key",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PoisoningDefenseError(Exception):
    """Base error for poisoning-defense ledger misuse."""


class BadIdError(PoisoningDefenseError):
    """Dataset/detection/cleaning id is not a non-empty str."""


class BadDigestError(PoisoningDefenseError):
    """Digest is not a ``sha256:<64hex>`` pin (or empty where allowed)."""


class BadThreatError(PoisoningDefenseError):
    """Threat kind is outside the pinned vocabulary."""


class BadActionError(PoisoningDefenseError):
    """Cleaning action is outside the pinned vocabulary."""


class BadCountError(PoisoningDefenseError):
    """Sample count is not a non-negative int."""


class DuplicateDatasetError(PoisoningDefenseError):
    """Dataset id is already registered (ids are never recycled)."""


class UnknownDatasetError(PoisoningDefenseError):
    """Operation named a dataset id that was never registered."""


class DuplicateDetectionError(PoisoningDefenseError):
    """Detection id is already booked."""


class DuplicateCleaningError(PoisoningDefenseError):
    """Cleaning id is already booked."""


class SeqOrderError(PoisoningDefenseError):
    """Seq is malformed or not strictly increasing."""


class AuditKindError(PoisoningDefenseError):
    """Unknown audit kind, or a banned raw key reached the audit boundary."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_digest(pin: str) -> bool:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        return False
    body = pin[len("sha256:"):]
    return len(body) == 64 and all(c in "0123456789abcdef" for c in body)


def _digest_pin(payload: Any) -> str:
    try:
        pin = _jcs_hash(payload)
    except Exception:
        raise BadDigestError("digest payload is not canonicalizable")
    if isinstance(pin, str) and pin.startswith("sha256:"):
        out = pin
    else:
        # the real canonicalizer returns bare hex; pin it ourselves
        out = "sha256:" + (pin if isinstance(pin, str) else "")
    if not _is_digest(out):
        raise BadDigestError("canonicalizer did not return a sha256 pin")
    return out


def _check_id(value: Any, label: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value:
        raise BadIdError(f"{label} must be a non-empty str")
    return value


def _check_optional_digest(value: Any, label: str) -> str:
    if value in ("", None):
        return ""
    if not isinstance(value, str) or not _is_digest(value):
        raise BadDigestError(f"{label} must be a sha256:<64hex> pin or ''")
    return value


def poisoning_defense_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the defense ledger.

    ``audit_kind`` is used instead of ``kind`` so a detail literally
    named ``kind`` cannot collide with the builder parameter (the
    batch-32/33 sibling collision).
    """
    if audit_kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": audit_kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DatasetRecord:
    """One dataset booked into the defense ledger."""

    dataset_id: str
    seq: int
    sample_digest: str
    n_samples: int
    digest: str
    version: str = POISONING_DEFENSE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "seq": self.seq,
            "sample_digest": self.sample_digest,
            "n_samples": self.n_samples,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        """Recompute the digest pin; integrity as data."""
        try:
            return _digest_pin(
                (
                    self.dataset_id,
                    self.seq,
                    self.sample_digest,
                    self.n_samples,
                    self.version,
                    self.schema,
                )
            ) == self.digest
        except PoisoningDefenseError:
            return False


@dataclass(frozen=True)
class DetectionRecord:
    """One host-declared poisoning detection booked against a dataset."""

    detection_id: str
    dataset_id: str
    threat: str
    seq: int
    affected_digest: str
    digest: str
    version: str = POISONING_DEFENSE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "dataset_id": self.dataset_id,
            "threat": self.threat,
            "seq": self.seq,
            "affected_digest": self.affected_digest,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        """Recompute the digest pin; integrity as data."""
        try:
            return _digest_pin(
                (
                    self.detection_id,
                    self.dataset_id,
                    self.threat,
                    self.seq,
                    self.affected_digest,
                    self.version,
                    self.schema,
                )
            ) == self.digest
        except PoisoningDefenseError:
            return False


@dataclass(frozen=True)
class CleaningRecord:
    """One host-declared remediation booked against a dataset."""

    cleaning_id: str
    dataset_id: str
    action: str
    seq: int
    dropped_digest: str
    digest: str
    version: str = POISONING_DEFENSE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "cleaning_id": self.cleaning_id,
            "dataset_id": self.dataset_id,
            "action": self.action,
            "seq": self.seq,
            "dropped_digest": self.dropped_digest,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        """Recompute the digest pin; integrity as data."""
        try:
            return _digest_pin(
                (
                    self.cleaning_id,
                    self.dataset_id,
                    self.action,
                    self.seq,
                    self.dropped_digest,
                    self.version,
                    self.schema,
                )
            ) == self.digest
        except PoisoningDefenseError:
            return False


@dataclass(frozen=True)
class VerificationReport:
    """Pure-read defense-posture report for a dataset.

    All fields are booked data: ``integrity_ok`` is ledger
    self-consistency (digest pins recompute), never proof the dataset
    is clean.
    """

    dataset_id: str
    seq: int
    integrity_ok: bool
    n_detections: int
    n_cleanings: int
    threats: Tuple[str, ...]
    actions: Tuple[str, ...]
    digest: str
    version: str = POISONING_DEFENSE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "seq": self.seq,
            "integrity_ok": self.integrity_ok,
            "n_detections": self.n_detections,
            "n_cleanings": self.n_cleanings,
            "threats": list(self.threats),
            "actions": list(self.actions),
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        """Recompute the digest pin; integrity as data."""
        try:
            return _digest_pin(
                (
                    self.dataset_id,
                    self.seq,
                    self.integrity_ok,
                    self.n_detections,
                    self.n_cleanings,
                    self.threats,
                    self.actions,
                    self.version,
                    self.schema,
                )
            ) == self.digest
        except PoisoningDefenseError:
            return False


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class PoisoningDefense:
    """Poisoning-defense lifecycle ledger (Simulated).

    ``register_dataset()`` / ``detect()`` / ``clean()`` mutate the ledger
    and consume caller seqs; ``verify()`` and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._datasets: Dict[str, DatasetRecord] = {}
        self._detections: Dict[str, DetectionRecord] = {}
        self._cleanings: Dict[str, CleaningRecord] = {}
        self._detection_ids: Dict[str, List[str]] = {}
        self._cleaning_ids: Dict[str, List[str]] = {}
        self._audit: List[Dict[str, Any]] = []
        self._seq = 0
        self._det_counter = 0
        self._cln_counter = 0

    # -- seq discipline ------------------------------------------------------

    def _check_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")

    def _claim(self, seq: int) -> None:
        self._check_seq(seq)
        self._seq = seq

    def _burn(self, seq: int, rejected_kind: str, **details: Any) -> None:
        """Failed mutation: seq is consumed and a rejected row is booked."""
        self._seq = seq
        try:
            row = poisoning_defense_audit_event(
                "rejected", seq, rejected_kind=rejected_kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": rejected_kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(poisoning_defense_audit_event(audit_kind, seq, **details))

    # -- mutations ------------------------------------------------------------

    def register_dataset(
        self,
        dataset_id: str,
        seq: int,
        sample_digest: str = "",
        n_samples: int = 0,
    ) -> DatasetRecord:
        """Book one dataset into the defense ledger.

        Raw samples never enter a record: ``sample_digest`` is a
        ``sha256:`` pin over the host's sample set (or ``""`` when the
        host declines to pin it).
        """
        with self._lock:
            self._claim(seq)
            try:
                dataset_id = _check_id(dataset_id, "dataset_id")
                sample_digest = _check_optional_digest(sample_digest, "sample_digest")
                if isinstance(n_samples, bool) or not isinstance(n_samples, int):
                    raise BadCountError("n_samples must be an int")
                if n_samples < 0:
                    raise BadCountError("n_samples must be >= 0")
                if dataset_id in self._datasets:
                    raise DuplicateDatasetError(
                        f"dataset already registered: {dataset_id!r}"
                    )
                digest = _digest_pin(
                    (
                        dataset_id,
                        seq,
                        sample_digest,
                        n_samples,
                        POISONING_DEFENSE_VERSION,
                        SCHEMA_PIN,
                    )
                )
                record = DatasetRecord(
                    dataset_id=dataset_id,
                    seq=seq,
                    sample_digest=sample_digest,
                    n_samples=n_samples,
                    digest=digest,
                )
                self._datasets[dataset_id] = record
                self._detection_ids[dataset_id] = []
                self._cleaning_ids[dataset_id] = []
                self._emit(
                    "dataset-registered",
                    seq,
                    dataset_id=dataset_id,
                    n_samples=n_samples,
                    digest=digest,
                )
                return record
            except PoisoningDefenseError:
                self._burn(seq, "register_dataset", dataset_id=dataset_id)
                raise

    def detect(
        self,
        dataset_id: str,
        seq: int,
        threat: str,
        affected_digest: str = "",
    ) -> DetectionRecord:
        """Book a host-declared poisoning detection.

        The threat is pinned to :data:`THREAT_KINDS`; the verdict is
        booked as data, never proof of a real poisoning event. Affected
        samples travel as a digest pin only.
        """
        with self._lock:
            self._claim(seq)
            try:
                dataset_id = _check_id(dataset_id, "dataset_id")
                affected_digest = _check_optional_digest(
                    affected_digest, "affected_digest"
                )
                if dataset_id not in self._datasets:
                    raise UnknownDatasetError(f"unknown dataset: {dataset_id!r}")
                if not isinstance(threat, str) or threat not in THREAT_KINDS:
                    raise BadThreatError(f"threat must be one of {THREAT_KINDS!r}")
                self._det_counter += 1
                detection_id = f"det-{self._det_counter}"
                digest = _digest_pin(
                    (
                        detection_id,
                        dataset_id,
                        threat,
                        seq,
                        affected_digest,
                        POISONING_DEFENSE_VERSION,
                        SCHEMA_PIN,
                    )
                )
                record = DetectionRecord(
                    detection_id=detection_id,
                    dataset_id=dataset_id,
                    threat=threat,
                    seq=seq,
                    affected_digest=affected_digest,
                    digest=digest,
                )
                self._detections[detection_id] = record
                self._detection_ids[dataset_id].append(detection_id)
                self._emit(
                    "detection-booked",
                    seq,
                    detection_id=detection_id,
                    dataset_id=dataset_id,
                    threat=threat,
                    digest=digest,
                )
                return record
            except PoisoningDefenseError:
                self._burn(seq, "detect", dataset_id=dataset_id)
                raise

    def clean(
        self,
        dataset_id: str,
        seq: int,
        action: str,
        dropped_digest: str = "",
    ) -> CleaningRecord:
        """Book a host-declared remediation for a dataset.

        The action is pinned to :data:`CLEAN_ACTIONS`; booking a
        ``drop-samples`` row books the *declaration*, never the actual
        removal of data. Dropped samples travel as a digest pin only.
        """
        with self._lock:
            self._claim(seq)
            try:
                dataset_id = _check_id(dataset_id, "dataset_id")
                dropped_digest = _check_optional_digest(
                    dropped_digest, "dropped_digest"
                )
                if dataset_id not in self._datasets:
                    raise UnknownDatasetError(f"unknown dataset: {dataset_id!r}")
                if not isinstance(action, str) or action not in CLEAN_ACTIONS:
                    raise BadActionError(
                        f"action must be one of {CLEAN_ACTIONS!r}"
                    )
                self._cln_counter += 1
                cleaning_id = f"cln-{self._cln_counter}"
                digest = _digest_pin(
                    (
                        cleaning_id,
                        dataset_id,
                        action,
                        seq,
                        dropped_digest,
                        POISONING_DEFENSE_VERSION,
                        SCHEMA_PIN,
                    )
                )
                record = CleaningRecord(
                    cleaning_id=cleaning_id,
                    dataset_id=dataset_id,
                    action=action,
                    seq=seq,
                    dropped_digest=dropped_digest,
                    digest=digest,
                )
                self._cleanings[cleaning_id] = record
                self._cleaning_ids[dataset_id].append(cleaning_id)
                self._emit(
                    "cleaning-booked",
                    seq,
                    cleaning_id=cleaning_id,
                    dataset_id=dataset_id,
                    action=action,
                    digest=digest,
                )
                return record
            except PoisoningDefenseError:
                self._burn(seq, "clean", dataset_id=dataset_id)
                raise

    # -- pure reads -------------------------------------------------------------

    def verify(self, dataset_id: str, seq: int) -> VerificationReport:
        """Re-walk a dataset's defense ledger and report posture as data.

        Pure read: ``seq`` shape is validated, never consumed, and no
        audit row is written. ``integrity_ok=False`` is reported as data
        on any tamper or unknown dataset, never raised.
        """
        with self._lock:
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                raise SeqOrderError("seq must be a non-negative int")
            dataset_id = _check_id(dataset_id, "dataset_id")
            dataset = self._datasets.get(dataset_id)
            detection_records = [
                self._detections[did] for did in self._detection_ids.get(dataset_id, [])
            ]
            cleaning_records = [
                self._cleanings[cid] for cid in self._cleaning_ids.get(dataset_id, [])
            ]
            integrity_ok = (
                dataset is not None
                and dataset.verify()
                and all(r.verify() for r in detection_records)
                and all(r.verify() for r in cleaning_records)
            )
            threats = tuple(r.threat for r in detection_records)
            actions = tuple(r.action for r in cleaning_records)
            digest = _digest_pin(
                (
                    dataset_id,
                    seq,
                    integrity_ok,
                    len(detection_records),
                    len(cleaning_records),
                    threats,
                    actions,
                    POISONING_DEFENSE_VERSION,
                    SCHEMA_PIN,
                )
            )
            return VerificationReport(
                dataset_id=dataset_id,
                seq=seq,
                integrity_ok=integrity_ok,
                n_detections=len(detection_records),
                n_cleanings=len(cleaning_records),
                threats=threats,
                actions=actions,
                digest=digest,
            )

    def dataset_record(self, dataset_id: str) -> DatasetRecord:
        with self._lock:
            record = self._datasets.get(_check_id(dataset_id, "dataset_id"))
            if record is None:
                raise UnknownDatasetError(f"unknown dataset: {dataset_id!r}")
            return record

    def detection_record(self, detection_id: str) -> DetectionRecord:
        with self._lock:
            record = self._detections.get(_check_id(detection_id, "detection_id"))
            if record is None:
                raise DuplicateDetectionError(
                    f"unknown detection: {detection_id!r}"
                )
            return record

    def cleaning_record(self, cleaning_id: str) -> CleaningRecord:
        with self._lock:
            record = self._cleanings.get(_check_id(cleaning_id, "cleaning_id"))
            if record is None:
                raise DuplicateCleaningError(f"unknown cleaning: {cleaning_id!r}")
            return record

    def dataset_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(self._datasets)

    def detections_for(self, dataset_id: str) -> Tuple[str, ...]:
        with self._lock:
            dataset_id = _check_id(dataset_id, "dataset_id")
            if dataset_id not in self._datasets:
                raise UnknownDatasetError(f"unknown dataset: {dataset_id!r}")
            return tuple(self._detection_ids[dataset_id])

    def cleanings_for(self, dataset_id: str) -> Tuple[str, ...]:
        with self._lock:
            dataset_id = _check_id(dataset_id, "dataset_id")
            if dataset_id not in self._datasets:
                raise UnknownDatasetError(f"unknown dataset: {dataset_id!r}")
            return tuple(self._cleaning_ids[dataset_id])

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "datasets": len(self._datasets),
                "detections": len(self._detections),
                "cleanings": len(self._cleanings),
                "audit_rows": len(self._audit),
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    """Self-check: register, detect, clean, verify, pins, audit."""
    defense = PoisoningDefense()
    digest = "sha256:" + hashlib.sha256(b"train-set").hexdigest()
    defense.register_dataset("ds-1", 1, sample_digest=digest, n_samples=100)
    defense.detect("ds-1", 2, "label-flip", affected_digest=digest)
    defense.clean("ds-1", 3, "drop-samples", dropped_digest=digest)
    report = defense.verify("ds-1", 4)
    assert report.integrity_ok and report.verify()
    assert defense.stats()["audit_rows"] == 3
    print("poisoning-defense OK: register, detect, clean, verify, pins, audit")


if __name__ == "__main__":
    main()
