"""Dataset datasheets: Gebru et al. (2021) "Datasheets for Datasets"-shaped
decision ledger.

Research note: a datasheet documents *who* made a dataset, *why*, *what* it
contains, *how* it was collected, and what it may be used for — the
accountability instrument for training data. Here it is a deterministic
single-host ledger: the host declares one datasheet per dataset, books
per-section content pins, asks for a completeness verdict, and books a
publication decision. Content itself travels as digest pins only; no
dataset bytes, no collection details, and no raw text ever enter a record.

House style: frozen dataclasses, caller int seqs strictly increasing with
claim-then-burn, no wall-clock, RLock-guarded, fail-closed, stdlib-only +
``canonical_json`` try/except fallback, ``sha256:`` digest pins with
``verify()``, ``audit.ndjson/1`` events.

Honest scope: a booked ``published`` verdict means "the host declared the
datasheet complete and published it" — the module verifies ledger
self-consistency (digest pins recompute, required sections present), not
that the dataset is safe, fair, or fit for purpose. ``verify()`` checks
ledger truth, never ground truth.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:  # pragma: no cover - in-repo canonicalizer when present
    from canonical_json import jcs_sha256_hex as _jcs_sha256_hex
    from canonical_json import jcs_dumps as _jcs_dumps

    def _canon_dumps(obj: object) -> bytes:
        out = _jcs_dumps(obj)
        return out if isinstance(out, bytes) else str(out).encode("utf-8")

    def _canon_pin(obj: object) -> str:
        return "sha256:" + _jcs_sha256_hex(obj)
except Exception:  # pragma: no cover - stdlib fallback
    import json as _json

    def _canon_dumps(obj: object) -> bytes:
        return _json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def _canon_pin(obj: object) -> str:
        return "sha256:" + hashlib.sha256(_canon_dumps(obj)).hexdigest()


#: Module version pin.
DATASHEET_VERSION = "datasheet.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.datasheet.v1"

#: Required sections per Gebru et al. "Datasheets for Datasets".
REQUIRED_SECTIONS = (
    "motivation",
    "composition",
    "collection",
    "preprocessing",
    "uses",
    "distribution",
    "maintenance",
)

# -- error taxonomy ------------------------------------------------------


class DatasheetError(Exception):
    """Base error for datasheet ledger misuse."""


class BadIdError(DatasheetError):
    """Raised when an id is not a non-empty str."""


class DuplicateDatasheetError(DatasheetError):
    """Raised when creating an already-created datasheet id."""


class UnknownDatasheetError(DatasheetError):
    """Raised when addressing a datasheet that was never created."""


class PublishedDatasheetError(DatasheetError):
    """Raised when mutating a published datasheet."""


class RetiredDatasheetError(DatasheetError):
    """Raised when reusing a retired (retracted) datasheet id."""


class BadDigestError(DatasheetError):
    """Raised when a digest pin is not ``sha256:<64hex>`` or ``""``."""


class BadSectionError(DatasheetError):
    """Raised when a section name is not in the pinned vocabulary."""


class DuplicateSectionError(DatasheetError):
    """Raised when booking a second record for the same section."""


class SeqOrderError(DatasheetError):
    """Raised when seq is not a strictly increasing int."""


class AuditKindError(DatasheetError):
    """Raised when the audit builder is asked for an unknown kind."""


# -- audit boundary ------------------------------------------------------


AUDIT_KINDS = ("created", "section-added", "published", "retracted", "rejected")

#: Raw-text keys that must never cross the audit boundary.
BANNED_AUDIT_KEYS = (
    "title", "content", "text", "description", "notes", "motivation",
    "rationale", "summary", "details", "details_text", "narrative",
    "composition_notes", "collection_notes", "secret", "raw",
)


def _check_audit_detail(detail: Dict[str, object]) -> Dict[str, object]:
    for key in detail:
        if key in BANNED_AUDIT_KEYS:
            raise DatasheetError(f"raw key banned from audit boundary: {key!r}")
    return detail


def datasheet_audit_event(kind: str, detail: Dict[str, object], seq: int) -> Dict[str, object]:
    """Build one audit row; raises :class:`AuditKindError` on bad kind."""
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": f"datasheet.{kind}",
        "seq": seq,
        "detail": _check_audit_detail(dict(detail)),
    }


# -- records -------------------------------------------------------------


def _check_seq(seq: object) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 1:
        raise SeqOrderError(f"seq must be >= 1, got {seq!r}")
    return seq


def _check_id(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise BadIdError(f"{name} must be a non-empty str")
    return value


def _check_digest(value: object, name: str) -> str:
    if value == "":
        return ""
    if not isinstance(value, str):
        raise BadDigestError(f"{name} must be 'sha256:<64hex>' or ''")
    if not value.startswith("sha256:") or len(value) != 71:
        raise BadDigestError(f"{name} must be 'sha256:<64hex>' or ''")
    try:
        int(value[7:], 16)
    except ValueError:
        raise BadDigestError(f"{name} must be 'sha256:<64hex>' or ''")
    return value


@dataclass(frozen=True)
class DatasheetRecord:
    """One declared datasheet for a dataset (dataset pinned by digest only)."""

    datasheet_id: str
    dataset_pin: str
    title_pin: str
    version: str
    digest: str
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "datasheet_id": self.datasheet_id,
            "dataset_pin": self.dataset_pin,
            "title_pin": self.title_pin,
            "version": self.version,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; ``False`` means tampered."""
        return self.digest == _canon_pin(
            {
                "datasheet_id": self.datasheet_id,
                "dataset_pin": self.dataset_pin,
                "title_pin": self.title_pin,
                "version": self.version,
            }
        )


@dataclass(frozen=True)
class SectionRecord:
    """One booked datasheet section (content travels as a digest pin only)."""

    section_id: str
    datasheet_id: str
    section: str
    content_pin: str
    digest: str
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "section_id": self.section_id,
            "datasheet_id": self.datasheet_id,
            "section": self.section,
            "content_pin": self.content_pin,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _canon_pin(
            {
                "section_id": self.section_id,
                "datasheet_id": self.datasheet_id,
                "section": self.section,
                "content_pin": self.content_pin,
            }
        )


@dataclass(frozen=True)
class VerifyReport:
    """Pure-read completeness verdict over a datasheet."""

    datasheet_id: str
    sections_present: Tuple[str, ...]
    sections_missing: Tuple[str, ...]
    complete: bool
    integrity_ok: bool
    digest: str
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "datasheet_id": self.datasheet_id,
            "sections_present": list(self.sections_present),
            "sections_missing": list(self.sections_missing),
            "complete": self.complete,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _canon_pin(
            {
                "datasheet_id": self.datasheet_id,
                "sections_present": list(self.sections_present),
                "sections_missing": list(self.sections_missing),
                "complete": self.complete,
                "integrity_ok": self.integrity_ok,
            }
        )


@dataclass(frozen=True)
class PublicationRecord:
    """Terminal publication decision for a datasheet."""

    datasheet_id: str
    digest: str
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "datasheet_id": self.datasheet_id,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _canon_pin({"datasheet_id": self.datasheet_id})


@dataclass(frozen=True)
class RetractionRecord:
    """Terminal retraction of a datasheet; id never recycled."""

    datasheet_id: str
    reason: str
    digest: str
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "datasheet_id": self.datasheet_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _canon_pin(
            {"datasheet_id": self.datasheet_id, "reason": self.reason}
        )


_RETRACT_REASONS = ("manual", "superseded", "invalidated")


class Datasheet:
    """Datasheet decision ledger: create -> section -> verify -> publish."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._datasheets: Dict[str, DatasheetRecord] = {}
        self._sections: Dict[str, SectionRecord] = {}
        self._sections_for: Dict[str, List[str]] = {}
        self._publications: Dict[str, PublicationRecord] = {}
        self._retractions: Dict[str, RetractionRecord] = {}
        self._sec_counter = 0
        self._audit: List[Dict[str, object]] = []
        self._rejected = 0

    # -- internal helpers ------------------------------------------------

    def _claim_seq(self, seq_v: int) -> None:
        if seq_v <= self._seq:
            raise SeqOrderError(
                f"seq must be strictly increasing, got {seq_v} after {self._seq}"
            )
        self._seq = seq_v

    def _burn(self, seq_v: int, method: str, exc: DatasheetError) -> None:
        self._rejected += 1
        self._audit.append(
            datasheet_audit_event(
                "rejected",
                {"method": method, "error": type(exc).__name__,
                 "error_detail": str(exc)},
                seq_v,
            )
        )

    def _emit(self, kind: str, detail: Dict[str, object], seq_v: int) -> None:
        self._audit.append(datasheet_audit_event(kind, detail, seq_v))

    def _live_id(self, datasheet_id: str) -> str:
        if datasheet_id in self._retractions:
            raise RetiredDatasheetError(
                f"datasheet id retired, never recycled: {datasheet_id!r}"
            )
        if datasheet_id not in self._datasheets:
            raise UnknownDatasheetError(f"unknown datasheet: {datasheet_id!r}")
        return datasheet_id

    # -- mutations --------------------------------------------------------

    def create(
        self,
        datasheet_id: object,
        seq: object,
        dataset_digest: object = "",
        title_digest: object = "",
        version: object = "1.0",
    ) -> DatasheetRecord:
        """Declare one datasheet for a dataset (digests only, no raw data)."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                did = _check_id(datasheet_id, "datasheet_id")
                if did in self._retractions:
                    raise RetiredDatasheetError(
                        f"datasheet id retired, never recycled: {did!r}"
                    )
                if did in self._datasheets:
                    raise DuplicateDatasheetError(
                        f"datasheet already created: {did!r}"
                    )
                dpin = _check_digest(dataset_digest, "dataset_digest")
                tpin = _check_digest(title_digest, "title_digest")
                if not isinstance(version, str) or not version:
                    raise BadIdError("version must be a non-empty str")
                rec = DatasheetRecord(
                    datasheet_id=did,
                    dataset_pin=dpin,
                    title_pin=tpin,
                    version=version,
                    digest=_canon_pin(
                        {
                            "datasheet_id": did,
                            "dataset_pin": dpin,
                            "title_pin": tpin,
                            "version": version,
                        }
                    ),
                )
                self._datasheets[did] = rec
                self._sections_for[did] = []
                self._emit("created", {"datasheet_id": did, "version": version},
                           seq_v)
                return rec
            except DatasheetError as exc:
                self._burn(seq_v, "create", exc)
                raise

    def section(
        self,
        datasheet_id: object,
        section: object,
        seq: object,
        content_digest: object = "",
    ) -> SectionRecord:
        """Book one datasheet section (minted ``sec-N``)."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                did = _check_id(datasheet_id, "datasheet_id")
                did = self._live_id(did)
                if did in self._publications:
                    raise PublishedDatasheetError(
                        f"datasheet already published: {did!r}"
                    )
                if not isinstance(section, str) or section not in REQUIRED_SECTIONS:
                    raise BadSectionError(
                        f"section must be one of {sorted(REQUIRED_SECTIONS)}"
                    )
                cpin = _check_digest(content_digest, "content_digest")
                for sid in self._sections_for[did]:
                    if self._sections[sid].section == section:
                        raise DuplicateSectionError(
                            f"section already booked: {section!r}"
                        )
                self._sec_counter += 1
                sid = f"sec-{self._sec_counter}"
                rec = SectionRecord(
                    section_id=sid,
                    datasheet_id=did,
                    section=section,
                    content_pin=cpin,
                    digest=_canon_pin(
                        {
                            "section_id": sid,
                            "datasheet_id": did,
                            "section": section,
                            "content_pin": cpin,
                        }
                    ),
                )
                self._sections[sid] = rec
                self._sections_for[did].append(sid)
                self._emit(
                    "section-added",
                    {"section_id": sid, "datasheet_id": did,
                     "section": section},
                    seq_v,
                )
                return rec
            except DatasheetError as exc:
                self._burn(seq_v, "section", exc)
                raise

    def verify(self, datasheet_id: object, seq: object) -> VerifyReport:
        """Derive a completeness verdict (pure read; verdict is data)."""
        with self._lock:
            seq_v = _check_seq(seq)  # validated, never consumed
            did = _check_id(datasheet_id, "datasheet_id")
            if did in self._retractions:
                raise RetiredDatasheetError(
                    f"datasheet id retired, never recycled: {did!r}"
                )
            if did not in self._datasheets:
                raise UnknownDatasheetError(f"unknown datasheet: {did!r}")
            sids = self._sections_for.get(did, [])
            recs = [self._sections[sid] for sid in sids]
            present = tuple(sorted(r.section for r in recs))
            missing = tuple(s for s in REQUIRED_SECTIONS if s not in present)
            integrity = self._datasheets[did].verify() and all(r.verify() for r in recs)
            complete = not missing
            report = VerifyReport(
                datasheet_id=did,
                sections_present=present,
                sections_missing=missing,
                complete=complete,
                integrity_ok=integrity,
                digest=_canon_pin(
                    {
                        "datasheet_id": did,
                        "sections_present": list(present),
                        "sections_missing": list(missing),
                        "complete": complete,
                        "integrity_ok": integrity,
                    }
                ),
            )
            _ = seq_v
            return report

    def publish(self, datasheet_id: object, seq: object) -> PublicationRecord:
        """Terminal publication decision; refused unless complete."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                did = _check_id(datasheet_id, "datasheet_id")
                did = self._live_id(did)
                if did in self._publications:
                    raise PublishedDatasheetError(
                        f"datasheet already published: {did!r}"
                    )
                rep = self._verify_inline(did)
                if not rep.complete:
                    raise DatasheetError(
                        f"cannot publish incomplete datasheet: "
                        f"missing {list(rep.sections_missing)}"
                    )
                if not rep.integrity_ok:
                    raise DatasheetError("cannot publish: ledger integrity broken")
                rec = PublicationRecord(
                    datasheet_id=did,
                    digest=_canon_pin({"datasheet_id": did}),
                )
                self._publications[did] = rec
                self._emit("published", {"datasheet_id": did}, seq_v)
                return rec
            except DatasheetError as exc:
                self._burn(seq_v, "publish", exc)
                raise

    def retract(
        self, datasheet_id: object, seq: object, reason: object = "manual"
    ) -> RetractionRecord:
        """Terminal retraction; id never recycled."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                did = _check_id(datasheet_id, "datasheet_id")
                did = self._live_id(did)
                if not isinstance(reason, str) or reason not in _RETRACT_REASONS:
                    raise BadIdError(
                        f"reason must be one of {sorted(_RETRACT_REASONS)}"
                    )
                rec = RetractionRecord(
                    datasheet_id=did,
                    reason=reason,
                    digest=_canon_pin(
                        {"datasheet_id": did, "reason": reason}
                    ),
                )
                self._retractions[did] = rec
                self._emit(
                    "retracted", {"datasheet_id": did, "reason": reason}, seq_v
                )
                return rec
            except DatasheetError as exc:
                self._burn(seq_v, "retract", exc)
                raise

    def _verify_inline(self, datasheet_id: str) -> VerifyReport:
        """Internal completeness derivation without seq validation."""
        sids = self._sections_for.get(datasheet_id, [])
        recs = [self._sections[sid] for sid in sids]
        present = tuple(sorted(r.section for r in recs))
        missing = tuple(s for s in REQUIRED_SECTIONS if s not in present)
        integrity = self._datasheets[datasheet_id].verify() and all(
            r.verify() for r in recs
        )
        complete = not missing
        return VerifyReport(
            datasheet_id=datasheet_id,
            sections_present=present,
            sections_missing=missing,
            complete=complete,
            integrity_ok=integrity,
            digest=_canon_pin(
                {
                    "datasheet_id": datasheet_id,
                    "sections_present": list(present),
                    "sections_missing": list(missing),
                    "complete": complete,
                    "integrity_ok": integrity,
                }
            ),
        )

    # -- pure-read views ---------------------------------------------------

    def datasheet_record(self, datasheet_id: object, seq: object) -> DatasheetRecord:
        with self._lock:
            _check_seq(seq)
            did = self._live_id(_check_id(datasheet_id, "datasheet_id"))
            return self._datasheets[did]

    def section_record(self, section_id: object, seq: object) -> SectionRecord:
        with self._lock:
            _check_seq(seq)
            sid = _check_id(section_id, "section_id")
            if sid not in self._sections:
                raise UnknownDatasheetError(f"unknown section: {sid!r}")
            return self._sections[sid]

    def datasheet_ids(self, seq: object) -> Tuple[str, ...]:
        with self._lock:
            _check_seq(seq)
            return tuple(self._datasheets.keys())

    def sections_for(self, datasheet_id: object, seq: object) -> Tuple[str, ...]:
        with self._lock:
            _check_seq(seq)
            did = self._live_id(_check_id(datasheet_id, "datasheet_id"))
            return tuple(self._sections_for.get(did, ()))

    def published_ids(self, seq: object) -> Tuple[str, ...]:
        with self._lock:
            _check_seq(seq)
            return tuple(self._publications.keys())

    def is_published(self, datasheet_id: object, seq: object) -> bool:
        with self._lock:
            _check_seq(seq)
            did = _check_id(datasheet_id, "datasheet_id")
            return did in self._publications

    def stats(self, seq: object) -> Dict[str, int]:
        with self._lock:
            _check_seq(seq)
            return {
                "datasheets": len(self._datasheets),
                "sections": len(self._sections),
                "published": len(self._publications),
                "retracted": len(self._retractions),
                "rejected": self._rejected,
            }

    def audit_log(self, seq: object) -> Tuple[Dict[str, object], ...]:
        with self._lock:
            _check_seq(seq)
            return tuple(self._audit)


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    d = Datasheet()
    pin = "sha256:" + "ab" * 32
    d.create("ds-1", 1, dataset_digest=pin, title_digest=pin)
    seq = 1
    for s in REQUIRED_SECTIONS:
        seq += 1
        d.section("ds-1", s, seq, content_digest=pin)
    rep = d.verify("ds-1", seq + 1)
    assert rep.verify() and rep.complete and rep.integrity_ok
    seq += 1
    d.publish("ds-1", seq + 1)
    seq += 1
    assert d.is_published("ds-1", seq + 1)
    assert d.stats(seq + 2)["published"] == 1
    print("datasheet OK: create, section, verify, publish, pins, audit")


if __name__ == "__main__":
    main()
