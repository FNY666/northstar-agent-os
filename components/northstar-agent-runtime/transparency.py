"""Transparency: AI transparency-obligation disclosure ledger, Simulated.

Research note: transparency obligations (EU AI Act Art. 50, Mitchell et
al.'s model cards, system cards, datasheets for datasets) structure the
gap between *what a system is* and *what the people around it are told*.
The operator must declare that a user is interacting with an AI system,
label AI-generated content, state capability limits, and name a point of
contact - but the dangerous half of any disclosure is the *detail*: raw
model outputs, user prompts, PII, and proprietary training data must never
be bundled with the bookkeeping record that tracks the disclosure itself.

This module is that bookkeeping layer, deliberately distinct from its
siblings ``transparency_log.py`` (append-only event log mechanics),
``identity_disclosure.py`` (identity-claim lifecycle), and
``vuln_disclosure.py`` (coordinated vulnerability disclosure): this module
runs no detector, renders no notice, and leaks no raw material. It books:

* **disclose()** - declare one transparency disclosure (pinned subject and
  disclosure-kind vocabulary; subject/content travel as ``sha256:`` digest
  pins only - raw text never enters a record).
* **verify()** - derive a verification report as data (pure read): digest
  pins recomputed, completeness checks evaluated, verdict pinned to
  ``complete`` / ``partial`` / ``stale``. A booked "complete" is ledger
  truth, never proof the notice was seen or understood.
* **audit()** - derive a digest-pinned aggregate report (pure read).
* **retract()** - terminal bookkeeping for superseded / erroneous
  disclosures; ids are never recycled.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``transparency.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: a booked disclosure is a host-declared claim, never proof a
notice was published or read; a booked "complete" verification means the
ledger's pins check out, never that the disclosure satisfied any statute;
a booked retraction is a declared decision, never proof the notice was
actually withdrawn from circulation.
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
TRANSPARENCY_VERSION = "transparency.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.transparency.v1"

#: Pinned disclosure-subject vocabulary (what the disclosure is about).
SUBJECTS = (
    "ai-model",
    "ai-system",
    "generated-content",
    "dataset",
    "agent",
)

#: Pinned disclosure-kind vocabulary (Art. 50 / model-card-shaped).
KINDS = (
    "ai-interaction",
    "ai-generated-content",
    "capability-limits",
    "training-data-summary",
    "watermarking",
    "human-oversight",
    "contact-point",
    "risk-warning",
)

#: Pinned verification-verdict vocabulary (booked as data).
VERDICTS = ("complete", "partial", "stale")

#: Pinned retraction-reason vocabulary.
RETRACT_REASONS = ("manual", "superseded", "erroneous", "revoked")

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "disclosed",
    "retracted",
    "rejected",
)

#: Keys that may never appear raw in an audit row (exact-key matching).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "content",
        "text",
        "prompt",
        "response",
        "output",
        "training",
        "training_data",
        "dataset",
        "weights",
        "document",
        "details",
        "summary",
        "user",
        "username",
        "email",
        "name",
        "personal",
        "pii",
        "secret",
        "raw",
        "payload",
        "value",
        "data",
        "input",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class TransparencyError(Exception):
    """Base error for transparency ledger misuse."""


class BadIdError(TransparencyError):
    """Malformed disclosure id."""


class DuplicateDisclosureError(TransparencyError):
    """A disclosure id was declared twice."""


class UnknownDisclosureError(TransparencyError):
    """Reference to a disclosure id that was never declared."""


class RetiredDisclosureError(TransparencyError):
    """A disclosure id was retracted and can never be reused."""


class BadSubjectError(TransparencyError):
    """Disclosure subject outside the pinned vocabulary."""


class BadKindError(TransparencyError):
    """Disclosure kind outside the pinned vocabulary."""


class BadDigestError(TransparencyError):
    """Malformed sha256: digest pin."""


class BadReasonError(TransparencyError):
    """Retraction reason outside the pinned vocabulary."""


class DisclosureStateError(TransparencyError):
    """Mutation attempted against a disclosure that is not live."""


class SeqOrderError(TransparencyError):
    """Caller seq did not strictly increase."""


class AuditKindError(TransparencyError):
    """Unknown audit kind or banned raw key in an audit row."""


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: str, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _require_optional_digest(pin: str, field_name: str) -> str:
    if pin == "":
        return pin
    return _require_digest(pin, field_name)


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DisclosureRecord:
    """One declared transparency disclosure (digest pins only, never raw text)."""

    disclosure_id: str
    subject: str
    disclosure_kind: str
    subject_digest: str
    content_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "disclosure_id": self.disclosure_id,
            "subject": self.subject,
            "disclosure_kind": self.disclosure_kind,
            "subject_digest": self.subject_digest,
            "content_digest": self.content_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "disclosure_id": self.disclosure_id,
                "subject": self.subject,
                "disclosure_kind": self.disclosure_kind,
                "subject_digest": self.subject_digest,
                "content_digest": self.content_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class VerificationReport:
    """One derived verification outcome (pure read; verdict booked as data)."""

    disclosure_id: str
    verdict: str
    checks: Tuple[Tuple[str, bool], ...]
    integrity_ok: bool
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "disclosure_id": self.disclosure_id,
            "verdict": self.verdict,
            "checks": [{"check": name, "ok": ok} for name, ok in self.checks],
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "disclosure_id": self.disclosure_id,
                "verdict": self.verdict,
                "checks": [{"check": name, "ok": ok} for name, ok in self.checks],
                "integrity_ok": self.integrity_ok,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class RetractRecord:
    """Terminal retraction of a disclosure (pinned reason)."""

    disclosure_id: str
    reason: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "disclosure_id": self.disclosure_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "disclosure_id": self.disclosure_id,
                "reason": self.reason,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class TransparencyAuditReport:
    """Pure-read aggregate of the disclosure ledger (digest-pinned)."""

    n_disclosures: int
    n_active: int
    n_retracted: int
    subject_tallies: Tuple[Tuple[str, int], ...]
    kind_tallies: Tuple[Tuple[str, int], ...]
    integrity_ok: bool
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "n_disclosures": self.n_disclosures,
            "n_active": self.n_active,
            "n_retracted": self.n_retracted,
            "subject_tallies": [
                {"subject": s, "count": c} for s, c in self.subject_tallies
            ],
            "kind_tallies": [
                {"disclosure_kind": k, "count": c} for k, c in self.kind_tallies
            ],
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "n_disclosures": self.n_disclosures,
                "n_active": self.n_active,
                "n_retracted": self.n_retracted,
                "subject_tallies": [
                    {"subject": s, "count": c} for s, c in self.subject_tallies
                ],
                "kind_tallies": [
                    {"disclosure_kind": k, "count": c}
                    for k, c in self.kind_tallies
                ],
                "integrity_ok": self.integrity_ok,
                "seq": self.seq,
            }
        )


def transparency_audit_event(
    kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the transparency ledger."""
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


class Transparency:
    """Transparency-obligation disclosure ledger (Simulated).

    ``disclose()`` / ``retract()`` mutate the ledger and consume caller
    seqs; ``verify()``, ``audit()``, and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._disclosures: Dict[str, DisclosureRecord] = {}
        self._retractions: Dict[str, RetractRecord] = {}
        self._retired: set = set()
        self._audit: List[Dict[str, Any]] = []

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
            row = transparency_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(
            transparency_audit_event(audit_kind, seq, **details)
        )

    # -- disclose --------------------------------------------------------

    def disclose(
        self,
        disclosure_id: str,
        subject: str,
        seq: int,
        disclosure_kind: str = "ai-interaction",
        subject_digest: str = "",
        content_digest: str = "",
    ) -> DisclosureRecord:
        """Book one transparency disclosure (digest pins only, never raw text)."""
        with self._lock:
            self._claim(seq)
            try:
                _require_id(disclosure_id, "disclosure_id")
                if disclosure_id in self._retired:
                    raise RetiredDisclosureError(
                        f"disclosure id retired forever: {disclosure_id!r}"
                    )
                if disclosure_id in self._disclosures:
                    raise DuplicateDisclosureError(
                        f"duplicate disclosure: {disclosure_id!r}"
                    )
                if subject not in SUBJECTS:
                    raise BadSubjectError(f"bad subject: {subject!r}")
                if disclosure_kind not in KINDS:
                    raise BadKindError(f"bad disclosure kind: {disclosure_kind!r}")
                subject_digest = _require_optional_digest(
                    subject_digest, "subject_digest"
                )
                content_digest = _require_optional_digest(
                    content_digest, "content_digest"
                )
                record = DisclosureRecord(
                    disclosure_id=disclosure_id,
                    subject=subject,
                    disclosure_kind=disclosure_kind,
                    subject_digest=subject_digest,
                    content_digest=content_digest,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "disclosure_id": disclosure_id,
                            "subject": subject,
                            "disclosure_kind": disclosure_kind,
                            "subject_digest": subject_digest,
                            "content_digest": content_digest,
                            "seq": seq,
                        }
                    ),
                )
                self._disclosures[disclosure_id] = record
                self._emit(
                    "disclosed",
                    seq,
                    disclosure_id=disclosure_id,
                    subject=subject,
                    disclosure_kind=disclosure_kind,
                )
                return record
            except TransparencyError:
                self._burn(seq, "disclose", disclosure_id=disclosure_id)
                raise

    # -- retract -----------------------------------------------------------

    def retract(
        self, disclosure_id: str, seq: int, reason: str = "manual"
    ) -> RetractRecord:
        """Terminally retract a disclosure (pinned reason); ids never recycled."""
        with self._lock:
            self._claim(seq)
            try:
                if not isinstance(disclosure_id, str) or not disclosure_id:
                    raise BadIdError("disclosure_id must be a non-empty str")
                if disclosure_id in self._retired:
                    raise RetiredDisclosureError(
                        f"disclosure id retired forever: {disclosure_id!r}"
                    )
                if disclosure_id not in self._disclosures:
                    raise UnknownDisclosureError(
                        f"unknown disclosure: {disclosure_id!r}"
                    )
                if reason not in RETRACT_REASONS:
                    raise BadReasonError(f"bad reason: {reason!r}")
                record = RetractRecord(
                    disclosure_id=disclosure_id,
                    reason=reason,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "disclosure_id": disclosure_id,
                            "reason": reason,
                            "seq": seq,
                        }
                    ),
                )
                self._retractions[disclosure_id] = record
                self._retired.add(disclosure_id)
                self._emit(
                    "retracted",
                    seq,
                    disclosure_id=disclosure_id,
                    reason=reason,
                )
                return record
            except TransparencyError:
                self._burn(seq, "retract", disclosure_id=disclosure_id)
                raise

    # -- pure-read views -----------------------------------------------------

    def _view_seq_ok(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("view seq must be a non-negative int")

    def _is_retired(self, disclosure_id: str) -> bool:
        return disclosure_id in self._retired

    def verify(self, disclosure_id: str, seq: int) -> VerificationReport:
        """Derive a verification report as data (pure read).

        Verdict is pinned: ``complete`` when every check holds,
        ``partial`` when the ledger record no longer recomputes, ``stale``
        when the disclosure was retracted. A booked "complete" is ledger
        truth, never proof the notice was seen or satisfied any statute.
        """
        with self._lock:
            self._view_seq_ok(seq)
            record = self._disclosures.get(disclosure_id)
            if record is None:
                raise UnknownDisclosureError(
                    f"unknown disclosure: {disclosure_id!r}"
                )
            integrity_ok = record.verify()
            retired = self._is_retired(disclosure_id)
            checks = (
                ("subject-pinned", record.subject in SUBJECTS),
                ("kind-pinned", record.disclosure_kind in KINDS),
                ("digest-pins-valid", integrity_ok),
                ("not-retracted", not retired),
            )
            if retired:
                verdict = "stale"
            elif all(ok for _, ok in checks):
                verdict = "complete"
            else:
                verdict = "partial"
            report = VerificationReport(
                disclosure_id=disclosure_id,
                verdict=verdict,
                checks=checks,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "disclosure_id": disclosure_id,
                        "verdict": verdict,
                        "checks": [
                            {"check": name, "ok": ok} for name, ok in checks
                        ],
                        "integrity_ok": integrity_ok,
                        "seq": seq,
                    }
                ),
            )
            return report

    def audit(self, seq: int, disclosure_id: str = "") -> TransparencyAuditReport:
        """Derive a digest-pinned aggregate report (pure read).

        When ``disclosure_id`` is given and unknown, an empty report is
        returned as data, never raised.
        """
        with self._lock:
            self._view_seq_ok(seq)
            if disclosure_id:
                records = (
                    [self._disclosures[disclosure_id]]
                    if disclosure_id in self._disclosures
                    else []
                )
            else:
                records = list(self._disclosures.values())
            subject_tally: Dict[str, int] = {}
            kind_tally: Dict[str, int] = {}
            integrity_ok = True
            n_retracted = 0
            for rec in records:
                subject_tally[rec.subject] = subject_tally.get(rec.subject, 0) + 1
                kind_tally[rec.disclosure_kind] = kind_tally.get(
                    rec.disclosure_kind, 0
                ) + 1
                if not rec.verify():
                    integrity_ok = False
                if self._is_retired(rec.disclosure_id):
                    n_retracted += 1
            n_disclosures = len(records)
            report = TransparencyAuditReport(
                n_disclosures=n_disclosures,
                n_active=n_disclosures - n_retracted,
                n_retracted=n_retracted,
                subject_tallies=tuple(sorted(subject_tally.items())),
                kind_tallies=tuple(sorted(kind_tally.items())),
                integrity_ok=integrity_ok,
                seq=seq,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "n_disclosures": n_disclosures,
                        "n_active": n_disclosures - n_retracted,
                        "n_retracted": n_retracted,
                        "subject_tallies": [
                            {"subject": s, "count": c}
                            for s, c in sorted(subject_tally.items())
                        ],
                        "kind_tallies": [
                            {"disclosure_kind": k, "count": c}
                            for k, c in sorted(kind_tally.items())
                        ],
                        "integrity_ok": integrity_ok,
                        "seq": seq,
                    }
                ),
            )
            return report

    def disclosure_record(self, disclosure_id: str, seq: int) -> DisclosureRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._disclosures.get(disclosure_id)
            if record is None:
                raise UnknownDisclosureError(
                    f"unknown disclosure: {disclosure_id!r}"
                )
            return record

    def retraction_record(self, disclosure_id: str, seq: int) -> RetractRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._retractions.get(disclosure_id)
            if record is None:
                raise UnknownDisclosureError(
                    f"no retraction for {disclosure_id!r}"
                )
            return record

    def disclosure_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._disclosures))

    def active_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(
                sorted(did for did in self._disclosures if did not in self._retired)
            )

    def retracted_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._retired))

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._audit)

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._view_seq_ok(seq)
            return {
                "disclosures": len(self._disclosures),
                "active": len(self.active_ids(0)),
                "retracted": len(self._retired),
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }


def main() -> None:
    pin = "sha256:" + "ab" * 32
    t = Transparency()
    d = t.disclose(
        "TR-1",
        "ai-system",
        1,
        disclosure_kind="ai-interaction",
        subject_digest=pin,
        content_digest=pin,
    )
    v = t.verify("TR-1", 0)
    r = t.audit(0)
    assert d.verify() and v.verify() and r.verify()
    assert v.verdict == "complete"
    assert v.integrity_ok is True
    assert r.n_disclosures == 1 and r.n_active == 1
    t.retract("TR-1", 2, reason="superseded")
    stale = t.verify("TR-1", 0)
    assert stale.verdict == "stale"
    print("transparency OK: disclose, verify, audit, retract, pins")


if __name__ == "__main__":
    main()
