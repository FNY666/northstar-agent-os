"""standards.py — standards-adoption and conformance-verification bookkeeping.

ISO 27001 / NIST AI RMF / SOC2 / EU AI Act-shaped standards compliance as a
deterministic single-host state machine: adopt a standard, book
conformance verifications against declared requirements, then certify when
the latest verification is fully conformant. Simulated: the ledger books
host-declared conformance claims; it cannot observe the real system and
cannot prove a standard is truly satisfied (the GIGO boundary shared with
every other bookkeeping module in this repo). A booked ``certified=True``
is ledger truth, never proof of real-world compliance.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # pragma: no cover
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover
    _jcs_dumps = None  # type: ignore

VERSION = "standards.v1"
SCHEMA = "northstar.standards.v1"
AUDIT_SCHEMA = "audit.ndjson/1"

_DIGEST_PREFIX = "sha256:"
_MAX_INT = 2 ** 53
_MAX_ID_LEN = 128

FRAMEWORKS = (
    "iso-27001",
    "nist-ai-rmf",
    "soc2",
    "eu-ai-act",
    "custom",
)

VERDICTS = (
    "conformant",
    "partial",
    "non-conformant",
)

AUDIT_KINDS = (
    "standard-adopted",
    "verified",
    "certified",
    "retired",
    "standards.rejected",
)


class StandardsError(Exception):
    """Base for all standards errors."""


class BadIdError(StandardsError):
    pass


class DuplicateStandardError(StandardsError):
    pass


class UnknownStandardError(StandardsError):
    pass


class RetiredStandardError(StandardsError):
    pass


class BadFrameworkError(StandardsError):
    pass


class BadRequirementError(StandardsError):
    pass


class BadVerdictError(StandardsError):
    pass


class NotConformantError(StandardsError):
    pass


class AlreadyCertifiedError(StandardsError):
    pass


class SeqOrderError(StandardsError):
    pass


class AuditKindError(StandardsError):
    pass


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    return seq


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{what} must be a str, got {type(value).__name__}")
    if not value or len(value) > _MAX_ID_LEN:
        raise BadIdError(f"{what} must be a non-empty str of <= {_MAX_ID_LEN} chars")
    return value


def _check_framework(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadFrameworkError(f"framework must be a str, got {type(value).__name__}")
    if value not in FRAMEWORKS:
        raise BadFrameworkError(f"framework {value!r} not in pinned vocabulary")
    return value


def _check_requirement_list(value: Any, what: str) -> Tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, (tuple, list)):
        raise BadRequirementError(f"{what} must be a tuple/list of str")
    out = []
    for item in value:
        out.append(_check_id(item, what + " item"))
    if len(set(out)) != len(out):
        raise BadRequirementError(f"{what} contains duplicates")
    return tuple(out)


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    if _jcs_dumps is not None:
        return _jcs_dumps(payload).encode("utf-8")  # type: ignore

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) > _MAX_INT:
                raise StandardsError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise StandardsError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise StandardsError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(_tag(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(
        tag.encode("utf-8") + b"\x1f" + _canonical(payload)
    ).hexdigest()


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdoptionRecord:
    """One booked standard adoption."""

    standard_id: str
    framework: str
    title_digest: str
    digest: str
    seq: int
    schema: str = SCHEMA
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "standard_id": self.standard_id,
            "framework": self.framework,
            "title_digest": self.title_digest,
            "digest": self.digest,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        expect = _digest_pin(
            (self.standard_id, self.framework, self.title_digest), "adoption"
        )
        return self.digest == expect


@dataclass(frozen=True)
class VerificationRecord:
    """One booked conformance verification; the verdict is data."""

    verification_id: str
    standard_id: str
    requirements: Tuple[str, ...]
    met: Tuple[str, ...]
    verdict: str
    coverage_text: str
    digest: str
    seq: int
    schema: str = SCHEMA
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "verification_id": self.verification_id,
            "standard_id": self.standard_id,
            "requirements": list(self.requirements),
            "met": list(self.met),
            "verdict": self.verdict,
            "coverage_text": self.coverage_text,
            "digest": self.digest,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.verification_id,
                self.standard_id,
                self.requirements,
                self.met,
                self.verdict,
                self.coverage_text,
            ),
            "verification",
        )
        return self.digest == expect


@dataclass(frozen=True)
class CertifyRecord:
    """One booked certification decision; certified is data, not proof."""

    standard_id: str
    verification_id: str
    certified: bool
    digest: str
    seq: int
    schema: str = SCHEMA
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "standard_id": self.standard_id,
            "verification_id": self.verification_id,
            "certified": self.certified,
            "digest": self.digest,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        expect = _digest_pin(
            (self.standard_id, self.verification_id, self.certified), "certify"
        )
        return self.digest == expect


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of a standard adoption."""

    standard_id: str
    digest: str
    seq: int
    schema: str = SCHEMA
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "standard_id": self.standard_id,
            "digest": self.digest,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        expect = _digest_pin((self.standard_id,), "retire")
        return self.digest == expect


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def standards_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw requirement/title text never crosses this boundary."""
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    banned = (
        "title",
        "text",
        "content",
        "payload",
        "raw",
        "body",
        "value",
        "message",
        "reason",
        "justification",
        "explanation",
        "requirements",
        "met",
    )
    for bad in banned:
        if bad in detail:
            raise AuditKindError(f"audit detail bans {bad!r}")
    _check_seq(seq)
    event = {
        "schema": AUDIT_SCHEMA,
        "module": "standards",
        "kind": kind,
        "seq": seq,
        "detail": detail,
    }
    event["digest"] = _digest_pin((kind, seq, tuple(sorted(detail))), "audit-event")
    return event


# ---------------------------------------------------------------------------
# Standards ledger
# ---------------------------------------------------------------------------


class Standards:
    """Standards-adoption and conformance-verification bookkeeping: adopt, verify, certify."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # standard_id -> AdoptionRecord (insertion ordered)
        self._adoptions: Dict[str, AdoptionRecord] = {}
        # verification_id -> VerificationRecord (insertion ordered)
        self._verifications: Dict[str, VerificationRecord] = {}
        # standard_id -> list of verification ids
        self._standard_verifications: Dict[str, List[str]] = {}
        # standard_id -> CertifyRecord
        self._certifications: Dict[str, CertifyRecord] = {}
        # retired standard ids
        self._retired: set = set()
        self._audit_events: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_events.append(standards_audit_event(audit_kind, seq, **detail))

    def _fail(self, seq: int, exc: StandardsError, **detail: Any) -> None:
        self._emit(AUDIT_KINDS[-1], seq, error=type(exc).__name__, **detail)
        raise exc

    # -- mutations ----------------------------------------------------------

    def adopt(
        self, standard_id: str, framework: str, seq: int, title: str = ""
    ) -> AdoptionRecord:
        """Adopt one standard under a pinned framework. Title travels as digest only."""
        with self._lock:
            seq = self._claim(seq)
            try:
                standard_id = _check_id(standard_id, "standard_id")
                framework = _check_framework(framework)
                if not isinstance(title, str):
                    raise BadIdError("title must be a str")
                if standard_id in self._retired:
                    raise RetiredStandardError(f"standard {standard_id!r} retired")
                if standard_id in self._adoptions:
                    raise DuplicateStandardError(f"standard {standard_id!r} already adopted")
                title_digest = (
                    _DIGEST_PREFIX
                    + hashlib.sha256(title.encode("utf-8")).hexdigest()
                    if title
                    else ""
                )
            except StandardsError as exc:
                self._fail(seq, exc, standard_id=str(standard_id))
            record = AdoptionRecord(
                standard_id=standard_id,
                framework=framework,
                title_digest=title_digest,
                digest=_digest_pin((standard_id, framework, title_digest), "adoption"),
                seq=seq,
            )
            self._adoptions[standard_id] = record
            self._standard_verifications[standard_id] = []
            self._emit("standard-adopted", seq, standard_id=standard_id, framework=framework)
            return record

    def verify(
        self,
        standard_id: str,
        seq: int,
        requirements: Tuple[str, ...] = (),
        met: Tuple[str, ...] = (),
    ) -> VerificationRecord:
        """Book a conformance verification. Verdict is data: conformant / partial / non-conformant."""
        with self._lock:
            seq = self._claim(seq)
            try:
                standard_id = _check_id(standard_id, "standard_id")
                if standard_id in self._retired:
                    raise RetiredStandardError(f"standard {standard_id!r} retired")
                if standard_id not in self._adoptions:
                    raise UnknownStandardError(f"standard {standard_id!r} not adopted")
                requirements = _check_requirement_list(requirements, "requirements")
                met = _check_requirement_list(met, "met")
                if len(requirements) == 0:
                    raise BadRequirementError("requirements must be non-empty")
                if not set(met) <= set(requirements):
                    raise BadRequirementError("met must be a subset of requirements")
            except StandardsError as exc:
                self._fail(seq, exc, standard_id=str(standard_id))
            met_sorted = tuple(sorted(met))
            req_sorted = tuple(sorted(requirements))
            if len(met) == len(requirements):
                verdict = "conformant"
            elif len(met) == 0:
                verdict = "non-conformant"
            else:
                verdict = "partial"
            coverage_text = f"{len(met)}/{len(requirements)}"
            verification_id = f"ver-{len(self._verifications) + 1}"
            record = VerificationRecord(
                verification_id=verification_id,
                standard_id=standard_id,
                requirements=req_sorted,
                met=met_sorted,
                verdict=verdict,
                coverage_text=coverage_text,
                digest=_digest_pin(
                    (
                        verification_id,
                        standard_id,
                        req_sorted,
                        met_sorted,
                        verdict,
                        coverage_text,
                    ),
                    "verification",
                ),
                seq=seq,
            )
            self._verifications[verification_id] = record
            self._standard_verifications[standard_id].append(verification_id)
            self._emit(
                "verified",
                seq,
                verification_id=verification_id,
                standard_id=standard_id,
                verdict=verdict,
                coverage_text=coverage_text,
            )
            return record

    def certify(self, standard_id: str, seq: int) -> CertifyRecord:
        """Book a certification decision. Requires the latest verification to be fully conformant."""
        with self._lock:
            seq = self._claim(seq)
            try:
                standard_id = _check_id(standard_id, "standard_id")
                if standard_id in self._retired:
                    raise RetiredStandardError(f"standard {standard_id!r} retired")
                if standard_id not in self._adoptions:
                    raise UnknownStandardError(f"standard {standard_id!r} not adopted")
                if standard_id in self._certifications:
                    raise AlreadyCertifiedError(f"standard {standard_id!r} already certified")
                vids = self._standard_verifications[standard_id]
                if not vids:
                    raise NotConformantError(f"standard {standard_id!r} has no verification")
                latest = self._verifications[vids[-1]]
                if latest.verdict != "conformant":
                    raise NotConformantError(
                        f"latest verification {latest.verdict!r} is not conformant"
                    )
            except StandardsError as exc:
                self._fail(seq, exc, standard_id=str(standard_id))
            record = CertifyRecord(
                standard_id=standard_id,
                verification_id=latest.verification_id,
                certified=True,
                digest=_digest_pin((standard_id, latest.verification_id, True), "certify"),
                seq=seq,
            )
            self._certifications[standard_id] = record
            self._emit(
                "certified",
                seq,
                standard_id=standard_id,
                verification_id=latest.verification_id,
            )
            return record

    def retire(self, standard_id: str, seq: int) -> RetireRecord:
        """Terminal retirement of a standard adoption; the id is never recycled."""
        with self._lock:
            seq = self._claim(seq)
            try:
                standard_id = _check_id(standard_id, "standard_id")
                if standard_id in self._retired:
                    raise RetiredStandardError(f"standard {standard_id!r} already retired")
                if standard_id not in self._adoptions:
                    raise UnknownStandardError(f"standard {standard_id!r} not adopted")
            except StandardsError as exc:
                self._fail(seq, exc, standard_id=str(standard_id))
            record = RetireRecord(
                standard_id=standard_id,
                digest=_digest_pin((standard_id,), "retire"),
                seq=seq,
            )
            self._retired.add(standard_id)
            self._emit("retired", seq, standard_id=standard_id)
            return record

    # -- views (pure reads: validate seq shape, never consume, no audit rows) --

    def adoption_record(self, standard_id: str, seq: int) -> AdoptionRecord:
        _check_seq(seq)
        _check_id(standard_id, "standard_id")
        if standard_id not in self._adoptions:
            raise UnknownStandardError(f"standard {standard_id!r} not adopted")
        return self._adoptions[standard_id]

    def adoption_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        return tuple(self._adoptions)

    def verifications_for(self, standard_id: str, seq: int) -> Tuple[VerificationRecord, ...]:
        _check_seq(seq)
        _check_id(standard_id, "standard_id")
        if standard_id not in self._adoptions:
            raise UnknownStandardError(f"standard {standard_id!r} not adopted")
        return tuple(self._verifications[v] for v in self._standard_verifications[standard_id])

    def certification(self, standard_id: str, seq: int) -> Optional[CertifyRecord]:
        _check_seq(seq)
        _check_id(standard_id, "standard_id")
        if standard_id not in self._adoptions:
            raise UnknownStandardError(f"standard {standard_id!r} not adopted")
        return self._certifications.get(standard_id)

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, int]:
        _check_seq(seq)
        return {
            "adoptions": len(self._adoptions),
            "verifications": len(self._verifications),
            "certifications": len(self._certifications),
            "retired": len(self._retired),
            "seq": self._seq,
        }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        _check_seq(seq)
        return tuple(self._audit_events)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    st = Standards()
    rec = st.adopt("acme-ai", "nist-ai-rmf", 1, title="Acme AI governance adoption")
    assert rec.verify() and rec.framework == "nist-ai-rmf"
    assert rec.title_digest.startswith(_DIGEST_PREFIX)
    # partial verification -> certify must refuse
    ver = st.verify("acme-ai", 2, requirements=("req-a", "req-b"), met=("req-a",))
    assert ver.verify() and ver.verdict == "partial" and ver.coverage_text == "1/2"
    try:
        st.certify("acme-ai", 3)
    except NotConformantError:
        pass
    else:
        raise AssertionError("certify-before-conformant accepted")
    # full conformance -> certify ok
    ver2 = st.verify("acme-ai", 4, requirements=("req-a", "req-b"), met=("req-a", "req-b"))
    assert ver2.verdict == "conformant"
    cert = st.certify("acme-ai", 5)
    assert cert.verify() and cert.certified is True
    try:
        st.certify("acme-ai", 6)
    except AlreadyCertifiedError:
        pass
    else:
        raise AssertionError("double certify accepted")
    try:
        st.adopt("acme-ai", "iso-27001", 7)
    except DuplicateStandardError:
        pass
    else:
        raise AssertionError("duplicate adopt accepted")
    try:
        st.verify("nope", 8, requirements=("x",), met=("x",))
    except UnknownStandardError:
        pass
    else:
        raise AssertionError("unknown standard verify accepted")
    ret = st.retire("acme-ai", 9)
    assert ret.verify()
    try:
        st.adopt("acme-ai", "soc2", 10)
    except RetiredStandardError:
        pass
    else:
        raise AssertionError("re-adopt of retired id accepted")
    try:
        st.verify("acme-ai", 11, requirements=("x",), met=("x",))
    except RetiredStandardError:
        pass
    else:
        raise AssertionError("verify on retired accepted")
    st2 = Standards()
    st2.adopt("b", "eu-ai-act", 1)
    st2.adopt("a", "soc2", 2)
    assert st2.stats(3)["adoptions"] == 2
    print("standards OK: adopt, verify, certify, retire, refusals")


if __name__ == "__main__":
    main()
