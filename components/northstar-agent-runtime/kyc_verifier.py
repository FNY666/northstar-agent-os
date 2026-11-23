"""KYC verifier: know-your-customer identity-verification bookkeeping.

Research note: KYC (know your customer) / CDD (customer due diligence) is the
regulated identity-verification step required of financial institutions by
instruments such as the FATF Recommendations (Rec. 10), the EU AMLD6
(2024/1640) and the US BSA: collect identifying documents, *verify* them
against a trusted source, screen the applicant against sanctions and PEP
(politically exposed person) lists, and record the decision so an auditor can
replay it. The load-bearing ideas are: (1) *evidence over assertion* — the
case pins exactly which documents were seen, their type/issuer/expiry, and
which checks ran; (2) *check independence* — document authenticity, expiry,
face match, liveness, address proof, sanctions screening and PEP screening
are separate checks that fail independently, so a reviewer can see *which*
check sank a case; (3) *fail-closed decisions* — unknown case, missing
document, or an inconclusive check is never silently approved; the case lands
in ``manual_review``; (4) *replayable decisions* — the verification report is
digest-pinned over (case, documents, check outcomes, decision seq) so an
auditor can recompute "why was this person approved?".

This module implements that shape as a deterministic, single-host ledger with
a *simulated* provider behind it:

* **Case management** — :meth:`KYCVerifier.submit` opens a frozen
  :class:`Case` for a holder with one or more :class:`Document` records.
  Required document types depend on the declared ``assurance_level``:
  ``standard`` needs one government ID (passport / national_id /
  driver_license) plus one address proof; ``enhanced`` additionally requires
  a selfie for face matching. Missing a required class is refused at submit
  time (fail-closed), not discovered later.
* **Verification** — :meth:`KYCVerifier.verify` runs the full check list and
  emits a frozen :class:`VerificationReport`: ``approved`` iff every check
  passes; ``rejected`` on any hard failure (forgery flag, expiry,
  sanctions/PEP hit); ``manual_review`` on soft failures (face-match miss,
  liveness miss, address mismatch). Check outcomes are a *deterministic*
  function of the document attributes the caller supplied at submit time —
  they stand in for a real document-authentication / watchlist provider's
  observations, which is the simulation boundary (see honest scope).
* **Status** — :meth:`KYCVerifier.status` returns a frozen read-only view of
  a case: current state, last decision, check summary, and the decision
  digest pin.

House style: frozen dataclasses, caller-supplied int seqs (strictly
increasing per verifier, no wall-clock, no RNG), RLock-guarded, fail-closed
(empty ids, unknown document types, bool/negative seqs, unknown check names
all raise a subclass of :class:`KYCError`), stdlib-only, type-tagged
canonical digest encoding (bool != int; NaN/inf and integral floats with
magnitude > 2**53 are refused at digest-pin time — the batch-5 JCS float-loss
caveat), audit events shaped for ``audit.ndjson/1``, ``main()`` self-check.

Honest scope: this is a *decision ledger over simulated observations*, not
an identity oracle. The document attributes (``tampered``, ``sanctions_hit``,
…) are *asserted by the caller*; the verifier cannot look at a real passport
image, detect a forgery, match a face, query a real sanctions list, or bind
a document to the human holding it. ``verify()`` pins "given these claimed
observations, the decision rules said X" — a caller that asserts clean
documents gets a consistent ledger of clean approvals (GIGO, same boundary
as every other bookkeeping module). An ``approved`` report means
"all recorded checks passed and the decision is untampered since pinning",
never "this person really is who they claim to be". For real assurance pair
with ``remote_attestation`` (binding the capture device) and a real
document-authentication provider.

Version pin: kyc-verifier.v1
Schema pin: northstar.kyc-verifier.v1
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Tuple

#: Module version pin.
KYC_VERIFIER_VERSION = "kyc-verifier.v1"

#: Schema pin for records produced by this module.
KYC_VERIFIER_SCHEMA = "northstar.kyc-verifier.v1"

#: Audit stream shape this module emits.
AUDIT_STREAM = "audit.ndjson/1"

#: Document classes that count as government-issued photo ID.
GOVERNMENT_ID_TYPES = frozenset({"passport", "national_id", "driver_license"})

#: Document classes accepted as proof of address.
ADDRESS_PROOF_TYPES = frozenset(
    {"proof_of_address", "utility_bill", "bank_statement"}
)

#: Every document type this module understands.
DOCUMENT_TYPES = frozenset(
    GOVERNMENT_ID_TYPES
    | ADDRESS_PROOF_TYPES
    | {"selfie", "company_registration"}
)

#: Checks run by verify(), in stable order.
CHECKS: Tuple[str, ...] = (
    "document_authenticity",
    "document_expiry",
    "face_match",
    "liveness",
    "address_verification",
    "sanctions_screening",
    "pep_screening",
)

#: Checks whose failure rejects the case outright.
HARD_FAIL_CHECKS = frozenset(
    {"document_authenticity", "document_expiry", "sanctions_screening",
     "pep_screening"}
)

#: Case states.
CASE_STATES = frozenset(
    {"submitted", "approved", "rejected", "manual_review"}
)

#: Assurance levels and their required document classes.
ASSURANCE_LEVELS = frozenset({"standard", "enhanced"})


class KYCError(Exception):
    """Base error for all kyc_verifier failures (fail-closed)."""


class InvalidDocumentError(KYCError):
    """Raised when a document record is malformed or of unknown type."""


class MissingRequirementError(KYCError):
    """Raised when a case lacks the documents its assurance level needs."""


class UnknownCaseError(KYCError):
    """Raised when a case_id is not known to this verifier."""


class BadSeqError(KYCError):
    """Raised when a caller-supplied seq is not a strictly increasing int."""


def _reject_bool(value: object, name: str) -> int:
    """Validate a seq: real int (not bool), non-negative."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadSeqError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise BadSeqError(f"{name} must be non-negative, got {value}")
    return value


def _canon(value: object) -> bytes:
    """Type-tagged canonical encoding for digest pinning.

    bool != int; floats must be finite and integral floats with magnitude
    > 2**53 are refused (batch-5 JCS float-loss caveat).
    """
    if value is None:
        return b"n"
    if isinstance(value, bool):
        return b"b" + (b"1" if value else b"0")
    if isinstance(value, int):
        return b"i" + str(value).encode("ascii")
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise KYCError("NaN/inf refused at digest-pin time")
        if value.is_integer() and abs(value) > 2**53:
            raise KYCError("integral float with magnitude > 2**53 refused")
        return b"f" + repr(value).encode("ascii")
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return b"s" + str(len(raw)).encode("ascii") + b":" + raw
    if isinstance(value, (tuple, list)):
        parts = b",".join(_canon(v) for v in value)
        return b"[" + parts + b"]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0])
        parts = b",".join(_canon(k) + b"=" + _canon(v) for k, v in items)
        return b"{" + parts + b"}"
    raise KYCError(f"cannot canonically encode {type(value).__name__}")


def _pin(*values: object) -> str:
    """Return a ``sha256:`` digest pin over canonically encoded values."""
    digest = hashlib.sha256()
    for value in values:
        digest.update(_canon(value))
        digest.update(b"|")
    return "sha256:" + digest.hexdigest()


def _audit_event(
    *,
    seq: int,
    event: str,
    case_id: str,
    detail: Mapping[str, object],
) -> Dict[str, object]:
    """Build an audit event shaped for ``audit.ndjson/1``."""
    return {
        "stream": AUDIT_STREAM,
        "schema": KYC_VERIFIER_SCHEMA,
        "module": KYC_VERIFIER_VERSION,
        "seq": seq,
        "event": event,
        "case_id": case_id,
        "detail": dict(detail),
    }


@dataclass(frozen=True)
class Document:
    """One identity document submitted for a case.

    The observation flags (``tampered``, ``sanctions_hit``, …) are
    *caller-asserted* stand-ins for a real provider's observations — the
    simulation boundary of this module.
    """

    doc_id: str
    doc_type: str
    holder_name: str
    issuer: str
    expiry_seq: int
    tampered: bool = False
    sanctions_hit: bool = False
    pep_hit: bool = False
    face_match_ok: bool = True
    liveness_ok: bool = True
    address_ok: bool = True

    def __post_init__(self) -> None:
        if not self.doc_id or not isinstance(self.doc_id, str):
            raise InvalidDocumentError("doc_id must be a non-empty string")
        if self.doc_type not in DOCUMENT_TYPES:
            raise InvalidDocumentError(
                f"unknown doc_type {self.doc_type!r}; "
                f"expected one of {sorted(DOCUMENT_TYPES)}"
            )
        if not self.holder_name or not isinstance(self.holder_name, str):
            raise InvalidDocumentError("holder_name must be a non-empty string")
        if not self.issuer or not isinstance(self.issuer, str):
            raise InvalidDocumentError("issuer must be a non-empty string")
        _reject_bool(self.expiry_seq, "expiry_seq")
        for flag in (
            "tampered", "sanctions_hit", "pep_hit",
            "face_match_ok", "liveness_ok", "address_ok",
        ):
            if not isinstance(getattr(self, flag), bool):
                raise InvalidDocumentError(f"{flag} must be a bool")

    def digest(self) -> str:
        """Digest pin over this document's canonical content."""
        return _pin(
            self.doc_id, self.doc_type, self.holder_name, self.issuer,
            self.expiry_seq, self.tampered, self.sanctions_hit, self.pep_hit,
            self.face_match_ok, self.liveness_ok, self.address_ok,
        )


@dataclass(frozen=True)
class CheckResult:
    """Outcome of one named check."""

    name: str
    passed: bool
    hard_fail: bool
    detail: str

    def __post_init__(self) -> None:
        if self.name not in CHECKS:
            raise KYCError(f"unknown check name {self.name!r}")
        if not isinstance(self.passed, bool):
            raise KYCError("passed must be a bool")
        if not isinstance(self.hard_fail, bool):
            raise KYCError("hard_fail must be a bool")


@dataclass(frozen=True)
class Case:
    """A frozen KYC case."""

    case_id: str
    holder_name: str
    assurance_level: str
    documents: Tuple[Document, ...]
    state: str
    submitted_seq: int
    decision_seq: Optional[int]
    case_pin: str

    def __post_init__(self) -> None:
        if self.state not in CASE_STATES:
            raise KYCError(f"unknown case state {self.state!r}")


@dataclass(frozen=True)
class VerificationReport:
    """Frozen decision report for one verify() call."""

    case_id: str
    decision: str
    checks: Tuple[CheckResult, ...]
    risk_score: int
    decision_seq: int
    decision_pin: str

    def __post_init__(self) -> None:
        if self.decision not in CASE_STATES - {"submitted"}:
            raise KYCError(f"unknown decision {self.decision!r}")
        if not (0 <= self.risk_score <= 100):
            raise KYCError("risk_score must be in [0, 100]")


@dataclass(frozen=True)
class CaseStatus:
    """Read-only status view of a case."""

    case_id: str
    holder_name: str
    state: str
    document_count: int
    last_decision_seq: Optional[int]
    decision_pin: Optional[str]
    submitted_seq: int


class KYCVerifier:
    """Deterministic KYC case ledger with a simulated verification provider."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._cases: Dict[str, Case] = {}
        self._reports: Dict[str, List[VerificationReport]] = {}
        self._audit: List[Dict[str, object]] = []
        self._last_seq = -1

    # -- seq discipline ----------------------------------------------------

    def _next_seq_guard(self, seq: int) -> int:
        _reject_bool(seq, "seq")
        if seq <= self._last_seq:
            raise BadSeqError(
                f"seq {seq} must be strictly greater than last seq "
                f"{self._last_seq}"
            )
        self._last_seq = seq
        return seq

    def _log(self, event: Dict[str, object]) -> None:
        self._audit.append(event)

    # -- case management ----------------------------------------------------

    def _requirement_errors(
        self, documents: Tuple[Document, ...], assurance_level: str
    ) -> List[str]:
        types = {doc.doc_type for doc in documents}
        errors: List[str] = []
        if not (types & GOVERNMENT_ID_TYPES):
            errors.append(
                "at least one government ID required "
                f"(one of {sorted(GOVERNMENT_ID_TYPES)})"
            )
        if not (types & ADDRESS_PROOF_TYPES):
            errors.append(
                "at least one proof of address required "
                f"(one of {sorted(ADDRESS_PROOF_TYPES)})"
            )
        if assurance_level == "enhanced" and "selfie" not in types:
            errors.append("enhanced assurance requires a selfie document")
        return errors

    def submit(
        self,
        *,
        case_id: str,
        holder_name: str,
        documents: Tuple[Document, ...],
        assurance_level: str = "standard",
        seq: int,
    ) -> Case:
        """Open a case. Fail-closed on missing document classes."""
        if not case_id or not isinstance(case_id, str):
            raise KYCError("case_id must be a non-empty string")
        if not holder_name or not isinstance(holder_name, str):
            raise KYCError("holder_name must be a non-empty string")
        if assurance_level not in ASSURANCE_LEVELS:
            raise KYCError(
                f"unknown assurance_level {assurance_level!r}; "
                f"expected one of {sorted(ASSURANCE_LEVELS)}"
            )
        docs = tuple(documents)
        if not docs:
            raise MissingRequirementError("at least one document is required")
        for doc in docs:
            if not isinstance(doc, Document):
                raise InvalidDocumentError(
                    f"expected Document, got {type(doc).__name__}"
                )
        errors = self._requirement_errors(docs, assurance_level)
        if errors:
            raise MissingRequirementError("; ".join(errors))
        with self._lock:
            self._next_seq_guard(seq)
            if case_id in self._cases:
                raise KYCError(f"case_id {case_id!r} already submitted")
            case_pin = _pin(case_id, holder_name, assurance_level,
                            tuple(d.digest() for d in docs))
            case = Case(
                case_id=case_id,
                holder_name=holder_name,
                assurance_level=assurance_level,
                documents=docs,
                state="submitted",
                submitted_seq=seq,
                decision_seq=None,
                case_pin=case_pin,
            )
            self._cases[case_id] = case
            self._reports[case_id] = []
            self._log(_audit_event(
                seq=seq, event="kyc.submitted", case_id=case_id,
                detail={"holder_name": holder_name,
                        "assurance_level": assurance_level,
                        "document_count": len(docs),
                        "case_pin": case_pin},
            ))
            return case

    # -- verification -------------------------------------------------------

    def _run_checks(self, case: Case, seq: int) -> Tuple[CheckResult, ...]:
        """Deterministic simulated check run over the case's documents.

        Simulated provider rule: each check inspects the caller-asserted
        document flags. In production this is where a real provider's
        observations would enter; here the flags ARE the observations.
        """
        ids = [d for d in case.documents if d.doc_type in GOVERNMENT_ID_TYPES]
        address_docs = [
            d for d in case.documents if d.doc_type in ADDRESS_PROOF_TYPES
        ]
        any_tampered = any(d.tampered for d in case.documents)
        any_expired = any(d.expiry_seq <= seq for d in ids)
        any_sanctions = any(d.sanctions_hit for d in case.documents)
        any_pep = any(d.pep_hit for d in case.documents)
        any_face_miss = any(not d.face_match_ok for d in case.documents)
        any_liveness_miss = any(not d.liveness_ok for d in case.documents)
        any_address_miss = any(not d.address_ok for d in address_docs)

        def check(name: str, ok: bool, detail: str) -> CheckResult:
            return CheckResult(
                name=name, passed=ok, hard_fail=name in HARD_FAIL_CHECKS,
                detail=detail,
            )

        return (
            check("document_authenticity", not any_tampered,
                  "no document flagged tampered" if not any_tampered
                  else "at least one document flagged tampered"),
            check("document_expiry", not any_expired,
                  "all government IDs unexpired at decision seq"
                  if not any_expired
                  else "at least one government ID expired at decision seq"),
            check("face_match", not any_face_miss,
                  "face match asserted ok" if not any_face_miss
                  else "face match miss asserted on a document"),
            check("liveness", not any_liveness_miss,
                  "liveness asserted ok" if not any_liveness_miss
                  else "liveness miss asserted on a document"),
            check("address_verification", not any_address_miss,
                  "address proof asserted ok" if not any_address_miss
                  else "address mismatch asserted on an address document"),
            check("sanctions_screening", not any_sanctions,
                  "no sanctions-list hit asserted" if not any_sanctions
                  else "sanctions-list hit asserted"),
            check("pep_screening", not any_pep,
                  "no PEP hit asserted" if not any_pep
                  else "PEP hit asserted"),
        )

    @staticmethod
    def _decide(checks: Tuple[CheckResult, ...]) -> Tuple[str, int]:
        """Map check outcomes to (decision, risk_score). Fail-closed."""
        failed = [c for c in checks if not c.passed]
        if any(c.hard_fail for c in failed):
            decision = "rejected"
        elif failed:
            decision = "manual_review"
        else:
            decision = "approved"
        # risk_score: hard fails weigh 25 each, soft fails 10 each, capped.
        score = sum(25 if c.hard_fail else 10 for c in failed)
        return decision, min(100, score)

    def verify(self, *, case_id: str, seq: int) -> VerificationReport:
        """Run all checks on a case and pin the decision."""
        with self._lock:
            self._next_seq_guard(seq)
            case = self._cases.get(case_id)
            if case is None:
                raise UnknownCaseError(f"unknown case_id {case_id!r}")
            checks = self._run_checks(case, seq)
            decision, risk_score = self._decide(checks)
            decision_pin = _pin(
                case_id, case.case_pin, decision, risk_score,
                tuple((c.name, c.passed) for c in checks), seq,
            )
            report = VerificationReport(
                case_id=case_id,
                decision=decision,
                checks=checks,
                risk_score=risk_score,
                decision_seq=seq,
                decision_pin=decision_pin,
            )
            self._reports[case_id].append(report)
            self._cases[case_id] = Case(
                case_id=case.case_id,
                holder_name=case.holder_name,
                assurance_level=case.assurance_level,
                documents=case.documents,
                state=decision,
                submitted_seq=case.submitted_seq,
                decision_seq=seq,
                case_pin=case.case_pin,
            )
            self._log(_audit_event(
                seq=seq, event="kyc.verified", case_id=case_id,
                detail={"decision": decision, "risk_score": risk_score,
                        "failed_checks": [c.name for c in checks
                                          if not c.passed],
                        "decision_pin": decision_pin},
            ))
            return report

    # -- status -------------------------------------------------------------

    def status(self, case_id: str) -> CaseStatus:
        """Return a read-only status view of a case (fail-closed)."""
        with self._lock:
            case = self._cases.get(case_id)
            if case is None:
                raise UnknownCaseError(f"unknown case_id {case_id!r}")
            reports = self._reports[case_id]
            last = reports[-1] if reports else None
            return CaseStatus(
                case_id=case.case_id,
                holder_name=case.holder_name,
                state=case.state,
                document_count=len(case.documents),
                last_decision_seq=last.decision_seq if last else None,
                decision_pin=last.decision_pin if last else None,
                submitted_seq=case.submitted_seq,
            )

    def audit_log(self) -> Tuple[Dict[str, object], ...]:
        """Return the in-memory audit events (audit.ndjson/1 shaped)."""
        with self._lock:
            return tuple(dict(e) for e in self._audit)


def main() -> None:
    """Self-check: submit a clean case, verify it, print the decision."""
    verifier = KYCVerifier()
    case = verifier.submit(
        case_id="case-demo-001",
        holder_name="Ada Applicant",
        assurance_level="enhanced",
        documents=(
            Document(doc_id="P-001", doc_type="passport",
                     holder_name="Ada Applicant", issuer="Exampleland",
                     expiry_seq=10_000),
            Document(doc_id="U-001", doc_type="utility_bill",
                     holder_name="Ada Applicant", issuer="Example Power",
                     expiry_seq=10_000),
            Document(doc_id="S-001", doc_type="selfie",
                     holder_name="Ada Applicant", issuer="capture-device",
                     expiry_seq=10_000),
        ),
        seq=1,
    )
    report = verifier.verify(case_id=case.case_id, seq=2)
    print(f"case={case.case_id} decision={report.decision} "
          f"risk={report.risk_score} pin={report.decision_pin}")
    assert report.decision == "approved"
    assert report.decision_pin.startswith("sha256:")
    print("kyc_verifier self-check OK")


if __name__ == "__main__":
    main()
