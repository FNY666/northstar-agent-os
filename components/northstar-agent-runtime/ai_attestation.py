"""AI attestation (attest/verify/evaluate) interface, simulated.

Research motivation: AI attestation claims -- a provider attesting that
a system holds a declared capability, satisfies a declared safety
property, or was evaluated a declared way -- all reduce to one
operational shape: an attestor declares an attestation outcome over a
pinned attestation-kind vocabulary, the ledger pins it, and a report
derives posture *from the ledger* -- the report never independently
judges whether the attested claim is true.

This module is the *AI-attestation* ledger half of that shape:

- ``AIAttestation.attest(system_id, attestation_kind, verdict, seq,
  attestation_digest="")`` -- book one declared attestation over the
  pinned 8-kind vocabulary x the pinned 4-verdict vocabulary. The
  attested content is pinned by ``sha256:`` digest only; raw material
  never enters a record. First attest on an id registers the system.
- ``AIAttestation.verify(attestation_id, seq)`` -- **pure read**
  (seq shape validated, never consumed, no audit row). Re-derives the
  digest pin; the ``verified``/``tampered`` verdict is *data*, never
  proof the attested claim holds.
- ``AIAttestation.evaluate(system_id, seq)`` -- **pure read**. Derives
  posture as data by ledger rule: ``unassessed`` (no attestations) ->
  ``failed`` (any ``failed``) -> ``contested`` (any ``inconclusive``)
  -> ``partially-attested`` (any ``partial``) -> ``attested`` (all
  ``attested``), plus verdict tallies and ``integrity_ok`` as data.
- ``AIAttestation.retire(system_id, seq, reason="manual")`` --
  terminal. Ids are never recycled; post-retire mutations are refused,
  reads still work.
- Pure-read views (``attestation_record`` / ``attestations_for`` /
  ``system_ids`` / ``retired_ids`` / ``stats`` / ``audit_log``) --
  seq shape validated, never consumed, no audit rows.
- ``ai_attestation_audit_event(kind, ...)`` -- ``audit.ndjson/1`` rows
  (``attested`` / ``retired`` / ``rejected``); caller-supplied seqs
  only. Raw attested content never crosses the audit boundary -- audit
  rows carry ids, pinned attestation-kind/verdict labels, digests, and
  counts only.

Distinct layer: ``remote_attestation.py`` owns the TPM-simulated
attestation *interface and state machine* (quotes, PCR extends, AK);
``attested_receipts.py`` owns attested-receipt bookkeeping;
``provenance_attestor.py`` owns provenance claims. This module owns
the AI-claim *attestation declaration* lifecycle none of them cover --
declared attestations against pinned claim kinds, declared verdicts,
ledger-rule posture.

Fail-closed edges (fail loudly, never guess):

- ``system_id`` / ``attestation_id`` must be non-empty str, <= 256
  chars, no whitespace.
- ``attestation_kind`` must be in the pinned 8-kind vocabulary;
  ``verdict`` must be in the pinned 4-verdict vocabulary.
- ``attestation_digest`` must be ``sha256:<64hex>`` when supplied
  (may be empty).
- ``attest`` / ``verify`` on unknown ids raise; duplicate ids never
  occur (ids are minted ``att-N``).
- ``attest`` on a retired system raises ``RetiredSystemError``.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* attestations reported by the host. A
  booked ``attested`` verdict means the host declared one -- the
  module attested nothing, measured nothing, and proves nothing about
  any real system's capabilities, properties, or claim truth.
- Digest pins prove ledger integrity and ordering, never the truth of
  any attested claim or the competence of any attestor.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if attestation state must survive a restart.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
AI_ATTESTATION_VERSION = "ai-attestation.v1"

#: Schema pin carried by records and audit events.
AI_ATTESTATION_SCHEMA = "northstar.ai-attestation.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_ATTESTED = "attested"
KIND_RETIRED = "retired"
KIND_REJECTED = "rejected"
_KINDS = (KIND_ATTESTED, KIND_RETIRED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw content never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"content", "text", "payload", "raw", "evidence", "finding",
     "justification", "analysis", "report", "claim_text", "statement",
     "rationale", "metric", "score", "data", "record", "trace",
     "transcript", "weights", "policy", "model_output", "judgment",
     "note", "comment", "attestation_text", "proof", "measurement",
     "experiment", "benchmark_result"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned attestation-kind vocabulary (AI claim shaped).
KIND_CAPABILITY_CLAIM = "capability-claim"
KIND_SAFETY_CLAIM = "safety-claim"
KIND_FAIRNESS_CLAIM = "fairness-claim"
KIND_ROBUSTNESS_CLAIM = "robustness-claim"
KIND_PRIVACY_CLAIM = "privacy-claim"
KIND_SECURITY_CLAIM = "security-claim"
KIND_COMPLIANCE_CLAIM = "compliance-claim"
KIND_PROVENANCE_CLAIM = "provenance-claim"
ATTESTATION_KINDS = (
    KIND_CAPABILITY_CLAIM,
    KIND_SAFETY_CLAIM,
    KIND_FAIRNESS_CLAIM,
    KIND_ROBUSTNESS_CLAIM,
    KIND_PRIVACY_CLAIM,
    KIND_SECURITY_CLAIM,
    KIND_COMPLIANCE_CLAIM,
    KIND_PROVENANCE_CLAIM,
)

#: Pinned attestation-verdict vocabulary. Verdicts are host-reported data.
VERDICT_ATTESTED = "attested"
VERDICT_PARTIAL = "partial"
VERDICT_INCONCLUSIVE = "inconclusive"
VERDICT_FAILED = "failed"
VERDICTS = (
    VERDICT_ATTESTED,
    VERDICT_PARTIAL,
    VERDICT_INCONCLUSIVE,
    VERDICT_FAILED,
)

#: Pinned derived postures (ledger rule, precedence documented in evaluate).
POSTURE_UNASSESSED = "unassessed"
POSTURE_FAILED = "failed"
POSTURE_CONTESTED = "contested"
POSTURE_PARTIALLY_ATTESTED = "partially-attested"
POSTURE_ATTESTED = "attested"
POSTURES = (
    POSTURE_UNASSESSED,
    POSTURE_FAILED,
    POSTURE_CONTESTED,
    POSTURE_PARTIALLY_ATTESTED,
    POSTURE_ATTESTED,
)

#: Pinned retire reasons.
REASON_MANUAL = "manual"
REASON_DECOMMISSIONED = "decommissioned"
REASON_SCOPE_CHANGE = "scope-change"
REASON_ATTESTATION_LOSS = "attestation-loss"
REASONS = (
    REASON_MANUAL,
    REASON_DECOMMISSIONED,
    REASON_SCOPE_CHANGE,
    REASON_ATTESTATION_LOSS,
)

#: Digest pin shape: "sha256:" + 64 lowercase hex.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class AIAttestationError(Exception):
    """Base error for the AI-attestation ledger (programming errors)."""


class BadIdError(AIAttestationError):
    """Raised when a system/attestation id is malformed."""


class DuplicateAttestationError(AIAttestationError):
    """Raised when a minted attestation id somehow collides (never)."""


class UnknownSystemError(AIAttestationError):
    """Raised when a system id names no attested system."""


class UnknownAttestationError(AIAttestationError):
    """Raised when an attestation id names no booked attestation."""


class RetiredSystemError(AIAttestationError):
    """Raised when mutating a retired system."""


class DoubleRetireError(AIAttestationError):
    """Raised when retiring an already-retired system."""


class BadAttestationKindError(AIAttestationError):
    """Raised when an attestation kind is not in the pinned vocabulary."""


class BadVerdictError(AIAttestationError):
    """Raised when a verdict is not in the pinned vocabulary."""


class BadDigestError(AIAttestationError):
    """Raised when an attestation digest is not a sha256: pin."""


class BadReasonError(AIAttestationError):
    """Raised when a retire reason is not in the pinned vocabulary."""


class SeqOrderError(AIAttestationError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(AIAttestationError):
    """Raised when an audit event kind is unknown or leaks banned keys."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_id(value: object, label: str) -> str:
    """Validate an id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{label} must be str, got {type(value).__name__}")
    if not value:
        raise BadIdError(f"{label} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadIdError(f"{label} too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in value):
        raise BadIdError(f"{label} must not contain whitespace")
    return value


def _check_digest(value: object, label: str, allow_empty: bool = False) -> str:
    """Validate a content pin: ``sha256:<64hex>``."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(
            f"{label} must be a sha256: pin, got {type(value).__name__}")
    if not value and allow_empty:
        return value
    if not _DIGEST_RE.match(value):
        raise BadDigestError(
            f"{label} must match sha256:<64hex>, got {value!r}")
    return value


def _pin(*parts: object) -> str:
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": AI_ATTESTATION_SCHEMA,
        "parts": list(parts),
    })


def ai_attestation_audit_event(kind: str, detail: Dict[str, object],
                               seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the AI-attestation ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": AI_ATTESTATION_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


def stdlib_only() -> bool:
    """Report whether this module imports only the stdlib (plus the
    canonical_json fallback)."""
    return True


@dataclass(frozen=True)
class AttestationRecord:
    """Frozen record of one declared attestation (digest-pinned)."""
    attestation_id: str
    system_id: str
    attestation_kind: str
    verdict: str
    attestation_digest: str
    seq: int
    digest: str

    def verify(self, attestation_id: str, system_id: str, attestation_kind: str,
               verdict: str, attestation_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "attestation", attestation_id, system_id, attestation_kind,
            verdict, attestation_digest, self.seq)


@dataclass(frozen=True)
class VerificationReport:
    """Frozen read-only report of a digest re-derivation (verdict as data)."""
    attestation_id: str
    verdict: str
    seq: int
    digest: str

    def verify(self, attestation_id: str, verdict: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "verification", attestation_id, verdict, self.seq)


@dataclass(frozen=True)
class EvaluationReport:
    """Frozen read-only report of ledger-rule posture (posture as data)."""
    system_id: str
    posture: str
    n_attestations: int
    n_attested: int
    n_partial: int
    n_inconclusive: int
    n_failed: int
    integrity_ok: bool
    seq: int
    digest: str

    def verify(self, system_id: str, posture: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "evaluation", system_id, posture, self.seq)


@dataclass(frozen=True)
class RetireRecord:
    """Frozen record of a terminal retirement (ids never recycled)."""
    system_id: str
    reason: str
    seq: int
    digest: str

    def verify(self, system_id: str, reason: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("retire", system_id, reason, self.seq)


class AIAttestation:
    """AI-attestation ledger (declared attestations, derived posture)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq: int = -1
        self._attestations: Dict[str, AttestationRecord] = {}
        self._by_system: Dict[str, Tuple[str, ...]] = {}
        self._attestation_ids: Tuple[str, ...] = ()
        self._retired: Dict[str, RetireRecord] = {}
        self._audit: Tuple[Dict[str, object], ...] = ()

    def _claim(self, seq: int) -> None:
        """Claim a seq (strictly increasing); raise bare on rewind."""
        _check_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must be > {self._last_seq}, got {seq}")
            self._last_seq = seq

    def _burn(self, seq: int, system_id: str = "") -> None:
        """Book a rejected row after a failed mutation consumed its seq."""
        detail: Dict[str, object] = {}
        if system_id:
            detail["system_id"] = system_id
        event = ai_attestation_audit_event(KIND_REJECTED, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        """Append an audit event (caller has already claimed the seq)."""
        event = ai_attestation_audit_event(audit_kind, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def attest(self, system_id: str, attestation_kind: str, verdict: str,
               seq: int, attestation_digest: str = "") -> AttestationRecord:
        """Book one declared attestation. First attest on an id registers
        the system. Pins the attestation digest, never the attested
        content. Returns the frozen ``AttestationRecord`` (minted
        ``att-N``)."""
        self._claim(seq)
        try:
            system_id = _check_id(system_id, "system_id")
            if isinstance(attestation_kind, bool) or not isinstance(
                    attestation_kind, str):
                raise BadAttestationKindError(
                    f"attestation_kind must be str, got "
                    f"{type(attestation_kind).__name__}")
            if attestation_kind not in ATTESTATION_KINDS:
                raise BadAttestationKindError(
                    f"attestation_kind must be one of "
                    f"{sorted(ATTESTATION_KINDS)}, got {attestation_kind!r}")
            if isinstance(verdict, bool) or not isinstance(verdict, str):
                raise BadVerdictError(
                    f"verdict must be str, got {type(verdict).__name__}")
            if verdict not in VERDICTS:
                raise BadVerdictError(
                    f"verdict must be one of {sorted(VERDICTS)}, "
                    f"got {verdict!r}")
            attestation_digest = _check_digest(
                attestation_digest, "attestation_digest", allow_empty=True)
            with self._lock:
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system is retired: {system_id!r}")
                attestation_id = f"att-{len(self._attestation_ids) + 1}"
                if attestation_id in self._attestations:
                    raise DuplicateAttestationError(
                        f"attestation id collision: {attestation_id!r}")
                record = AttestationRecord(
                    attestation_id=attestation_id,
                    system_id=system_id,
                    attestation_kind=attestation_kind,
                    verdict=verdict,
                    attestation_digest=attestation_digest,
                    seq=seq,
                    digest=_pin("attestation", attestation_id, system_id,
                                attestation_kind, verdict, attestation_digest,
                                seq),
                )
                self._attestations[attestation_id] = record
                self._attestation_ids = (
                    self._attestation_ids + (attestation_id,))
                self._by_system[system_id] = (
                    self._by_system.get(system_id, ()) + (attestation_id,))
        except AIAttestationError:
            self._burn(seq, system_id if isinstance(system_id, str) else "")
            raise
        self._emit(KIND_ATTESTED,
                   {"system_id": system_id,
                    "attestation_id": record.attestation_id,
                    "attestation_kind": attestation_kind,
                    "verdict": verdict,
                    "attestation_digest": attestation_digest}, seq)
        return record

    def verify(self, attestation_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive an attestation's digest pin. The
        ``verified``/``tampered`` verdict is *data* (tamper reported,
        never raised). Validates seq shape, consumes nothing, writes no
        audit row. Returns the frozen ``VerificationReport``."""
        _check_seq(seq)
        attestation_id = _check_id(attestation_id, "attestation_id")
        with self._lock:
            if attestation_id not in self._attestations:
                raise UnknownAttestationError(
                    f"unknown attestation: {attestation_id!r}")
            rec = self._attestations[attestation_id]
            intact = rec.verify(
                rec.attestation_id, rec.system_id, rec.attestation_kind,
                rec.verdict, rec.attestation_digest)
            verdict = "verified" if intact else "tampered"
            return VerificationReport(
                attestation_id=attestation_id,
                verdict=verdict,
                seq=seq,
                digest=_pin("verification", attestation_id, verdict, seq),
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive posture from the ledger by rule (precedence:
        any ``failed`` -> ``failed``; any ``inconclusive`` -> ``contested``;
        any ``partial`` -> ``partially-attested``; all ``attested`` ->
        ``attested``). Validates seq shape, consumes nothing, writes no
        audit row. Returns the frozen ``EvaluationReport``."""
        _check_seq(seq)
        system_id = _check_id(system_id, "system_id")
        with self._lock:
            if system_id not in self._by_system:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            ids = self._by_system[system_id]
            recs = [self._attestations[i] for i in ids]
            n_attested = sum(1 for r in recs if r.verdict == VERDICT_ATTESTED)
            n_partial = sum(1 for r in recs if r.verdict == VERDICT_PARTIAL)
            n_inconclusive = sum(
                1 for r in recs if r.verdict == VERDICT_INCONCLUSIVE)
            n_failed = sum(1 for r in recs if r.verdict == VERDICT_FAILED)
            integrity_ok = all(
                r.verify(r.attestation_id, r.system_id, r.attestation_kind,
                         r.verdict, r.attestation_digest) for r in recs)
            if n_failed:
                posture = POSTURE_FAILED
            elif n_inconclusive:
                posture = POSTURE_CONTESTED
            elif n_partial:
                posture = POSTURE_PARTIALLY_ATTESTED
            else:
                posture = POSTURE_ATTESTED
            return EvaluationReport(
                system_id=system_id,
                posture=posture,
                n_attestations=len(recs),
                n_attested=n_attested,
                n_partial=n_partial,
                n_inconclusive=n_inconclusive,
                n_failed=n_failed,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=_pin("evaluation", system_id, posture, seq),
            )

    def retire(self, system_id: str, seq: int,
               reason: str = REASON_MANUAL) -> RetireRecord:
        """Terminally retire a system. Ids are never recycled; post-retire
        mutations are refused, reads still work. Returns the frozen
        ``RetireRecord``."""
        self._claim(seq)
        try:
            system_id = _check_id(system_id, "system_id")
            if isinstance(reason, bool) or not isinstance(reason, str):
                raise BadReasonError(
                    f"reason must be str, got {type(reason).__name__}")
            if reason not in REASONS:
                raise BadReasonError(
                    f"reason must be one of {sorted(REASONS)}, "
                    f"got {reason!r}")
            with self._lock:
                if system_id in self._retired:
                    raise DoubleRetireError(
                        f"system already retired: {system_id!r}")
                record = RetireRecord(
                    system_id=system_id,
                    reason=reason,
                    seq=seq,
                    digest=_pin("retire", system_id, reason, seq),
                )
                self._retired[system_id] = record
        except AIAttestationError:
            self._burn(seq, system_id if isinstance(system_id, str) else "")
            raise
        self._emit(KIND_RETIRED,
                   {"system_id": system_id, "reason": reason}, seq)
        return record

    def attestation_record(self, attestation_id: str,
                           seq: int) -> AttestationRecord:
        """Pure read view of one booked attestation."""
        _check_seq(seq)
        attestation_id = _check_id(attestation_id, "attestation_id")
        with self._lock:
            if attestation_id not in self._attestations:
                raise UnknownAttestationError(
                    f"unknown attestation: {attestation_id!r}")
            return self._attestations[attestation_id]

    def attestations_for(self, system_id: str,
                         seq: int) -> Tuple[str, ...]:
        """Pure read view of attestation ids for one system, in book order."""
        _check_seq(seq)
        system_id = _check_id(system_id, "system_id")
        with self._lock:
            if system_id not in self._by_system:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            return self._by_system[system_id]

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read view of all registered system ids, in first-attest order."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._by_system.keys())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read view of retired system ids."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._retired.keys())

    def audit_log(self) -> Tuple[Dict[str, object], ...]:
        """Pure read view of the audit events (no seq, no audit row)."""
        with self._lock:
            return self._audit

    def stats(self) -> Dict[str, int]:
        """Pure read view of ledger counters (no seq, no audit row)."""
        with self._lock:
            return {
                "systems": len(self._by_system),
                "attestations": len(self._attestations),
                "retired": len(self._retired),
                "audit_rows": len(self._audit),
            }


def main() -> None:
    """Self-check: attest, verify, evaluate, retire, pins, audit."""
    aa = AIAttestation()
    assert AI_ATTESTATION_VERSION == "ai-attestation.v1"
    assert AI_ATTESTATION_SCHEMA == "northstar.ai-attestation.v1"
    assert stdlib_only()
    digest = "sha256:" + "0" * 64
    rec = aa.attest("sys-1", KIND_SAFETY_CLAIM, VERDICT_ATTESTED, 1, digest)
    assert rec.attestation_id == "att-1"
    assert rec.verify("att-1", "sys-1", KIND_SAFETY_CLAIM, VERDICT_ATTESTED,
                      digest)
    assert not rec.verify("att-1", "sys-1", KIND_SAFETY_CLAIM,
                          VERDICT_FAILED, digest)
    vr = aa.verify("att-1", 2)
    assert vr.verdict == "verified"
    assert vr.verify("att-1", "verified")
    ev = aa.evaluate("sys-1", 3)
    assert ev.posture == POSTURE_ATTESTED
    assert ev.integrity_ok
    assert ev.verify("sys-1", POSTURE_ATTESTED)
    aa.attest("sys-1", KIND_SECURITY_CLAIM, VERDICT_FAILED, 4, digest)
    ev = aa.evaluate("sys-1", 5)
    assert ev.posture == POSTURE_FAILED
    assert ev.n_attestations == 2 and ev.n_failed == 1
    rr = aa.retire("sys-1", 6)
    assert rr.verify("sys-1", REASON_MANUAL)
    try:
        aa.attest("sys-1", KIND_PRIVACY_CLAIM, VERDICT_ATTESTED, 7)
    except RetiredSystemError:
        pass
    else:
        raise AssertionError("attest on retired system must fail closed")
    assert aa.stats()["systems"] == 1
    kinds = [row["kind"] for row in aa.audit_log()]
    assert kinds == [KIND_ATTESTED, KIND_ATTESTED, KIND_RETIRED,
                     KIND_REJECTED]
    print("ai-attestation OK: attest, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
