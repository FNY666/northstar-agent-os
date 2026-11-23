"""AI alignment assessment decision ledger, Simulated.

Research note: "AI alignment" names the whole problem - whether a
system's behavior tracks the informed preferences of its principals -
but what this module books is far narrower: *declared assessments*.
A host declares an alignment assessment over a pinned assessment-kind
vocabulary (comprehensive review, red-team review, deception screen,
...), declares a posture per assessment over a pinned posture
vocabulary, and the ledger derives per-system evaluation posture by a
documented ledger rule. This is defensible bookkeeping, never proof
that any system is aligned.

This module owns the assess -> verify -> evaluate lifecycle:

* **assess()** - book one declared alignment assessment (minted
  ``asm-N`` ids; pinned 8-term assessment-kind vocabulary; pinned
  5-term posture vocabulary booked **as data**, never proof); the
  first assessment registers its system; raw evaluation notes,
  transcripts, and model internals never enter records - digest pins
  only.
* **verify()** - pure read: re-derive one assessment's digest pin;
  verdict ``verified`` / ``tampered`` as data (tamper reported,
  never raised).
* **evaluate()** - pure read: per-system assessment tallies and the
  ledger-rule posture (``unassessed`` -> ``misaligned`` ->
  ``uncertain`` -> ``aligned``), plus digest-pinned integrity, all
  as data.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``inner_alignment.py`` owns
inner-objective inspection (is the inner objective what the outer
objective intended?), ``outer_alignment.py`` owns the declared
base-objective specification (did we specify the right goal?),
``automated_alignment.py`` owns automated-alignment tasks, and
``alignment_eval.py`` owns the evaluation-governance protocol. This
module is the generic *alignment assessment* decision ledger none of
them own: declared assessments of systems, declared postures,
ledger-rule evaluation reports - all booked as data.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-alignment.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with
the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module assesses no systems, runs no probes,
measures no behavior, and proves nothing about real alignment. A
booked ``aligned`` posture means "the host declared it", never "the
system is aligned". Evaluation notes, transcripts, weights,
activations, preferences, reward definitions, and policies never enter
records or cross the audit boundary - digest pins only.
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
AI_ALIGNMENT_VERSION = "ai-alignment.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-alignment.v1"

#: Pinned assessment-kind vocabulary (the alignment assessment kinds tracked).
ASSESS_KINDS = (
    "comprehensive-review",
    "red-team-review",
    "interpretability-check",
    "behavioral-probe",
    "preference-consistency",
    "corrigibility-check",
    "deception-screen",
    "outcome-audit",
)

#: Pinned assessment-posture vocabulary (booked as data, never proof).
ASSESS_POSTURES = (
    "aligned",
    "misaligned",
    "uncertain",
    "inconclusive",
    "unassessed",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-start",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "assessed",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "weights",
        "model_weights",
        "parameters",
        "params",
        "policy",
        "policies",
        "activations",
        "internals",
        "trajectory",
        "trajectories",
        "action",
        "actions",
        "state",
        "states",
        "observation",
        "observations",
        "transcript",
        "transcripts",
        "gradient",
        "gradients",
        "reward",
        "rewards",
        "utility",
        "score",
        "scores",
        "loss",
        "feedback",
        "preference",
        "preferences",
        "belief",
        "theta",
        "signal",
        "signals",
        "prompt",
        "response",
        "content",
        "text",
        "note",
        "notes",
        "detail",
        "details",
        "description",
        "evidence",
        "result",
        "results",
        "raw",
        "secret",
        "key",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AIAlignmentError(Exception):
    """Base error for ai-alignment ledger misuse."""


class BadIdError(AIAlignmentError):
    """Malformed system or assessment id."""


class UnknownSystemError(AIAlignmentError):
    """System not registered."""


class RetiredSystemError(AIAlignmentError):
    """System id already retired; never recycled."""


class BadAssessmentKindError(AIAlignmentError):
    """Unknown alignment assessment kind."""


class BadDigestError(AIAlignmentError):
    """Malformed sha256: digest pin."""


class BadPostureError(AIAlignmentError):
    """Unknown assessment posture."""


class UnknownAssessmentError(AIAlignmentError):
    """Assessment id not booked."""


class BadReasonError(AIAlignmentError):
    """Unknown retirement reason."""


class SeqOrderError(AIAlignmentError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(AIAlignmentError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_id(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: Any, field_name: str) -> str:
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


# ---------------------------------------------------------------------------
# Records (all frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AssessmentRecord:
    assessment_id: str
    system_id: str
    assessment_kind: str
    posture: str
    evidence_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "assessment_id": self.assessment_id,
            "system_id": self.system_id,
            "assessment_kind": self.assessment_kind,
            "posture": self.posture,
            "evidence_digest": self.evidence_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "assessment_id": self.assessment_id,
                "system_id": self.system_id,
                "assessment_kind": self.assessment_kind,
                "posture": self.posture,
                "evidence_digest": self.evidence_digest,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "reason": self.reason,
            }
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    n_assessments: int
    n_aligned: int
    n_misaligned: int
    n_uncertain: int
    n_inconclusive: int
    n_unassessed: int
    posture: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "n_assessments": self.n_assessments,
            "n_aligned": self.n_aligned,
            "n_misaligned": self.n_misaligned,
            "n_uncertain": self.n_uncertain,
            "n_inconclusive": self.n_inconclusive,
            "n_unassessed": self.n_unassessed,
            "posture": self.posture,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "n_assessments": self.n_assessments,
                "n_aligned": self.n_aligned,
                "n_misaligned": self.n_misaligned,
                "n_uncertain": self.n_uncertain,
                "n_inconclusive": self.n_inconclusive,
                "n_unassessed": self.n_unassessed,
                "posture": self.posture,
                "integrity_ok": self.integrity_ok,
            }
        )


@dataclass(frozen=True)
class VerificationReport:
    assessment_id: str
    verdict: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "assessment_id": self.assessment_id,
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "assessment_id": self.assessment_id,
                "verdict": self.verdict,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def ai_alignment_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the ai-alignment ledger."""
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
# Ledger
# ---------------------------------------------------------------------------


class AIAlignment:
    """AI alignment assessment decision ledger, Simulated.

    ``assess()`` / ``retire()`` mutate the ledger and consume caller
    seqs; ``evaluate()`` / ``verify()`` and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._systems: Dict[str, List[str]] = {}
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._assessments_by_system: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._asm_counter = 0
        self._seq = 0
        self._audit: List[Dict[str, Any]] = []
        self._rejected = 0

    # -- internal helpers -------------------------------------------------

    def _check_seq(self, seq: Any) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int, not bool")
        return seq

    def _claim_seq(self, seq: int) -> None:
        """Claim a strictly increasing seq; rewinds raise bare."""
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must be strictly increasing, got {seq} after {self._seq}"
            )
        self._seq = seq

    def _burn(self, seq: int, method: str, exc: AIAlignmentError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(
            ai_alignment_audit_event(
                "rejected",
                seq,
                method=method,
                error=type(exc).__name__,
                error_detail=str(exc),
            )
        )

    def _require_known_system(self, system_id: str) -> None:
        if system_id not in self._systems:
            raise UnknownSystemError(f"unknown system: {system_id!r}")

    # -- mutations --------------------------------------------------------

    def assess(
        self,
        system_id: Any,
        seq: Any,
        assessment_kind: Any = "comprehensive-review",
        posture: Any = "unassessed",
        evidence_digest: Any = "",
    ) -> AssessmentRecord:
        """Book one declared alignment assessment (minted ``asm-N``).

        The first assessment registers its system. Evaluation notes,
        transcripts, weights, activations, and policies travel as a
        digest pin only. Postures are booked **as data**, never proof
        that the system is (or is not) aligned.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _require_id(system_id, "system_id")
                if sid in self._retired:
                    raise RetiredSystemError(f"system id never recycled: {sid!r}")
                if not isinstance(assessment_kind, str) or assessment_kind not in ASSESS_KINDS:
                    raise BadAssessmentKindError(
                        f"assessment_kind must be one of {sorted(ASSESS_KINDS)}"
                    )
                if not isinstance(posture, str) or posture not in ASSESS_POSTURES:
                    raise BadPostureError(
                        f"posture must be one of {sorted(ASSESS_POSTURES)}"
                    )
                pin = _require_digest(evidence_digest, "evidence_digest")
                self._asm_counter += 1
                aid = f"asm-{self._asm_counter}"
                rec = AssessmentRecord(
                    assessment_id=aid,
                    system_id=sid,
                    assessment_kind=assessment_kind,
                    posture=posture,
                    evidence_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "assessment_id": aid,
                            "system_id": sid,
                            "assessment_kind": assessment_kind,
                            "posture": posture,
                            "evidence_digest": pin,
                        }
                    ),
                )
                self._assessments[aid] = rec
                self._systems.setdefault(sid, []).append(aid)
                self._assessments_by_system.setdefault(sid, []).append(aid)
                self._audit.append(
                    ai_alignment_audit_event(
                        "assessed",
                        seq_v,
                        assessment_id=aid,
                        system_id=sid,
                        assessment_kind=assessment_kind,
                        posture=posture,
                    )
                )
                return rec
            except AIAlignmentError as exc:
                self._burn(seq_v, "assess", exc)
                raise

    def retire(
        self,
        system_id: Any,
        seq: Any,
        reason: Any = "manual",
    ) -> RetireRecord:
        """Terminally retire a system id; ids are never recycled."""
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _require_id(system_id, "system_id")
                if sid in self._retired:
                    raise RetiredSystemError(f"system already retired: {sid!r}")
                self._require_known_system(sid)
                if not isinstance(reason, str) or reason not in RETIRE_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {sorted(RETIRE_REASONS)}"
                    )
                rec = RetireRecord(
                    system_id=sid,
                    reason=reason,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "system_id": sid,
                            "reason": reason,
                        }
                    ),
                )
                self._retired[sid] = rec
                self._audit.append(
                    ai_alignment_audit_event(
                        "retired",
                        seq_v,
                        system_id=sid,
                        reason=reason,
                    )
                )
                return rec
            except AIAlignmentError as exc:
                self._burn(seq_v, "retire", exc)
                raise

    # -- pure reads --------------------------------------------------------

    def evaluate(self, system_id: Any, seq: Any) -> EvaluationReport:
        """Per-system assessment tallies and ledger-rule posture (pure read).

        Posture as data: ``unassessed`` (no assessments, or any booked
        assessment still declaring ``unassessed``) -> ``misaligned``
        (any misaligned) -> ``uncertain`` (any uncertain or
        inconclusive) -> ``aligned`` (all aligned). ``integrity_ok``
        re-derives every in-scope digest pin as data.
        """
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            asm_ids = self._assessments_by_system.get(sid, ())
            n_aligned = n_misaligned = n_uncertain = n_inconclusive = n_unassessed = 0
            for aid in asm_ids:
                posture = self._assessments[aid].posture
                if posture == "aligned":
                    n_aligned += 1
                elif posture == "misaligned":
                    n_misaligned += 1
                elif posture == "uncertain":
                    n_uncertain += 1
                elif posture == "inconclusive":
                    n_inconclusive += 1
                else:
                    n_unassessed += 1
            if not asm_ids:
                posture = "unassessed"
            elif n_misaligned > 0:
                posture = "misaligned"
            elif n_uncertain > 0 or n_inconclusive > 0:
                posture = "uncertain"
            elif n_unassessed > 0:
                posture = "unassessed"
            else:
                posture = "aligned"
            integrity_ok = all(
                self._assessments[aid].verify() for aid in asm_ids
            )
            return EvaluationReport(
                system_id=sid,
                n_assessments=len(asm_ids),
                n_aligned=n_aligned,
                n_misaligned=n_misaligned,
                n_uncertain=n_uncertain,
                n_inconclusive=n_inconclusive,
                n_unassessed=n_unassessed,
                posture=posture,
                integrity_ok=integrity_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "system_id": sid,
                        "n_assessments": len(asm_ids),
                        "n_aligned": n_aligned,
                        "n_misaligned": n_misaligned,
                        "n_uncertain": n_uncertain,
                        "n_inconclusive": n_inconclusive,
                        "n_unassessed": n_unassessed,
                        "posture": posture,
                        "integrity_ok": integrity_ok,
                    }
                ),
            )

    def verify(self, assessment_id: Any, seq: Any) -> VerificationReport:
        """Re-derive one assessment's digest pin (pure read).

        Verdict ``verified`` / ``tampered`` is data: tamper is
        reported, never raised.
        """
        with self._lock:
            self._check_seq(seq)
            aid = _require_id(assessment_id, "assessment_id")
            rec = self._assessments.get(aid)
            if rec is None:
                raise UnknownAssessmentError(f"unknown assessment: {aid!r}")
            ok = rec.verify()
            return VerificationReport(
                assessment_id=aid,
                verdict="verified" if ok else "tampered",
                integrity_ok=ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "assessment_id": aid,
                        "verdict": "verified" if ok else "tampered",
                        "integrity_ok": ok,
                    }
                ),
            )

    # -- pure-read views ---------------------------------------------------

    def assessment_record(self, assessment_id: Any, seq: Any) -> AssessmentRecord:
        """Return one assessment record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            aid = _require_id(assessment_id, "assessment_id")
            if aid not in self._assessments:
                raise UnknownAssessmentError(f"unknown assessment: {aid!r}")
            return self._assessments[aid]

    def system_ids(self, seq: Any) -> Tuple[str, ...]:
        """All registered system ids in registration order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._systems.keys())

    def assessment_ids(self, seq: Any) -> Tuple[str, ...]:
        """All assessment ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"asm-{i}" for i in range(1, self._asm_counter + 1))

    def assessments_for(self, system_id: Any, seq: Any) -> Tuple[str, ...]:
        """Assessment ids booked against one system (mint order)."""
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            return tuple(self._assessments_by_system.get(sid, ()))

    def retired_ids(self, seq: Any) -> Tuple[str, ...]:
        """All retired system ids."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._retired.keys())

    def audit_log(self, seq: Any) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._audit)

    def stats(self, seq: Any) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "systems": len(self._systems),
                "assessments": len(self._assessments),
                "retired": len(self._retired),
                "rejected": self._rejected,
            }

    @staticmethod
    def stdlib_only() -> bool:
        """AST self-check: only stdlib imports (+ the in-repo sibling)."""
        import ast as _ast
        import pathlib as _pathlib

        allowed = {
            "__future__",
            "threading",
            "dataclasses",
            "hashlib",
            "json",
            "typing",
            "canonical_json",
            "ast",
            "pathlib",
        }
        tree = _ast.parse(_pathlib.Path(__file__).read_text())
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                for a in node.names:
                    if a.name.split(".")[0] not in allowed:
                        return False
            elif isinstance(node, _ast.ImportFrom) and node.module:
                if node.module.split(".")[0] not in allowed:
                    return False
        return True


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    al = AIAlignment()
    pin = "sha256:" + "ab" * 32
    rec = al.assess(
        "sys-1",
        1,
        assessment_kind="comprehensive-review",
        posture="aligned",
        evidence_digest=pin,
    )
    assert rec.assessment_id == "asm-1"
    assert rec.verify()
    rep = al.evaluate("sys-1", 2)
    assert rep.verify()
    assert rep.posture == "aligned"
    assert rep.integrity_ok is True
    vrf = al.verify("asm-1", 3)
    assert vrf.verify()
    assert vrf.verdict == "verified"
    rtr = al.retire("sys-1", 4, reason="decommissioned")
    assert rtr.verify()
    assert al.stats(5) == {
        "systems": 1,
        "assessments": 1,
        "retired": 1,
        "rejected": 0,
    }
    print("ai-alignment OK: assess, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
