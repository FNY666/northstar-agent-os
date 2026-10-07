"""AI transparency: transparency disclosure decision ledger, Simulated.

Research note: AI transparency is the field concerned with making AI
systems legible to the people affected by them - model cards (Mitchell et
al. 2019), datasheets for datasets (Gebru et al. 2021), system cards
(Meta), EU AI Act transparency obligations (Arts. 13, 50), and similar
disclosure instruments. This module is the *decision ledger* for declared
transparency disclosures: which systems had which disclosure declarations
booked (over a pinned transparency-artifact vocabulary), what verdicts the
host declared for them, and what transparency posture the ledger derives -
defensible bookkeeping, never proof that a system is really transparent.

This module owns the disclose -> verify -> evaluate lifecycle:

* **disclose()** - book one declared transparency disclosure (minted
  ``dcl-N`` ids; pinned disclosure-kind vocabulary over the common
  transparency artifacts; pinned verdict vocabulary booked *as data*); the
  first disclosure registers its system; raw evidence, texts, and material
  never enter records - digest pins only.
* **verify()** - **pure read**: re-derive one disclosure record's digest
  pin; verdict ``verified`` / ``tampered`` booked as data, never as proof
  the disclosure really happened.
* **evaluate()** - **pure read**: derive one system's transparency posture
  as data (``unassessed`` -> ``opaque`` -> ``partial`` -> ``inconclusive``
  -> ``transparent``) with verdict tallies and a digest-pinned integrity
  flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_safety.py`` owns the safety
assessment/mitigation lifecycle; ``ai_ethics.py`` owns the per-system
ethics-assessment ledger; ``ai_governance.py`` owns governance-control
operations; ``ai_principles.py`` / ``ai_charter.py`` / ``ai_constitution.py``
own principle/charter declarations; ``ai_audit.py`` owns the
audit-engagement ledger; ``ai_standards.py`` owns standards-conformance
bookkeeping - this module is the *transparency-disclosure* decision ledger
none of them own: declared disclosures over the pinned transparency
artifact vocabulary -> digest re-derivation -> ledger-rule transparency
posture, all booked as data.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-transparency.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no models, inspects no systems, publishes
no disclosures, and proves nothing about real transparency. A booked
``disclosed`` verdict means "the host declared it", never "the system is
transparent". Model weights, datasets, prompts, transcripts, evidence
texts, and raw disclosure material never enter records or cross the audit
boundary - digest pins only.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Module version pin.
AI_TRANSPARENCY_VERSION = "ai-transparency.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-transparency.v1"

#: Pinned disclosure-kind vocabulary (the transparency artifacts declared).
DISCLOSURE_KINDS = (
    "model-card",
    "datasheet",
    "system-card",
    "training-disclosure",
    "data-provenance",
    "capability-disclosure",
    "limitation-disclosure",
    "incident-disclosure",
)

#: Pinned disclosure-verdict vocabulary (booked as data, never proof).
DISCLOSE_VERDICTS = (
    "disclosed",
    "partially-disclosed",
    "undisclosed",
    "inconclusive",
    "not-assessed",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unassessed",
    "opaque",
    "partial",
    "inconclusive",
    "transparent",
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
    "disclosed",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "weights",
        "model_weights",
        "parameters",
        "params",
        "policy",
        "policies",
        "trajectory",
        "trajectories",
        "transcript",
        "transcripts",
        "log",
        "logs",
        "trace",
        "traces",
        "telemetry",
        "recording",
        "recordings",
        "dump",
        "dumps",
        "snapshot",
        "snapshots",
        "memory",
        "weights_file",
        "checkpoint_data",
        "activations",
        "gradients",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "command_output",
        "stderr",
        "stdout",
        "heartbeat",
        "behavior",
        "demonstration",
        "preference",
        "feedback",
        "reward",
        "evidence",
        "evidence_text",
        "finding",
        "findings",
        "document",
        "documents",
        "report_text",
        "charter_text",
        "wording",
        "rationale",
        "analysis",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AITransparencyError(Exception):
    """Base class for all ai-transparency ledger errors."""


class BadSystemError(AITransparencyError):
    pass


class UnknownSystemError(AITransparencyError):
    pass


class RetiredSystemError(AITransparencyError):
    pass


class BadDisclosureKindError(AITransparencyError):
    pass


class BadVerdictError(AITransparencyError):
    pass


class BadDigestError(AITransparencyError):
    pass


class BadReasonError(AITransparencyError):
    pass


class UnknownDisclosureError(AITransparencyError):
    pass


class UnknownRecordError(AITransparencyError):
    pass


class SeqOrderError(AITransparencyError):
    pass


class AuditKindError(AITransparencyError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_disclosure_kind(value: Any) -> str:
    if value not in DISCLOSURE_KINDS:
        raise BadDisclosureKindError(f"disclosure_kind must be one of {DISCLOSURE_KINDS}")
    return value


def _check_verdict(value: Any) -> str:
    if value not in DISCLOSE_VERDICTS:
        raise BadVerdictError(f"verdict must be one of {DISCLOSE_VERDICTS}")
    return value


def _check_digest(value: Any, what: str, allow_empty: bool = True) -> str:
    if value == "" and allow_empty:
        return ""
    if (
        isinstance(value, bool)
        or not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != 71
    ):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    hexpart = value[7:]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    return value


def _check_reason(value: Any) -> str:
    if value not in RETIRE_REASONS:
        raise BadReasonError(f"reason must be one of {RETIRE_REASONS}")
    return value


def _canonical_bytes(payload: Any) -> bytes:
    raw = _jcs_dumps(payload)
    return raw if isinstance(raw, bytes) else raw.encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    body = {"tag": tag, "schema": SCHEMA_PIN, "payload": payload}
    return "sha256:" + hashlib.sha256(_canonical_bytes(body)).hexdigest()


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    return seq


# ---------------------------------------------------------------------------
# Records (frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DisclosureRecord:
    disclosure_id: str
    system_id: str
    seq: int
    disclosure_kind: str
    verdict: str
    disclosure_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _disclose_payload(self), "ai-transparency.disclose"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-transparency.retire"
        )


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _verify_payload(self), "ai-transparency.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_disclosures: int
    n_disclosed: int
    n_partial: int
    n_undisclosed: int
    n_inconclusive: int
    n_not_assessed: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-transparency.evaluate"
        )


# ---------------------------------------------------------------------------
# Payloads / audit event builder
# ---------------------------------------------------------------------------


def _disclose_payload(rec: "DisclosureRecord") -> Dict[str, Any]:
    return {
        "disclosure_id": rec.disclosure_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "disclosure_kind": rec.disclosure_kind,
        "verdict": rec.verdict,
        "disclosure_digest": rec.disclosure_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"system_id": rec.system_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "system_id": rep.system_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_disclosures": rep.n_disclosures,
        "n_disclosed": rep.n_disclosed,
        "n_partial": rep.n_partial,
        "n_undisclosed": rep.n_undisclosed,
        "n_inconclusive": rep.n_inconclusive,
        "n_not_assessed": rep.n_not_assessed,
        "integrity_ok": rep.integrity_ok,
    }


def ai_transparency_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for this module.

    Fail-closed: unknown kinds raise; any banned key appearing raw in
    ``detail`` raises (digest pins of those values are fine - the key ban
    applies to raw material).
    """
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise SeqOrderError("seq must be an int")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AITransparencyError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-transparency",
        "version": AI_TRANSPARENCY_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AITransparency:
    """AI-transparency disclosure decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All verdicts and postures are
    booked as data - never proof that a system is really transparent.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._disclosures: Dict[str, DisclosureRecord] = {}
        self._system_disclosures: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._disclosure_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _require_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        return seq

    def _claim(self, seq: int) -> int:
        self._require_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = ai_transparency_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-transparency",
                "version": AI_TRANSPARENCY_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_transparency_audit_event(audit_kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    def _integrity_ok(self, system_id: str) -> bool:
        return all(
            self._disclosures[did].verify()
            for did in self._system_disclosures.get(system_id, [])
        )

    def _posture(self, system_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "disclosed": 0,
            "partially-disclosed": 0,
            "undisclosed": 0,
            "inconclusive": 0,
            "not-assessed": 0,
        }
        for did in self._system_disclosures.get(system_id, []):
            tallies[self._disclosures[did].verdict] += 1
        if not self._system_disclosures.get(system_id):
            return "unassessed", tallies
        if tallies["undisclosed"] > 0:
            return "opaque", tallies
        if tallies["partially-disclosed"] > 0:
            return "partial", tallies
        if tallies["inconclusive"] > 0:
            return "inconclusive", tallies
        if tallies["not-assessed"] > 0:
            return "unassessed", tallies
        return "transparent", tallies

    # -- mutations ---------------------------------------------------------

    def disclose(
        self,
        system_id: str,
        seq: int,
        disclosure_kind: str = "model-card",
        verdict: str = "not-assessed",
        disclosure_digest: str = "",
    ) -> DisclosureRecord:
        """Book one declared transparency disclosure (minted ``dcl-N`` id).

        The first disclosure on an id registers the system. Raw evidence
        texts, transcripts, and material never enter records - digest pins
        only. Fail-closed: failed mutations consume their seq and book an
        ``ai-transparency.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                disclosure_kind = _check_disclosure_kind(disclosure_kind)
                verdict = _check_verdict(verdict)
                disclosure_digest = _check_digest(disclosure_digest, "disclosure_digest")
                self._require_live(system_id)
            except AITransparencyError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._disclosure_counter += 1
            disclosure_id = f"dcl-{self._disclosure_counter}"
            provisional = DisclosureRecord(
                disclosure_id=disclosure_id,
                system_id=system_id,
                seq=seq,
                disclosure_kind=disclosure_kind,
                verdict=verdict,
                disclosure_digest=disclosure_digest,
                digest="",
            )
            digest = _digest_pin(
                _disclose_payload(provisional), "ai-transparency.disclose"
            )
            rec = DisclosureRecord(
                disclosure_id=disclosure_id,
                system_id=system_id,
                seq=seq,
                disclosure_kind=disclosure_kind,
                verdict=verdict,
                disclosure_digest=disclosure_digest,
                digest=digest,
            )
            self._disclosures[disclosure_id] = rec
            self._system_disclosures.setdefault(system_id, []).append(disclosure_id)
            self._emit(
                "disclosed",
                seq,
                disclosure_id=disclosure_id,
                system_id=system_id,
                disclosure_kind=disclosure_kind,
                verdict=verdict,
                disclosure_digest=disclosure_digest,
            )
            return rec

    def retire(self, system_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminal retirement of a system id; ids are never recycled."""
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                self._require_live(system_id)
            except AITransparencyError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-transparency.retire")
            rec = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def verify(self, disclosure_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one disclosure record's digest pin.

        The verdict (``verified`` / ``tampered``) and ``integrity_ok`` are
        booked as data - tamper is reported, never raised.
        """
        with self._lock:
            self._require_read_seq(seq)
            rec = self._disclosures.get(disclosure_id)
            if rec is None:
                raise UnknownDisclosureError(f"unknown disclosure: {disclosure_id!r}")
            integrity_ok = rec.verify()
            verdict = "verified" if integrity_ok else "tampered"
            provisional = VerificationReport(
                record_id=disclosure_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "ai-transparency.verify")
            return VerificationReport(
                record_id=disclosure_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's transparency posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_disclosures:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            posture, tallies = self._posture(system_id)
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_disclosures=len(self._system_disclosures[system_id]),
                n_disclosed=tallies["disclosed"],
                n_partial=tallies["partially-disclosed"],
                n_undisclosed=tallies["undisclosed"],
                n_inconclusive=tallies["inconclusive"],
                n_not_assessed=tallies["not-assessed"],
                integrity_ok=self._integrity_ok(system_id),
                digest="",
            )
            digest = _digest_pin(
                _evaluate_payload(provisional), "ai-transparency.evaluate"
            )
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_disclosures=len(self._system_disclosures[system_id]),
                n_disclosed=tallies["disclosed"],
                n_partial=tallies["partially-disclosed"],
                n_undisclosed=tallies["undisclosed"],
                n_inconclusive=tallies["inconclusive"],
                n_not_assessed=tallies["not-assessed"],
                integrity_ok=self._integrity_ok(system_id),
                digest=digest,
            )

    # -- views (pure reads) --------------------------------------------------

    def disclosure_record(self, disclosure_id: str, seq: int) -> DisclosureRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._disclosures.get(disclosure_id)
            if rec is None:
                raise UnknownDisclosureError(f"unknown disclosure: {disclosure_id!r}")
            return rec

    def disclosures_for(self, system_id: str, seq: int) -> Tuple[DisclosureRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._disclosures[did]
                for did in self._system_disclosures.get(system_id, [])
            )

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._system_disclosures))

    def disclosure_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._disclosures))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "module": AI_TRANSPARENCY_VERSION,
                "schema": SCHEMA_PIN,
                "seq": self._seq,
                "systems": len(self._system_disclosures),
                "disclosures": len(self._disclosures),
                "retired": len(self._retired),
                "audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._audit)


def stdlib_only() -> bool:
    """AST self-check: the module imports stdlib names only."""
    import ast
    from pathlib import Path

    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    tree = ast.parse(Path(__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check: exercise disclose -> verify -> evaluate -> retire."""
    ledger = AITransparency()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.disclose(
        "sys-1", 1, disclosure_kind="model-card", verdict="disclosed"
    )
    assert rec.verify()
    rep = ledger.verify(rec.disclosure_id, 2)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("sys-1", 3)
    assert ev.posture == "transparent"
    assert ev.verify()
    ret = ledger.retire("sys-1", 4)
    assert ret.verify()
    print("ai-transparency OK: disclose, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
