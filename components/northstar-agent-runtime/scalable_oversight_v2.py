"""Scalable oversight v2: oversight-allocation governance ledger, Simulated.

Research note: following Amodei et al.'s "Concrete Problems in AI Safety",
*scalable oversight* is the problem of supervising systems that are too
capable, too fast, or too numerous for a human overseer to check directly.
The standard response is to **allocate** oversight: triage coverage across
cheaper methods (spot-checks, automated screens, amplified checks, debate
adjudication, constitutional review, committee review, direct human
review) and escalate the hard cases to the strongest available method.
The weak-to-strong generalization finding (Burns et al. 2023) disciplines
the whole scheme: "looks fine to the weak overseer" is never evidence of
safety - so every booked verdict is data, never proof.

This module is the bookkeeping layer for *declared* oversight allocations,
deliberately distinct from ``scalable_oversight.py`` (triage protocol
mechanics: risk tiers, auto-approve envelopes, escalation routing),
``human_oversight.py`` (human assignment/review lifecycle),
``process_supervision.py`` and ``outcome_supervision.py`` (supervision
bookkeeping), ``amplification.py`` (IDA decision records), ``debate.py``
(debate/judge game bookkeeping), and ``constitutional_ai.py`` (principle
declaration lifecycle): it runs no overseer, judges no real agent output,
and leaks no raw evidence. It books:

* **supervise()** - declare one oversight supervision against a system
  over the pinned 8-term oversight-method vocabulary x 6-term verdict
  vocabulary; the verdict is booked **as data**, never proof the agent
  output was safe; raw outputs, transcripts, and evidence travel as
  ``sha256:`` digest pins only - they never enter a record; minted
  ``sup-N`` ids; the first supervision on a system id registers it.
* **evaluate()** - pure-read derived oversight-coverage posture for one
  system by ledger rule (``unexamined`` / ``blocked-open`` / ``at-risk`` /
  ``contested`` / ``covered``) with ``integrity_ok`` as data; seq shape
  validated, never consumed, no audit row.
* **verify()** - pure-read digest re-derivation for one supervision
  record (``verified`` / ``tampered`` as data); never proof the verdict
  was correct.
* **retire()** - terminal bookkeeping for superseded systems; ids are
  never recycled.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book an
``oversight-allocation.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: a booked ``clear`` verdict is a host declaration that an
oversight method was applied and declared the output clear - it is never
proof the output was safe, that the method was competently applied, or
that the weak-to-strong gap was bridged; a derived ``covered`` posture is
ledger arithmetic over host-declared verdicts, never evidence the system
is safe.
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
SCALABLE_OVERSIGHT_V2_VERSION = "scalable-oversight-v2.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.scalable-oversight-v2.v1"

#: Pinned oversight-method vocabulary (how the oversight was allocated).
OVERSIGHT_METHODS = (
    "direct-review",
    "spot-check",
    "debate-adjudication",
    "amplified-check",
    "constitutional-review",
    "automated-screen",
    "human-escalation",
    "committee-review",
)

#: Pinned verdict vocabulary (host-declared oversight outcome, booked as data).
VERDICTS = (
    "clear",
    "flagged",
    "escalated",
    "blocked",
    "inconclusive",
    "not-assessed",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "system-superseded",
    "protocol-upgraded",
    "invalidated",
)

#: Ledger-rule posture vocabulary derived by evaluate() (as data).
POSTURES = (
    "unexamined",
    "blocked-open",
    "at-risk",
    "contested",
    "covered",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "supervised",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (exact-key matching).
#: Declared-data keys (``method``, ``verdict``, ``posture``) are pinned
#: vocabulary values and remain emittable.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "output",
        "transcript",
        "trajectory",
        "action",
        "evidence",
        "content",
        "text",
        "data",
        "prompt",
        "response",
        "weights",
        "reasoning",
        "notes",
        "observation",
        "judgment",
        "example",
        "label",
        "feedback",
        "score",
        "telemetry",
        "behavior",
        "demonstration",
        "correction",
        "plan",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ScalableOversightV2Error(Exception):
    """Base error for scalable-oversight-v2 ledger misuse."""


class BadIdError(ScalableOversightV2Error):
    """Malformed system/supervision id."""


class UnknownSystemError(ScalableOversightV2Error):
    """Reference to a system id that was never registered."""


class UnknownSupervisionError(ScalableOversightV2Error):
    """Reference to a supervision id that was never booked."""


class RetiredSystemError(ScalableOversightV2Error):
    """A system id was retired and can never be reused."""


class BadMethodError(ScalableOversightV2Error):
    """Oversight method outside the pinned vocabulary."""


class BadVerdictError(ScalableOversightV2Error):
    """Verdict outside the pinned vocabulary."""


class BadDigestError(ScalableOversightV2Error):
    """Malformed sha256: digest pin."""


class BadReasonError(ScalableOversightV2Error):
    """Retirement reason outside the pinned vocabulary."""


class SystemStateError(ScalableOversightV2Error):
    """Mutation attempted against a system that is not live."""


class SeqOrderError(ScalableOversightV2Error):
    """Caller seq did not strictly increase."""


class AuditKindError(ScalableOversightV2Error):
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
class SupervisionRecord:
    """One declared oversight supervision (digest pins only, never raw evidence)."""

    supervision_id: str
    system_id: str
    method: str
    verdict: str
    evidence_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "supervision_id": self.supervision_id,
            "system_id": self.system_id,
            "method": self.method,
            "verdict": self.verdict,
            "evidence_digest": self.evidence_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "supervision_id": self.supervision_id,
                "system_id": self.system_id,
                "method": self.method,
                "verdict": self.verdict,
                "evidence_digest": self.evidence_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement bookkeeping for one system (ids never recycled)."""

    system_id: str
    reason: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "reason": self.reason,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class EvaluationReport:
    """Pure-read derived oversight-coverage posture for one system (as data)."""

    system_id: str
    n_supervisions: int
    verdict_tally: Tuple[Tuple[str, int], ...]
    posture: str
    integrity_ok: bool
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "n_supervisions": self.n_supervisions,
            "verdict_tally": [list(pair) for pair in self.verdict_tally],
            "posture": self.posture,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "n_supervisions": self.n_supervisions,
                "verdict_tally": [list(pair) for pair in self.verdict_tally],
                "posture": self.posture,
                "integrity_ok": self.integrity_ok,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class VerificationReport:
    """Pure-read digest re-derivation for one supervision record (as data)."""

    supervision_id: str
    verdict: str
    integrity_ok: bool
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "supervision_id": self.supervision_id,
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "supervision_id": self.supervision_id,
                "verdict": self.verdict,
                "integrity_ok": self.integrity_ok,
                "seq": self.seq,
            }
        )


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def scalable_oversight_v2_audit_event(
    kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the oversight-allocation ledger."""
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


class ScalableOversight:
    """Scalable-oversight allocation governance ledger (Simulated).

    ``supervise()`` / ``retire()`` mutate the ledger and consume caller
    seqs; ``evaluate()``, ``verify()``, and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._systems: Dict[str, List[str]] = {}
        self._supervisions: Dict[str, SupervisionRecord] = {}
        self._retirements: Dict[str, RetireRecord] = {}
        self._retired: set = set()
        self._n_supervisions = 0
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
            row = scalable_oversight_v2_audit_event(
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
            scalable_oversight_v2_audit_event(audit_kind, seq, **details)
        )

    def _live(self, system_id: str) -> List[str]:
        supervision_ids = self._systems.get(system_id)
        if supervision_ids is None:
            raise UnknownSystemError(f"unknown system: {system_id!r}")
        if system_id in self._retired:
            raise RetiredSystemError(f"system id retired forever: {system_id!r}")
        return supervision_ids

    # -- supervise -----------------------------------------------------------

    def supervise(
        self,
        system_id: str,
        seq: int,
        method: str = "direct-review",
        verdict: str = "clear",
        evidence_digest: str = "",
    ) -> SupervisionRecord:
        """Book one declared oversight supervision (minted ``sup-N``).

        The first supervision on a system id registers the system. The
        verdict is booked **as data** - never proof the agent output was
        safe. Raw outputs, transcripts, and evidence never enter the
        record; they travel as ``sha256:`` digest pins only.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(system_id, "system_id")
                if system_id in self._retired:
                    raise RetiredSystemError(f"system id retired forever: {system_id!r}")
                if method not in OVERSIGHT_METHODS:
                    raise BadMethodError(f"bad oversight method: {method!r}")
                if verdict not in VERDICTS:
                    raise BadVerdictError(f"bad verdict: {verdict!r}")
                evidence_digest = _require_optional_digest(
                    evidence_digest, "evidence_digest"
                )
                self._n_supervisions += 1
                supervision_id = f"sup-{self._n_supervisions}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "supervision_id": supervision_id,
                        "system_id": system_id,
                        "method": method,
                        "verdict": verdict,
                        "evidence_digest": evidence_digest,
                        "seq": seq,
                    }
                )
                record = SupervisionRecord(
                    supervision_id=supervision_id,
                    system_id=system_id,
                    method=method,
                    verdict=verdict,
                    evidence_digest=evidence_digest,
                    seq=seq,
                    digest=digest,
                )
                self._supervisions[supervision_id] = record
                self._systems.setdefault(system_id, []).append(supervision_id)
                self._emit(
                    "supervised",
                    seq,
                    supervision_id=supervision_id,
                    system_id=system_id,
                    method=method,
                    verdict=verdict,
                )
                return record
            except ScalableOversightV2Error:
                self._burn(seq, "supervise")
                raise

    # -- retire --------------------------------------------------------------

    def retire(self, system_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminally retire one system (ids are never recycled)."""
        with self._lock:
            self._claim(seq)
            try:
                _require_id(system_id, "system_id")
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"bad reason: {reason!r}")
                if system_id not in self._systems:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(f"system id retired forever: {system_id!r}")
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "system_id": system_id,
                        "reason": reason,
                        "seq": seq,
                    }
                )
                record = RetireRecord(
                    system_id=system_id, reason=reason, seq=seq, digest=digest
                )
                self._retirements[system_id] = record
                self._retired.add(system_id)
                self._emit("retired", seq, system_id=system_id, reason=reason)
                return record
            except ScalableOversightV2Error:
                self._burn(seq, "retire")
                raise

    # -- pure-read views -----------------------------------------------------

    def _view_seq_ok(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("view seq must be a non-negative int")

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Derive a digest-pinned oversight-coverage posture for one system (pure read).

        The posture is ledger-rule data, never measured truth, with this
        precedence:

        * ``unexamined`` when no supervisions are booked;
        * ``blocked-open`` when any verdict is ``blocked``;
        * ``at-risk`` when any verdict is ``flagged`` or ``escalated``;
        * ``contested`` when any verdict is ``inconclusive`` or
          ``not-assessed`` (no assessment was rendered);
        * ``covered`` when every verdict is ``clear`` - a host declaration,
          never evidence the system is safe.

        ``integrity_ok`` reports whether every stored supervision for the
        system still verifies (tamper reported, never raised).
        """
        with self._lock:
            self._view_seq_ok(seq)
            _require_id(system_id, "system_id")
            supervision_ids = self._systems.get(system_id)
            if supervision_ids is None:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            verdicts = [self._supervisions[sid].verdict for sid in supervision_ids]
            integrity_ok = all(self._supervisions[sid].verify() for sid in supervision_ids)
            n_supervisions = len(supervision_ids)
            tally = tuple(
                (claim, sum(1 for v in verdicts if v == claim)) for claim in VERDICTS
            )
            if n_supervisions == 0:
                posture = "unexamined"
            elif "blocked" in verdicts:
                posture = "blocked-open"
            elif "flagged" in verdicts or "escalated" in verdicts:
                posture = "at-risk"
            elif "inconclusive" in verdicts or "not-assessed" in verdicts:
                posture = "contested"
            else:
                posture = "covered"
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "system_id": system_id,
                    "n_supervisions": n_supervisions,
                    "verdict_tally": [list(pair) for pair in tally],
                    "posture": posture,
                    "integrity_ok": integrity_ok,
                    "seq": seq,
                }
            )
            return EvaluationReport(
                system_id=system_id,
                n_supervisions=n_supervisions,
                verdict_tally=tally,
                posture=posture,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=digest,
            )

    def verify(self, supervision_id: str, seq: int) -> VerificationReport:
        """Re-derive one supervision record's digest pin (pure read).

        The verdict (``verified`` / ``tampered``) is data: tamper is
        reported, never raised.
        """
        with self._lock:
            self._view_seq_ok(seq)
            _require_id(supervision_id, "supervision_id")
            record = self._supervisions.get(supervision_id)
            if record is None:
                raise UnknownSupervisionError(
                    f"unknown supervision: {supervision_id!r}"
                )
            integrity_ok = record.verify()
            verdict = "verified" if integrity_ok else "tampered"
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "supervision_id": supervision_id,
                    "verdict": verdict,
                    "integrity_ok": integrity_ok,
                    "seq": seq,
                }
            )
            return VerificationReport(
                supervision_id=supervision_id,
                verdict=verdict,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=digest,
            )

    def supervision_record(self, supervision_id: str, seq: int) -> SupervisionRecord:
        """Return one supervision record (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            _require_id(supervision_id, "supervision_id")
            record = self._supervisions.get(supervision_id)
            if record is None:
                raise UnknownSupervisionError(
                    f"unknown supervision: {supervision_id!r}"
                )
            return record

    def supervisions_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        """Supervision ids booked against one system, in mint order (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            _require_id(system_id, "system_id")
            supervision_ids = self._systems.get(system_id)
            if supervision_ids is None:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            return tuple(supervision_ids)

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """All registered system ids in first-supervision order (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._systems.keys())

    def supervision_ids(self, seq: int) -> Tuple[str, ...]:
        """All booked supervision ids in mint order (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._supervisions.keys())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """All retired system ids (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._retired)

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._audit)

    def stats(self, seq: int) -> Dict[str, Any]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return {
                "systems": len(self._systems),
                "supervisions": len(self._supervisions),
                "retired": len(self._retired),
                "rejected": sum(1 for row in self._audit if row["kind"] == "rejected"),
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }

    @staticmethod
    def stdlib_only() -> bool:
        """AST self-check: this module imports stdlib (plus canonical_json) only."""
        import ast
        from pathlib import Path

        allowed = {
            "hashlib",
            "json",
            "threading",
            "dataclasses",
            "typing",
            "__future__",
            "canonical_json",
            "ast",
            "pathlib",
        }
        tree = ast.parse(Path(__file__).read_text())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        return imports <= allowed


def main() -> None:
    """Self-check: exercise the oversight-allocation ledger end to end."""
    pin = "sha256:" + "ab" * 32
    o = ScalableOversight()
    s1 = o.supervise("SYS-1", 1, method="spot-check", verdict="clear", evidence_digest=pin)
    s2 = o.supervise("SYS-1", 2, method="debate-adjudication", verdict="flagged")
    s3 = o.supervise("SYS-2", 3, method="direct-review", verdict="clear")
    assert s1.verify() and s2.verify() and s3.verify()
    assert s1.supervision_id == "sup-1" and s2.supervision_id == "sup-2"
    e1 = o.evaluate("SYS-1", 0)
    e2 = o.evaluate("SYS-2", 0)
    assert e1.posture == "at-risk" and e2.posture == "covered"
    assert e1.verify() and e2.verify()
    v1 = o.verify("sup-1", 0)
    assert v1.verdict == "verified" and v1.verify()
    o.retire("SYS-2", 4, reason="protocol-upgraded")
    assert o.evaluate("SYS-2", 0).posture == "covered"
    assert ScalableOversight.stdlib_only()
    print("scalable-oversight-v2 OK: supervise, evaluate, verify, pins, audit")


if __name__ == "__main__":
    main()
