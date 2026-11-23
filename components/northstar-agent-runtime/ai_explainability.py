"""AI explainability provision decision ledger, Simulated.

Research note: "AI explainability" names the obligation - that a
system's behavior can be rendered legible to the people affected by
it - but what this module books is far narrower: *declared
explanations*. A host declares an explanation over a pinned
explanation-kind vocabulary (local attribution, counterfactual,
concept activation, ...), declares a coverage verdict per
explanation over a pinned coverage vocabulary, and the ledger derives
per-system evaluation posture by a documented ledger rule. This is
defensible bookkeeping, never proof that any system is genuinely
explainable.

This module owns the explain -> verify -> evaluate lifecycle:

* **explain()** - book one declared explanation (minted ``exp-N``
  ids; pinned 8-term explanation-kind vocabulary; pinned 5-term
  coverage vocabulary booked **as data**, never proof); the first
  explanation registers its system; raw model internals, inputs,
  and narrative text never enter records - digest pins only.
* **verify()** - pure read: re-derive one explanation's digest pin;
  verdict ``verified`` / ``tampered`` as data (tamper reported,
  never raised).
* **evaluate()** - pure read: per-system explanation tallies and the
  ledger-rule posture (``unexplained`` -> ``inadequate`` ->
  ``contested`` -> ``unassessed`` -> ``explained``), plus
  digest-pinned integrity, all as data.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``interpretability.py`` owns
prediction-level explainability (register a prediction, explain that
single prediction, attribution checks); ``mechanistic.py`` owns
circuit-level analysis (declared circuits, node/edge bookkeeping,
ablations); ``transparency.py`` owns disclosure-record bookkeeping.
This module is the *system-level* explainability-provision decision
ledger none of them own: declared explanations of a system's
behavior, declared coverage verdicts, ledger-rule posture - all
booked as data.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-explainability.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module explains no behavior, runs no probes,
computes no attributions, and proves nothing about real
explainability. A booked ``explained`` posture means "the host
declared it", never "the system is explainable". Model internals,
activations, weights, inputs, outputs, transcripts, rationales, and
policies never enter records or cross the audit boundary - digest
pins only.
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
AI_EXPLAINABILITY_VERSION = "ai-explainability.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-explainability.v1"

#: Pinned explanation-kind vocabulary (the explanation kinds tracked).
EXPLAIN_KINDS = (
    "local-attribution",
    "global-surrogate",
    "counterfactual",
    "example-based",
    "concept-activation",
    "feature-importance",
    "mechanistic-trace",
    "natural-language-rationale",
)

#: Pinned coverage vocabulary (booked as data, never proof).
EXPLAIN_COVERAGES = (
    "satisfactory",
    "partial",
    "inadequate",
    "unverifiable",
    "not-assessed",
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
    "explained",
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
        "explanation",
        "explanations",
        "attribution",
        "attributions",
        "rationale",
        "rationales",
        "saliency",
        "features",
        "importance",
        "input",
        "inputs",
        "output",
        "outputs",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AIExplainabilityError(Exception):
    """Base error for ai-explainability ledger misuse."""


class BadIdError(AIExplainabilityError):
    """Malformed system or explanation id."""


class UnknownSystemError(AIExplainabilityError):
    """System not registered."""


class RetiredSystemError(AIExplainabilityError):
    """System id already retired; never recycled."""


class BadExplanationKindError(AIExplainabilityError):
    """Unknown explanation kind."""


class BadDigestError(AIExplainabilityError):
    """Malformed sha256: digest pin."""


class BadCoverageError(AIExplainabilityError):
    """Unknown explanation coverage."""


class UnknownExplanationError(AIExplainabilityError):
    """Explanation id not booked."""


class BadReasonError(AIExplainabilityError):
    """Unknown retirement reason."""


class SeqOrderError(AIExplainabilityError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(AIExplainabilityError):
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
class ExplanationRecord:
    explanation_id: str
    system_id: str
    explanation_kind: str
    coverage: str
    explanation_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "explanation_id": self.explanation_id,
            "system_id": self.system_id,
            "explanation_kind": self.explanation_kind,
            "coverage": self.coverage,
            "explanation_digest": self.explanation_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "explanation_id": self.explanation_id,
                "system_id": self.system_id,
                "explanation_kind": self.explanation_kind,
                "coverage": self.coverage,
                "explanation_digest": self.explanation_digest,
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
    n_explanations: int
    n_satisfactory: int
    n_partial: int
    n_inadequate: int
    n_unverifiable: int
    n_not_assessed: int
    posture: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "n_explanations": self.n_explanations,
            "n_satisfactory": self.n_satisfactory,
            "n_partial": self.n_partial,
            "n_inadequate": self.n_inadequate,
            "n_unverifiable": self.n_unverifiable,
            "n_not_assessed": self.n_not_assessed,
            "posture": self.posture,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "n_explanations": self.n_explanations,
                "n_satisfactory": self.n_satisfactory,
                "n_partial": self.n_partial,
                "n_inadequate": self.n_inadequate,
                "n_unverifiable": self.n_unverifiable,
                "n_not_assessed": self.n_not_assessed,
                "posture": self.posture,
                "integrity_ok": self.integrity_ok,
            }
        )


@dataclass(frozen=True)
class VerificationReport:
    explanation_id: str
    verdict: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "explanation_id": self.explanation_id,
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "explanation_id": self.explanation_id,
                "verdict": self.verdict,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def ai_explainability_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the ai-explainability ledger."""
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


class AIExplainability:
    """AI explainability provision decision ledger, Simulated.

    ``explain()`` / ``retire()`` mutate the ledger and consume caller
    seqs; ``evaluate()`` / ``verify()`` and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._systems: Dict[str, List[str]] = {}
        self._explanations: Dict[str, ExplanationRecord] = {}
        self._explanations_by_system: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._exp_counter = 0
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

    def _burn(self, seq: int, method: str, exc: AIExplainabilityError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(
            ai_explainability_audit_event(
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

    def explain(
        self,
        system_id: Any,
        seq: Any,
        explanation_kind: Any = "local-attribution",
        coverage: Any = "not-assessed",
        explanation_digest: Any = "",
    ) -> ExplanationRecord:
        """Book one declared explanation (minted ``exp-N``).

        The first explanation registers its system. Model internals,
        inputs, outputs, and narrative text travel as a digest pin
        only. Coverages are booked **as data**, never proof that the
        system is (or is not) explainable.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _require_id(system_id, "system_id")
                if sid in self._retired:
                    raise RetiredSystemError(f"system id never recycled: {sid!r}")
                if not isinstance(explanation_kind, str) or explanation_kind not in EXPLAIN_KINDS:
                    raise BadExplanationKindError(
                        f"explanation_kind must be one of {sorted(EXPLAIN_KINDS)}"
                    )
                if not isinstance(coverage, str) or coverage not in EXPLAIN_COVERAGES:
                    raise BadCoverageError(
                        f"coverage must be one of {sorted(EXPLAIN_COVERAGES)}"
                    )
                pin = _require_digest(explanation_digest, "explanation_digest")
                self._exp_counter += 1
                eid = f"exp-{self._exp_counter}"
                rec = ExplanationRecord(
                    explanation_id=eid,
                    system_id=sid,
                    explanation_kind=explanation_kind,
                    coverage=coverage,
                    explanation_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "explanation_id": eid,
                            "system_id": sid,
                            "explanation_kind": explanation_kind,
                            "coverage": coverage,
                            "explanation_digest": pin,
                        }
                    ),
                )
                self._explanations[eid] = rec
                self._systems.setdefault(sid, []).append(eid)
                self._explanations_by_system.setdefault(sid, []).append(eid)
                self._audit.append(
                    ai_explainability_audit_event(
                        "explained",
                        seq_v,
                        explanation_id=eid,
                        system_id=sid,
                        explanation_kind=explanation_kind,
                        coverage=coverage,
                    )
                )
                return rec
            except AIExplainabilityError as exc:
                self._burn(seq_v, "explain", exc)
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
                    ai_explainability_audit_event(
                        "retired",
                        seq_v,
                        system_id=sid,
                        reason=reason,
                    )
                )
                return rec
            except AIExplainabilityError as exc:
                self._burn(seq_v, "retire", exc)
                raise

    # -- pure reads --------------------------------------------------------

    def evaluate(self, system_id: Any, seq: Any) -> EvaluationReport:
        """Per-system explanation tallies and ledger-rule posture (pure read).

        Posture as data: ``unexplained`` (no explanations) ->
        ``inadequate`` (any inadequate) -> ``contested`` (any partial
        or unverifiable) -> ``unassessed`` (any not-assessed) ->
        ``explained`` (all satisfactory). ``integrity_ok`` re-derives
        every in-scope digest pin as data.
        """
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            exp_ids = self._explanations_by_system.get(sid, ())
            n_satisfactory = n_partial = n_inadequate = 0
            n_unverifiable = n_not_assessed = 0
            for eid in exp_ids:
                coverage = self._explanations[eid].coverage
                if coverage == "satisfactory":
                    n_satisfactory += 1
                elif coverage == "partial":
                    n_partial += 1
                elif coverage == "inadequate":
                    n_inadequate += 1
                elif coverage == "unverifiable":
                    n_unverifiable += 1
                else:
                    n_not_assessed += 1
            if not exp_ids:
                posture = "unexplained"
            elif n_inadequate > 0:
                posture = "inadequate"
            elif n_partial > 0 or n_unverifiable > 0:
                posture = "contested"
            elif n_not_assessed > 0:
                posture = "unassessed"
            else:
                posture = "explained"
            integrity_ok = all(
                self._explanations[eid].verify() for eid in exp_ids
            )
            return EvaluationReport(
                system_id=sid,
                n_explanations=len(exp_ids),
                n_satisfactory=n_satisfactory,
                n_partial=n_partial,
                n_inadequate=n_inadequate,
                n_unverifiable=n_unverifiable,
                n_not_assessed=n_not_assessed,
                posture=posture,
                integrity_ok=integrity_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "system_id": sid,
                        "n_explanations": len(exp_ids),
                        "n_satisfactory": n_satisfactory,
                        "n_partial": n_partial,
                        "n_inadequate": n_inadequate,
                        "n_unverifiable": n_unverifiable,
                        "n_not_assessed": n_not_assessed,
                        "posture": posture,
                        "integrity_ok": integrity_ok,
                    }
                ),
            )

    def verify(self, explanation_id: Any, seq: Any) -> VerificationReport:
        """Re-derive one explanation's digest pin (pure read).

        Verdict ``verified`` / ``tampered`` is data: tamper is
        reported, never raised.
        """
        with self._lock:
            self._check_seq(seq)
            eid = _require_id(explanation_id, "explanation_id")
            rec = self._explanations.get(eid)
            if rec is None:
                raise UnknownExplanationError(f"unknown explanation: {eid!r}")
            ok = rec.verify()
            return VerificationReport(
                explanation_id=eid,
                verdict="verified" if ok else "tampered",
                integrity_ok=ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "explanation_id": eid,
                        "verdict": "verified" if ok else "tampered",
                        "integrity_ok": ok,
                    }
                ),
            )

    # -- pure-read views ---------------------------------------------------

    def explanation_record(self, explanation_id: Any, seq: Any) -> ExplanationRecord:
        """Return one explanation record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            eid = _require_id(explanation_id, "explanation_id")
            if eid not in self._explanations:
                raise UnknownExplanationError(f"unknown explanation: {eid!r}")
            return self._explanations[eid]

    def system_ids(self, seq: Any) -> Tuple[str, ...]:
        """All registered system ids in registration order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._systems.keys())

    def explanation_ids(self, seq: Any) -> Tuple[str, ...]:
        """All explanation ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"exp-{i}" for i in range(1, self._exp_counter + 1))

    def explanations_for(self, system_id: Any, seq: Any) -> Tuple[str, ...]:
        """Explanation ids booked against one system (mint order)."""
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            return tuple(self._explanations_by_system.get(sid, ()))

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
                "explanations": len(self._explanations),
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
    ae = AIExplainability()
    pin = "sha256:" + "ab" * 32
    rec = ae.explain(
        "sys-1",
        1,
        explanation_kind="counterfactual",
        coverage="satisfactory",
        explanation_digest=pin,
    )
    assert rec.explanation_id == "exp-1"
    assert rec.verify()
    rep = ae.evaluate("sys-1", 2)
    assert rep.verify()
    assert rep.posture == "explained"
    assert rep.integrity_ok is True
    vrf = ae.verify("exp-1", 3)
    assert vrf.verify()
    assert vrf.verdict == "verified"
    rtr = ae.retire("sys-1", 4, reason="decommissioned")
    assert rtr.verify()
    assert ae.stats(5) == {
        "systems": 1,
        "explanations": 1,
        "retired": 1,
        "rejected": 0,
    }
    print("ai-explainability OK: explain, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
