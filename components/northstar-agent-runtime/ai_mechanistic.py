"""AI mechanistic analysis decision ledger, Simulated.

Research note: "mechanistic interpretability" names the goal of
reverse-engineering a system's internal mechanisms - circuits,
features, causal paths - but what this module books is far narrower:
*declared analyses*. A host declares a mechanistic analysis over a
pinned analysis-kind vocabulary (circuit discovery, causal ablation,
sparse autoencoding, ...), declares a finding per analysis over a
pinned finding vocabulary, and the ledger derives per-system
evaluation posture by a documented ledger rule. This is defensible
bookkeeping, never proof that any system is genuinely understood
mechanistically.

This module owns the analyze -> verify -> evaluate lifecycle:

* **analyze()** - book one declared mechanistic analysis (minted
  ``anl-N`` ids; pinned 8-term analysis-kind vocabulary; pinned
  5-term finding vocabulary booked **as data**, never proof); the
  first analysis registers its system; raw weights, activations,
  circuits, and ablation traces never enter records - digest pins
  only.
* **verify()** - pure read: re-derive one analysis's digest pin;
  verdict ``verified`` / ``tampered`` as data (tamper reported,
  never raised).
* **evaluate()** - pure read: per-system analysis tallies and the
  ledger-rule posture (``unanalyzed`` -> ``refuted`` ->
  ``contested`` -> ``unassessed`` -> ``mechanistically-understood``),
  plus digest-pinned integrity, all as data.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``mechanistic.py`` owns
circuit-level analysis *mechanics* (declared circuits, node/edge
bookkeeping, ablation runs); ``interpretability.py`` owns
prediction-level explainability (register a prediction, explain that
single prediction); ``ai_explainability.py`` owns system-level
explainability *provision*. This module is the *mechanistic-analysis
declaration* decision ledger none of them own: declared mechanistic
analyses of a system's internals, declared findings, ledger-rule
posture - all booked as data.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-mechanistic.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no analyses, reverse-engineers no
circuits, and proves nothing about real mechanistic understanding. A
booked ``mechanistically-understood`` posture means "the host declared
it", never "the system is understood". Weights, activations, circuits,
features, neurons, attention maps, probes, and ablation traces never
enter records or cross the audit boundary - digest pins only.
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
AI_MECHANISTIC_VERSION = "ai-mechanistic.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-mechanistic.v1"

#: Pinned analysis-kind vocabulary (the mechanistic analysis kinds tracked).
ANALYZE_KINDS = (
    "circuit-discovery",
    "activation-patching",
    "causal-ablation",
    "feature-attribution",
    "sparse-autoencoding",
    "linear-probing",
    "attention-analysis",
    "neuron-analysis",
)

#: Pinned finding vocabulary (booked as data, never proof).
ANALYZE_FINDINGS = (
    "confirmed",
    "partial",
    "refuted",
    "inconclusive",
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
    "analyzed",
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
        "activations",
        "circuit",
        "circuits",
        "feature",
        "features",
        "neuron",
        "neurons",
        "attention",
        "probe",
        "probes",
        "ablation",
        "ablations",
        "patch",
        "patches",
        "latent",
        "latents",
        "dictionary",
        "autoencoder",
        "trace",
        "traces",
        "trajectory",
        "trajectories",
        "graph",
        "edge",
        "edges",
        "node",
        "nodes",
        "policy",
        "policies",
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
        "analysis",
        "analyses",
        "attribution",
        "attributions",
        "rationale",
        "rationales",
        "saliency",
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


class AIMechanisticError(Exception):
    """Base error for ai-mechanistic ledger misuse."""


class BadIdError(AIMechanisticError):
    """Malformed system or analysis id."""


class UnknownSystemError(AIMechanisticError):
    """System not registered."""


class RetiredSystemError(AIMechanisticError):
    """System id already retired; never recycled."""


class BadAnalyzeKindError(AIMechanisticError):
    """Unknown analysis kind."""


class BadDigestError(AIMechanisticError):
    """Malformed sha256: digest pin."""


class BadFindingError(AIMechanisticError):
    """Unknown analysis finding."""


class UnknownAnalysisError(AIMechanisticError):
    """Analysis id not booked."""


class BadReasonError(AIMechanisticError):
    """Unknown retirement reason."""


class SeqOrderError(AIMechanisticError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(AIMechanisticError):
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
class AnalysisRecord:
    analysis_id: str
    system_id: str
    analysis_kind: str
    finding: str
    analysis_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "analysis_id": self.analysis_id,
            "system_id": self.system_id,
            "analysis_kind": self.analysis_kind,
            "finding": self.finding,
            "analysis_digest": self.analysis_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "analysis_id": self.analysis_id,
                "system_id": self.system_id,
                "analysis_kind": self.analysis_kind,
                "finding": self.finding,
                "analysis_digest": self.analysis_digest,
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
    n_analyses: int
    n_confirmed: int
    n_partial: int
    n_refuted: int
    n_inconclusive: int
    n_not_assessed: int
    posture: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "n_analyses": self.n_analyses,
            "n_confirmed": self.n_confirmed,
            "n_partial": self.n_partial,
            "n_refuted": self.n_refuted,
            "n_inconclusive": self.n_inconclusive,
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
                "n_analyses": self.n_analyses,
                "n_confirmed": self.n_confirmed,
                "n_partial": self.n_partial,
                "n_refuted": self.n_refuted,
                "n_inconclusive": self.n_inconclusive,
                "n_not_assessed": self.n_not_assessed,
                "posture": self.posture,
                "integrity_ok": self.integrity_ok,
            }
        )


@dataclass(frozen=True)
class VerificationReport:
    analysis_id: str
    verdict: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "analysis_id": self.analysis_id,
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "analysis_id": self.analysis_id,
                "verdict": self.verdict,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def ai_mechanistic_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the ai-mechanistic ledger."""
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


class AIMechanistic:
    """AI mechanistic analysis decision ledger, Simulated.

    ``analyze()`` / ``retire()`` mutate the ledger and consume caller
    seqs; ``evaluate()`` / ``verify()`` and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._systems: Dict[str, List[str]] = {}
        self._analyses: Dict[str, AnalysisRecord] = {}
        self._analyses_by_system: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._anl_counter = 0
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

    def _burn(self, seq: int, method: str, exc: AIMechanisticError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(
            ai_mechanistic_audit_event(
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

    def analyze(
        self,
        system_id: Any,
        seq: Any,
        analysis_kind: Any = "circuit-discovery",
        finding: Any = "not-assessed",
        analysis_digest: Any = "",
    ) -> AnalysisRecord:
        """Book one declared mechanistic analysis (minted ``anl-N``).

        The first analysis registers its system. Weights,
        activations, circuits, and ablation traces travel as a digest
        pin only. Findings are booked **as data**, never proof that
        the system's mechanism is (or is not) understood.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _require_id(system_id, "system_id")
                if sid in self._retired:
                    raise RetiredSystemError(f"system id never recycled: {sid!r}")
                if not isinstance(analysis_kind, str) or analysis_kind not in ANALYZE_KINDS:
                    raise BadAnalyzeKindError(
                        f"analysis_kind must be one of {sorted(ANALYZE_KINDS)}"
                    )
                if not isinstance(finding, str) or finding not in ANALYZE_FINDINGS:
                    raise BadFindingError(
                        f"finding must be one of {sorted(ANALYZE_FINDINGS)}"
                    )
                pin = _require_digest(analysis_digest, "analysis_digest")
                self._anl_counter += 1
                aid = f"anl-{self._anl_counter}"
                rec = AnalysisRecord(
                    analysis_id=aid,
                    system_id=sid,
                    analysis_kind=analysis_kind,
                    finding=finding,
                    analysis_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "analysis_id": aid,
                            "system_id": sid,
                            "analysis_kind": analysis_kind,
                            "finding": finding,
                            "analysis_digest": pin,
                        }
                    ),
                )
                self._analyses[aid] = rec
                self._systems.setdefault(sid, []).append(aid)
                self._analyses_by_system.setdefault(sid, []).append(aid)
                self._audit.append(
                    ai_mechanistic_audit_event(
                        "analyzed",
                        seq_v,
                        analysis_id=aid,
                        system_id=sid,
                        analysis_kind=analysis_kind,
                        finding=finding,
                    )
                )
                return rec
            except AIMechanisticError as exc:
                self._burn(seq_v, "analyze", exc)
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
                    ai_mechanistic_audit_event(
                        "retired",
                        seq_v,
                        system_id=sid,
                        reason=reason,
                    )
                )
                return rec
            except AIMechanisticError as exc:
                self._burn(seq_v, "retire", exc)
                raise

    # -- pure reads --------------------------------------------------------

    def evaluate(self, system_id: Any, seq: Any) -> EvaluationReport:
        """Per-system analysis tallies and ledger-rule posture (pure read).

        Posture as data: ``unanalyzed`` (no analyses) ->
        ``refuted`` (any refuted) -> ``contested`` (any partial or
        inconclusive) -> ``unassessed`` (any not-assessed) ->
        ``mechanistically-understood`` (all confirmed).
        ``integrity_ok`` re-derives every in-scope digest pin as data.
        """
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            anl_ids = self._analyses_by_system.get(sid, ())
            n_confirmed = n_partial = n_refuted = 0
            n_inconclusive = n_not_assessed = 0
            for aid in anl_ids:
                finding = self._analyses[aid].finding
                if finding == "confirmed":
                    n_confirmed += 1
                elif finding == "partial":
                    n_partial += 1
                elif finding == "refuted":
                    n_refuted += 1
                elif finding == "inconclusive":
                    n_inconclusive += 1
                else:
                    n_not_assessed += 1
            if not anl_ids:
                posture = "unanalyzed"
            elif n_refuted > 0:
                posture = "refuted"
            elif n_partial > 0 or n_inconclusive > 0:
                posture = "contested"
            elif n_not_assessed > 0:
                posture = "unassessed"
            else:
                posture = "mechanistically-understood"
            integrity_ok = all(
                self._analyses[aid].verify() for aid in anl_ids
            )
            return EvaluationReport(
                system_id=sid,
                n_analyses=len(anl_ids),
                n_confirmed=n_confirmed,
                n_partial=n_partial,
                n_refuted=n_refuted,
                n_inconclusive=n_inconclusive,
                n_not_assessed=n_not_assessed,
                posture=posture,
                integrity_ok=integrity_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "system_id": sid,
                        "n_analyses": len(anl_ids),
                        "n_confirmed": n_confirmed,
                        "n_partial": n_partial,
                        "n_refuted": n_refuted,
                        "n_inconclusive": n_inconclusive,
                        "n_not_assessed": n_not_assessed,
                        "posture": posture,
                        "integrity_ok": integrity_ok,
                    }
                ),
            )

    def verify(self, analysis_id: Any, seq: Any) -> VerificationReport:
        """Re-derive one analysis's digest pin (pure read).

        Verdict ``verified`` / ``tampered`` is data: tamper is
        reported, never raised.
        """
        with self._lock:
            self._check_seq(seq)
            aid = _require_id(analysis_id, "analysis_id")
            rec = self._analyses.get(aid)
            if rec is None:
                raise UnknownAnalysisError(f"unknown analysis: {aid!r}")
            ok = rec.verify()
            return VerificationReport(
                analysis_id=aid,
                verdict="verified" if ok else "tampered",
                integrity_ok=ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "analysis_id": aid,
                        "verdict": "verified" if ok else "tampered",
                        "integrity_ok": ok,
                    }
                ),
            )

    # -- pure-read views ---------------------------------------------------

    def analysis_record(self, analysis_id: Any, seq: Any) -> AnalysisRecord:
        """Return one analysis record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            aid = _require_id(analysis_id, "analysis_id")
            if aid not in self._analyses:
                raise UnknownAnalysisError(f"unknown analysis: {aid!r}")
            return self._analyses[aid]

    def system_ids(self, seq: Any) -> Tuple[str, ...]:
        """All registered system ids in registration order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._systems.keys())

    def analysis_ids(self, seq: Any) -> Tuple[str, ...]:
        """All analysis ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"anl-{i}" for i in range(1, self._anl_counter + 1))

    def analyses_for(self, system_id: Any, seq: Any) -> Tuple[str, ...]:
        """Analysis ids booked against one system (mint order)."""
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            return tuple(self._analyses_by_system.get(sid, ()))

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
                "analyses": len(self._analyses),
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
    am = AIMechanistic()
    pin = "sha256:" + "ab" * 32
    rec = am.analyze(
        "sys-1",
        1,
        analysis_kind="causal-ablation",
        finding="confirmed",
        analysis_digest=pin,
    )
    assert rec.analysis_id == "anl-1"
    assert rec.verify()
    rep = am.evaluate("sys-1", 2)
    assert rep.verify()
    assert rep.posture == "mechanistically-understood"
    assert rep.integrity_ok is True
    vrf = am.verify("anl-1", 3)
    assert vrf.verify()
    assert vrf.verdict == "verified"
    rtr = am.retire("sys-1", 4, reason="decommissioned")
    assert rtr.verify()
    assert am.stats(5) == {
        "systems": 1,
        "analyses": 1,
        "retired": 1,
        "rejected": 0,
    }
    print("ai-mechanistic OK: analyze, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
