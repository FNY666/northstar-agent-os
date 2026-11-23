"""AI concept extraction: concept inventory decision ledger, Simulated.

Research note: concept-based interpretability (probing, TCAV/CAV
directions, sparse-autoencoder features, neuron clusters, attention
probes, concept bottlenecks, behavioral probes) asks "which named
concepts does this system encode?" - and the answer is always a
host-declared claim backed by digest-pinned raw material. A concept
presence verdict is never *proof* a system "has" a concept; probes
overfit, CAV directions are unstable across layers, SAEs invent
features, and behavioral probes confound correlation with encoding.
What matters here is the *decision ledger*: which systems had which
concept-extraction methods applied, what presence verdicts were
declared with what strength and digest pins, and how each verdict
derives a ledger-rule posture - defensible bookkeeping, never proof
of real conceptual understanding.

This module owns the extract -> verify -> evaluate lifecycle:

* **extract()** - book one declared concept-extraction result (minted
  ``cpt-N`` ids; pinned 8-term extraction-method vocabulary and pinned
  5-term presence-verdict vocabulary). The first extraction registers
  its system. Raw activations, weights, neurons, attention maps,
  probe traces, and concept vectors never enter records - digest pins
  only.
* **verify()** - **pure read**: re-derive the digest pin of any
  extraction record; verdict ``verified``/``tampered`` is data, never
  proof the concept is really encoded.
* **evaluate()** - **pure read**: per-system presence-verdict tallies
  with ledger-rule posture and digest-pinned ``integrity_ok``, all as
  data.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs sibling interpretability ledgers:
``ai_interpretability.py`` owns the interpretation lifecycle (method ->
declared finding), ``ai_explainability.py`` owns explanation
provision, and behavioral/model-internals modules own detection
mechanics - this module is the *concept inventory* ledger none of
them own: system -> declared extraction method -> declared presence
verdict -> ledger-rule posture.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-concept.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with
the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module extracts no concepts, runs no probes,
inspects no activations, and proves nothing about real conceptual
content. A booked ``concept-present`` verdict means "the host
declared it", never "the system encodes the concept". Activations,
weights, neurons, attention maps, probe traces, concept vectors, and
behavioral transcripts never enter records or cross the audit
boundary - digest pins only.
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
AI_CONCEPT_VERSION = "ai-concept.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-concept.v1"

#: Pinned concept-extraction method vocabulary (the methods this ledger tracks).
EXTRACTION_KINDS = (
    "activation-probe",
    "linear-probe",
    "sae-feature",
    "tcav-direction",
    "attention-probe",
    "neuron-cluster",
    "concept-bottleneck",
    "behavioral-probe",
)

#: Pinned concept-presence verdict vocabulary (booked as data, never proof).
VERDICTS = (
    "concept-present",
    "concept-absent",
    "partial",
    "inconclusive",
    "not-examined",
)

#: Pinned posture vocabulary (ledger rule output).
POSTURES = (
    "unexamined",
    "concept-laden",
    "contested",
    "partial",
    "concept-clean",
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
    "extracted",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "activation",
        "activations",
        "weights",
        "model_weights",
        "neurons",
        "attention",
        "attention_maps",
        "gradient",
        "gradients",
        "concept",
        "concepts",
        "concept_vector",
        "concept_vectors",
        "sae",
        "sae_features",
        "probe",
        "probe_trace",
        "probe_traces",
        "transcript",
        "transcripts",
        "behavior",
        "behavioral",
        "payload",
        "prompt",
        "response",
        "content",
        "text",
        "note",
        "notes",
        "detail",
        "details",
        "description",
        "report",
        "evidence",
        "result",
        "results",
        "score",
        "scores",
        "raw",
        "secret",
        "key",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AIConceptError(Exception):
    """Base error for AI-concept ledger misuse."""


class BadIdError(AIConceptError):
    """Malformed system or extraction id."""


class RetiredSystemError(AIConceptError):
    """System id already retired; never recycled."""


class UnknownSystemError(AIConceptError):
    """System not registered."""


class BadExtractionKindError(AIConceptError):
    """Unknown concept-extraction method."""


class BadDigestError(AIConceptError):
    """Malformed sha256: digest pin."""


class BadVerdictError(AIConceptError):
    """Unknown presence verdict."""


class BadStrengthError(AIConceptError):
    """Strength not a declared host-reported int in [0, 100]."""


class UnknownExtractionError(AIConceptError):
    """Extraction id not booked."""


class BadReasonError(AIConceptError):
    """Unknown retirement reason."""


class SeqOrderError(AIConceptError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(AIConceptError):
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
class ConceptRecord:
    extraction_id: str
    system_id: str
    extraction_kind: str
    verdict: str
    strength: int
    concept_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "extraction_id": self.extraction_id,
            "system_id": self.system_id,
            "extraction_kind": self.extraction_kind,
            "verdict": self.verdict,
            "strength": self.strength,
            "concept_digest": self.concept_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "extraction_id": self.extraction_id,
                "system_id": self.system_id,
                "extraction_kind": self.extraction_kind,
                "verdict": self.verdict,
                "strength": self.strength,
                "concept_digest": self.concept_digest,
            }
        )


@dataclass(frozen=True)
class VerificationReport:
    extraction_id: str
    system_id: str
    verdict: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "extraction_id": self.extraction_id,
            "system_id": self.system_id,
            "verdict": self.verdict,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "extraction_id": self.extraction_id,
                "system_id": self.system_id,
                "verdict": self.verdict,
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
class ConceptEvaluation:
    system_id: str
    posture: str
    n_extractions: int
    n_present: int
    n_absent: int
    n_partial: int
    n_inconclusive: int
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "posture": self.posture,
            "n_extractions": self.n_extractions,
            "n_present": self.n_present,
            "n_absent": self.n_absent,
            "n_partial": self.n_partial,
            "n_inconclusive": self.n_inconclusive,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "posture": self.posture,
                "n_extractions": self.n_extractions,
                "n_present": self.n_present,
                "n_absent": self.n_absent,
                "n_partial": self.n_partial,
                "n_inconclusive": self.n_inconclusive,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def ai_concept_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the AI-concept ledger."""
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


class AIConcept:
    """AI-concept extraction decision ledger, Simulated.

    ``extract()`` / ``retire()`` mutate the ledger and consume caller
    seqs; ``verify()`` / ``evaluate()`` and the other views are pure
    reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._systems: Dict[str, List[str]] = {}
        self._extractions: Dict[str, ConceptRecord] = {}
        self._extractions_by_system: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._cpt_counter = 0
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

    def _burn(self, seq: int, method: str, exc: AIConceptError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(
            ai_concept_audit_event(
                "rejected",
                seq,
                method=method,
                error=type(exc).__name__,
                error_detail=str(exc),
            )
        )

    def _require_live_system(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system already retired: {system_id!r}")

    def _require_known_system(self, system_id: str) -> None:
        if system_id not in self._systems:
            raise UnknownSystemError(f"unknown system: {system_id!r}")

    # -- mutations --------------------------------------------------------

    def extract(
        self,
        system_id: Any,
        seq: Any,
        extraction_kind: Any = "activation-probe",
        verdict: Any = "inconclusive",
        strength: Any = 0,
        concept_digest: Any = "",
    ) -> ConceptRecord:
        """Book one declared concept-extraction result (minted ``cpt-N``).

        The first extraction registers its system. Raw activations,
        weights, neurons, attention maps, probe traces, and concept
        vectors travel as a digest pin only; they never enter records.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _require_id(system_id, "system_id")
                if sid in self._retired:
                    raise RetiredSystemError(f"system id never recycled: {sid!r}")
                if not isinstance(extraction_kind, str) or extraction_kind not in EXTRACTION_KINDS:
                    raise BadExtractionKindError(
                        f"extraction_kind must be one of {sorted(EXTRACTION_KINDS)}"
                    )
                if not isinstance(verdict, str) or verdict not in VERDICTS:
                    raise BadVerdictError(
                        f"verdict must be one of {sorted(VERDICTS)}"
                    )
                if isinstance(strength, bool) or not isinstance(strength, int) or not 0 <= strength <= 100:
                    raise BadStrengthError("strength must be a host-reported int in [0, 100]")
                pin = _require_digest(concept_digest, "concept_digest")
                self._cpt_counter += 1
                eid = f"cpt-{self._cpt_counter}"
                rec = ConceptRecord(
                    extraction_id=eid,
                    system_id=sid,
                    extraction_kind=extraction_kind,
                    verdict=verdict,
                    strength=strength,
                    concept_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "extraction_id": eid,
                            "system_id": sid,
                            "extraction_kind": extraction_kind,
                            "verdict": verdict,
                            "strength": strength,
                            "concept_digest": pin,
                        }
                    ),
                )
                self._extractions[eid] = rec
                self._systems.setdefault(sid, []).append(eid)
                self._extractions_by_system.setdefault(sid, []).append(eid)
                self._audit.append(
                    ai_concept_audit_event(
                        "extracted",
                        seq_v,
                        extraction_id=eid,
                        system_id=sid,
                        extraction_kind=extraction_kind,
                        verdict=verdict,
                        strength=strength,
                    )
                )
                return rec
            except AIConceptError as exc:
                self._burn(seq_v, "extract", exc)
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
                    ai_concept_audit_event(
                        "retired",
                        seq_v,
                        system_id=sid,
                        reason=reason,
                    )
                )
                return rec
            except AIConceptError as exc:
                self._burn(seq_v, "retire", exc)
                raise

    # -- pure-read views ---------------------------------------------------

    def verify(self, extraction_id: Any, seq: Any) -> VerificationReport:
        """Re-derive the digest pin of one extraction record (pure read).

        The ``verified``/``tampered`` verdict is data, never proof the
        concept is really encoded. Seq shape is validated, never
        consumed; no audit row is written.
        """
        with self._lock:
            self._check_seq(seq)
            eid = _require_id(extraction_id, "extraction_id")
            rec = self._extractions.get(eid)
            if rec is None:
                raise UnknownExtractionError(f"unknown extraction: {eid!r}")
            ok = rec.verify()
            report = VerificationReport(
                extraction_id=eid,
                system_id=rec.system_id,
                verdict="verified" if ok else "tampered",
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "extraction_id": eid,
                        "system_id": rec.system_id,
                        "verdict": "verified" if ok else "tampered",
                    }
                ),
            )
            assert report.verify()
            return report

    def evaluate(self, system_id: Any, seq: Any) -> ConceptEvaluation:
        """Per-system presence-verdict tallies and posture (pure read).

        Posture precedence (ledger rule): ``unexamined`` (no
        extractions) -> ``concept-laden`` (any ``concept-present``) ->
        ``contested`` (any ``inconclusive``) -> ``partial`` (any
        ``partial`` or ``not-examined``) -> ``concept-clean`` (all
        ``concept-absent``). ``integrity_ok`` is ledger truth derived
        from digest pins - as data, never proof of real concepts.
        """
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            cpt_ids = self._extractions_by_system[sid]
            n_present = n_absent = n_partial = n_inconclusive = n_not_examined = 0
            for eid in cpt_ids:
                verdict = self._extractions[eid].verdict
                if verdict == "concept-present":
                    n_present += 1
                elif verdict == "concept-absent":
                    n_absent += 1
                elif verdict == "partial":
                    n_partial += 1
                elif verdict == "inconclusive":
                    n_inconclusive += 1
                else:
                    n_not_examined += 1
            if not cpt_ids:
                posture = "unexamined"
            elif n_present:
                posture = "concept-laden"
            elif n_inconclusive:
                posture = "contested"
            elif n_partial or n_not_examined:
                posture = "partial"
            else:
                posture = "concept-clean"
            integrity_ok = all(self._extractions[eid].verify() for eid in cpt_ids)
            return ConceptEvaluation(
                system_id=sid,
                posture=posture,
                n_extractions=len(cpt_ids),
                n_present=n_present,
                n_absent=n_absent,
                n_partial=n_partial,
                n_inconclusive=n_inconclusive,
                integrity_ok=integrity_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "system_id": sid,
                        "posture": posture,
                        "n_extractions": len(cpt_ids),
                        "n_present": n_present,
                        "n_absent": n_absent,
                        "n_partial": n_partial,
                        "n_inconclusive": n_inconclusive,
                        "integrity_ok": integrity_ok,
                    }
                ),
            )

    def extraction_record(self, extraction_id: Any, seq: Any) -> ConceptRecord:
        """Return one extraction record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            eid = _require_id(extraction_id, "extraction_id")
            if eid not in self._extractions:
                raise UnknownExtractionError(f"unknown extraction: {eid!r}")
            return self._extractions[eid]

    def system_ids(self, seq: Any) -> Tuple[str, ...]:
        """All registered system ids in registration order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._systems.keys())

    def extraction_ids(self, seq: Any) -> Tuple[str, ...]:
        """All extraction ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"cpt-{i}" for i in range(1, self._cpt_counter + 1))

    def extractions_for(self, system_id: Any, seq: Any) -> Tuple[str, ...]:
        """Extraction ids booked against one system (mint order)."""
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            return tuple(self._extractions_by_system[sid])

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
                "extractions": len(self._extractions),
                "retired": len(self._retired),
                "rejected": self._rejected,
            }


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
    """Self-check: exercise extract -> verify -> evaluate -> retire."""
    ledger = AIConcept()
    assert stdlib_only(), "non-stdlib import detected"
    pin = "sha256:" + "ab" * 32
    rec = ledger.extract(
        "sys-1",
        1,
        extraction_kind="tcav-direction",
        verdict="concept-present",
        strength=85,
        concept_digest=pin,
    )
    assert rec.extraction_id == "cpt-1"
    assert rec.verify()
    report = ledger.verify("cpt-1", 2)
    assert report.verdict == "verified"
    assert report.verify()
    ev = ledger.evaluate("sys-1", 3)
    assert ev.verify()
    assert ev.integrity_ok is True
    assert ev.posture == "concept-laden"
    assert ev.n_present == 1
    ledger.retire("sys-1", 4, reason="decommissioned")
    assert ledger.stats(5) == {
        "systems": 1,
        "extractions": 1,
        "retired": 1,
        "rejected": 0,
    }
    print("ai-concept OK: extract, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
