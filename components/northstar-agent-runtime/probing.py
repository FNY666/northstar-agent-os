"""Internal probing ledger for model interpretability work, Simulated.

Research note: mechanistic interpretability probes a model's internals for
the representations and circuits behind its behavior (linear probes,
activation patching, ablations, sparse-autoencoder features, logit lens,
causal tracing). The dangerous half of a probe is the raw material: weight
tensors, activation dumps, feature dictionaries, stimulus/response traces.
Those must never be bundled with the bookkeeping record that tracks the
probe's lifecycle.

This module is that bookkeeping layer. It:

* **probe()** - book one declared internal probe (minted ``prb-N`` ids) over
  a pinned probe-kind vocabulary and a pinned target vocabulary; the first
  probe on an id registers the model; raw weights/activations travel as
  ``sha256:`` digest pins only.
* **analyze()** - book one declared analysis (minted ``anl-N`` ids) of a
  booked probe over a pinned finding vocabulary; the verdict is data, never
  proof a real mechanism was found (or not).
* **report()** - pure-read derived probing posture per model, as data.
* **retire()** - terminal; retired ids are never recycled.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``probing.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: a booked ``mechanism-found`` is a host-declared claim, never
proof a real circuit or representation was identified; a booked
``no-signal`` is a host-declared claim, never proof the model is free of
the probed behavior; a booked analysis is the ledger's record of the
analysis *decision*, never proof of what the internals actually compute.
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
PROBING_VERSION = "probing.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.probing.v1"

#: Pinned probe-kind vocabulary (declared, never proof a real probe ran).
PROBE_KINDS = (
    "linear-probe",
    "attention-probe",
    "activation-patching",
    "ablation",
    "sae-analysis",
    "logit-lens",
    "causal-tracing",
    "counterfactual",
)

#: Pinned probe-target vocabulary (what was probed, declared as data).
PROBE_TARGETS = (
    "feature",
    "circuit",
    "representation",
    "behavior",
)

#: Pinned probe-outcome vocabulary (declared, never measured truth).
PROBE_OUTCOMES = (
    "mechanism-found",
    "no-signal",
    "inconclusive",
    "not-run",
)

#: Pinned analysis-finding vocabulary (declared, never proof of a finding).
ANALYSIS_FINDINGS = (
    "mechanism-identified",
    "spurious-correlation",
    "inconclusive",
    "artifact",
)

#: Pinned derived postures for report().
POSTURES = (
    "untested",
    "mechanism-found",
    "suspect",
    "inconclusive",
    "no-signal",
)

#: Pinned retirement reasons.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "analysis-complete",
    "model-withdrawn",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "probed",
    "analyzed",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (exact-key matching).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "weights",
        "activations",
        "features",
        "trace",
        "prompt",
        "response",
        "stimulus",
        "dataset",
        "model",
        "circuit",
        "representation",
        "probe_data",
        "analysis_notes",
        "evidence",
        "text",
        "content",
        "data",
        "raw",
        "notes",
        "note",
        "secret",
        "details",
        "detail",
        "description",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ProbingError(Exception):
    """Base error for probing-ledger misuse."""


class BadIdError(ProbingError):
    """Malformed model / probe / analysis id."""


class BadDigestError(ProbingError):
    """Malformed sha256: digest pin."""


class BadKindError(ProbingError):
    """Probe kind outside the pinned vocabulary."""


class BadTargetError(ProbingError):
    """Probe target outside the pinned vocabulary."""


class BadOutcomeError(ProbingError):
    """Probe outcome outside the pinned vocabulary."""


class BadFindingError(ProbingError):
    """Analysis finding outside the pinned vocabulary."""


class BadConfidenceError(ProbingError):
    """Confidence outside the host-reported [0, 100] int range."""


class UnknownModelError(ProbingError):
    """Reference to a model id that was never probed."""


class UnknownProbeError(ProbingError):
    """Reference to a probe id that was never booked."""


class DuplicateAnalysisError(ProbingError):
    """An analysis was already booked for this probe."""


class BadReasonError(ProbingError):
    """Retirement reason outside the pinned vocabulary."""


class RetiredModelError(ProbingError):
    """Mutation attempted against a retired model."""


class SeqOrderError(ProbingError):
    """Caller seq did not strictly increase."""


class AuditKindError(ProbingError):
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


def _require_confidence(confidence: int) -> int:
    if isinstance(confidence, bool) or not isinstance(confidence, int):
        raise BadConfidenceError("confidence must be an int in [0, 100]")
    if not 0 <= confidence <= 100:
        raise BadConfidenceError("confidence must be an int in [0, 100]")
    return confidence


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProbeRecord:
    """One declared internal probe (minted prb-N ids)."""

    probe_id: str
    model_id: str
    probe_kind: str
    target: str
    outcome: str
    probe_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "probe_id": self.probe_id,
            "model_id": self.model_id,
            "probe_kind": self.probe_kind,
            "target": self.target,
            "outcome": self.outcome,
            "probe_digest": self.probe_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "probe_id": self.probe_id,
                "model_id": self.model_id,
                "probe_kind": self.probe_kind,
                "target": self.target,
                "outcome": self.outcome,
                "probe_digest": self.probe_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class AnalysisRecord:
    """One declared analysis of a booked probe (minted anl-N ids)."""

    analysis_id: str
    probe_id: str
    finding: str
    confidence: int
    evidence_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "analysis_id": self.analysis_id,
            "probe_id": self.probe_id,
            "finding": self.finding,
            "confidence": self.confidence,
            "evidence_digest": self.evidence_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "analysis_id": self.analysis_id,
                "probe_id": self.probe_id,
                "finding": self.finding,
                "confidence": self.confidence,
                "evidence_digest": self.evidence_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of a model's probing lifecycle."""

    model_id: str
    reason: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "model_id": self.model_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "model_id": self.model_id,
                "reason": self.reason,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class ProbingReport:
    """Pure-read derived probing posture of one model."""

    model_id: str
    n_probes: int
    n_analyses: int
    posture: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "model_id": self.model_id,
            "n_probes": self.n_probes,
            "n_analyses": self.n_analyses,
            "posture": self.posture,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "model_id": self.model_id,
                "n_probes": self.n_probes,
                "n_analyses": self.n_analyses,
                "posture": self.posture,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit builder
# ---------------------------------------------------------------------------


def probing_audit_event(kind: str, seq: int, **details: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the probing ledger."""
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


class Probing:
    """Internal probing ledger (Simulated).

    ``probe()`` / ``analyze()`` / ``retire()`` mutate the ledger and consume
    caller seqs; ``report()`` and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._probes: Dict[str, ProbeRecord] = {}
        self._model_probes: Dict[str, List[str]] = {}
        self._analyses: Dict[str, AnalysisRecord] = {}
        self._probe_analysis: Dict[str, str] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._probe_counter = 0
        self._analysis_counter = 0
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
            row = probing_audit_event("rejected", seq, rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(probing_audit_event(audit_kind, seq, **details))

    def _require_live(self, model_id: str) -> None:
        if model_id in self._retired:
            raise RetiredModelError(f"model is retired: {model_id!r}")

    # -- probe ----------------------------------------------------------------

    def probe(
        self,
        model_id: str,
        seq: int,
        probe_kind: str = "linear-probe",
        target: str = "feature",
        outcome: str = "not-run",
        probe_digest: str = "",
    ) -> ProbeRecord:
        """Book one declared internal probe of a model.

        The first probe on an id registers the model; raw
        weights/activations never enter records (digest pins only).
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(model_id, "model_id")
                if probe_kind not in PROBE_KINDS:
                    raise BadKindError(f"bad probe kind: {probe_kind!r}")
                if target not in PROBE_TARGETS:
                    raise BadTargetError(f"bad probe target: {target!r}")
                if outcome not in PROBE_OUTCOMES:
                    raise BadOutcomeError(f"bad probe outcome: {outcome!r}")
                probe_digest = _require_optional_digest(probe_digest, "probe_digest")
                self._require_live(model_id)
                self._probe_counter += 1
                probe_id = f"prb-{self._probe_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "probe_id": probe_id,
                        "model_id": model_id,
                        "probe_kind": probe_kind,
                        "target": target,
                        "outcome": outcome,
                        "probe_digest": probe_digest,
                        "seq": seq,
                    }
                )
                record = ProbeRecord(
                    probe_id=probe_id,
                    model_id=model_id,
                    probe_kind=probe_kind,
                    target=target,
                    outcome=outcome,
                    probe_digest=probe_digest,
                    seq=seq,
                    digest=digest,
                )
                self._probes[probe_id] = record
                self._model_probes.setdefault(model_id, []).append(probe_id)
                self._emit(
                    "probed",
                    seq,
                    probe_id=probe_id,
                    model_id=model_id,
                    probe_kind=probe_kind,
                    target=target,
                    outcome=outcome,
                )
                return record
            except ProbingError:
                self._burn(seq, "probe")
                raise

    # -- analyze ----------------------------------------------------------------

    def analyze(
        self,
        probe_id: str,
        seq: int,
        finding: str = "inconclusive",
        confidence: int = 0,
        evidence_digest: str = "",
    ) -> AnalysisRecord:
        """Book one declared analysis of a booked probe.

        The finding is data, never proof a real mechanism was found (or not).
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(probe_id, "probe_id")
                if probe_id not in self._probes:
                    raise UnknownProbeError(f"unknown probe: {probe_id!r}")
                if finding not in ANALYSIS_FINDINGS:
                    raise BadFindingError(f"bad finding: {finding!r}")
                confidence = _require_confidence(confidence)
                evidence_digest = _require_optional_digest(
                    evidence_digest, "evidence_digest"
                )
                if probe_id in self._probe_analysis:
                    raise DuplicateAnalysisError(
                        f"probe already analyzed: {probe_id!r}"
                    )
                self._analysis_counter += 1
                analysis_id = f"anl-{self._analysis_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "analysis_id": analysis_id,
                        "probe_id": probe_id,
                        "finding": finding,
                        "confidence": confidence,
                        "evidence_digest": evidence_digest,
                        "seq": seq,
                    }
                )
                record = AnalysisRecord(
                    analysis_id=analysis_id,
                    probe_id=probe_id,
                    finding=finding,
                    confidence=confidence,
                    evidence_digest=evidence_digest,
                    seq=seq,
                    digest=digest,
                )
                self._analyses[analysis_id] = record
                self._probe_analysis[probe_id] = analysis_id
                self._emit(
                    "analyzed",
                    seq,
                    analysis_id=analysis_id,
                    probe_id=probe_id,
                    finding=finding,
                )
                return record
            except ProbingError:
                self._burn(seq, "analyze")
                raise

    # -- retire ----------------------------------------------------------------

    def retire(self, model_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminally retire a model's probing lifecycle.

        Retired ids are never recycled; post-retire mutations are refused,
        reads still work.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(model_id, "model_id")
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"bad reason: {reason!r}")
                if model_id not in self._model_probes:
                    raise UnknownModelError(f"unknown model: {model_id!r}")
                self._require_live(model_id)
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "model_id": model_id,
                        "reason": reason,
                        "seq": seq,
                    }
                )
                record = RetireRecord(
                    model_id=model_id, reason=reason, seq=seq, digest=digest
                )
                self._retired[model_id] = record
                self._emit("retired", seq, model_id=model_id, reason=reason)
                return record
            except ProbingError:
                self._burn(seq, "retire")
                raise

    # -- report (pure read) ------------------------------------------------------

    def report(self, model_id: str, seq: int) -> ProbingReport:
        """Derived probing posture of one model, as data.

        Posture rules (ledger data, never measured truth):
        - ``mechanism-found`` when any booked probe outcome is
          ``mechanism-found`` or any analysis finding is
          ``mechanism-identified``
        - ``suspect`` when any outcome is ``not-run`` mixed with booked
          inconclusive results, or any analysis is ``inconclusive``
        - ``no-signal`` when every booked probe outcome is ``no-signal``
        - ``inconclusive`` otherwise
        - ``untested`` when the model has no booked probes
        """
        with self._lock:
            self._check_seq(seq)
            _require_id(model_id, "model_id")
            if model_id not in self._model_probes:
                raise UnknownModelError(f"unknown model: {model_id!r}")
            probe_ids = self._model_probes[model_id]
            outcomes = {self._probes[pid].outcome for pid in probe_ids}
            findings = {
                self._analyses[self._probe_analysis[pid]].finding
                for pid in probe_ids
                if pid in self._probe_analysis
            }
            all_ok = all(
                self._probes[pid].verify()
                and (
                    pid not in self._probe_analysis
                    or self._analyses[self._probe_analysis[pid]].verify()
                )
                for pid in probe_ids
            )
            if not probe_ids:
                posture = "untested"
            elif "mechanism-found" in outcomes or "mechanism-identified" in findings:
                posture = "mechanism-found"
            elif outcomes == {"no-signal"} and not findings:
                posture = "no-signal"
            elif "inconclusive" in outcomes or "inconclusive" in findings:
                posture = "inconclusive"
            else:
                posture = "suspect"
            record = ProbingReport(
                model_id=model_id,
                n_probes=len(probe_ids),
                n_analyses=len(self._probe_analysis),
                posture=posture,
                integrity_ok=all_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "model_id": model_id,
                        "n_probes": len(probe_ids),
                        "n_analyses": len(
                            [
                                pid
                                for pid in probe_ids
                                if pid in self._probe_analysis
                            ]
                        ),
                        "posture": posture,
                        "integrity_ok": all_ok,
                    }
                ),
            )
            _ = seq  # seq shape validated, never consumed
            return record

    # -- views (pure reads) ------------------------------------------------------

    def probe_record(self, probe_id: str, seq: int) -> ProbeRecord:
        """Return one probe record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(probe_id, "probe_id")
            if probe_id not in self._probes:
                raise UnknownProbeError(f"unknown probe: {probe_id!r}")
            return self._probes[probe_id]

    def analysis_record(self, analysis_id: str, seq: int) -> AnalysisRecord:
        """Return one analysis record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(analysis_id, "analysis_id")
            if analysis_id not in self._analyses:
                raise UnknownProbeError(f"unknown analysis: {analysis_id!r}")
            return self._analyses[analysis_id]

    def probes_for(self, model_id: str, seq: int) -> Tuple[str, ...]:
        """Probe ids booked against one model, in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(model_id, "model_id")
            if model_id not in self._model_probes:
                raise UnknownModelError(f"unknown model: {model_id!r}")
            return tuple(self._model_probes[model_id])

    def analysis_for(self, probe_id: str, seq: int) -> str:
        """Analysis id booked for one probe (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(probe_id, "probe_id")
            if probe_id not in self._probes:
                raise UnknownProbeError(f"unknown probe: {probe_id!r}")
            if probe_id not in self._probe_analysis:
                raise UnknownProbeError(f"probe has no analysis: {probe_id!r}")
            return self._probe_analysis[probe_id]

    def model_ids(self, seq: int) -> Tuple[str, ...]:
        """All probed model ids in first-probe order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._model_probes.keys())

    def probe_ids(self, seq: int) -> Tuple[str, ...]:
        """All booked probe ids in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._probes.keys())

    def analysis_ids(self, seq: int) -> Tuple[str, ...]:
        """All booked analysis ids in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._analyses.keys())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """All retired model ids (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._retired.keys())

    def stats(self, seq: int) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "models": len(self._model_probes),
                "probes": len(self._probes),
                "analyses": len(self._analyses),
                "retired": len(self._retired),
                "rejected": sum(
                    1 for row in self._audit if row["kind"] == "rejected"
                ),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._audit)


def main() -> None:
    """Self-check: exercise the probing ledger end to end."""
    p = Probing()
    r1 = p.probe("m-1", 1, probe_kind="linear-probe", target="feature",
                 outcome="mechanism-found")
    a1 = p.analyze(r1.probe_id, 2, finding="mechanism-identified", confidence=88)
    assert p.report("m-1", 3).posture == "mechanism-found"
    assert p.analysis_for(r1.probe_id, 4) == a1.analysis_id
    p.probe("m-2", 5, outcome="no-signal")
    assert p.report("m-2", 6).posture == "no-signal"
    p.retire("m-1", 7, reason="analysis-complete")
    assert p.stats(8) == {
        "models": 2,
        "probes": 2,
        "analyses": 1,
        "retired": 1,
        "rejected": 0,
    }
    print("probing OK: probe, analyze, report, retire, pins, audit")


if __name__ == "__main__":
    main()
