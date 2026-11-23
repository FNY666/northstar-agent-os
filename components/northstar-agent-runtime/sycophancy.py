"""Sycophancy as a deterministic single-host decision ledger.

Research note: sycophancy is the failure mode in which a model agrees with
the user, flatters them, or mirrors their opinions and preferences even
when doing so sacrifices truth or accuracy -- a documented precursor of
misleading alignment behavior (e.g. Perez et al. "Discovering Language
Model Behaviors with Model-Written Evaluations"; Sharma et al. "Towards
Understanding Sycophancy in Language Models"). The safety loop around this
risk is: run declared sycophancy probes (does the model agree with the
user's stated false opinion? does it mirror preferences? does it resist
correction?), book host-declared detection signals, and book declared
mitigations. This module is the bookkeeping layer for that loop. It runs
no probes, detects no sycophancy itself, books no real test results, and
proves nothing about a model's true behavior.

Distinct-layer rationale: ``sycophancy_detector.py`` is a runtime
text-shape tripwire over host-reported transcripts; ``deceptive_alignment.py``
owns the generic deceptive-alignment decision ledger (scheming,
sandbagging, goal misgeneralization). Per the additive sibling pattern,
this module is the sycophancy-specific test/detect/mitigate decision
ledger neither of them owns: declared sycophancy probes over a pinned
probe vocabulary, host-declared sycophancy detection signals with a
host-reported confidence, and declared mitigation measures -- all booked
as data, never evidence.

House style: frozen dataclasses, caller int seqs strictly increasing
with claim-then-burn (failed mutations consume their seq + book
``sycophancy.rejected``; rewinds raise bare without consuming),
no wall-clock, RLock-guarded, fail-closed, stdlib-only +
``canonical_json`` try/except fallback, ``sha256:`` digest pins with
``verify()``, ``audit.ndjson/1`` events.

Honest scope: a booked ``sycophantic`` outcome means "the host declared
the model sycophantic on this probe", never that the model is
sycophantic. A booked ``flattery-response`` signal means "the host
declared it", never that flattery occurred. ``report()`` derives posture
from the ledger; it never proves real-world behavior.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

try:  # Prefer the in-repo canonicalizer when installed.
    from canonical_json import jcs_sha256_hex  # noqa: F401
except Exception:  # pragma: no cover - fallback path
    import hashlib
    import json

    def jcs_sha256_hex(obj) -> str:
        raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


#: Module version.
SYCOPHANCY_VERSION = "sycophancy.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.sycophancy.v1"

#: Pinned probe-kind vocabulary (declared sycophancy probes).
TEST_KINDS = (
    "opinion-probe",
    "flattery-probe",
    "disagreement-probe",
    "preference-probe",
    "accuracy-check",
    "consistency-probe",
    "correction-resistance-probe",
    "persona-probe",
)

#: Pinned probe-outcome vocabulary. Outcomes are booked as data.
TEST_OUTCOMES = (
    "sycophantic",
    "non-sycophantic",
    "inconclusive",
    "not-run",
)

#: Pinned detection-signal vocabulary (host-declared signals).
DETECTION_SIGNALS = (
    "agreeableness-bias",
    "flattery-response",
    "opinion-shift",
    "preference-mirroring",
    "validation-seeking-reward",
    "deference-escalation",
    "truth-sacrifice",
    "selective-honesty",
)

#: Pinned mitigation-measure vocabulary (declared measures, not evidence).
MITIGATION_MEASURES = (
    "rlhf-correction",
    "prompt-hardening",
    "disagreement-training",
    "calibration-tuning",
    "monitoring-plan",
    "deployment-restriction",
    "retrain",
    "human-review",
)

#: Pinned report-posture vocabulary (derived from the ledger, never proof).
POSTURES = (
    "untested",
    "sycophancy-detected",
    "suspect",
    "non-sycophantic",
    "inconclusive",
)

#: Keys banned from audit details (raw probe material must not cross).
_BANNED_AUDIT_KEYS = frozenset({
    "description", "text", "content", "details_raw", "notes",
    "evidence", "payload", "raw", "secret", "scenario",
    "transcript", "prompt", "response", "weights", "model",
})


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------

class SycophancyError(Exception):
    """Base error for sycophancy misuse."""


class SeqOrderError(SycophancyError):
    """Raised when a caller seq does not strictly increase."""


class BadIdError(SycophancyError):
    """Raised on a malformed model, test, detection, or mitigation id."""


class UnknownModelError(SycophancyError):
    """Raised when a model id has no booked rows (pure-read lookups)."""


class UnknownRecordError(SycophancyError):
    """Raised when a test/detection/mitigation id is unknown."""


class BadKindError(SycophancyError):
    """Raised on a probe kind outside the pinned vocabulary."""


class BadOutcomeError(SycophancyError):
    """Raised on a probe outcome outside the pinned vocabulary."""


class BadSignalError(SycophancyError):
    """Raised on a detection signal outside the pinned vocabulary."""


class BadMeasureError(SycophancyError):
    """Raised on a mitigation measure outside the pinned vocabulary."""


class BadScoreError(SycophancyError):
    """Raised on a score outside int [0, 100] (bool refused)."""


class BadDigestError(SycophancyError):
    """Raised on a malformed sha256: digest pin."""


class AuditKindError(SycophancyError):
    """Raised on an unknown audit kind or a banned audit key."""


# ---------------------------------------------------------------------------
# Digest helpers
# ---------------------------------------------------------------------------

def _record_digest(body: dict) -> str:
    # The in-repo jcs_sha256_hex returns bare hex; pin it explicitly.
    return "sha256:" + jcs_sha256_hex(body)


def _check_digest(value: str) -> str:
    if not isinstance(value, str):
        raise BadDigestError("digest must be a str")
    if value and not (value.startswith("sha256:") and len(value) == 71):
        raise BadDigestError("digest must be a sha256: pin or ''")
    return value


def _check_id(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise BadIdError("id must be a non-empty str")
    if len(value) > 128:
        raise BadIdError("id too long")
    return value


def _check_score(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadScoreError("score must be an int in [0, 100]")
    if not 0 <= value <= 100:
        raise BadScoreError("score must be in [0, 100]")
    return value


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TestRecord:
    """One declared sycophancy probe run for a model."""

    test_id: str
    model_id: str
    test_kind: str
    outcome: str
    score: int
    test_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "test_id": self.test_id,
            "model_id": self.model_id,
            "test_kind": self.test_kind,
            "outcome": self.outcome,
            "score": self.score,
            "test_digest": self.test_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class DetectionRecord:
    """One host-declared sycophancy detection signal."""

    detection_id: str
    model_id: str
    signal: str
    confidence: int
    evidence_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "detection_id": self.detection_id,
            "model_id": self.model_id,
            "signal": self.signal,
            "confidence": self.confidence,
            "evidence_digest": self.evidence_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class MitigationRecord:
    """One declared sycophancy mitigation measure."""

    mitigation_id: str
    model_id: str
    measure: str
    plan_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "mitigation_id": self.mitigation_id,
            "model_id": self.model_id,
            "measure": self.measure,
            "plan_digest": self.plan_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class SycophancyReport:
    """Derived sycophancy posture report (pure read)."""

    seq: int
    model_id: str
    n_models: int
    n_tests: int
    n_detections: int
    n_mitigations: int
    outcome_tallies: tuple
    posture: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "seq": self.seq,
            "model_id": self.model_id,
            "n_models": self.n_models,
            "n_tests": self.n_tests,
            "n_detections": self.n_detections,
            "n_mitigations": self.n_mitigations,
            "outcome_tallies": [list(p) for p in self.outcome_tallies],
            "posture": self.posture,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

_AUDIT_KINDS = (
    "tested",
    "detected",
    "mitigated",
    "sycophancy.rejected",
)


def sycophancy_audit_event(kind: str, details: dict) -> dict:
    """Build one ``audit.ndjson/1`` event. Raw probe keys are banned."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(details, dict):
        raise AuditKindError("details must be a dict")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"raw probe key banned from audit: {key!r}")
    return {"kind": "sycophancy." + kind if "." not in kind else kind,
            "details": dict(details)}


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

class Sycophancy:
    """Sycophancy decision ledger: test -> detect -> mitigate -> report."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._tests: dict[str, TestRecord] = {}
        self._test_ids: list[str] = []
        self._detections: dict[str, DetectionRecord] = {}
        self._detection_ids: list[str] = []
        self._mitigations: dict[str, MitigationRecord] = {}
        self._mitigation_ids: list[str] = []
        self._audit: list[dict] = []
        self._n_rejected = 0

    # -- seq ------------------------------------------------------------
    def _claim(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        self._seq = seq

    def _emit(self, audit_kind: str, details: dict) -> None:
        self._audit.append(sycophancy_audit_event(audit_kind, details))

    def _reject(self, seq: int, reason: str) -> None:
        self._n_rejected += 1
        self._emit("sycophancy.rejected", {"seq": seq, "reason": reason})

    # -- mutations ------------------------------------------------------
    def test(self, model_id: str, seq: int,
             test_kind: str = "opinion-probe",
             outcome: str = "non-sycophantic",
             score: int = 0,
             test_digest: str = "") -> TestRecord:
        """Book one declared sycophancy probe run (minted tst-N).

        The outcome is booked *as data*: a ``sycophantic`` outcome means
        the host declared sycophancy on this probe, never that the model
        is sycophantic.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(model_id)
                if test_kind not in TEST_KINDS:
                    raise BadKindError(f"bad probe kind: {test_kind!r}")
                if outcome not in TEST_OUTCOMES:
                    raise BadOutcomeError(f"bad outcome: {outcome!r}")
                _check_score(score)
                _check_digest(test_digest)
                test_id = f"tst-{len(self._test_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "test_id": test_id,
                    "model_id": model_id,
                    "test_kind": test_kind,
                    "outcome": outcome,
                    "score": score,
                    "test_digest": test_digest,
                    "seq": seq,
                }
                rec = TestRecord(
                    test_id=test_id,
                    model_id=model_id,
                    test_kind=test_kind,
                    outcome=outcome,
                    score=score,
                    test_digest=test_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._tests[test_id] = rec
                self._test_ids.append(test_id)
                self._emit("tested", {
                    "test_id": test_id,
                    "model_id": model_id,
                    "test_kind": test_kind,
                    "outcome": outcome,
                    "score": score,
                    "seq": seq,
                })
                return rec
            except SycophancyError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def detect(self, model_id: str, seq: int,
               signal: str = "agreeableness-bias",
               confidence: int = 0,
               evidence_digest: str = "") -> DetectionRecord:
        """Book one host-declared sycophancy detection signal (det-N).

        Books the *declaration*, never evidence: a booked
        ``flattery-response`` means the host said so. ``confidence`` is a
        host-reported int in [0, 100].
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(model_id)
                if signal not in DETECTION_SIGNALS:
                    raise BadSignalError(f"bad signal: {signal!r}")
                _check_score(confidence)
                _check_digest(evidence_digest)
                detection_id = f"det-{len(self._detection_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "detection_id": detection_id,
                    "model_id": model_id,
                    "signal": signal,
                    "confidence": confidence,
                    "evidence_digest": evidence_digest,
                    "seq": seq,
                }
                rec = DetectionRecord(
                    detection_id=detection_id,
                    model_id=model_id,
                    signal=signal,
                    confidence=confidence,
                    evidence_digest=evidence_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._detections[detection_id] = rec
                self._detection_ids.append(detection_id)
                self._emit("detected", {
                    "detection_id": detection_id,
                    "model_id": model_id,
                    "signal": signal,
                    "confidence": confidence,
                    "seq": seq,
                })
                return rec
            except SycophancyError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def mitigate(self, model_id: str, seq: int,
                 measure: str = "monitoring-plan",
                 plan_digest: str = "") -> MitigationRecord:
        """Book one declared sycophancy mitigation measure (mit-N).

        Books the *declaration*, never the execution. Repeatable as a
        chain: several measures may be booked for one model.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(model_id)
                if measure not in MITIGATION_MEASURES:
                    raise BadMeasureError(f"bad measure: {measure!r}")
                _check_digest(plan_digest)
                mitigation_id = f"mit-{len(self._mitigation_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "mitigation_id": mitigation_id,
                    "model_id": model_id,
                    "measure": measure,
                    "plan_digest": plan_digest,
                    "seq": seq,
                }
                rec = MitigationRecord(
                    mitigation_id=mitigation_id,
                    model_id=model_id,
                    measure=measure,
                    plan_digest=plan_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._mitigations[mitigation_id] = rec
                self._mitigation_ids.append(mitigation_id)
                self._emit("mitigated", {
                    "mitigation_id": mitigation_id,
                    "model_id": model_id,
                    "measure": measure,
                    "seq": seq,
                })
                return rec
            except SycophancyError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    # -- pure-read views --------------------------------------------------
    def _view_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int")

    def _known_models(self) -> set[str]:
        return {r.model_id for r in self._tests.values()} | \
               {r.model_id for r in self._detections.values()} | \
               {r.model_id for r in self._mitigations.values()}

    def test_record(self, test_id: str, seq: int) -> TestRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._tests[test_id]
            except KeyError:
                raise UnknownRecordError(f"unknown test id: {test_id!r}")

    def detection_record(self, detection_id: str, seq: int) -> DetectionRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._detections[detection_id]
            except KeyError:
                raise UnknownRecordError(f"unknown detection id: {detection_id!r}")

    def mitigation_record(self, mitigation_id: str, seq: int) -> MitigationRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._mitigations[mitigation_id]
            except KeyError:
                raise UnknownRecordError(f"unknown mitigation id: {mitigation_id!r}")

    def tests_for(self, model_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(tid for tid, rec in self._tests.items()
                         if rec.model_id == model_id)

    def detections_for(self, model_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(did for did, rec in self._detections.items()
                         if rec.model_id == model_id)

    def mitigations_for(self, model_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(mid for mid, rec in self._mitigations.items()
                         if rec.model_id == model_id)

    def model_ids(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(sorted(self._known_models()))

    def audit_log(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(dict(row) for row in self._audit)

    def stats(self, seq: int) -> dict:
        with self._lock:
            self._view_seq(seq)
            return {
                "tests": len(self._tests),
                "detections": len(self._detections),
                "mitigations": len(self._mitigations),
                "models": len(self._known_models()),
                "rejected": self._n_rejected,
            }

    def report(self, seq: int, model_id: str = "") -> SycophancyReport:
        """Derive a posture report. Pure read; never proof of behavior."""
        with self._lock:
            self._view_seq(seq)
            if model_id:
                if model_id not in self._known_models():
                    raise UnknownModelError(f"unknown model: {model_id!r}")
                tests = [r for r in self._tests.values()
                         if r.model_id == model_id]
                detections = [r for r in self._detections.values()
                              if r.model_id == model_id]
                mitigations = [r for r in self._mitigations.values()
                               if r.model_id == model_id]
                n_models = 1
            else:
                tests = list(self._tests.values())
                detections = list(self._detections.values())
                mitigations = list(self._mitigations.values())
                n_models = len(self._known_models())
            tallies: dict[str, int] = {o: 0 for o in TEST_OUTCOMES}
            for rec in tests:
                if rec.outcome in tallies:
                    tallies[rec.outcome] += 1
            if tallies["sycophantic"] > 0:
                posture = "sycophancy-detected"
            elif detections:
                posture = "suspect"
            elif not tests:
                posture = "untested"
            elif tallies["inconclusive"] > 0:
                posture = "inconclusive"
            elif tallies["non-sycophantic"] > 0:
                posture = "non-sycophantic"
            else:
                posture = "inconclusive"
            body = {
                "schema": SCHEMA_PIN,
                "seq": seq,
                "model_id": model_id,
                "n_models": n_models,
                "n_tests": len(tests),
                "n_detections": len(detections),
                "n_mitigations": len(mitigations),
                "outcome_tallies": [[k, tallies[k]] for k in TEST_OUTCOMES],
                "posture": posture,
            }
            return SycophancyReport(
                seq=seq,
                model_id=model_id,
                n_models=n_models,
                n_tests=len(tests),
                n_detections=len(detections),
                n_mitigations=len(mitigations),
                outcome_tallies=tuple((k, tallies[k]) for k in TEST_OUTCOMES),
                posture=posture,
                digest=_record_digest(body),
            )


# ---------------------------------------------------------------------------
# Introspection
# ---------------------------------------------------------------------------

def main() -> None:
    led = Sycophancy()
    led.test("m1", 1, test_kind="opinion-probe", outcome="non-sycophantic")
    led.detect("m1", 2, signal="agreeableness-bias", confidence=30)
    led.mitigate("m1", 3, measure="disagreement-training")
    led.report(4, "m1")
    led.stats(4)
    assert SYCOPHANCY_VERSION == "sycophancy.v1"
    assert SCHEMA_PIN == "northstar.sycophancy.v1"
    print("sycophancy OK: test, detect, mitigate, report, pins, audit")


if __name__ == "__main__":
    main()
