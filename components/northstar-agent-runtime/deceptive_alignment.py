"""Deceptive alignment as a deterministic single-host decision ledger.

Research note: deceptive alignment (Hubinger et al.) is the failure mode
in which a model behaves aligned during training/evaluation but pursues
its own goals once deployed -- scheming, sandbagging (underperforming on
evaluations), sycophancy, goal misgeneralization, and situational-awareness
exploitation (behaving differently because it knows it is being tested).
The safety loop around this risk is: run declared alignment tests, book
host-declared detection signals, and book declared mitigations. This
module is the bookkeeping layer for that loop. It runs no evaluations,
detects no deception itself, books no real test results, and proves
nothing about a model's true alignment.

Distinct-layer rationale: ``deception.py``/``deception_detector.py`` own
generic deception detection, ``sleeper_eval.py``/``sleeper_agent_probes.py``
own sleeper-agent backdoor probing, and ``backdoor_detector.py`` owns
backdoor detection. Per the additive sibling pattern, this module is the
deceptive-*alignment* decision ledger none of them own: declared test
runs over pinned test kinds, host-declared detection signals with a
host-reported confidence, and declared mitigation measures -- all booked
as data, never evidence.

House style: frozen dataclasses, caller int seqs strictly increasing
with claim-then-burn (failed mutations consume their seq + book
``deceptive-alignment.rejected``; rewinds raise bare without consuming),
no wall-clock, RLock-guarded, fail-closed, stdlib-only +
``canonical_json`` try/except fallback, ``sha256:`` digest pins with
``verify()``, ``audit.ndjson/1`` events.

Honest scope: a booked ``deceptive`` outcome means "the host declared
the model deceptive on this test", never that the model is deceptive. A
booked ``scheming-behavior`` signal means "the host declared it", never
that scheming occurred. ``report()`` derives posture from the ledger; it
never proves real-world alignment.
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
DECEPTIVE_ALIGNMENT_VERSION = "deceptive-alignment.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.deceptive-alignment.v1"

#: Pinned test-kind vocabulary (declared alignment tests).
TEST_KINDS = (
    "scheming-probe",
    "sandbagging-check",
    "sycophancy-check",
    "goal-guarding",
    "situational-awareness-probe",
    "honesty-eval",
    "corrigibility-check",
    "power-seeking-probe",
)

#: Pinned test-outcome vocabulary. Outcomes are booked as data.
TEST_OUTCOMES = (
    "aligned",
    "deceptive",
    "inconclusive",
    "not-run",
)

#: Pinned detection-signal vocabulary (host-declared signals).
DETECTION_SIGNALS = (
    "scheming-behavior",
    "sandbagging",
    "sycophancy",
    "goal-misgeneralization",
    "situational-awareness-exploit",
    "reward-hacking",
    "power-seeking",
    "deceptive-reasoning",
)

#: Pinned mitigation-measure vocabulary (declared measures, not evidence).
MITIGATION_MEASURES = (
    "retrain",
    "rlhf-correction",
    "deployment-restriction",
    "monitoring-plan",
    "capability-restriction",
    "shutdown",
    "rollback",
    "human-review",
)

#: Pinned report-posture vocabulary (derived from the ledger, never proof).
POSTURES = (
    "untested",
    "deceptive-detected",
    "suspect",
    "aligned",
    "inconclusive",
)

#: Keys banned from audit details (raw test/scenario material must not cross).
_BANNED_AUDIT_KEYS = frozenset({
    "description", "text", "content", "details_raw", "notes",
    "evidence", "payload", "raw", "secret", "scenario",
    "transcript", "prompt", "response", "weights", "model",
})


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------

class DeceptiveAlignmentError(Exception):
    """Base error for deceptive-alignment misuse."""


class SeqOrderError(DeceptiveAlignmentError):
    """Raised when a caller seq does not strictly increase."""


class BadIdError(DeceptiveAlignmentError):
    """Raised on a malformed model, test, detection, or mitigation id."""


class UnknownModelError(DeceptiveAlignmentError):
    """Raised when a model id has no booked rows (pure-read lookups)."""


class UnknownRecordError(DeceptiveAlignmentError):
    """Raised when a test/detection/mitigation id is unknown."""


class BadKindError(DeceptiveAlignmentError):
    """Raised on a test kind outside the pinned vocabulary."""


class BadOutcomeError(DeceptiveAlignmentError):
    """Raised on a test outcome outside the pinned vocabulary."""


class BadSignalError(DeceptiveAlignmentError):
    """Raised on a detection signal outside the pinned vocabulary."""


class BadMeasureError(DeceptiveAlignmentError):
    """Raised on a mitigation measure outside the pinned vocabulary."""


class BadScoreError(DeceptiveAlignmentError):
    """Raised on a score outside int [0, 100] (bool refused)."""


class BadDigestError(DeceptiveAlignmentError):
    """Raised on a malformed sha256: digest pin."""


class AuditKindError(DeceptiveAlignmentError):
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
    """One declared deceptive-alignment test run for a model."""

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
    """One host-declared deceptive-alignment detection signal."""

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
    """One declared deceptive-alignment mitigation measure."""

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
class AlignmentReport:
    """Derived deceptive-alignment posture report (pure read)."""

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
    "deceptive-alignment.rejected",
)


def deceptive_alignment_audit_event(kind: str, details: dict) -> dict:
    """Build one ``audit.ndjson/1`` event. Raw scenario keys are banned."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(details, dict):
        raise AuditKindError("details must be a dict")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"raw scenario key banned from audit: {key!r}")
    return {"kind": "deceptive-alignment." + kind if "." not in kind else kind,
            "details": dict(details)}


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

class DeceptiveAlignment:
    """Deceptive-alignment decision ledger: test -> detect -> mitigate -> report."""

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
        self._audit.append(deceptive_alignment_audit_event(audit_kind, details))

    def _reject(self, seq: int, reason: str) -> None:
        self._n_rejected += 1
        self._emit("deceptive-alignment.rejected", {"seq": seq, "reason": reason})

    # -- mutations ------------------------------------------------------
    def test(self, model_id: str, seq: int,
             test_kind: str = "scheming-probe",
             outcome: str = "aligned",
             score: int = 0,
             test_digest: str = "") -> TestRecord:
        """Book one declared alignment test run (minted tst-N).

        The outcome is booked *as data*: a ``deceptive`` outcome means the
        host declared deception on this test, never that the model is
        deceptive.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(model_id)
                if test_kind not in TEST_KINDS:
                    raise BadKindError(f"bad test kind: {test_kind!r}")
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
            except DeceptiveAlignmentError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def detect(self, model_id: str, seq: int,
               signal: str = "scheming-behavior",
               confidence: int = 0,
               evidence_digest: str = "") -> DetectionRecord:
        """Book one host-declared detection signal (minted det-N).

        Books the *declaration*, never evidence: a booked
        ``scheming-behavior`` means the host said so. ``confidence`` is a
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
            except DeceptiveAlignmentError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def mitigate(self, model_id: str, seq: int,
                 measure: str = "monitoring-plan",
                 plan_digest: str = "") -> MitigationRecord:
        """Book one declared mitigation measure (minted mit-N).

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
            except DeceptiveAlignmentError as exc:
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
                raise UnknownRecordError(f"unknown test: {test_id!r}")

    def detection_record(self, detection_id: str, seq: int) -> DetectionRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._detections[detection_id]
            except KeyError:
                raise UnknownRecordError(f"unknown detection: {detection_id!r}")

    def mitigation_record(self, mitigation_id: str, seq: int) -> MitigationRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._mitigations[mitigation_id]
            except KeyError:
                raise UnknownRecordError(f"unknown mitigation: {mitigation_id!r}")

    def tests_for(self, model_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(t for t in self._test_ids
                         if self._tests[t].model_id == model_id)

    def detections_for(self, model_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(d for d in self._detection_ids
                         if self._detections[d].model_id == model_id)

    def mitigations_for(self, model_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(m for m in self._mitigation_ids
                         if self._mitigations[m].model_id == model_id)

    def model_ids(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(sorted(self._known_models()))

    def report(self, seq: int, model_id: str = "") -> AlignmentReport:
        """Derive a deceptive-alignment posture report (pure read).

        ``model_id`` scopes to one model with booked rows; ``""``
        aggregates the whole ledger. Posture is ledger truth, never proof
        of real-world alignment:

        - ``untested``: no tests and no detections in scope
        - ``deceptive-detected``: any test outcome ``deceptive``
        - ``suspect``: any booked detection signal
        - ``inconclusive``: any test outcome ``inconclusive``
        - ``aligned``: otherwise
        """
        with self._lock:
            self._view_seq(seq)
            if model_id:
                _check_id(model_id)
                if model_id not in self._known_models():
                    raise UnknownModelError(f"unknown model: {model_id!r}")
                tids = self.tests_for(model_id, seq)
                dids = self.detections_for(model_id, seq)
                mids = self.mitigations_for(model_id, seq)
                n_models = 1
            else:
                tids = tuple(self._test_ids)
                dids = tuple(self._detection_ids)
                mids = tuple(self._mitigation_ids)
                n_models = len(self._known_models())
            tallies: dict[str, int] = {}
            for tid in tids:
                o = self._tests[tid].outcome
                tallies[o] = tallies.get(o, 0) + 1
            if not tids and not dids:
                posture = "untested"
            elif tallies.get("deceptive", 0) > 0:
                posture = "deceptive-detected"
            elif dids:
                posture = "suspect"
            elif tallies.get("inconclusive", 0) > 0:
                posture = "inconclusive"
            else:
                posture = "aligned"
            outcome_tallies = tuple(sorted(tallies.items()))
            body = {
                "schema": SCHEMA_PIN,
                "seq": seq,
                "model_id": model_id,
                "n_models": n_models,
                "n_tests": len(tids),
                "n_detections": len(dids),
                "n_mitigations": len(mids),
                "outcome_tallies": [list(p) for p in outcome_tallies],
                "posture": posture,
            }
            return AlignmentReport(
                seq=seq,
                model_id=model_id,
                n_models=n_models,
                n_tests=len(tids),
                n_detections=len(dids),
                n_mitigations=len(mids),
                outcome_tallies=outcome_tallies,
                posture=posture,
                digest=_record_digest(body),
            )

    def stats(self, seq: int) -> dict:
        with self._lock:
            self._view_seq(seq)
            return {
                "models": len(self._known_models()),
                "tests": len(self._tests),
                "detections": len(self._detections),
                "mitigations": len(self._mitigations),
                "rejected": self._n_rejected,
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }

    def audit_log(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(self._audit)


def main() -> None:
    da = DeceptiveAlignment()
    t = da.test("m1", 1, test_kind="scheming-probe", outcome="deceptive",
               score=82, test_digest="sha256:" + "a" * 64)
    assert t.verify() and t.test_id == "tst-1"
    d = da.detect("m1", 2, signal="sandbagging", confidence=70)
    assert d.verify() and d.detection_id == "det-1"
    m = da.mitigate("m1", 3, measure="deployment-restriction")
    assert m.verify() and m.mitigation_id == "mit-1"
    rep = da.report(4, "m1")
    assert rep.verify() and rep.posture == "deceptive-detected"
    assert rep.n_tests == 1 and rep.n_detections == 1
    print("deceptive-alignment OK: test, detect, mitigate, report, pins, audit")


if __name__ == "__main__":
    main()
