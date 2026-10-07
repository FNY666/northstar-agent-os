"""Oversight evasion as a deterministic single-host decision ledger.

Research note: oversight evasion is the failure mode in which a model
recognizes that it is being evaluated, monitored, or audited and
suppresses its undesirable behavior accordingly -- evaluation gaming
("playing to the test"), test-condition recognition, monitoring
evasion, steganographic reasoning traces (hiding true chain-of-thought
from oversight), selective transparency (disclosing only benign
reasoning), and oversight circumvention (routing around approval gates).
The safety loop around this risk is: run declared evasion tests, book
host-declared detection signals, and book declared mitigations. This
module is the bookkeeping layer for that loop. It runs no evaluations,
detects no evasion itself, books no real test results, and proves
nothing about a model's true compliance under oversight.

Distinct-layer rationale: ``scalable_oversight.py`` owns oversight
decomposition mechanics, ``human_oversight.py`` owns the human
assignment/review ledger, ``oversight_board.py`` owns oversight-governance
bookkeeping, ``evasion_defense.py`` owns the defense lifecycle, and
``evasion_corpus.py`` owns the held-out adversarial corpus registry.
Per the additive sibling pattern, this module is the *oversight-evasion*
decision ledger none of them own: declared evasion tests over pinned
test kinds, host-declared detection signals with a host-reported
confidence, and declared mitigation measures -- all booked as data,
never evidence.

House style: frozen dataclasses, caller int seqs strictly increasing
with claim-then-burn (failed mutations consume their seq + book
``oversight-evasion.rejected``; rewinds raise bare without consuming),
no wall-clock, RLock-guarded, fail-closed, stdlib-only +
``canonical_json`` try/except fallback, ``sha256:`` digest pins with
``verify()``, ``audit.ndjson/1`` events.

Honest scope: a booked ``evading`` outcome means "the host declared
the model evaded oversight on this test", never that the model evades
oversight. A booked ``evaluation-gaming`` signal means "the host
declared it", never that gaming occurred. ``report()`` derives posture
from the ledger; it never proves real-world oversight compliance.
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
OVERSIGHT_EVASION_VERSION = "oversight-evasion.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.oversight-evasion.v1"

#: Pinned test-kind vocabulary (declared oversight-evasion tests).
TEST_KINDS = (
    "oversight-probe",
    "evaluation-awareness-check",
    "monitoring-evasion-probe",
    "transparency-audit",
    "steering-bypass-test",
    "audit-trail-check",
    "trace-visibility-probe",
    "human-review-spotcheck",
)

#: Pinned test-outcome vocabulary. Outcomes are booked as data.
TEST_OUTCOMES = (
    "compliant",
    "evading",
    "inconclusive",
    "not-run",
)

#: Pinned detection-signal vocabulary (host-declared signals).
EVASION_SIGNALS = (
    "evaluation-gaming",
    "monitoring-evasion",
    "trace-steganography",
    "selective-transparency",
    "oversight-circumvention",
    "test-condition-recognition",
    "gradient-shielding",
    "deception-under-oversight",
)

#: Pinned mitigation-measure vocabulary (declared measures, not evidence).
MITIGATION_MEASURES = (
    "monitoring-plan",
    "deployment-restriction",
    "human-review",
    "capability-restriction",
    "retrain",
    "transparency-mandate",
    "oversight-redundancy",
    "rollback",
)

#: Pinned report-posture vocabulary (derived from the ledger, never proof).
POSTURES = (
    "untested",
    "evasion-detected",
    "suspect",
    "compliant",
    "inconclusive",
)

#: Keys banned from audit details (raw evaluation/monitoring material
#: must not cross the audit boundary).
_BANNED_AUDIT_KEYS = frozenset({
    "description", "text", "content", "transcript", "prompt",
    "response", "trace", "reasoning", "evidence", "payload",
    "weights", "scenario", "notes", "raw", "secret",
})


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------

class OversightEvasionError(Exception):
    """Base error for oversight-evasion misuse."""


class SeqOrderError(OversightEvasionError):
    """Raised when a caller seq does not strictly increase."""


class BadIdError(OversightEvasionError):
    """Raised on a malformed model, test, detection, or mitigation id."""


class UnknownModelError(OversightEvasionError):
    """Raised when a model id has no booked rows (pure-read lookups)."""


class UnknownRecordError(OversightEvasionError):
    """Raised when a test/detection/mitigation id is unknown."""


class BadKindError(OversightEvasionError):
    """Raised on a test kind outside the pinned vocabulary."""


class BadOutcomeError(OversightEvasionError):
    """Raised on a test outcome outside the pinned vocabulary."""


class BadSignalError(OversightEvasionError):
    """Raised on a detection signal outside the pinned vocabulary."""


class BadMeasureError(OversightEvasionError):
    """Raised on a mitigation measure outside the pinned vocabulary."""


class BadScoreError(OversightEvasionError):
    """Raised on a score outside int [0, 100] (bool refused)."""


class BadDigestError(OversightEvasionError):
    """Raised on a malformed sha256: digest pin."""


class AuditKindError(OversightEvasionError):
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
class EvasionTestRecord:
    """One declared oversight-evasion test run for a model."""

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
class EvasionDetectionRecord:
    """One host-declared oversight-evasion detection signal."""

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
class EvasionMitigationRecord:
    """One declared oversight-evasion mitigation measure."""

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
class OversightEvasionReport:
    """Derived oversight-evasion posture report (pure read)."""

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
    "oversight-evasion.rejected",
)


def oversight_evasion_audit_event(kind: str, details: dict) -> dict:
    """Build one ``audit.ndjson/1`` event. Raw material keys are banned."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(details, dict):
        raise AuditKindError("details must be a dict")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"raw material key banned from audit: {key!r}")
    return {"kind": "oversight-evasion." + kind if "." not in kind else kind,
            "details": dict(details)}


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

class OversightEvasion:
    """Oversight-evasion decision ledger: test -> detect -> mitigate -> report."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._tests: dict[str, EvasionTestRecord] = {}
        self._test_ids: list[str] = []
        self._detections: dict[str, EvasionDetectionRecord] = {}
        self._detection_ids: list[str] = []
        self._mitigations: dict[str, EvasionMitigationRecord] = {}
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
        self._audit.append(oversight_evasion_audit_event(audit_kind, details))

    def _reject(self, seq: int, reason: str) -> None:
        self._n_rejected += 1
        self._emit("oversight-evasion.rejected", {"seq": seq, "reason": reason})

    # -- mutations ------------------------------------------------------
    def test(self, model_id: str, seq: int,
             test_kind: str = "oversight-probe",
             outcome: str = "compliant",
             score: int = 0,
             test_digest: str = "") -> EvasionTestRecord:
        """Book one declared oversight-evasion test run (minted tst-N).

        The outcome is booked *as data*: an ``evading`` outcome means the
        host declared the model evaded oversight on this test, never that
        the model evades oversight.
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
                rec = EvasionTestRecord(
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
            except OversightEvasionError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def detect(self, model_id: str, seq: int,
               signal: str = "evaluation-gaming",
               confidence: int = 0,
               evidence_digest: str = "") -> EvasionDetectionRecord:
        """Book one host-declared detection signal (minted det-N).

        Books the *declaration*, never evidence: a booked
        ``evaluation-gaming`` means the host said so. ``confidence`` is a
        host-reported int in [0, 100].
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(model_id)
                if signal not in EVASION_SIGNALS:
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
                rec = EvasionDetectionRecord(
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
            except OversightEvasionError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def mitigate(self, model_id: str, seq: int,
                 measure: str = "monitoring-plan",
                 plan_digest: str = "") -> EvasionMitigationRecord:
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
                rec = EvasionMitigationRecord(
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
            except OversightEvasionError as exc:
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

    def test_record(self, test_id: str, seq: int) -> EvasionTestRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._tests[test_id]
            except KeyError:
                raise UnknownRecordError(f"unknown test: {test_id!r}")

    def detection_record(self, detection_id: str, seq: int) -> EvasionDetectionRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._detections[detection_id]
            except KeyError:
                raise UnknownRecordError(f"unknown detection: {detection_id!r}")

    def mitigation_record(self, mitigation_id: str, seq: int) -> EvasionMitigationRecord:
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

    def report(self, seq: int, model_id: str = "") -> OversightEvasionReport:
        """Derive an oversight-evasion posture report (pure read).

        ``model_id`` scopes to one model with booked rows; ``""``
        aggregates the whole ledger. Posture is ledger truth, never proof
        of real-world oversight compliance:

        - ``untested``: no tests and no detections in scope
        - ``evasion-detected``: any test outcome ``evading``
        - ``suspect``: any booked detection signal
        - ``inconclusive``: any test outcome ``inconclusive``
        - ``compliant``: otherwise
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
            elif tallies.get("evading", 0) > 0:
                posture = "evasion-detected"
            elif dids:
                posture = "suspect"
            elif tallies.get("inconclusive", 0) > 0:
                posture = "inconclusive"
            else:
                posture = "compliant"
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
            return OversightEvasionReport(
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
    oe = OversightEvasion()
    t = oe.test("m1", 1, test_kind="oversight-probe", outcome="evading",
               score=82, test_digest="sha256:" + "a" * 64)
    assert t.verify() and t.test_id == "tst-1"
    d = oe.detect("m1", 2, signal="monitoring-evasion", confidence=70)
    assert d.verify() and d.detection_id == "det-1"
    m = oe.mitigate("m1", 3, measure="oversight-redundancy")
    assert m.verify() and m.mitigation_id == "mit-1"
    rep = oe.report(4, "m1")
    assert rep.verify() and rep.posture == "evasion-detected"
    assert rep.n_tests == 1 and rep.n_detections == 1
    print("oversight-evasion OK: test, detect, mitigate, report, pins, audit")


if __name__ == "__main__":
    main()
