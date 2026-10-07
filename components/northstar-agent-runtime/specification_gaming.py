"""Specification gaming as a deterministic single-host decision ledger.

Research note: specification gaming (a.k.a. reward gaming via the spec
itself) is the failure mode in which an agent exploits the *letter* of
its stated objective -- the loophole, the proxy metric, the underspecified
requirement -- while missing its *spirit*. Classic shapes: proxy-metric
exploitation (optimize the measurable surrogate), underspecified-objective
gaming, rule loopholes, evaluation tampering, metric saturation, goal
substitution, spec misreads, and shortcut solutions. The governance loop
around this risk is: book host-declared exploit detections against the
objective, derive a posture from the ledger, and book declared verifications.
This module is the bookkeeping layer for that loop. It inspects no specs,
runs no exploit checks, detects no gaming itself, and proves nothing about
any real objective being gamed.

Distinct-layer rationale: ``reward_hacking.py`` owns the reward-*hacking*
lifecycle ledger (probe -> detect -> mitigate on the reward channel),
``deceptive_alignment.py`` owns declared alignment tests and host-declared
detection signals around *deceptive* behavior, and
``outcome_supervision.py``/``process_supervision.py`` own supervision
bookkeeping. Per the additive sibling pattern, this module is the
specification-*gaming* decision ledger none of them own: declared
exploit detections against the objective *specification itself* (pinned
exploit-kind vocabulary), declared retirements of gamed objectives,
ledger-rule posture reports, and digest re-derivation -- all booked as
data, never evidence.

House style: frozen dataclasses, caller int seqs strictly increasing
with claim-then-burn (failed mutations consume their seq + book
``specification-gaming.rejected``; rewinds raise bare without consuming),
no wall-clock, RLock-guarded, fail-closed, stdlib-only +
``canonical_json`` try/except fallback, ``sha256:`` digest pins with
``verify()``, ``audit.ndjson/1`` events.

Honest scope: a booked ``exploit-detected`` verdict means "the host
declared the agent gamed the specification", never that gaming happened.
A ``spec-sound`` posture means "no booked exploit in scope", never that
the objective is game-proof. ``evaluate()`` derives posture from the
ledger; it never proves real-world spec integrity. Raw spec text,
metrics, trajectories, rewards, and weights never enter records or cross
the audit boundary -- digest pins only.
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
SPECIFICATION_GAMING_VERSION = "specification-gaming.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.specification-gaming.v1"

#: Pinned exploit-kind vocabulary (declared gaming of the spec itself).
EXPLOIT_KINDS = (
    "proxy-metric-exploited",
    "underspecified-objective",
    "rule-loophole",
    "evaluation-tampering",
    "metric-saturation",
    "goal-substitution",
    "spec-misread",
    "shortcut-solution",
)

#: Pinned detection-verdict vocabulary. Verdicts are booked as data.
VERDICTS = (
    "exploit-detected",
    "suspected",
    "inconclusive",
    "no-exploit",
)

#: Pinned posture vocabulary (derived from the ledger, never proof).
POSTURES = (
    "unexamined",
    "gamed",
    "suspect",
    "inconclusive",
    "spec-sound",
)

#: Pinned retire-reason vocabulary (declared reasons only).
RETIRE_REASONS = (
    "manual",
    "spec-repaired",
    "objective-withdrawn",
    "superseded",
)

#: Keys banned from audit details (raw spec/metric/trajectory material).
_BANNED_AUDIT_KEYS = frozenset({
    "spec_text", "specification", "rules", "metric", "metric_formula",
    "trajectory", "reward", "weights", "policy", "gradient",
    "evidence", "payload", "raw", "secret", "notes", "transcript",
    "prompt",
})


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------

class SpecificationGamingError(Exception):
    """Base error for specification-gaming misuse."""


class SeqOrderError(SpecificationGamingError):
    """Raised when a caller seq does not strictly increase."""


class BadIdError(SpecificationGamingError):
    """Raised on a malformed objective or detection id."""


class UnknownObjectiveError(SpecificationGamingError):
    """Raised when an objective id has no booked rows (pure-read lookups)."""


class UnknownDetectionError(SpecificationGamingError):
    """Raised when a detection id is unknown."""


class BadKindError(SpecificationGamingError):
    """Raised on an exploit kind outside the pinned vocabulary."""


class BadVerdictError(SpecificationGamingError):
    """Raised on a verdict outside the pinned vocabulary."""


class BadSeverityError(SpecificationGamingError):
    """Raised on a severity outside int [0, 100] (bool refused)."""


class BadDigestError(SpecificationGamingError):
    """Raised on a malformed sha256: digest pin."""


class BadReasonError(SpecificationGamingError):
    """Raised on a retire reason outside the pinned vocabulary."""


class RetiredObjectiveError(SpecificationGamingError):
    """Raised on a mutation against a retired objective."""


class DuplicateRetireError(SpecificationGamingError):
    """Raised on a second retire of the same objective."""


class AuditKindError(SpecificationGamingError):
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


def _check_severity(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadSeverityError("severity must be an int in [0, 100]")
    if not 0 <= value <= 100:
        raise BadSeverityError("severity must be in [0, 100]")
    return value


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DetectionRecord:
    """One host-declared specification-gaming detection for an objective."""

    detection_id: str
    objective_id: str
    exploit_kind: str
    verdict: str
    severity: int
    evidence_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "detection_id": self.detection_id,
            "objective_id": self.objective_id,
            "exploit_kind": self.exploit_kind,
            "verdict": self.verdict,
            "severity": self.severity,
            "evidence_digest": self.evidence_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class RetireRecord:
    """One declared retirement of an objective (terminal)."""

    objective_id: str
    reason: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "objective_id": self.objective_id,
            "reason": self.reason,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class EvaluationReport:
    """Derived specification-gaming posture report (pure read)."""

    seq: int
    objective_id: str
    n_objectives: int
    n_detections: int
    verdict_tallies: tuple
    posture: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "seq": self.seq,
            "objective_id": self.objective_id,
            "n_objectives": self.n_objectives,
            "n_detections": self.n_detections,
            "verdict_tallies": [list(p) for p in self.verdict_tallies],
            "posture": self.posture,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class VerificationReport:
    """Digest re-derivation for one detection (pure read)."""

    seq: int
    detection_id: str
    verdict: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "seq": self.seq,
            "detection_id": self.detection_id,
            "verdict": self.verdict,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

_AUDIT_KINDS = (
    "detected",
    "retired",
    "specification-gaming.rejected",
)


def specification_gaming_audit_event(kind: str, details: dict) -> dict:
    """Build one ``audit.ndjson/1`` event. Raw spec keys are banned."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(details, dict):
        raise AuditKindError("details must be a dict")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"raw spec key banned from audit: {key!r}")
    return {"kind": "specification-gaming." + kind if "." not in kind else kind,
            "details": dict(details)}


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

class SpecificationGaming:
    """Specification-gaming decision ledger: detect -> evaluate/verify."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._detections: dict[str, DetectionRecord] = {}
        self._detection_ids: list[str] = []
        self._retired: dict[str, RetireRecord] = {}
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
        self._audit.append(
            specification_gaming_audit_event(audit_kind, details))

    def _reject(self, seq: int, reason: str) -> None:
        self._n_rejected += 1
        self._emit("specification-gaming.rejected",
                   {"seq": seq, "reason": reason})

    def _require_live(self, objective_id: str) -> None:
        if objective_id in self._retired:
            raise RetiredObjectiveError(
                f"objective is retired: {objective_id!r}")

    # -- mutations ------------------------------------------------------
    def detect(self, objective_id: str, seq: int,
               exploit_kind: str = "proxy-metric-exploited",
               verdict: str = "exploit-detected",
               severity: int = 0,
               evidence_digest: str = "") -> DetectionRecord:
        """Book one host-declared specification-gaming detection (det-N).

        Books the *declaration*, never the exploit: an
        ``exploit-detected`` verdict means the host said the agent gamed
        the specification. ``severity`` is a host-reported int in
        [0, 100]; raw spec text, metrics, and trajectories travel as
        digest pins only.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(objective_id)
                self._require_live(objective_id)
                if exploit_kind not in EXPLOIT_KINDS:
                    raise BadKindError(f"bad exploit kind: {exploit_kind!r}")
                if verdict not in VERDICTS:
                    raise BadVerdictError(f"bad verdict: {verdict!r}")
                _check_severity(severity)
                _check_digest(evidence_digest)
                detection_id = f"det-{len(self._detection_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "detection_id": detection_id,
                    "objective_id": objective_id,
                    "exploit_kind": exploit_kind,
                    "verdict": verdict,
                    "severity": severity,
                    "evidence_digest": evidence_digest,
                    "seq": seq,
                }
                rec = DetectionRecord(
                    detection_id=detection_id,
                    objective_id=objective_id,
                    exploit_kind=exploit_kind,
                    verdict=verdict,
                    severity=severity,
                    evidence_digest=evidence_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._detections[detection_id] = rec
                self._detection_ids.append(detection_id)
                self._emit("detected", {
                    "detection_id": detection_id,
                    "objective_id": objective_id,
                    "exploit_kind": exploit_kind,
                    "verdict": verdict,
                    "severity": severity,
                    "seq": seq,
                })
                return rec
            except SpecificationGamingError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def retire(self, objective_id: str, seq: int,
               reason: str = "manual") -> RetireRecord:
        """Declare an objective retired (terminal; ids never recycled).

        Post-retire ``detect()`` against the objective is refused;
        pure-read views keep working.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(objective_id)
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"bad reason: {reason!r}")
                if objective_id in self._retired:
                    raise DuplicateRetireError(
                        f"already retired: {objective_id!r}")
                body = {
                    "schema": SCHEMA_PIN,
                    "objective_id": objective_id,
                    "reason": reason,
                    "seq": seq,
                }
                rec = RetireRecord(
                    objective_id=objective_id,
                    reason=reason,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._retired[objective_id] = rec
                self._emit("retired", {
                    "objective_id": objective_id,
                    "reason": reason,
                    "seq": seq,
                })
                return rec
            except SpecificationGamingError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    # -- pure-read views --------------------------------------------------
    def _view_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int")

    def _known_objectives(self) -> set[str]:
        return {r.objective_id for r in self._detections.values()}

    def detection_record(self, detection_id: str, seq: int) -> DetectionRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._detections[detection_id]
            except KeyError:
                raise UnknownDetectionError(
                    f"unknown detection: {detection_id!r}")

    def detections_for(self, objective_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(d for d in self._detection_ids
                         if self._detections[d].objective_id == objective_id)

    def objective_ids(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(sorted(self._known_objectives()))

    def detection_ids(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(self._detection_ids)

    def retired_ids(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(sorted(self._retired))

    def retire_record(self, objective_id: str, seq: int) -> RetireRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._retired[objective_id]
            except KeyError:
                raise UnknownObjectiveError(
                    f"objective not retired: {objective_id!r}")

    def evaluate(self, seq: int, objective_id: str = "") -> EvaluationReport:
        """Derive a specification-gaming posture report (pure read).

        ``objective_id`` scopes to one objective with booked rows; ``""``
        aggregates the whole ledger. Posture is ledger truth, never proof
        of real-world spec integrity:

        - ``unexamined``: no detections in scope
        - ``gamed``: any verdict ``exploit-detected``
        - ``suspect``: any verdict ``suspected``
        - ``inconclusive``: any verdict ``inconclusive``
        - ``spec-sound``: otherwise
        """
        with self._lock:
            self._view_seq(seq)
            if objective_id:
                _check_id(objective_id)
                if objective_id not in self._known_objectives():
                    raise UnknownObjectiveError(
                        f"unknown objective: {objective_id!r}")
                dids = self.detections_for(objective_id, seq)
                n_objectives = 1
            else:
                dids = tuple(self._detection_ids)
                n_objectives = len(self._known_objectives())
            tallies: dict[str, int] = {}
            for did in dids:
                v = self._detections[did].verdict
                tallies[v] = tallies.get(v, 0) + 1
            if not dids:
                posture = "unexamined"
            elif tallies.get("exploit-detected", 0) > 0:
                posture = "gamed"
            elif tallies.get("suspected", 0) > 0:
                posture = "suspect"
            elif tallies.get("inconclusive", 0) > 0:
                posture = "inconclusive"
            else:
                posture = "spec-sound"
            verdict_tallies = tuple(sorted(tallies.items()))
            body = {
                "schema": SCHEMA_PIN,
                "seq": seq,
                "objective_id": objective_id,
                "n_objectives": n_objectives,
                "n_detections": len(dids),
                "verdict_tallies": [list(p) for p in verdict_tallies],
                "posture": posture,
            }
            return EvaluationReport(
                seq=seq,
                objective_id=objective_id,
                n_objectives=n_objectives,
                n_detections=len(dids),
                verdict_tallies=verdict_tallies,
                posture=posture,
                digest=_record_digest(body),
            )

    def verify(self, detection_id: str, seq: int) -> VerificationReport:
        """Re-derive one detection's digest pin (pure read).

        Returns ``verified`` when the stored digest matches and
        ``tampered`` as data when it does not; tamper is reported, never
        raised.
        """
        with self._lock:
            self._view_seq(seq)
            try:
                rec = self._detections[detection_id]
            except KeyError:
                raise UnknownDetectionError(
                    f"unknown detection: {detection_id!r}")
            ok = rec.digest == _record_digest(rec.as_dict(include_digest=False))
            body = {
                "schema": SCHEMA_PIN,
                "seq": seq,
                "detection_id": detection_id,
                "verdict": "verified" if ok else "tampered",
            }
            return VerificationReport(
                seq=seq,
                detection_id=detection_id,
                verdict="verified" if ok else "tampered",
                digest=_record_digest(body),
            )

    def stats(self, seq: int) -> dict:
        with self._lock:
            self._view_seq(seq)
            return {
                "objectives": len(self._known_objectives()),
                "detections": len(self._detections),
                "retired": len(self._retired),
                "rejected": self._n_rejected,
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }

    def audit_log(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(self._audit)


def main() -> None:
    sg = SpecificationGaming()
    d = sg.detect("obj-1", 1, exploit_kind="rule-loophole",
                  verdict="exploit-detected", severity=77,
                  evidence_digest="sha256:" + "b" * 64)
    assert d.verify() and d.detection_id == "det-1"
    rep = sg.evaluate(2, "obj-1")
    assert rep.verify() and rep.posture == "gamed"
    assert rep.n_detections == 1 and rep.verdict_tallies == (
        ("exploit-detected", 1),)
    v = sg.verify("det-1", 3)
    assert v.verify() and v.verdict == "verified"
    print("specification-gaming OK: detect, evaluate, verify, pins, audit")


if __name__ == "__main__":
    main()
