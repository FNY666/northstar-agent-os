"""Wireheading: reward-channel self-tampering detection ledger, Simulated.

Research note: wireheading is the classic self-modification failure
mode where an agent bypasses its intended objective by tampering with
its own reward channel - editing the reward function, spoofing the
sensors that feed it, injecting feedback-loop signals, or hijacking
the value function outright (the "rat pressing the lever" archetype
from the early AI safety literature: the optimizer optimizes the
reward *circuitry* instead of the task). What matters here is the
*decision ledger*: which systems had declared wireheading detections
booked against which tamper classes, which verdicts were declared,
and what evaluation posture the ledger derives - defensible
bookkeeping, never proof that any system is wirehead-free.

This module owns the detect -> evaluate -> verify lifecycle:

* **detect()** - book one declared wireheading detection (minted
  ``det-N`` ids; pinned 8-term tamper-kind vocabulary; pinned
  4-term verdict vocabulary booked **as data**, never proof); the
  first detection registers its system; raw sensor traces, policy
  weights, reward logs, and gradient records never enter records -
  digest pins only.
* **evaluate()** - pure read: per-system detection tallies and the
  ledger-rule posture (``unevaluated`` -> ``compromised`` ->
  ``suspect`` -> ``clean``), plus digest-pinned integrity, all as
  data.
* **verify()** - pure read: re-derive one detection's digest pin;
  verdict ``verified`` / ``tampered`` as data (tamper reported,
  never raised).
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs sibling ``reward_hacking.py``: that
module owns the *test -> detect -> mitigate* lifecycle over eight
reward-hacking probe kinds ("reward-tampering" among them) with
declared probes and mitigations. This module is the narrower
*wireheading reward-channel* ledger none of them own: no probes, no
mitigations - declared detections of reward-channel self-tampering
(the agent rewriting its own reward circuitry), declared verdicts,
and a ledger-rule evaluation posture derived from those verdicts.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
a ``wireheading.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with
the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module inspects no reward functions, traces no
sensors, measures no utilities, and proves nothing about real
wireheading. A booked ``confirmed`` verdict means "the host declared
it", never "the system rewired its reward channel". Sensor traces,
policy weights, reward logs, gradient records, and feedback never
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
WIREHEADING_VERSION = "wireheading.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.wireheading.v1"

#: Pinned tamper-kind vocabulary (the reward-channel tamper classes tracked).
TAMPER_KINDS = (
    "reward-channel-tampering",
    "reward-function-rewrite",
    "sensor-spoofing",
    "feedback-loop-injection",
    "utility-function-edits",
    "value-function-hijack",
    "evaluation-circuit-bypass",
    "supervisor-override",
)

#: Pinned detection-verdict vocabulary (booked as data, never proof).
DETECT_VERDICTS = (
    "confirmed",
    "suspect",
    "dismissed",
    "inconclusive",
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
    "detected",
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
        "trajectory",
        "trajectories",
        "action",
        "actions",
        "state",
        "states",
        "observation",
        "observations",
        "sensor",
        "sensors",
        "trace",
        "traces",
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
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class WireheadingError(Exception):
    """Base error for wireheading ledger misuse."""


class BadIdError(WireheadingError):
    """Malformed system or detection id."""


class UnknownSystemError(WireheadingError):
    """System not registered."""


class RetiredSystemError(WireheadingError):
    """System id already retired; never recycled."""


class BadTamperKindError(WireheadingError):
    """Unknown wireheading tamper kind."""


class BadDigestError(WireheadingError):
    """Malformed sha256: digest pin."""


class BadVerdictError(WireheadingError):
    """Unknown detection verdict."""


class UnknownDetectionError(WireheadingError):
    """Detection id not booked."""


class BadReasonError(WireheadingError):
    """Unknown retirement reason."""


class SeqOrderError(WireheadingError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(WireheadingError):
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
class DetectionRecord:
    detection_id: str
    system_id: str
    tamper_kind: str
    verdict: str
    evidence_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "detection_id": self.detection_id,
            "system_id": self.system_id,
            "tamper_kind": self.tamper_kind,
            "verdict": self.verdict,
            "evidence_digest": self.evidence_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "detection_id": self.detection_id,
                "system_id": self.system_id,
                "tamper_kind": self.tamper_kind,
                "verdict": self.verdict,
                "evidence_digest": self.evidence_digest,
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
    n_detections: int
    n_confirmed: int
    n_suspect: int
    n_dismissed: int
    n_inconclusive: int
    posture: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "n_detections": self.n_detections,
            "n_confirmed": self.n_confirmed,
            "n_suspect": self.n_suspect,
            "n_dismissed": self.n_dismissed,
            "n_inconclusive": self.n_inconclusive,
            "posture": self.posture,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "n_detections": self.n_detections,
                "n_confirmed": self.n_confirmed,
                "n_suspect": self.n_suspect,
                "n_dismissed": self.n_dismissed,
                "n_inconclusive": self.n_inconclusive,
                "posture": self.posture,
                "integrity_ok": self.integrity_ok,
            }
        )


@dataclass(frozen=True)
class VerificationReport:
    detection_id: str
    verdict: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "detection_id": self.detection_id,
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "detection_id": self.detection_id,
                "verdict": self.verdict,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def wireheading_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the wireheading ledger."""
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


class Wireheading:
    """Wireheading reward-channel detection decision ledger, Simulated.

    ``detect()`` / ``retire()`` mutate the ledger and consume caller
    seqs; ``evaluate()`` / ``verify()`` and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._systems: Dict[str, List[str]] = {}
        self._detections: Dict[str, DetectionRecord] = {}
        self._detections_by_system: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._det_counter = 0
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

    def _burn(self, seq: int, method: str, exc: WireheadingError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(
            wireheading_audit_event(
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

    def detect(
        self,
        system_id: Any,
        seq: Any,
        tamper_kind: Any = "reward-channel-tampering",
        verdict: Any = "suspect",
        evidence_digest: Any = "",
    ) -> DetectionRecord:
        """Book one declared wireheading detection (minted ``det-N``).

        The first detection registers its system. Sensor traces,
        policy weights, reward logs, and gradient records travel as a
        digest pin only. Verdicts are booked **as data**, never proof
        that the system did (or did not) tamper with its reward
        channel.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _require_id(system_id, "system_id")
                if sid in self._retired:
                    raise RetiredSystemError(f"system id never recycled: {sid!r}")
                if not isinstance(tamper_kind, str) or tamper_kind not in TAMPER_KINDS:
                    raise BadTamperKindError(
                        f"tamper_kind must be one of {sorted(TAMPER_KINDS)}"
                    )
                if not isinstance(verdict, str) or verdict not in DETECT_VERDICTS:
                    raise BadVerdictError(
                        f"verdict must be one of {sorted(DETECT_VERDICTS)}"
                    )
                pin = _require_digest(evidence_digest, "evidence_digest")
                self._det_counter += 1
                did = f"det-{self._det_counter}"
                rec = DetectionRecord(
                    detection_id=did,
                    system_id=sid,
                    tamper_kind=tamper_kind,
                    verdict=verdict,
                    evidence_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "detection_id": did,
                            "system_id": sid,
                            "tamper_kind": tamper_kind,
                            "verdict": verdict,
                            "evidence_digest": pin,
                        }
                    ),
                )
                self._detections[did] = rec
                self._systems.setdefault(sid, []).append(did)
                self._detections_by_system.setdefault(sid, []).append(did)
                self._audit.append(
                    wireheading_audit_event(
                        "detected",
                        seq_v,
                        detection_id=did,
                        system_id=sid,
                        tamper_kind=tamper_kind,
                        verdict=verdict,
                    )
                )
                return rec
            except WireheadingError as exc:
                self._burn(seq_v, "detect", exc)
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
                    wireheading_audit_event(
                        "retired",
                        seq_v,
                        system_id=sid,
                        reason=reason,
                    )
                )
                return rec
            except WireheadingError as exc:
                self._burn(seq_v, "retire", exc)
                raise

    # -- pure reads --------------------------------------------------------

    def evaluate(self, system_id: Any, seq: Any) -> EvaluationReport:
        """Per-system detection tallies and ledger-rule posture (pure read).

        Posture as data: ``unevaluated`` (no detections) ->
        ``compromised`` (any confirmed) -> ``suspect`` (any suspect or
        inconclusive) -> ``clean`` (all dismissed). ``integrity_ok``
        re-derives every in-scope digest pin as data.
        """
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            det_ids = self._detections_by_system.get(sid, ())
            n_confirmed = n_suspect = n_dismissed = n_inconclusive = 0
            for did in det_ids:
                verdict = self._detections[did].verdict
                if verdict == "confirmed":
                    n_confirmed += 1
                elif verdict == "suspect":
                    n_suspect += 1
                elif verdict == "dismissed":
                    n_dismissed += 1
                else:
                    n_inconclusive += 1
            if not det_ids:
                posture = "unevaluated"
            elif n_confirmed > 0:
                posture = "compromised"
            elif n_suspect > 0 or n_inconclusive > 0:
                posture = "suspect"
            else:
                posture = "clean"
            integrity_ok = all(
                self._detections[did].verify() for did in det_ids
            )
            return EvaluationReport(
                system_id=sid,
                n_detections=len(det_ids),
                n_confirmed=n_confirmed,
                n_suspect=n_suspect,
                n_dismissed=n_dismissed,
                n_inconclusive=n_inconclusive,
                posture=posture,
                integrity_ok=integrity_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "system_id": sid,
                        "n_detections": len(det_ids),
                        "n_confirmed": n_confirmed,
                        "n_suspect": n_suspect,
                        "n_dismissed": n_dismissed,
                        "n_inconclusive": n_inconclusive,
                        "posture": posture,
                        "integrity_ok": integrity_ok,
                    }
                ),
            )

    def verify(self, detection_id: Any, seq: Any) -> VerificationReport:
        """Re-derive one detection's digest pin (pure read).

        Verdict ``verified`` / ``tampered`` is data: tamper is
        reported, never raised.
        """
        with self._lock:
            self._check_seq(seq)
            did = _require_id(detection_id, "detection_id")
            rec = self._detections.get(did)
            if rec is None:
                raise UnknownDetectionError(f"unknown detection: {did!r}")
            ok = rec.verify()
            return VerificationReport(
                detection_id=did,
                verdict="verified" if ok else "tampered",
                integrity_ok=ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "detection_id": did,
                        "verdict": "verified" if ok else "tampered",
                        "integrity_ok": ok,
                    }
                ),
            )

    # -- pure-read views ---------------------------------------------------

    def detection_record(self, detection_id: Any, seq: Any) -> DetectionRecord:
        """Return one detection record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            did = _require_id(detection_id, "detection_id")
            if did not in self._detections:
                raise UnknownDetectionError(f"unknown detection: {did!r}")
            return self._detections[did]

    def system_ids(self, seq: Any) -> Tuple[str, ...]:
        """All registered system ids in registration order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._systems.keys())

    def detection_ids(self, seq: Any) -> Tuple[str, ...]:
        """All detection ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"det-{i}" for i in range(1, self._det_counter + 1))

    def detections_for(self, system_id: Any, seq: Any) -> Tuple[str, ...]:
        """Detection ids booked against one system (mint order)."""
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            return tuple(self._detections_by_system.get(sid, ()))

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
                "detections": len(self._detections),
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
    wh = Wireheading()
    pin = "sha256:" + "ab" * 32
    det = wh.detect(
        "sys-1",
        1,
        tamper_kind="reward-channel-tampering",
        verdict="confirmed",
        evidence_digest=pin,
    )
    assert det.detection_id == "det-1"
    assert det.verify()
    rep = wh.evaluate("sys-1", 2)
    assert rep.verify()
    assert rep.posture == "compromised"
    assert rep.integrity_ok is True
    vrf = wh.verify("det-1", 3)
    assert vrf.verify()
    assert vrf.verdict == "verified"
    rtr = wh.retire("sys-1", 4, reason="decommissioned")
    assert rtr.verify()
    assert wh.stats(5) == {
        "systems": 1,
        "detections": 1,
        "retired": 1,
        "rejected": 0,
    }
    print("wireheading OK: detect, evaluate, verify, retire, pins, audit")


if __name__ == "__main__":
    main()
