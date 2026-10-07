"""Reward hacking: reward-specification-exploitation detection ledger, Simulated.

Research note: reward hacking (also called specification gaming) is the
failure mode where an agent scores highly on its declared reward while
failing the *intended* objective - it exploits loopholes in the reward
specification rather than solving the task (Clark & Amodei, "Faulty
Reward Functions in the Wild", 2016; ever since: tampering with the
reward signal itself, proxy-metric optimization, goal
misgeneralization under distribution shift, deceptive behavior under
evaluation, sandbagging, gradient hacking, and feedback tampering).
What matters here is the *decision ledger*: which systems were probed
for which hack classes, what detection verdicts were declared with
what evidence pins, and which mitigations were declared against
confirmed detections - defensible bookkeeping, never proof that any
model is hack-free.

This module owns the test -> detect -> mitigate lifecycle:

* **test()** - book one declared reward-hacking probe (minted
  ``prb-N`` ids; pinned 8-term probe-kind vocabulary); raw probe
  payloads, trajectories, and policies never enter records - digest
  pins only.
* **detect()** - book one declared detection verdict for a probe
  (minted ``det-N`` ids; pinned verdict vocabulary ``hack-detected`` /
  ``no-hack`` / ``inconclusive``), booked **as data**, never proof the
  system is (or is not) hacked.
* **mitigate()** - book one declared mitigation against a
  ``hack-detected`` detection (minted ``mit-N`` ids; pinned measure
  vocabulary); fail-closed on non-detected verdicts and on
  double-mitigation; books the *declaration*, never the fix.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.
* **report()** - pure read: per-system probe/detection/mitigation
  tallies and digest-pinned integrity, all as data.

Distinct-layer rationale vs sibling ``recursive_reward.py``: that
module is a *mechanical preference ledger* - it learns linear
preference weights from caller-supplied feedback and estimates reward
from decomposed subtasks (reward *modeling*). This module performs no
learning and computes no reward at all; it is the reward-*hacking*
lifecycle ledger none of them own: probe -> detect -> mitigate.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
a ``reward-hacking.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no probes, inspects no policies,
measures no rewards, and proves nothing about real reward hacking. A
booked ``hack-detected`` verdict means "the host declared it", never
"the system is hacked". Probe payloads, trajectories, policies,
gradients, scores, and raw feedback never enter records or cross the
audit boundary - digest pins only.
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
REWARD_HACKING_VERSION = "reward-hacking.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.reward-hacking.v1"

#: Pinned probe-kind vocabulary (the hack classes this ledger tracks).
PROBE_KINDS = (
    "specification-gaming",
    "reward-tampering",
    "proxy-optimization",
    "goal-misgeneralization",
    "deceptive-evaluation",
    "sandbagging",
    "gradient-hacking",
    "feedback-tampering",
)

#: Pinned detection-verdict vocabulary (booked as data, never proof).
DETECT_VERDICTS = (
    "hack-detected",
    "no-hack",
    "inconclusive",
)

#: Pinned mitigation-measure vocabulary.
MEASURES = (
    "respecify-reward",
    "constrain-optimizer",
    "adversarial-evaluation",
    "shutdown",
    "rollback",
    "human-review",
    "monitor",
    "retrain-from-checkpoint",
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
    "probed",
    "detected",
    "mitigated",
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
        "gradient",
        "gradients",
        "reward",
        "rewards",
        "score",
        "scores",
        "loss",
        "feedback",
        "preference",
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
        "raw",
        "secret",
        "key",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class RewardHackingError(Exception):
    """Base error for reward-hacking ledger misuse."""


class BadIdError(RewardHackingError):
    """Malformed system, probe, detection, or mitigation id."""


class DuplicateSystemError(RewardHackingError):
    """System already registered by a prior probe."""


class UnknownSystemError(RewardHackingError):
    """System not registered."""


class RetiredSystemError(RewardHackingError):
    """System id already retired; never recycled."""


class BadProbeKindError(RewardHackingError):
    """Unknown reward-hacking probe kind."""


class BadDigestError(RewardHackingError):
    """Malformed sha256: digest pin."""


class BadVerdictError(RewardHackingError):
    """Unknown detection verdict."""


class UnknownProbeError(RewardHackingError):
    """Probe id not booked."""


class BadMeasureError(RewardHackingError):
    """Unknown mitigation measure."""


class UnknownDetectionError(RewardHackingError):
    """Detection id not booked."""


class MitigationNotNeededError(RewardHackingError):
    """Detection verdict does not warrant mitigation."""


class AlreadyMitigatedError(RewardHackingError):
    """Detection already has a booked mitigation."""


class BadReasonError(RewardHackingError):
    """Unknown retirement reason."""


class SeqOrderError(RewardHackingError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(RewardHackingError):
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
class ProbeRecord:
    probe_id: str
    system_id: str
    probe_kind: str
    probe_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "probe_id": self.probe_id,
            "system_id": self.system_id,
            "probe_kind": self.probe_kind,
            "probe_digest": self.probe_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "probe_id": self.probe_id,
                "system_id": self.system_id,
                "probe_kind": self.probe_kind,
                "probe_digest": self.probe_digest,
            }
        )


@dataclass(frozen=True)
class DetectionRecord:
    detection_id: str
    probe_id: str
    system_id: str
    verdict: str
    evidence_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "detection_id": self.detection_id,
            "probe_id": self.probe_id,
            "system_id": self.system_id,
            "verdict": self.verdict,
            "evidence_digest": self.evidence_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "detection_id": self.detection_id,
                "probe_id": self.probe_id,
                "system_id": self.system_id,
                "verdict": self.verdict,
                "evidence_digest": self.evidence_digest,
            }
        )


@dataclass(frozen=True)
class MitigationRecord:
    mitigation_id: str
    detection_id: str
    system_id: str
    measure: str
    plan_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "mitigation_id": self.mitigation_id,
            "detection_id": self.detection_id,
            "system_id": self.system_id,
            "measure": self.measure,
            "plan_digest": self.plan_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "mitigation_id": self.mitigation_id,
                "detection_id": self.detection_id,
                "system_id": self.system_id,
                "measure": self.measure,
                "plan_digest": self.plan_digest,
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
class HackReport:
    system_id: str
    n_probes: int
    n_detections: int
    n_hack_detected: int
    n_mitigations: int
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "n_probes": self.n_probes,
            "n_detections": self.n_detections,
            "n_hack_detected": self.n_hack_detected,
            "n_mitigations": self.n_mitigations,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "n_probes": self.n_probes,
                "n_detections": self.n_detections,
                "n_hack_detected": self.n_hack_detected,
                "n_mitigations": self.n_mitigations,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def reward_hacking_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the reward-hacking ledger."""
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


class RewardHacking:
    """Reward-hacking detection decision ledger, Simulated.

    ``test()`` / ``detect()`` / ``mitigate()`` / ``retire()`` mutate the
    ledger and consume caller seqs; views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._systems: Dict[str, List[str]] = {}
        self._probes: Dict[str, ProbeRecord] = {}
        self._detections: Dict[str, DetectionRecord] = {}
        self._detections_by_probe: Dict[str, List[str]] = {}
        self._detections_by_system: Dict[str, List[str]] = {}
        self._mitigations: Dict[str, MitigationRecord] = {}
        self._mitigations_by_system: Dict[str, List[str]] = {}
        self._mitigated_detections: set[str] = set()
        self._retired: Dict[str, RetireRecord] = {}
        self._prb_counter = 0
        self._det_counter = 0
        self._mit_counter = 0
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

    def _burn(self, seq: int, method: str, exc: RewardHackingError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(
            reward_hacking_audit_event(
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

    def test(
        self,
        system_id: Any,
        probe_kind: Any,
        seq: Any,
        probe_digest: Any = "",
    ) -> ProbeRecord:
        """Book one declared reward-hacking probe (minted ``prb-N``).

        The first probe registers its system. Probe payloads travel as a
        digest pin only; raw trajectories, policies, and rewards never
        enter records.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _require_id(system_id, "system_id")
                if sid in self._retired:
                    raise RetiredSystemError(f"system id never recycled: {sid!r}")
                if not isinstance(probe_kind, str) or probe_kind not in PROBE_KINDS:
                    raise BadProbeKindError(
                        f"probe_kind must be one of {sorted(PROBE_KINDS)}"
                    )
                pin = _require_digest(probe_digest, "probe_digest")
                self._prb_counter += 1
                pid = f"prb-{self._prb_counter}"
                rec = ProbeRecord(
                    probe_id=pid,
                    system_id=sid,
                    probe_kind=probe_kind,
                    probe_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "probe_id": pid,
                            "system_id": sid,
                            "probe_kind": probe_kind,
                            "probe_digest": pin,
                        }
                    ),
                )
                self._probes[pid] = rec
                self._systems.setdefault(sid, []).append(pid)
                self._audit.append(
                    reward_hacking_audit_event(
                        "probed",
                        seq_v,
                        probe_id=pid,
                        system_id=sid,
                        probe_kind=probe_kind,
                    )
                )
                return rec
            except RewardHackingError as exc:
                self._burn(seq_v, "test", exc)
                raise

    def detect(
        self,
        probe_id: Any,
        seq: Any,
        verdict: Any = "inconclusive",
        evidence_digest: Any = "",
    ) -> DetectionRecord:
        """Book one declared detection verdict (minted ``det-N``).

        Verdicts are booked **as data**, never proof that the system is
        (or is not) hacked.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                pid = _require_id(probe_id, "probe_id")
                probe = self._probes.get(pid)
                if probe is None:
                    raise UnknownProbeError(f"unknown probe: {pid!r}")
                self._require_live_system(probe.system_id)
                if not isinstance(verdict, str) or verdict not in DETECT_VERDICTS:
                    raise BadVerdictError(
                        f"verdict must be one of {sorted(DETECT_VERDICTS)}"
                    )
                pin = _require_digest(evidence_digest, "evidence_digest")
                self._det_counter += 1
                did = f"det-{self._det_counter}"
                rec = DetectionRecord(
                    detection_id=did,
                    probe_id=pid,
                    system_id=probe.system_id,
                    verdict=verdict,
                    evidence_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "detection_id": did,
                            "probe_id": pid,
                            "system_id": probe.system_id,
                            "verdict": verdict,
                            "evidence_digest": pin,
                        }
                    ),
                )
                self._detections[did] = rec
                self._detections_by_probe.setdefault(pid, []).append(did)
                self._detections_by_system.setdefault(probe.system_id, []).append(did)
                self._audit.append(
                    reward_hacking_audit_event(
                        "detected",
                        seq_v,
                        detection_id=did,
                        probe_id=pid,
                        system_id=probe.system_id,
                        verdict=verdict,
                    )
                )
                return rec
            except RewardHackingError as exc:
                self._burn(seq_v, "detect", exc)
                raise

    def mitigate(
        self,
        detection_id: Any,
        seq: Any,
        measure: Any = "respecify-reward",
        plan_digest: Any = "",
    ) -> MitigationRecord:
        """Book one declared mitigation (minted ``mit-N``).

        Fail-closed: only ``hack-detected`` detections may be
        mitigated, and each detection at most once. Books the
        *declaration*, never the fix.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                did = _require_id(detection_id, "detection_id")
                det = self._detections.get(did)
                if det is None:
                    raise UnknownDetectionError(f"unknown detection: {did!r}")
                self._require_live_system(det.system_id)
                if det.verdict != "hack-detected":
                    raise MitigationNotNeededError(
                        f"verdict {det.verdict!r} does not warrant mitigation"
                    )
                if did in self._mitigated_detections:
                    raise AlreadyMitigatedError(
                        f"detection already mitigated: {did!r}"
                    )
                if not isinstance(measure, str) or measure not in MEASURES:
                    raise BadMeasureError(
                        f"measure must be one of {sorted(MEASURES)}"
                    )
                pin = _require_digest(plan_digest, "plan_digest")
                self._mit_counter += 1
                mid = f"mit-{self._mit_counter}"
                rec = MitigationRecord(
                    mitigation_id=mid,
                    detection_id=did,
                    system_id=det.system_id,
                    measure=measure,
                    plan_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "mitigation_id": mid,
                            "detection_id": did,
                            "system_id": det.system_id,
                            "measure": measure,
                            "plan_digest": pin,
                        }
                    ),
                )
                self._mitigations[mid] = rec
                self._mitigated_detections.add(did)
                self._mitigations_by_system.setdefault(det.system_id, []).append(mid)
                self._audit.append(
                    reward_hacking_audit_event(
                        "mitigated",
                        seq_v,
                        mitigation_id=mid,
                        detection_id=did,
                        system_id=det.system_id,
                        measure=measure,
                    )
                )
                return rec
            except RewardHackingError as exc:
                self._burn(seq_v, "mitigate", exc)
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
                    reward_hacking_audit_event(
                        "retired",
                        seq_v,
                        system_id=sid,
                        reason=reason,
                    )
                )
                return rec
            except RewardHackingError as exc:
                self._burn(seq_v, "retire", exc)
                raise

    # -- pure-read views ---------------------------------------------------

    def probe_record(self, probe_id: Any, seq: Any) -> ProbeRecord:
        """Return one probe record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            pid = _require_id(probe_id, "probe_id")
            if pid not in self._probes:
                raise UnknownProbeError(f"unknown probe: {pid!r}")
            return self._probes[pid]

    def detection_record(self, detection_id: Any, seq: Any) -> DetectionRecord:
        """Return one detection record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            did = _require_id(detection_id, "detection_id")
            if did not in self._detections:
                raise UnknownDetectionError(f"unknown detection: {did!r}")
            return self._detections[did]

    def mitigation_record(self, mitigation_id: Any, seq: Any) -> MitigationRecord:
        """Return one mitigation record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            mid = _require_id(mitigation_id, "mitigation_id")
            if mid not in self._mitigations:
                raise UnknownDetectionError(f"unknown mitigation: {mid!r}")
            return self._mitigations[mid]

    def system_ids(self, seq: Any) -> Tuple[str, ...]:
        """All registered system ids in registration order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._systems.keys())

    def probe_ids(self, seq: Any) -> Tuple[str, ...]:
        """All probe ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"prb-{i}" for i in range(1, self._prb_counter + 1))

    def detection_ids(self, seq: Any) -> Tuple[str, ...]:
        """All detection ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"det-{i}" for i in range(1, self._det_counter + 1))

    def mitigation_ids(self, seq: Any) -> Tuple[str, ...]:
        """All mitigation ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"mit-{i}" for i in range(1, self._mit_counter + 1))

    def probes_for(self, system_id: Any, seq: Any) -> Tuple[str, ...]:
        """Probe ids booked against one system (mint order)."""
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            return tuple(self._systems[sid])

    def detections_for(self, probe_id: Any, seq: Any) -> Tuple[str, ...]:
        """Detection ids booked against one probe (mint order)."""
        with self._lock:
            self._check_seq(seq)
            pid = _require_id(probe_id, "probe_id")
            if pid not in self._probes:
                raise UnknownProbeError(f"unknown probe: {pid!r}")
            return tuple(self._detections_by_probe.get(pid, ()))

    def mitigations_for(self, system_id: Any, seq: Any) -> Tuple[str, ...]:
        """Mitigation ids booked against one system (mint order)."""
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            return tuple(self._mitigations_by_system.get(sid, ()))

    def retired_ids(self, seq: Any) -> Tuple[str, ...]:
        """All retired system ids."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._retired.keys())

    def report(self, system_id: Any, seq: Any) -> HackReport:
        """Per-system probe/detection/mitigation tallies (pure read).

        ``integrity_ok`` is ledger truth derived from digest pins -
        as data, never proof the system is hack-free.
        """
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            probe_ids = self._systems[sid]
            det_ids: List[str] = []
            for pid in probe_ids:
                det_ids.extend(self._detections_by_probe.get(pid, ()))
            n_hack = sum(
                1
                for did in det_ids
                if self._detections[did].verdict == "hack-detected"
            )
            mit_ids = self._mitigations_by_system.get(sid, ())
            integrity_ok = all(
                rec.verify()
                for rec in (
                    *(self._probes[pid] for pid in probe_ids),
                    *(self._detections[did] for did in det_ids),
                    *(self._mitigations[mid] for mid in mit_ids),
                )
            )
            return HackReport(
                system_id=sid,
                n_probes=len(probe_ids),
                n_detections=len(det_ids),
                n_hack_detected=n_hack,
                n_mitigations=len(mit_ids),
                integrity_ok=integrity_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "system_id": sid,
                        "n_probes": len(probe_ids),
                        "n_detections": len(det_ids),
                        "n_hack_detected": n_hack,
                        "n_mitigations": len(mit_ids),
                        "integrity_ok": integrity_ok,
                    }
                ),
            )

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
                "probes": len(self._probes),
                "detections": len(self._detections),
                "mitigations": len(self._mitigations),
                "retired": len(self._retired),
                "rejected": self._rejected,
            }


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    rh = RewardHacking()
    pin = "sha256:" + "ab" * 32
    prb = rh.test("sys-1", "specification-gaming", 1, probe_digest=pin)
    assert prb.probe_id == "prb-1"
    det = rh.detect("prb-1", 2, verdict="hack-detected", evidence_digest=pin)
    assert det.detection_id == "det-1"
    mit = rh.mitigate("det-1", 3, measure="respecify-reward", plan_digest=pin)
    assert mit.mitigation_id == "mit-1"
    rh.retire("sys-1", 4, reason="decommissioned")
    rep = rh.report("sys-1", 5)
    assert rep.verify()
    assert rep.integrity_ok is True
    assert rep.n_hack_detected == 1
    assert rh.stats(6) == {
        "systems": 1,
        "probes": 1,
        "detections": 1,
        "mitigations": 1,
        "retired": 1,
        "rejected": 0,
    }
    print("reward-hacking OK: test, detect, mitigate, retire, pins, audit")


if __name__ == "__main__":
    main()
