"""AI attack: attack detection/defense decision ledger, Simulated.

Research note: AI attacks are the hostile actions directed at AI
systems - prompt injection, jailbreaks, model extraction, data
poisoning, backdoor triggers, adversarial examples, inference abuse,
and supply-chain compromise. This module is the *decision ledger* for
declared AI-attack activity: which systems had which attack detections
booked (over a pinned attack-kind vocabulary), what verdicts were
declared against them, what defenses the host declared, and what attack
posture the ledger derives - defensible bookkeeping, never proof that a
system is really under attack or really defended.

This module owns the detect -> defend -> verify lifecycle:

* **detect()** - book one declared attack detection (minted ``det-N``
  ids; pinned attack-kind vocabulary over the common AI-attack classes;
  pinned verdict vocabulary booked *as data*); the first detection
  registers its system; raw payloads, exploit code, weights, and
  material never enter records - digest pins only.
* **defend()** - book one declared defense against a booked detection
  (minted ``def-N`` ids; pinned defense-strategy vocabulary booked *as
  data*); repeatable chain; books the *declaration*, never the deployed
  defense.
* **verify()** - **pure read**: re-derive one detection/defense record's
  digest pin; verdict ``verified`` / ``tampered`` booked as data, never
  as proof the detection really happened.
* **evaluate()** - **pure read**: derive one system's attack posture as
  data (``unassessed`` -> ``under-attack`` -> ``contested`` ->
  ``defended`` -> ``clean``) with verdict tallies and a digest-pinned
  integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings:
``federated_attack_detector.py`` owns *federated-attack detection
mechanics*; ``injection_detector.py`` / ``jailbreak_defense.py`` /
``adversarial_detector.py`` own detector mechanics;
``threat_hunting.py`` / ``threat_intel.py`` own threat bookkeeping;
``ai_security.py`` owns the AI-*security* assessment/mitigation
lifecycle over security-threat classes - this module is the AI-*attack*
detection/defense decision ledger none of them own: declared attack
detections over the pinned attack vocabulary, declared defenses,
digest re-derivation, and the ledger-rule posture that turns declared
verdicts into an attack claim, always as data, never as measured
truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-attack.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with
the standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no detectors, inspects no systems,
deploys no defenses, and proves nothing about real AI attacks. A booked
``attack-detected`` verdict means "the host declared it", never "the
system was attacked"; a booked defense means "the host declared it",
never "the attack was stopped". Payloads, exploit code, weights,
credentials, and raw detection material never enter records or cross
the audit boundary - digest pins only.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Module version pin.
AI_ATTACK_VERSION = "ai-attack.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-attack.v1"

#: Pinned attack-kind vocabulary (the AI-attack classes detected).
ATTACK_KINDS = (
    "prompt-injection",
    "jailbreak",
    "model-extraction",
    "data-poisoning",
    "backdoor-trigger",
    "adversarial-example",
    "inference-abuse",
    "supply-chain-attack",
)

#: Pinned detection-verdict vocabulary (booked as data, never proof).
DETECT_VERDICTS = (
    "attack-detected",
    "suspected",
    "inconclusive",
    "no-attack",
)

#: Pinned defense-strategy vocabulary (booked as data, never proof).
DEFENSE_STRATEGIES = (
    "block-source",
    "isolate-system",
    "input-filtering",
    "rate-limiting",
    "rotate-credentials",
    "patch-deployment",
    "escalate-response",
    "no-action",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unassessed",
    "under-attack",
    "contested",
    "defended",
    "clean",
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
    "defended",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "payload",
        "payloads",
        "exploit",
        "exploits",
        "shellcode",
        "backdoor",
        "malware",
        "vulnerability",
        "vulnerabilities",
        "cve",
        "zero_day",
        "credentials",
        "credential",
        "password",
        "passwords",
        "api_key",
        "secret_key",
        "private_key",
        "ssh_key",
        "certificate",
        "token",
        "session_token",
        "auth",
        "weights",
        "model_weights",
        "parameters",
        "params",
        "policy",
        "policies",
        "trajectory",
        "trajectories",
        "transcript",
        "transcripts",
        "log",
        "logs",
        "trace",
        "traces",
        "telemetry",
        "recording",
        "recordings",
        "dump",
        "dumps",
        "snapshot",
        "snapshots",
        "memory",
        "weights_file",
        "checkpoint_data",
        "activations",
        "gradients",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "command_output",
        "stderr",
        "stdout",
        "heartbeat",
        "behavior",
        "demonstration",
        "preference",
        "feedback",
        "reward",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIAttackError(Exception):
    """Base class for all ai-attack ledger errors."""


class BadSystemError(AIAttackError):
    pass


class UnknownSystemError(AIAttackError):
    pass


class RetiredSystemError(AIAttackError):
    pass


class BadAttackKindError(AIAttackError):
    pass


class BadVerdictError(AIAttackError):
    pass


class BadSeverityError(AIAttackError):
    pass


class BadDigestError(AIAttackError):
    pass


class BadReasonError(AIAttackError):
    pass


class UnknownDetectionError(AIAttackError):
    pass


class UnknownDefenseError(AIAttackError):
    pass


class UnknownRecordError(AIAttackError):
    pass


class BadStrategyError(AIAttackError):
    pass


class SeqOrderError(AIAttackError):
    pass


class AuditKindError(AIAttackError):
    pass


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_attack_kind(value: Any) -> str:
    if value not in ATTACK_KINDS:
        raise BadAttackKindError(f"attack_kind must be one of {ATTACK_KINDS}")
    return value


def _check_verdict(value: Any) -> str:
    if value not in DETECT_VERDICTS:
        raise BadVerdictError(f"verdict must be one of {DETECT_VERDICTS}")
    return value


def _check_strategy(value: Any) -> str:
    if value not in DEFENSE_STRATEGIES:
        raise BadStrategyError(f"strategy must be one of {DEFENSE_STRATEGIES}")
    return value


def _check_severity(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadSeverityError("severity must be an int")
    if not 0 <= value <= 100:
        raise BadSeverityError("severity must be in [0, 100]")
    return value


def _check_digest(value: Any, what: str, allow_empty: bool = True) -> str:
    if value == "" and allow_empty:
        return ""
    if (
        isinstance(value, bool)
        or not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != 71
    ):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    hexpart = value[7:]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    return value


def _check_reason(value: Any) -> str:
    if value not in RETIRE_REASONS:
        raise BadReasonError(f"reason must be one of {RETIRE_REASONS}")
    return value


def _canonical_bytes(payload: Any) -> bytes:
    raw = _jcs_dumps(payload)
    return raw if isinstance(raw, bytes) else raw.encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    body = {"tag": tag, "schema": SCHEMA_PIN, "payload": payload}
    return "sha256:" + hashlib.sha256(_canonical_bytes(body)).hexdigest()


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    return seq


# ---------------------------------------------------------------------------
# Records (frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DetectionRecord:
    detection_id: str
    system_id: str
    seq: int
    attack_kind: str
    verdict: str
    severity: int
    detection_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _detect_payload(self), "ai-attack.detect"
        )


@dataclass(frozen=True)
class DefenseRecord:
    defense_id: str
    detection_id: str
    system_id: str
    seq: int
    strategy: str
    defense_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _defend_payload(self), "ai-attack.defend"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-attack.retire"
        )


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _verify_payload(self), "ai-attack.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_detections: int
    n_attack_detected: int
    n_suspected: int
    n_inconclusive: int
    n_no_attack: int
    n_defended: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-attack.evaluate"
        )


def _detect_payload(rec: "DetectionRecord") -> Dict[str, Any]:
    return {
        "detection_id": rec.detection_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "attack_kind": rec.attack_kind,
        "verdict": rec.verdict,
        "severity": rec.severity,
        "detection_digest": rec.detection_digest,
    }


def _defend_payload(rec: "DefenseRecord") -> Dict[str, Any]:
    return {
        "defense_id": rec.defense_id,
        "detection_id": rec.detection_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "strategy": rec.strategy,
        "defense_digest": rec.defense_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"system_id": rec.system_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "system_id": rep.system_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_detections": rep.n_detections,
        "n_attack_detected": rep.n_attack_detected,
        "n_suspected": rep.n_suspected,
        "n_inconclusive": rep.n_inconclusive,
        "n_no_attack": rep.n_no_attack,
        "n_defended": rep.n_defended,
        "integrity_ok": rep.integrity_ok,
    }


def ai_attack_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for this module.

    Fail-closed: unknown kinds raise; any banned key appearing raw in
    ``detail`` raises (digest pins of those values are fine - the key ban
    applies to raw material).
    """
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise SeqOrderError("seq must be an int")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AIAttackError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-attack",
        "version": AI_ATTACK_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIAttack:
    """AI-attack detection/defense decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All verdicts and defenses
    are booked as data - never proof that a system was really attacked
    or really defended.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._detections: Dict[str, DetectionRecord] = {}
        self._defenses: Dict[str, DefenseRecord] = {}
        self._system_detections: Dict[str, List[str]] = {}
        self._detection_defenses: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._detection_counter = 0
        self._defense_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _require_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._require_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = ai_attack_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-attack",
                "version": AI_ATTACK_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_attack_audit_event(kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def detect(
        self,
        system_id: str,
        seq: int,
        attack_kind: str = "prompt-injection",
        verdict: str = "no-attack",
        severity: int = 0,
        detection_digest: str = "",
    ) -> DetectionRecord:
        """Book one declared attack detection (minted ``det-N`` id).

        The first detection on an id registers the system. Raw payloads,
        exploit code, and material never enter records - digest pins
        only. Fail-closed: failed mutations consume their seq and book
        an ``ai-attack.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                attack_kind = _check_attack_kind(attack_kind)
                verdict = _check_verdict(verdict)
                severity = _check_severity(severity)
                detection_digest = _check_digest(
                    detection_digest, "detection_digest"
                )
                self._require_live(system_id)
            except AIAttackError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._detection_counter += 1
            detection_id = f"det-{self._detection_counter}"
            provisional = DetectionRecord(
                detection_id=detection_id,
                system_id=system_id,
                seq=seq,
                attack_kind=attack_kind,
                verdict=verdict,
                severity=severity,
                detection_digest=detection_digest,
                digest="",
            )
            digest = _digest_pin(_detect_payload(provisional), "ai-attack.detect")
            rec = DetectionRecord(
                detection_id=detection_id,
                system_id=system_id,
                seq=seq,
                attack_kind=attack_kind,
                verdict=verdict,
                severity=severity,
                detection_digest=detection_digest,
                digest=digest,
            )
            self._detections[detection_id] = rec
            self._system_detections.setdefault(system_id, []).append(detection_id)
            self._emit(
                "detected",
                seq,
                detection_id=detection_id,
                system_id=system_id,
                attack_kind=attack_kind,
                verdict=verdict,
                severity=severity,
            )
            return rec

    def defend(
        self,
        detection_id: str,
        seq: int,
        strategy: str = "no-action",
        defense_digest: str = "",
    ) -> DefenseRecord:
        """Book one declared defense against a booked detection (minted ``def-N`` id).

        Books the *declaration*, never the deployed defense. Repeatable
        as a chain. Fail-closed: failed mutations consume their seq and
        book an ``ai-attack.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                detection_id = _check_id(detection_id, "detection_id")
                self._require_seq(seq)
                strategy = _check_strategy(strategy)
                defense_digest = _check_digest(
                    defense_digest, "defense_digest"
                )
                detection = self._detections.get(detection_id)
                if detection is None:
                    raise UnknownDetectionError(
                        f"unknown detection: {detection_id!r}"
                    )
                self._require_live(detection.system_id)
            except AIAttackError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._defense_counter += 1
            defense_id = f"def-{self._defense_counter}"
            provisional = DefenseRecord(
                defense_id=defense_id,
                detection_id=detection_id,
                system_id=detection.system_id,
                seq=seq,
                strategy=strategy,
                defense_digest=defense_digest,
                digest="",
            )
            digest = _digest_pin(_defend_payload(provisional), "ai-attack.defend")
            rec = DefenseRecord(
                defense_id=defense_id,
                detection_id=detection_id,
                system_id=detection.system_id,
                seq=seq,
                strategy=strategy,
                defense_digest=defense_digest,
                digest=digest,
            )
            self._defenses[defense_id] = rec
            self._detection_defenses.setdefault(detection_id, []).append(
                defense_id
            )
            self._emit(
                "defended",
                seq,
                defense_id=defense_id,
                detection_id=detection_id,
                system_id=detection.system_id,
                strategy=strategy,
            )
            return rec

    def retire(
        self, system_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminally retire a system id; ids are never recycled."""
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if system_id not in self._system_detections:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system already retired: {system_id!r}"
                    )
            except AIAttackError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-attack.retire")
            rec = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure reads ----------------------------------------------------------

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        return seq

    def _integrity_ok(self, system_id: str) -> bool:
        return all(
            self._detections[did].verify()
            and all(
                self._defenses[fid].verify()
                for fid in self._detection_defenses.get(did, [])
            )
            for did in self._system_detections.get(system_id, [])
        )

    def _posture(self, system_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "attack-detected": 0,
            "suspected": 0,
            "inconclusive": 0,
            "no-attack": 0,
            "defended": 0,
        }
        ids = self._system_detections.get(system_id, [])
        for did in ids:
            rec = self._detections[did]
            tallies[rec.verdict] += 1
            if self._detection_defenses.get(did):
                tallies["defended"] += 1
        if not ids:
            return "unassessed", tallies
        if any(
            self._detections[did].verdict == "attack-detected"
            and not self._detection_defenses.get(did)
            for did in ids
        ):
            return "under-attack", tallies
        if tallies["suspected"] or tallies["inconclusive"]:
            return "contested", tallies
        if tallies["attack-detected"]:
            return "defended", tallies
        if all(self._detections[did].verdict == "no-attack" for did in ids):
            return "clean", tallies
        return "contested", tallies

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one record's digest pin; verdict as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._detections.get(record_id) or self._defenses.get(record_id)
            if rec is None:
                raise UnknownRecordError(f"unknown record: {record_id!r}")
            verdict = "verified" if rec.verify() else "tampered"
            provisional = VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "ai-attack.verify")
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's attack posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_detections:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            posture, tallies = self._posture(system_id)
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_detections=len(self._system_detections[system_id]),
                n_attack_detected=tallies["attack-detected"],
                n_suspected=tallies["suspected"],
                n_inconclusive=tallies["inconclusive"],
                n_no_attack=tallies["no-attack"],
                n_defended=tallies["defended"],
                integrity_ok=self._integrity_ok(system_id),
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-attack.evaluate")
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_detections=len(self._system_detections[system_id]),
                n_attack_detected=tallies["attack-detected"],
                n_suspected=tallies["suspected"],
                n_inconclusive=tallies["inconclusive"],
                n_no_attack=tallies["no-attack"],
                n_defended=tallies["defended"],
                integrity_ok=self._integrity_ok(system_id),
                digest=digest,
            )

    # -- views (pure reads) ----------------------------------------------------

    def detection_record(self, detection_id: str, seq: int) -> DetectionRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._detections.get(detection_id)
            if rec is None:
                raise UnknownDetectionError(
                    f"unknown detection: {detection_id!r}"
                )
            return rec

    def defense_record(self, defense_id: str, seq: int) -> DefenseRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._defenses.get(defense_id)
            if rec is None:
                raise UnknownDefenseError(
                    f"unknown defense: {defense_id!r}"
                )
            return rec

    def detections_for(self, system_id: str, seq: int) -> Tuple[DetectionRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._detections[did]
                for did in self._system_detections.get(system_id, [])
            )

    def defenses_for(self, detection_id: str, seq: int) -> Tuple[DefenseRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._defenses[fid]
                for fid in self._detection_defenses.get(detection_id, [])
            )

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._system_detections.keys()))

    def detection_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._detections.keys()))

    def defense_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._defenses.keys()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired.keys()))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_systems": len(self._system_detections),
                "n_detections": len(self._detections),
                "n_defenses": len(self._defenses),
                "n_retired": len(self._retired),
                "n_audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# stdlib self-check and CLI
# ---------------------------------------------------------------------------


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
    """Self-check: exercise detect -> defend -> verify -> evaluate."""
    ledger = AIAttack()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.detect(
        "sys-1", 1, attack_kind="jailbreak",
        verdict="attack-detected", severity=70,
    )
    assert rec.verify()
    dfn = ledger.defend(rec.detection_id, 2, strategy="block-source")
    assert dfn.verify()
    rep = ledger.verify(rec.detection_id, 3)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("sys-1", 4)
    assert ev.posture == "defended"
    ret = ledger.retire("sys-1", 5)
    assert ret.verify()
    print("ai-attack OK: detect, defend, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
