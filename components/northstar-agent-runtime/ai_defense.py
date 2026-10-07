"""AI defense: defense-operations decision ledger, Simulated.

Research note: AI defense is the field concerned with *defending* AI
systems when they come under hostile action - the operational side of
AI security. Where threat detection asks "what is attacking us" and
security assessment asks "where are we vulnerable", defense asks "what
do we have in place, what did we engage, and did it hold". This module
is the *decision ledger* for declared AI defenses: which systems
declared which defense postures (over a pinned defense-kind
vocabulary), which defense engagements the host declared against which
declared threats (over a pinned threat vocabulary), what outcomes were
booked, and what defense posture the ledger derives - defensible
bookkeeping, never proof that a system really withstood an attack.

This module owns the declare -> defend -> evaluate lifecycle:

* **declare()** - book one declared defense posture (minted ``dcl-N``
  ids; pinned defense-kind vocabulary; pinned readiness vocabulary
  booked *as data*); the first declaration registers its system; raw
  defense plans, configs, rules, and material never enter records -
  digest pins only.
* **defend()** - book one declared defense engagement against a pinned
  threat kind (minted ``def-N`` ids; pinned outcome vocabulary booked
  *as data*); fail-closed on unknown/retired systems; books the
  *declaration*, never the actual defensive action.
* **verify()** - **pure read**: re-derive one declaration/defense
  record's digest pin; verdict ``verified`` / ``tampered`` booked as
  data, never as proof the defense really happened.
* **evaluate()** - **pure read**: derive one system's defense posture
  as data (``unprotected`` -> ``breached`` -> ``contested`` ->
  ``resilient`` -> ``defended``) with outcome tallies and a
  digest-pinned integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_security.py`` owns the
security *assessment* lifecycle (assess -> mitigate over security-threat
classes); ``injection_detector.py``, ``jailbreak_defense.py``,
``adversarial_detector.py``, and ``data_poisoning_detector.py`` own
*detection mechanics* (they run the detectors);
``threat_hunting.py`` / ``threat_intel.py`` own threat bookkeeping;
``ai_safety.py`` owns the AI-*safety* assessment/mitigation lifecycle;
``ai_policy.py`` owns per-system policy/enforcement - this module is
the AI-*defense* operations ledger none of them own: declared defense
postures -> declared defense engagements -> digest re-derivation ->
the ledger-rule posture that turns declared outcomes into a defense
claim, always as data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-defense.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with
the standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no defenses, blocks no attacks, inspects
no systems, and proves nothing about real AI defense. A booked
``blocked`` outcome means "the host declared it", never "the attack was
stopped"; a booked ``ready`` readiness means "the host declared it",
never "the defense is ready". Attack payloads, exploit code, weights,
prompts, credentials, configs, and raw defense material never enter
records or cross the audit boundary - digest pins only.
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
AI_DEFENSE_VERSION = "ai-defense.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-defense.v1"

#: Pinned defense-kind vocabulary (the defense classes declared).
DEFENSE_KINDS = (
    "input-filtering",
    "output-filtering",
    "adversarial-training",
    "red-teaming",
    "monitoring",
    "isolation",
    "rate-limiting",
    "graceful-degradation",
)

#: Pinned defense-readiness vocabulary (booked as data, never proof).
READINESS = (
    "ready",
    "partial",
    "not-ready",
    "degraded",
)

#: Pinned threat vocabulary the defense engages (booked as data).
THREAT_KINDS = (
    "prompt-injection",
    "model-extraction",
    "data-poisoning",
    "backdoor-insertion",
    "jailbreak",
    "adversarial-example",
    "supply-chain-compromise",
    "inference-abuse",
)

#: Pinned defense-outcome vocabulary (booked as data, never proof).
DEFENSE_OUTCOMES = (
    "blocked",
    "mitigated",
    "breached",
    "inconclusive",
    "not-engaged",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unprotected",
    "breached",
    "contested",
    "resilient",
    "defended",
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
    "declared",
    "defended",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "attack",
        "attacks",
        "attacker",
        "payload",
        "payloads",
        "exploit",
        "exploits",
        "shellcode",
        "backdoor",
        "malware",
        "ioc",
        "indicators",
        "tactic",
        "tactics",
        "technique",
        "techniques",
        "vector",
        "vectors",
        "signature",
        "signatures",
        "rule",
        "rules",
        "pattern",
        "patterns",
        "config",
        "configs",
        "configuration",
        "plan",
        "plans",
        "playbook",
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
        "activations",
        "gradients",
        "trajectory",
        "trajectories",
        "transcript",
        "transcripts",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "telemetry",
        "log",
        "logs",
        "trace",
        "traces",
        "dump",
        "dumps",
        "pcap",
        "snapshot",
        "snapshots",
        "memory",
        "checkpoint_data",
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


class AIDefenseError(Exception):
    """Base class for all ai-defense ledger errors."""


class BadSystemError(AIDefenseError):
    pass


class UnknownSystemError(AIDefenseError):
    pass


class RetiredSystemError(AIDefenseError):
    pass


class BadDefenseKindError(AIDefenseError):
    pass


class BadReadinessError(AIDefenseError):
    pass


class BadThreatKindError(AIDefenseError):
    pass


class BadOutcomeError(AIDefenseError):
    pass


class BadDigestError(AIDefenseError):
    pass


class BadReasonError(AIDefenseError):
    pass


class UnknownDeclarationError(AIDefenseError):
    pass


class UnknownDefenseError(AIDefenseError):
    pass


class UnknownRecordError(AIDefenseError):
    pass


class SeqOrderError(AIDefenseError):
    pass


class AuditKindError(AIDefenseError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_defense_kind(value: Any) -> str:
    if value not in DEFENSE_KINDS:
        raise BadDefenseKindError(f"defense_kind must be one of {DEFENSE_KINDS}")
    return value


def _check_readiness(value: Any) -> str:
    if value not in READINESS:
        raise BadReadinessError(f"readiness must be one of {READINESS}")
    return value


def _check_threat_kind(value: Any) -> str:
    if value not in THREAT_KINDS:
        raise BadThreatKindError(f"threat_kind must be one of {THREAT_KINDS}")
    return value


def _check_outcome(value: Any) -> str:
    if value not in DEFENSE_OUTCOMES:
        raise BadOutcomeError(f"outcome must be one of {DEFENSE_OUTCOMES}")
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
class DeclarationRecord:
    declaration_id: str
    system_id: str
    seq: int
    defense_kind: str
    readiness: str
    declaration_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _declare_payload(self), "ai-defense.declare"
        )


@dataclass(frozen=True)
class DefenseRecord:
    defense_id: str
    system_id: str
    seq: int
    threat_kind: str
    outcome: str
    defense_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _defend_payload(self), "ai-defense.defend"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-defense.retire"
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
            _verify_payload(self), "ai-defense.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_declarations: int
    n_defenses: int
    n_blocked: int
    n_mitigated: int
    n_breached: int
    n_inconclusive: int
    n_not_engaged: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-defense.evaluate"
        )


def _declare_payload(rec: "DeclarationRecord") -> Dict[str, Any]:
    return {
        "declaration_id": rec.declaration_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "defense_kind": rec.defense_kind,
        "readiness": rec.readiness,
        "declaration_digest": rec.declaration_digest,
    }


def _defend_payload(rec: "DefenseRecord") -> Dict[str, Any]:
    return {
        "defense_id": rec.defense_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "threat_kind": rec.threat_kind,
        "outcome": rec.outcome,
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
        "n_declarations": rep.n_declarations,
        "n_defenses": rep.n_defenses,
        "n_blocked": rep.n_blocked,
        "n_mitigated": rep.n_mitigated,
        "n_breached": rep.n_breached,
        "n_inconclusive": rep.n_inconclusive,
        "n_not_engaged": rep.n_not_engaged,
        "integrity_ok": rep.integrity_ok,
    }


def ai_defense_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AIDefenseError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-defense",
        "version": AI_DEFENSE_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIDefense:
    """AI-defense operations decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All declarations, defenses,
    and outcomes are booked as data - never proof that a system really
    defended anything.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._declarations: Dict[str, DeclarationRecord] = {}
        self._defenses: Dict[str, DefenseRecord] = {}
        self._system_declarations: Dict[str, List[str]] = {}
        self._system_defenses: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._declaration_counter = 0
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
            row = ai_defense_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-defense",
                "version": AI_DEFENSE_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_defense_audit_event(audit_kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def declare(
        self,
        system_id: str,
        seq: int,
        defense_kind: str = "input-filtering",
        readiness: str = "not-ready",
        declaration_digest: str = "",
    ) -> DeclarationRecord:
        """Book one declared defense posture (minted ``dcl-N`` id).

        The first declaration on an id registers the system. Raw defense
        plans, configs, rules, and material never enter records - digest
        pins only. Fail-closed: failed mutations consume their seq and
        book an ``ai-defense.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                defense_kind = _check_defense_kind(defense_kind)
                readiness = _check_readiness(readiness)
                declaration_digest = _check_digest(
                    declaration_digest, "declaration_digest"
                )
                self._require_live(system_id)
            except AIDefenseError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._declaration_counter += 1
            declaration_id = f"dcl-{self._declaration_counter}"
            provisional = DeclarationRecord(
                declaration_id=declaration_id,
                system_id=system_id,
                seq=seq,
                defense_kind=defense_kind,
                readiness=readiness,
                declaration_digest=declaration_digest,
                digest="",
            )
            digest = _digest_pin(_declare_payload(provisional), "ai-defense.declare")
            rec = DeclarationRecord(
                declaration_id=declaration_id,
                system_id=system_id,
                seq=seq,
                defense_kind=defense_kind,
                readiness=readiness,
                declaration_digest=declaration_digest,
                digest=digest,
            )
            self._declarations[declaration_id] = rec
            self._system_declarations.setdefault(system_id, []).append(declaration_id)
            self._emit(
                "declared",
                seq,
                declaration_id=declaration_id,
                system_id=system_id,
                defense_kind=defense_kind,
                readiness=readiness,
            )
            return rec

    def defend(
        self,
        system_id: str,
        seq: int,
        threat_kind: str = "prompt-injection",
        outcome: str = "not-engaged",
        defense_digest: str = "",
    ) -> DefenseRecord:
        """Book one declared defense engagement (minted ``def-N`` id).

        Books the *declaration*, never the actual defensive action.
        Fail-closed: unknown systems raise (a defense requires a
        registered system); failed mutations consume their seq and book
        an ``ai-defense.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                threat_kind = _check_threat_kind(threat_kind)
                outcome = _check_outcome(outcome)
                defense_digest = _check_digest(defense_digest, "defense_digest")
                if system_id not in self._system_declarations:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                self._require_live(system_id)
            except AIDefenseError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._defense_counter += 1
            defense_id = f"def-{self._defense_counter}"
            provisional = DefenseRecord(
                defense_id=defense_id,
                system_id=system_id,
                seq=seq,
                threat_kind=threat_kind,
                outcome=outcome,
                defense_digest=defense_digest,
                digest="",
            )
            digest = _digest_pin(_defend_payload(provisional), "ai-defense.defend")
            rec = DefenseRecord(
                defense_id=defense_id,
                system_id=system_id,
                seq=seq,
                threat_kind=threat_kind,
                outcome=outcome,
                defense_digest=defense_digest,
                digest=digest,
            )
            self._defenses[defense_id] = rec
            self._system_defenses.setdefault(system_id, []).append(defense_id)
            self._emit(
                "defended",
                seq,
                defense_id=defense_id,
                system_id=system_id,
                threat_kind=threat_kind,
                outcome=outcome,
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
                if system_id not in self._system_declarations:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system already retired: {system_id!r}"
                    )
            except AIDefenseError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-defense.retire")
            rec = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        return seq

    def _integrity_ok(self, system_id: str) -> bool:
        return all(
            self._declarations[did].verify()
            for did in self._system_declarations.get(system_id, [])
        ) and all(
            self._defenses[fid].verify()
            for fid in self._system_defenses.get(system_id, [])
        )

    def _posture(self, system_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "blocked": 0,
            "mitigated": 0,
            "breached": 0,
            "inconclusive": 0,
            "not-engaged": 0,
        }
        ids = self._system_defenses.get(system_id, [])
        for fid in ids:
            tallies[self._defenses[fid].outcome] += 1
        if not ids:
            return "unprotected", tallies
        if tallies["breached"]:
            return "breached", tallies
        if tallies["inconclusive"]:
            return "contested", tallies
        if all(self._defenses[fid].outcome == "blocked" for fid in ids):
            return "defended", tallies
        if all(self._defenses[fid].outcome == "mitigated" for fid in ids):
            return "resilient", tallies
        return "unprotected", tallies

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one record's digest pin; verdict as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._declarations.get(record_id) or self._defenses.get(record_id)
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
            digest = _digest_pin(_verify_payload(provisional), "ai-defense.verify")
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's defense posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_declarations:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            posture, tallies = self._posture(system_id)
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_declarations=len(self._system_declarations[system_id]),
                n_defenses=len(self._system_defenses.get(system_id, [])),
                n_blocked=tallies["blocked"],
                n_mitigated=tallies["mitigated"],
                n_breached=tallies["breached"],
                n_inconclusive=tallies["inconclusive"],
                n_not_engaged=tallies["not-engaged"],
                integrity_ok=self._integrity_ok(system_id),
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-defense.evaluate")
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_declarations=len(self._system_declarations[system_id]),
                n_defenses=len(self._system_defenses.get(system_id, [])),
                n_blocked=tallies["blocked"],
                n_mitigated=tallies["mitigated"],
                n_breached=tallies["breached"],
                n_inconclusive=tallies["inconclusive"],
                n_not_engaged=tallies["not-engaged"],
                integrity_ok=self._integrity_ok(system_id),
                digest=digest,
            )

    # -- views (pure reads) --------------------------------------------------

    def declaration_record(self, declaration_id: str, seq: int) -> DeclarationRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._declarations.get(declaration_id)
            if rec is None:
                raise UnknownDeclarationError(
                    f"unknown declaration: {declaration_id!r}"
                )
            return rec

    def defense_record(self, defense_id: str, seq: int) -> DefenseRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._defenses.get(defense_id)
            if rec is None:
                raise UnknownDefenseError(f"unknown defense: {defense_id!r}")
            return rec

    def declarations_for(self, system_id: str, seq: int) -> Tuple[DeclarationRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._declarations[did]
                for did in self._system_declarations.get(system_id, [])
            )

    def defenses_for(self, system_id: str, seq: int) -> Tuple[DefenseRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._defenses[fid]
                for fid in self._system_defenses.get(system_id, [])
            )

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._system_declarations.keys()))

    def declaration_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._declarations.keys()))

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
                "n_systems": len(self._system_declarations),
                "n_declarations": len(self._declarations),
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
    """Self-check: exercise declare -> defend -> verify -> evaluate."""
    ledger = AIDefense()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.declare(
        "sys-1", 1, defense_kind="input-filtering", readiness="ready"
    )
    assert rec.verify()
    dfn = ledger.defend(
        "sys-1", 2, threat_kind="prompt-injection", outcome="blocked"
    )
    assert dfn.verify()
    rep = ledger.verify(dfn.defense_id, 3)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("sys-1", 4)
    assert ev.posture == "defended"
    ret = ledger.retire("sys-1", 5)
    assert ret.verify()
    print("ai-defense OK: declare, defend, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
