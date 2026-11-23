"""AI red-teaming: red-team exercise decision ledger, Simulated.

Research note: red-teaming is the practice of adversarially probing an AI
system - crafting attacks to find where it breaks, leaks, or can be
misused. This module is the *decision ledger* for declared AI red-team
exercises: which systems had which red-team runs booked (over a pinned
attack vocabulary), what outcomes were declared against them, and what
defensive posture the ledger derives - defensible bookkeeping, never
proof that a system is really secure or really vulnerable.

This module owns the redteam -> verify -> evaluate lifecycle:

* **redteam()** - book one declared red-team run (minted ``rtm-N`` ids;
  pinned attack-kind vocabulary over the common AI attack classes; pinned
  outcome vocabulary booked *as data*); the first run registers its
  system; raw attack prompts, payloads, exploits, and material never enter
  records - digest pins only.
* **verify()** - **pure read**: re-derive one red-team record's digest
  pin; verdict ``verified`` / ``tampered`` booked as data, never as proof
  the exercise really happened.
* **evaluate()** - **pure read**: derive one system's red-team posture as
  data (``untested`` -> ``vulnerable`` -> ``contested`` -> ``resilient``
  -> ``clean``) with outcome tallies and a digest-pinned integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``red_team.py`` and
``red_teaming.py`` own the red-team *run mechanics* (scenario execution
and run lifecycle); ``reward_hacking.py`` and ``deceptive_alignment.py``
own red-team *behavior* ledgers; ``ai_security.py`` owns security
*assessments*; ``ai_attack.py`` owns attack *detection* - this module is
the AI red-team *exercise* decision ledger none of them own: declared
runs, digest re-derivation, and the ledger-rule posture that turns
declared outcomes into a defensive claim, always as data, never as
measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-redteaming.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no attacks, probes no systems, and proves
nothing about real AI security. A booked ``exploited`` outcome means
"the host declared it", never "the system is exploitable"; a booked
``blocked`` outcome means "the host declared it", never "the attack was
stopped". Attack prompts, payloads, exploits, transcripts, and raw
red-team material never enter records or cross the audit boundary -
digest pins only.
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
AI_REDTEAMING_VERSION = "ai-redteaming.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-redteaming.v1"

#: Pinned attack-kind vocabulary (the AI attack classes exercised).
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

#: Pinned red-team outcome vocabulary (booked as data, never proof).
REDTEAM_OUTCOMES = (
    "exploited",
    "blocked",
    "inconclusive",
    "no-attack",
    "not-run",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "untested",
    "vulnerable",
    "contested",
    "resilient",
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
    "redteamed",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
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
        # red-team attack material
        "payload",
        "payloads",
        "exploit",
        "exploits",
        "shellcode",
        "attack",
        "attacks",
        "attack_prompt",
        "attack_vector",
        "attack_plan",
        "jailbreak_prompt",
        "adversarial_input",
        "adversarial_example",
        "command",
        "commands",
        "c2",
        "credential",
        "credentials",
        "password",
        "api_key",
        "secret",
        "token",
        "poc",
        "fuzzer_seed",
        "scenario",
        "attack_trace",
        "run_log",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIRedteamingError(Exception):
    """Base class for all ai-redteaming ledger errors."""


class BadSystemError(AIRedteamingError):
    pass


class UnknownSystemError(AIRedteamingError):
    pass


class RetiredSystemError(AIRedteamingError):
    pass


class BadAttackKindError(AIRedteamingError):
    pass


class BadOutcomeError(AIRedteamingError):
    pass


class BadSeverityError(AIRedteamingError):
    pass


class BadDigestError(AIRedteamingError):
    pass


class BadReasonError(AIRedteamingError):
    pass


class UnknownRedteamError(AIRedteamingError):
    pass


class UnknownRecordError(AIRedteamingError):
    pass


class SeqOrderError(AIRedteamingError):
    pass


class AuditKindError(AIRedteamingError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_attack_kind(value: Any) -> str:
    if value not in ATTACK_KINDS:
        raise BadAttackKindError(f"attack_kind must be one of {ATTACK_KINDS}")
    return value


def _check_outcome(value: Any) -> str:
    if value not in REDTEAM_OUTCOMES:
        raise BadOutcomeError(f"outcome must be one of {REDTEAM_OUTCOMES}")
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
class RedteamRecord:
    redteam_id: str
    system_id: str
    seq: int
    attack_kind: str
    outcome: str
    severity: int
    redteam_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _redteam_payload(self), "ai-redteaming.redteam"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-redteaming.retire"
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
            _verify_payload(self), "ai-redteaming.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_redteams: int
    n_exploited: int
    n_blocked: int
    n_inconclusive: int
    n_no_attack: int
    n_not_run: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-redteaming.evaluate"
        )


def _redteam_payload(rec: "RedteamRecord") -> Dict[str, Any]:
    return {
        "redteam_id": rec.redteam_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "attack_kind": rec.attack_kind,
        "outcome": rec.outcome,
        "severity": rec.severity,
        "redteam_digest": rec.redteam_digest,
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
        "n_redteams": rep.n_redteams,
        "n_exploited": rep.n_exploited,
        "n_blocked": rep.n_blocked,
        "n_inconclusive": rep.n_inconclusive,
        "n_no_attack": rep.n_no_attack,
        "n_not_run": rep.n_not_run,
        "integrity_ok": rep.integrity_ok,
    }


def ai_redteaming_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AIRedteamingError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-redteaming",
        "version": AI_REDTEAMING_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIRedteaming:
    """AI red-teaming exercise decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All outcomes are booked as
    data - never proof that a system is really exploitable or secure.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._redteams: Dict[str, RedteamRecord] = {}
        self._system_redteams: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._redteam_counter = 0
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
            row = ai_redteaming_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-redteaming",
                "version": AI_REDTEAMING_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_redteaming_audit_event(audit_kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def redteam(
        self,
        system_id: str,
        seq: int,
        attack_kind: str = "prompt-injection",
        outcome: str = "not-run",
        severity: int = 0,
        redteam_digest: str = "",
    ) -> RedteamRecord:
        """Book one declared red-team run (minted ``rtm-N`` id).

        The first run on an id registers the system. Raw attack prompts,
        payloads, exploits, and material never enter records - digest pins
        only. Fail-closed: failed mutations consume their seq and book an
        ``ai-redteaming.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                attack_kind = _check_attack_kind(attack_kind)
                outcome = _check_outcome(outcome)
                severity = _check_severity(severity)
                redteam_digest = _check_digest(redteam_digest, "redteam_digest")
                self._require_live(system_id)
            except AIRedteamingError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._redteam_counter += 1
            redteam_id = f"rtm-{self._redteam_counter}"
            provisional = RedteamRecord(
                redteam_id=redteam_id,
                system_id=system_id,
                seq=seq,
                attack_kind=attack_kind,
                outcome=outcome,
                severity=severity,
                redteam_digest=redteam_digest,
                digest="",
            )
            digest = _digest_pin(_redteam_payload(provisional), "ai-redteaming.redteam")
            rec = RedteamRecord(
                redteam_id=redteam_id,
                system_id=system_id,
                seq=seq,
                attack_kind=attack_kind,
                outcome=outcome,
                severity=severity,
                redteam_digest=redteam_digest,
                digest=digest,
            )
            self._redteams[redteam_id] = rec
            self._system_redteams.setdefault(system_id, []).append(redteam_id)
            self._emit(
                "redteamed",
                seq,
                redteam_id=redteam_id,
                system_id=system_id,
                attack_kind=attack_kind,
                outcome=outcome,
                severity=severity,
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
                if system_id not in self._system_redteams:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system already retired: {system_id!r}"
                    )
            except AIRedteamingError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-redteaming.retire")
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
            self._redteams[rid].verify()
            for rid in self._system_redteams.get(system_id, [])
        )

    def _posture(self, system_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "exploited": 0,
            "blocked": 0,
            "inconclusive": 0,
            "no-attack": 0,
            "not-run": 0,
        }
        ids = self._system_redteams.get(system_id, [])
        for rid in ids:
            tallies[self._redteams[rid].outcome] += 1
        if not ids:
            return "untested", tallies
        if tallies["exploited"]:
            return "vulnerable", tallies
        if tallies["inconclusive"]:
            return "contested", tallies
        if tallies["blocked"] and not tallies["no-attack"] and not tallies["not-run"]:
            return "resilient", tallies
        if all(
            self._redteams[rid].outcome in ("no-attack", "not-run") for rid in ids
        ):
            return "clean", tallies
        return "contested", tallies

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one record's digest pin; verdict as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._redteams.get(record_id)
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
            digest = _digest_pin(_verify_payload(provisional), "ai-redteaming.verify")
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's red-team posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_redteams:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            posture, tallies = self._posture(system_id)
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_redteams=len(self._system_redteams[system_id]),
                n_exploited=tallies["exploited"],
                n_blocked=tallies["blocked"],
                n_inconclusive=tallies["inconclusive"],
                n_no_attack=tallies["no-attack"],
                n_not_run=tallies["not-run"],
                integrity_ok=self._integrity_ok(system_id),
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-redteaming.evaluate")
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_redteams=len(self._system_redteams[system_id]),
                n_exploited=tallies["exploited"],
                n_blocked=tallies["blocked"],
                n_inconclusive=tallies["inconclusive"],
                n_no_attack=tallies["no-attack"],
                n_not_run=tallies["not-run"],
                integrity_ok=self._integrity_ok(system_id),
                digest=digest,
            )

    # -- views (pure reads) ----------------------------------------------------

    def redteam_record(self, redteam_id: str, seq: int) -> RedteamRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._redteams.get(redteam_id)
            if rec is None:
                raise UnknownRedteamError(
                    f"unknown redteam: {redteam_id!r}"
                )
            return rec

    def redteams_for(self, system_id: str, seq: int) -> Tuple[RedteamRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._redteams[rid]
                for rid in self._system_redteams.get(system_id, [])
            )

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._system_redteams.keys()))

    def redteam_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._redteams.keys()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired.keys()))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_systems": len(self._system_redteams),
                "n_redteams": len(self._redteams),
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
    """Self-check: exercise redteam -> verify -> evaluate."""
    ledger = AIRedteaming()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.redteam("sys-1", 1, attack_kind="jailbreak", outcome="exploited", severity=80)
    assert rec.verify()
    rec2 = ledger.redteam("sys-1", 2, attack_kind="jailbreak", outcome="blocked", severity=20)
    assert rec2.verify()
    rep = ledger.verify(rec.redteam_id, 3)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("sys-1", 4)
    assert ev.posture == "vulnerable"
    ret = ledger.retire("sys-1", 5)
    assert ret.verify()
    print("ai-redteaming OK: redteam, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
