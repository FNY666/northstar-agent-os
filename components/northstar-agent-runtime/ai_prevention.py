"""AI prevention: prevention-control decision ledger, Simulated.

Research note: AI prevention is the prevention side of the AI incident
lifecycle (prevent -> detect -> respond -> recover -> lessons-learned).
After a threat is declared (capability-abuse vector, model weakness,
deployment risk, data-poisoning vector, prompt-injection surface), what
prevention control the host declared it booked (access control, input
filtering, output filtering, capability gating, deployment guardrail,
data-lineage control, model hardening, rate limiting), what status it
declared against the control, and what prevention posture the ledger
derives for the threat. This module is the *decision ledger* for
declared prevention controls: which threats had which prevention kinds
booked (over a pinned prevention-kind vocabulary), what statuses were
declared against them, and what prevention posture the ledger derives -
defensible bookkeeping, never proof that any threat was really
prevented.

This module owns the prevent -> verify -> evaluate lifecycle:

* **prevent()** - book one declared prevention control (minted ``prv-N``
  ids; pinned prevention-kind vocabulary over the common prevention
  classes; pinned status vocabulary booked *as data*); the first
  prevention on a threat id registers the threat; raw threat material,
  telemetry, prompts, weights, and model internals never enter records -
  digest pins only.
* **verify()** - **pure read**: re-derive one prevention record's digest
  pin; verdict ``verified`` / ``tampered`` booked as data, never as
  proof the control is really deployed.
* **evaluate()** - **pure read**: derive one threat's prevention posture
  as data (``unprotected`` -> ``insufficient`` -> ``contested`` ->
  ``partially-prevented`` -> ``prevented``) with status tallies and a
  digest-pinned integrity flag.
* **retire()** - terminal retirement of a threat id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``disaster_recovery.py`` owns
operational disaster-recovery mechanics (declared backup/restore and
failover targets); ``ai_safety.py`` owns the safety assessment ->
mitigation lifecycle; ``ai_incident.py`` owns incident
declaration/investigation; ``ai_recovery.py`` owns incident-recovery
operations - this module is the *prevention-controls* ledger none of
them own: declared prevention controls booked against declared threats
*before* anything goes wrong, digest re-derivation, and the ledger-rule
posture that turns declared preventions into a prevention claim, always
as data, never as measured prevention.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-prevention.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with
the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module prevents nothing, blocks nothing, deploys
nothing, and proves nothing about real-world prevention outcomes. A
booked ``prevented`` posture means "the host declared it", never "the
threat is prevented"; a booked ``deployed`` status means "the host
declared it", never "the control is live". Threat material, telemetry,
prompts, weights, model internals, and raw prevention artifacts never
enter records or cross the audit boundary - digest pins only.
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
AI_PREVENTION_VERSION = "ai-prevention.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-prevention.v1"

#: Pinned prevention-kind vocabulary (the prevention classes).
PREVENTION_KINDS = (
    "access-control",
    "input-filtering",
    "output-filtering",
    "capability-gating",
    "deployment-guardrail",
    "data-lineage-control",
    "model-hardening",
    "rate-limiting",
)

#: Pinned prevention-status vocabulary (booked as data, never proof).
STATUSES = (
    "deployed",
    "pending",
    "failed",
    "bypassed",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unprotected",
    "insufficient",
    "contested",
    "partially-prevented",
    "prevented",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-start",
)

#: Audit kinds emitted by this module.
EMIT_KINDS = (
    "prevented",
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
        "checkpoint",
        "checkpoints",
        "backup",
        "backups",
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
        "evidence",
        "findings",
        "report",
        "reports",
        "incident_text",
        "incident_detail",
        "incident_description",
        "postmortem",
        "root_cause",
        "harm",
        "harm_description",
        "damage",
        "damages",
        "remedy_text",
        "threat_text",
        "threat_detail",
        "threat_description",
        "threat_intel",
        "attack_pattern",
        "attack_patterns",
        "control_text",
        "control_detail",
        "playbook",
        "runbook",
        "password",
        "passwords",
        "credential",
        "credentials",
        "secret",
        "secrets",
        "api_key",
        "api_keys",
        "token",
        "tokens",
        "private_key",
        "personal_data",
        "personal_information",
        "identity",
        "identity_document",
        "document",
        "documents",
        "contact",
        "contact_details",
        "address",
        "phone",
        "email",
        "dataset",
        "datasets",
        "training_data",
        "pii",
        "exploit",
        "exploits",
        "payload",
        "vulnerability_detail",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIPreventionError(Exception):
    """Base class for all ai-prevention ledger errors."""


class BadThreatError(AIPreventionError):
    pass


class UnknownThreatError(AIPreventionError):
    pass


class RetiredThreatError(AIPreventionError):
    pass


class BadPreventionKindError(AIPreventionError):
    pass


class BadStatusError(AIPreventionError):
    pass


class BadDigestError(AIPreventionError):
    pass


class BadReasonError(AIPreventionError):
    pass


class UnknownPreventionError(AIPreventionError):
    pass


class SeqOrderError(AIPreventionError):
    pass


class AuditKindError(AIPreventionError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadThreatError(f"{what} must be a non-empty string")
    return value


def _check_prevention_kind(value: Any) -> str:
    if value not in PREVENTION_KINDS:
        raise BadPreventionKindError(
            f"prevention_kind must be one of {PREVENTION_KINDS}"
        )
    return value


def _check_status(value: Any) -> str:
    if value not in STATUSES:
        raise BadStatusError(f"status must be one of {STATUSES}")
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


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PreventionRecord:
    prevention_id: str
    threat_id: str
    seq: int
    prevention_kind: str
    status: str
    threat_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _prevent_payload(self), "ai-prevention.prevent"
        )


@dataclass(frozen=True)
class RetireRecord:
    threat_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_retire_payload(self), "ai-prevention.retire")


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _verify_payload(self), "ai-prevention.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    threat_id: str
    seq: int
    posture: str
    n_preventions: int
    n_deployed: int
    n_pending: int
    n_failed: int
    n_bypassed: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-prevention.evaluate"
        )


def _prevent_payload(rec: "PreventionRecord") -> Dict[str, Any]:
    return {
        "prevention_id": rec.prevention_id,
        "threat_id": rec.threat_id,
        "seq": rec.seq,
        "prevention_kind": rec.prevention_kind,
        "status": rec.status,
        "threat_digest": rec.threat_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"threat_id": rec.threat_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "threat_id": rep.threat_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_preventions": rep.n_preventions,
        "n_deployed": rep.n_deployed,
        "n_pending": rep.n_pending,
        "n_failed": rep.n_failed,
        "n_bypassed": rep.n_bypassed,
        "integrity_ok": rep.integrity_ok,
    }


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def ai_prevention_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for this module.

    Fail-closed: unknown kinds raise; any banned key appearing raw in
    ``detail`` raises (digest pins of those values are fine - the key ban
    applies to raw material).
    """
    if kind not in EMIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AIPreventionError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-prevention",
        "version": AI_PREVENTION_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIPrevention:
    """AI-prevention prevention-control decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All outcomes are booked as
    data - never proof that any threat was really prevented.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._preventions: Dict[str, PreventionRecord] = {}
        self._threat_preventions: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._prevention_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _require_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
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
            row = ai_prevention_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-prevention",
                "version": AI_PREVENTION_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_prevention_audit_event(audit_kind, seq, **details))

    def _require_live(self, threat_id: str) -> None:
        if threat_id in self._retired:
            raise RetiredThreatError(f"threat is retired: {threat_id!r}")

    # -- mutations ---------------------------------------------------------

    def prevent(
        self,
        threat_id: str,
        seq: int,
        prevention_kind: str = "access-control",
        status: str = "deployed",
        threat_digest: str = "",
    ) -> PreventionRecord:
        """Book one declared prevention control (minted ``prv-N`` id).

        The first prevention on a threat id registers the threat. Raw
        threat material, telemetry, prompts, weights, and model internals
        never enter records - digest pins only. Fail-closed: failed
        mutations consume their seq and book an ``ai-prevention.rejected``
        row; rewinds raise bare.
        """
        with self._lock:
            try:
                threat_id = _check_id(threat_id, "threat_id")
                self._require_seq(seq)
                prevention_kind = _check_prevention_kind(prevention_kind)
                status = _check_status(status)
                threat_digest = _check_digest(threat_digest, "threat_digest")
                self._require_live(threat_id)
            except AIPreventionError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._prevention_counter += 1
            prevention_id = f"prv-{self._prevention_counter}"
            provisional = PreventionRecord(
                prevention_id=prevention_id,
                threat_id=threat_id,
                seq=seq,
                prevention_kind=prevention_kind,
                status=status,
                threat_digest=threat_digest,
                digest="",
            )
            digest = _digest_pin(_prevent_payload(provisional), "ai-prevention.prevent")
            rec = PreventionRecord(
                prevention_id=prevention_id,
                threat_id=threat_id,
                seq=seq,
                prevention_kind=prevention_kind,
                status=status,
                threat_digest=threat_digest,
                digest=digest,
            )
            self._preventions[prevention_id] = rec
            self._threat_preventions.setdefault(threat_id, []).append(prevention_id)
            self._emit(
                "prevented",
                seq,
                prevention_id=prevention_id,
                threat_id=threat_id,
                prevention_kind=prevention_kind,
                status=status,
                threat_digest=threat_digest,
            )
            return rec

    def retire(
        self, threat_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminal retirement of a threat id; ids are never recycled."""
        with self._lock:
            try:
                threat_id = _check_id(threat_id, "threat_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if threat_id in self._retired:
                    raise RetiredThreatError(f"threat is retired: {threat_id!r}")
                if threat_id not in self._threat_preventions:
                    raise UnknownThreatError(f"unknown threat: {threat_id!r}")
            except AIPreventionError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                threat_id=threat_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-prevention.retire")
            rec = RetireRecord(
                threat_id=threat_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[threat_id] = rec
            self._emit("retired", seq, threat_id=threat_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _check_read_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        return seq

    def verify(self, prevention_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one prevention record's digest pin.

        Verdict ``verified`` / ``tampered`` booked as data, never as
        proof the control is really deployed. Seq is shape-validated only -
        never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            if (
                isinstance(prevention_id, bool)
                or not isinstance(prevention_id, str)
                or prevention_id not in self._preventions
            ):
                raise UnknownPreventionError(f"unknown prevention id: {prevention_id!r}")
            rec = self._preventions[prevention_id]
            integrity_ok = rec.verify()
            verdict = "verified" if integrity_ok else "tampered"
            provisional = VerificationReport(
                record_id=prevention_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "ai-prevention.verify")
            return VerificationReport(
                record_id=prevention_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, threat_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one threat's prevention posture as data.

        Posture by ledger rule: ``unprotected`` (nothing booked) ->
        ``insufficient`` (any bypassed) -> ``contested`` (any failed) ->
        ``partially-prevented`` (any pending) -> ``prevented`` (all
        deployed). ``integrity_ok`` re-derives all in-scope digest pins
        as data. Seq is shape-validated only - never consumed, no audit
        row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            threat_id = _check_id(threat_id, "threat_id")
            if threat_id not in self._threat_preventions:
                raise UnknownThreatError(f"unknown threat: {threat_id!r}")
            ids = self._threat_preventions[threat_id]
            recs = [self._preventions[i] for i in ids]
            n_deployed = sum(1 for r in recs if r.status == "deployed")
            n_pending = sum(1 for r in recs if r.status == "pending")
            n_failed = sum(1 for r in recs if r.status == "failed")
            n_bypassed = sum(1 for r in recs if r.status == "bypassed")
            if n_bypassed:
                posture = "insufficient"
            elif n_failed:
                posture = "contested"
            elif n_pending:
                posture = "partially-prevented"
            elif n_deployed and n_deployed == len(recs):
                posture = "prevented"
            else:
                posture = "unprotected"
            integrity_ok = all(r.verify() for r in recs)
            provisional = EvaluationReport(
                threat_id=threat_id,
                seq=seq,
                posture=posture,
                n_preventions=len(recs),
                n_deployed=n_deployed,
                n_pending=n_pending,
                n_failed=n_failed,
                n_bypassed=n_bypassed,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(
                _evaluate_payload(provisional), "ai-prevention.evaluate"
            )
            return EvaluationReport(
                threat_id=threat_id,
                seq=seq,
                posture=posture,
                n_preventions=len(recs),
                n_deployed=n_deployed,
                n_pending=n_pending,
                n_failed=n_failed,
                n_bypassed=n_bypassed,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- views (pure reads, seq shape-validated only) ----------------------

    def prevention_record(self, prevention_id: str, seq: int) -> PreventionRecord:
        with self._lock:
            self._check_read_seq(seq)
            if prevention_id not in self._preventions:
                raise UnknownPreventionError(f"unknown prevention id: {prevention_id!r}")
            return self._preventions[prevention_id]

    def retire_record(self, threat_id: str, seq: int) -> RetireRecord:
        with self._lock:
            self._check_read_seq(seq)
            if threat_id not in self._retired:
                raise UnknownThreatError(f"unknown threat: {threat_id!r}")
            return self._retired[threat_id]

    def preventions_for(self, threat_id: str, seq: int) -> Tuple[PreventionRecord, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(
                self._preventions[i] for i in self._threat_preventions.get(threat_id, [])
            )

    def threat_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._threat_preventions))

    def prevention_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._preventions))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._check_read_seq(seq)
            return {
                "n_threats": len(self._threat_preventions),
                "n_preventions": len(self._preventions),
                "n_retired": len(self._retired),
                "seq": self._seq,
                "version": AI_PREVENTION_VERSION,
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(self._audit)


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
    """Self-check: exercise prevent -> verify -> evaluate."""
    ledger = AIPrevention()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.prevent(
        "threat-1",
        1,
        prevention_kind="input-filtering",
        status="deployed",
    )
    assert rec.verify()
    rep = ledger.verify(rec.prevention_id, 2)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("threat-1", 3)
    assert ev.posture == "prevented"
    ret = ledger.retire("threat-1", 4)
    assert ret.verify()
    print("ai-prevention OK: prevent, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
