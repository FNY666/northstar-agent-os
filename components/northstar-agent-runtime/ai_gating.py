"""AI gating: capability-gating decision ledger, Simulated.

Research note: AI gating is the permission-gate side of the AI safety
stack - for a declared agent (or session), which capabilities, tools,
actions, and data accesses the host declared it allowed or denied. This
module is the *decision ledger* for declared AI gating decisions: which
agents had which gate kinds booked (over a pinned gate-kind
vocabulary), which decisions (``allow`` / ``deny``) were declared
against them, and what gating posture the ledger derives for the agent.
Defensible bookkeeping, never proof that any gate was really enforced.

This module owns the gate -> verify -> evaluate lifecycle:

* **gate()** - book one declared gating decision (minted ``gate-N``
  ids; pinned gate-kind vocabulary over the common gate classes; the
  allow/deny decision booked *as data*); the first gate on an id
  registers the agent; raw agent material, tool calls, transcripts,
  weights, and permission payloads never enter records - digest pins
  only.
* **verify()** - **pure read**: re-derive one gate record's digest pin;
  verdict ``verified`` / ``tampered`` booked as data, never as proof
  the gate was really enforced.
* **evaluate()** - **pure read**: derive one agent's gating posture as
  data (``open`` -> ``allowlisted`` -> ``locked-down`` ->
  ``contested``) with allow/deny tallies and a digest-pinned integrity
  flag.

Distinct-layer rationale vs siblings: ``ai_policy.py`` owns declared
policy text; ``ai_oversight.py`` owns oversight declarations;
``ai_containment.py`` / ``ai_isolation.py`` own operational
restriction mechanics; ``ai_safety.py`` owns the safety assessment ->
mitigation lifecycle; ``ai_audit.py`` owns audit scheduling - this
module is the *gating-decision* ledger none of them own: the
interface-level allow/deny switchboard for declared agents, digest
re-derivation, and the ledger-rule posture that turns declared gates
into a gating claim, always as data, never as measured enforcement.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-gating.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with
the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module enforces nothing, gates nothing at
runtime, and proves nothing about real-world enforcement. A booked
``locked-down`` posture means "the host declared it", never "the
agent is actually denied"; a booked ``allow`` decision means "the host
declared it", never "the capability is really reachable". Agent
material, tool calls, transcripts, weights, prompts, outputs, and raw
permission payloads never enter records or cross the audit boundary -
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
AI_GATING_VERSION = "ai-gating.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-gating.v1"

#: Pinned gate-kind vocabulary (the gate classes).
GATE_KINDS = (
    "capability-allow",
    "capability-deny",
    "tool-allow",
    "tool-deny",
    "action-allow",
    "action-deny",
    "data-access-allow",
    "data-access-deny",
)

#: Pinned gate-decision vocabulary (booked as data, never proof).
GATE_DECISIONS = (
    "allow",
    "deny",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "open",
    "allowlisted",
    "locked-down",
    "contested",
)

#: Audit kinds emitted by this module.
EMIT_KINDS = (
    "gated",
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
        "restore_point",
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
        "tool_call",
        "tool_calls",
        "tool_arguments",
        "permission_payload",
        "capability_payload",
        "gate_payload",
        "gate_target",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIGatingError(Exception):
    """Base class for all ai-gating ledger errors."""


class BadAgentError(AIGatingError):
    pass


class BadGateKindError(AIGatingError):
    pass


class BadDecisionError(AIGatingError):
    pass


class BadDigestError(AIGatingError):
    pass


class UnknownGateError(AIGatingError):
    pass


class SeqOrderError(AIGatingError):
    pass


class AuditKindError(AIGatingError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadAgentError(f"{what} must be a non-empty string")
    return value


def _check_gate_kind(value: Any) -> str:
    if value not in GATE_KINDS:
        raise BadGateKindError(f"gate_kind must be one of {GATE_KINDS}")
    return value


def _check_decision(value: Any) -> str:
    if value not in GATE_DECISIONS:
        raise BadDecisionError(f"decision must be one of {GATE_DECISIONS}")
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
class GateRecord:
    gate_id: str
    agent_id: str
    seq: int
    gate_kind: str
    decision: str
    context_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_gate_payload(self), "ai-gating.gate")


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_verify_payload(self), "ai-gating.verify")


@dataclass(frozen=True)
class EvaluationReport:
    agent_id: str
    seq: int
    posture: str
    n_gates: int
    n_allow: int
    n_deny: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_evaluate_payload(self), "ai-gating.evaluate")


def _gate_payload(rec: "GateRecord") -> Dict[str, Any]:
    return {
        "gate_id": rec.gate_id,
        "agent_id": rec.agent_id,
        "seq": rec.seq,
        "gate_kind": rec.gate_kind,
        "decision": rec.decision,
        "context_digest": rec.context_digest,
    }


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "agent_id": rep.agent_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_gates": rep.n_gates,
        "n_allow": rep.n_allow,
        "n_deny": rep.n_deny,
        "integrity_ok": rep.integrity_ok,
    }


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def ai_gating_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AIGatingError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-gating",
        "version": AI_GATING_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIGating:
    """AI-gating gating-decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All gating decisions are
    booked as data - never proof that any gate was really enforced.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._gates: Dict[str, GateRecord] = {}
        self._agent_gates: Dict[str, List[str]] = {}
        self._gate_counter = 0
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
            row = ai_gating_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-gating",
                "version": AI_GATING_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_gating_audit_event(audit_kind, seq, **details))

    # -- mutation ----------------------------------------------------------

    def gate(
        self,
        agent_id: str,
        seq: int,
        gate_kind: str = "capability-allow",
        decision: str = "allow",
        context_digest: str = "",
    ) -> GateRecord:
        """Book one declared gating decision (minted ``gate-N`` id).

        The first gate on an id registers the agent. Raw agent
        material, tool calls, transcripts, weights, and permission
        payloads never enter records - digest pins only. Fail-closed:
        failed mutations consume their seq and book an
        ``ai-gating.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                agent_id = _check_id(agent_id, "agent_id")
                self._require_seq(seq)
                gate_kind = _check_gate_kind(gate_kind)
                decision = _check_decision(decision)
                context_digest = _check_digest(context_digest, "context_digest")
            except AIGatingError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._gate_counter += 1
            gate_id = f"gate-{self._gate_counter}"
            provisional = GateRecord(
                gate_id=gate_id,
                agent_id=agent_id,
                seq=seq,
                gate_kind=gate_kind,
                decision=decision,
                context_digest=context_digest,
                digest="",
            )
            digest = _digest_pin(_gate_payload(provisional), "ai-gating.gate")
            rec = GateRecord(
                gate_id=gate_id,
                agent_id=agent_id,
                seq=seq,
                gate_kind=gate_kind,
                decision=decision,
                context_digest=context_digest,
                digest=digest,
            )
            self._gates[gate_id] = rec
            self._agent_gates.setdefault(agent_id, []).append(gate_id)
            self._emit(
                "gated",
                seq,
                gate_id=gate_id,
                agent_id=agent_id,
                gate_kind=gate_kind,
                decision=decision,
                context_digest=context_digest,
            )
            return rec

    # -- pure reads --------------------------------------------------------

    def _check_read_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        return seq

    def verify(self, gate_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one gate record's digest pin.

        Verdict ``verified`` / ``tampered`` booked as data, never as
        proof the gate was really enforced. Seq is shape-validated only
        - never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            if (
                isinstance(gate_id, bool)
                or not isinstance(gate_id, str)
                or gate_id not in self._gates
            ):
                raise UnknownGateError(f"unknown gate id: {gate_id!r}")
            rec = self._gates[gate_id]
            integrity_ok = rec.verify()
            verdict = "verified" if integrity_ok else "tampered"
            provisional = VerificationReport(
                record_id=gate_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "ai-gating.verify")
            return VerificationReport(
                record_id=gate_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, agent_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one agent's gating posture as data.

        Ledger rules, as data:

        * no gates booked on the agent -> ``open``
        * only ``allow`` decisions -> ``allowlisted``
        * only ``deny`` decisions -> ``locked-down``
        * both ``allow`` and ``deny`` -> ``contested``

        Unknown agents evaluate as ``open`` with zero tallies. Seq is
        shape-validated only - never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            if (
                isinstance(agent_id, bool)
                or not isinstance(agent_id, str)
                or not agent_id.strip()
            ):
                raise BadAgentError("agent_id must be a non-empty string")
            gate_ids = self._agent_gates.get(agent_id, [])
            recs = [self._gates[gid] for gid in gate_ids]
            n_allow = sum(1 for r in recs if r.decision == "allow")
            n_deny = sum(1 for r in recs if r.decision == "deny")
            integrity_ok = all(r.verify() for r in recs)
            if n_deny and n_allow:
                posture = "contested"
            elif n_deny:
                posture = "locked-down"
            elif n_allow:
                posture = "allowlisted"
            else:
                posture = "open"
            provisional = EvaluationReport(
                agent_id=agent_id,
                seq=seq,
                posture=posture,
                n_gates=len(recs),
                n_allow=n_allow,
                n_deny=n_deny,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-gating.evaluate")
            return EvaluationReport(
                agent_id=agent_id,
                seq=seq,
                posture=posture,
                n_gates=len(recs),
                n_allow=n_allow,
                n_deny=n_deny,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- introspection -------------------------------------------------------

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """Return a snapshot of the audit rows, oldest first."""
        with self._lock:
            return tuple(self._audit)

    def gate_ids(self) -> Tuple[str, ...]:
        """Return minted gate ids, oldest first."""
        with self._lock:
            return tuple(self._gates)
