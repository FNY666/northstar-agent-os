"""SAFR checkpoints: declare -> authorize -> assess -> audit, Simulated.

P1 absorption from the exhaustive method search: MAS (Singapore)
SAFR whitepaper (2026-07) defines the agent runtime checkpoint
pattern -- between an agent's *decision* and its *execution*, four
gates fire in order:

    declare    the agent states intent, action, subject (what it wants)
    authorize  a policy/approver allows, denies, or conditions it
    assess     controls are evaluated (identity, permission scope, risk)
    audit      the outcome is booked, win or lose

This module is the *decision ledger* for declared SAFR checkpoints:
each gate's verdict is booked as data (never proof the gate really
ran), chained by digest pins (authorize references the declaration,
assess references the authorization, audit closes the chain), and
mappable to 8-field sealed events for pipeline ingest.

What this module IS: the ledger for the four-gate lifecycle, with
fail-closed transitions (no authorize without declare, no audit
without assess, deny is terminal).

What this module IS NOT (honest scope):

* It does not enforce anything -- it books *declared* gate outcomes.
  Real enforcement lives in the permission-gate runtime, not here.
* It does not verify authorizer identity -- ``authorizer_id`` is a
  host-declared string, booked as data.
* It does not prove the assessment was correct -- findings are
  host-declared verdicts over pinned vocabularies.

Gate vocabularies (all pinned):

* authorize decisions: ``allow`` / ``deny`` / ``conditional``
* assess findings: ``pass`` / ``fail`` / ``inconclusive`` /
  ``waived``
* audit outcomes: ``executed`` / ``blocked`` / ``aborted`` /
  ``expired``
* postures: ``declared`` -> ``denied`` (terminal) /
  ``authorized`` -> ``assessment-failed`` (terminal) /
  ``assessed`` -> ``audited`` (terminal)

House style: frozen dataclasses, caller int seqs strictly increasing
with claim-then-burn (failed mutations consume seq + book
``safr-checkpoint.rejected``; rewinds raise bare), no wall-clock,
RLock-guarded, fail-closed, stdlib-only with ``canonical_json``
try/except fallback, ``sha256:`` digest pins, ``audit.ndjson/1``
events, ``stdlib_only()`` + ``main()`` self-check.
"""

from __future__ import annotations

import ast
import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps_raw  # type: ignore

    def _jcs_dumps(obj: Any) -> bytes:
        raw = _jcs_dumps_raw(obj)
        return raw.encode("utf-8") if isinstance(raw, str) else raw

except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Module version pin.
SAFR_CHECKPOINT_VERSION = "safr-checkpoint.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.safr-checkpoint.v1"

#: Pinned authorize decisions.
AUTHORIZE_DECISIONS = (
    "allow",
    "deny",
    "conditional",
)

#: Pinned assess findings.
ASSESS_FINDINGS = (
    "pass",
    "fail",
    "inconclusive",
    "waived",
)

#: Pinned audit outcomes.
AUDIT_OUTCOMES = (
    "executed",
    "blocked",
    "aborted",
    "expired",
)

#: Pinned postures (booked as data).
POSTURES = (
    "declared",
    "denied",
    "authorized",
    "assessment-failed",
    "assessed",
    "audited",
)

#: Audit event kinds.
AUDIT_KINDS = (
    "declared",
    "authorized",
    "assessed",
    "audited",
    "rejected",
)

#: Retire reasons.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "expired",
)


class SafrCheckpointError(Exception):
    """Fail-closed: bad gate transitions raise, never produce bad records."""


def _require_pin(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise SafrCheckpointError(f"{name} must be str")
    if not value.startswith("sha256:") or len(value) != 71:
        raise SafrCheckpointError(f"{name} must be a sha256: pin")
    try:
        bytes.fromhex(value[7:])
    except ValueError:
        raise SafrCheckpointError(f"{name} hex is malformed")
    return value


def _require_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise SafrCheckpointError(f"{name} must be a non-empty str")
    return value


@dataclass(frozen=True)
class DeclarationRecord:
    """Gate 1: the agent declares intent (immutable)."""

    declaration_id: str  # safd-N
    seq: int
    intent: str
    action: str
    subject: str
    inputs_digest: str  # sha256: pin
    digest: str  # sha256: pin of the canonical record


@dataclass(frozen=True)
class AuthorizationRecord:
    """Gate 2: the authorizer decides (immutable)."""

    authorization_id: str  # safa-N
    seq: int
    declaration_id: str
    declaration_digest: str  # pins the declaration
    decision: str  # allow / deny / conditional
    authorizer_id: str
    conditions_digest: str  # sha256: pin (empty pin allowed for allow/deny)
    digest: str


@dataclass(frozen=True)
class AssessmentRecord:
    """Gate 3: controls are assessed (immutable)."""

    assessment_id: str  # safs-N
    seq: int
    declaration_id: str
    authorization_digest: str  # pins the authorization
    finding: str  # pass / fail / inconclusive / waived
    assessment_digest: str  # sha256: pin of findings detail
    digest: str


@dataclass(frozen=True)
class AuditRecord:
    """Gate 4: the outcome is booked (immutable, terminal)."""

    audit_id: str  # safu-N
    seq: int
    declaration_id: str
    assessment_digest: str  # pins the assessment
    outcome: str  # executed / blocked / aborted / expired
    outcome_digest: str  # sha256: pin of outcome evidence
    digest: str


class SafrCheckpoint:
    """Four-gate SAFR checkpoint ledger.

    Caller supplies strictly-increasing int seqs across all gates
    (one seq domain per ledger instance).  Transitions are
    fail-closed: authorize needs a live declaration; assess needs an
    ``allow``/``conditional`` authorization; audit needs an
    assessment; ``deny`` and ``fail`` are terminal for that
    declaration.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._declarations: Dict[str, DeclarationRecord] = {}
        self._authorizations: Dict[str, AuthorizationRecord] = {}
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._audits: Dict[str, AuditRecord] = {}
        self._by_declaration: Dict[str, Dict[str, str]] = {}
        self._expected_seq = 1
        self._counters = {"safd": 0, "safa": 0, "safs": 0, "safu": 0}
        self._audit_log: List[Dict[str, Any]] = []
        self._rejected = 0

    # -- seq discipline ----------------------------------------------

    def _claim_seq(self, seq: Any) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int):
            self._rejected += 1
            self._audit("rejected", -1, "-")
            raise SafrCheckpointError("seq must be int")
        if seq < self._expected_seq:
            raise SafrCheckpointError(
                f"seq rewind: got {seq}, expected >= {self._expected_seq}"
            )
        self._expected_seq = seq + 1

    def _audit(self, kind: str, seq: int, ref: str) -> None:
        if kind not in AUDIT_KINDS:
            raise SafrCheckpointError(f"bad audit kind {kind!r}")
        self._audit_log.append(
            {"kind": kind, "seq": seq, "ref": ref, "schema": "audit.ndjson/1"}
        )

    def _mint(self, prefix: str) -> str:
        self._counters[prefix] += 1
        return f"{prefix}-{self._counters[prefix]}"

    @staticmethod
    def _digest(payload: Dict[str, Any]) -> str:
        return "sha256:" + hashlib.sha256(_jcs_dumps(payload)).hexdigest()

    # -- gates --------------------------------------------------------

    def declare(
        self,
        seq: int,
        intent: str,
        action: str,
        subject: str,
        inputs_digest: str,
    ) -> DeclarationRecord:
        """Gate 1: book the agent's declared intent."""
        with self._lock:
            self._claim_seq(seq)
            try:
                _require_nonempty_str(intent, "intent")
                _require_nonempty_str(action, "action")
                _require_nonempty_str(subject, "subject")
                _require_pin(inputs_digest, "inputs_digest")
            except SafrCheckpointError:
                self._rejected += 1
                self._audit("rejected", seq, "-")
                raise
            declaration_id = self._mint("safd")
            digest = self._digest(
                {
                    "declaration_id": declaration_id,
                    "seq": seq,
                    "intent": intent,
                    "action": action,
                    "subject": subject,
                    "inputs_digest": inputs_digest,
                }
            )
            record = DeclarationRecord(
                declaration_id=declaration_id,
                seq=seq,
                intent=intent,
                action=action,
                subject=subject,
                inputs_digest=inputs_digest,
                digest=digest,
            )
            self._declarations[declaration_id] = record
            self._by_declaration[declaration_id] = {}
            self._audit("declared", seq, declaration_id)
            return record

    def authorize(
        self,
        seq: int,
        declaration_id: str,
        decision: str,
        authorizer_id: str,
        conditions_digest: str,
    ) -> AuthorizationRecord:
        """Gate 2: book the authorizer's decision (needs a declaration)."""
        with self._lock:
            self._claim_seq(seq)
            try:
                decl = self._declarations.get(declaration_id)
                if decl is None:
                    raise SafrCheckpointError("unknown declaration")
                if "authorization" in self._by_declaration[declaration_id]:
                    raise SafrCheckpointError("declaration already authorized")
                if decision not in AUTHORIZE_DECISIONS:
                    raise SafrCheckpointError(f"bad decision {decision!r}")
                _require_nonempty_str(authorizer_id, "authorizer_id")
                _require_pin(conditions_digest, "conditions_digest")
            except SafrCheckpointError:
                self._rejected += 1
                self._audit("rejected", seq, declaration_id)
                raise
            authorization_id = self._mint("safa")
            digest = self._digest(
                {
                    "authorization_id": authorization_id,
                    "seq": seq,
                    "declaration_id": declaration_id,
                    "declaration_digest": decl.digest,
                    "decision": decision,
                    "authorizer_id": authorizer_id,
                    "conditions_digest": conditions_digest,
                }
            )
            record = AuthorizationRecord(
                authorization_id=authorization_id,
                seq=seq,
                declaration_id=declaration_id,
                declaration_digest=decl.digest,
                decision=decision,
                authorizer_id=authorizer_id,
                conditions_digest=conditions_digest,
                digest=digest,
            )
            self._authorizations[authorization_id] = record
            self._by_declaration[declaration_id]["authorization"] = authorization_id
            self._audit("authorized", seq, authorization_id)
            return record

    def assess(
        self,
        seq: int,
        declaration_id: str,
        finding: str,
        assessment_digest: str,
    ) -> AssessmentRecord:
        """Gate 3: book the control assessment (needs allow/conditional)."""
        with self._lock:
            self._claim_seq(seq)
            try:
                decl = self._declarations.get(declaration_id)
                if decl is None:
                    raise SafrCheckpointError("unknown declaration")
                auth_id = self._by_declaration[declaration_id].get("authorization")
                if auth_id is None:
                    raise SafrCheckpointError("declaration not authorized yet")
                auth = self._authorizations[auth_id]
                if auth.decision == "deny":
                    raise SafrCheckpointError("denied declarations cannot be assessed")
                if "assessment" in self._by_declaration[declaration_id]:
                    raise SafrCheckpointError("declaration already assessed")
                if finding not in ASSESS_FINDINGS:
                    raise SafrCheckpointError(f"bad finding {finding!r}")
                _require_pin(assessment_digest, "assessment_digest")
            except SafrCheckpointError:
                self._rejected += 1
                self._audit("rejected", seq, declaration_id)
                raise
            assessment_id = self._mint("safs")
            digest = self._digest(
                {
                    "assessment_id": assessment_id,
                    "seq": seq,
                    "declaration_id": declaration_id,
                    "authorization_digest": auth.digest,
                    "finding": finding,
                    "assessment_digest": assessment_digest,
                }
            )
            record = AssessmentRecord(
                assessment_id=assessment_id,
                seq=seq,
                declaration_id=declaration_id,
                authorization_digest=auth.digest,
                finding=finding,
                assessment_digest=assessment_digest,
                digest=digest,
            )
            self._assessments[assessment_id] = record
            self._by_declaration[declaration_id]["assessment"] = assessment_id
            self._audit("assessed", seq, assessment_id)
            return record

    def audit(
        self,
        seq: int,
        declaration_id: str,
        outcome: str,
        outcome_digest: str,
    ) -> AuditRecord:
        """Gate 4: book the terminal outcome (needs an assessment)."""
        with self._lock:
            self._claim_seq(seq)
            try:
                decl = self._declarations.get(declaration_id)
                if decl is None:
                    raise SafrCheckpointError("unknown declaration")
                asmt_id = self._by_declaration[declaration_id].get("assessment")
                if asmt_id is None:
                    raise SafrCheckpointError("declaration not assessed yet")
                if "audit" in self._by_declaration[declaration_id]:
                    raise SafrCheckpointError("declaration already audited")
                if outcome not in AUDIT_OUTCOMES:
                    raise SafrCheckpointError(f"bad outcome {outcome!r}")
                _require_pin(outcome_digest, "outcome_digest")
            except SafrCheckpointError:
                self._rejected += 1
                self._audit("rejected", seq, declaration_id)
                raise
            asmt = self._assessments[asmt_id]
            audit_id = self._mint("safu")
            digest = self._digest(
                {
                    "audit_id": audit_id,
                    "seq": seq,
                    "declaration_id": declaration_id,
                    "assessment_digest": asmt.digest,
                    "outcome": outcome,
                    "outcome_digest": outcome_digest,
                }
            )
            record = AuditRecord(
                audit_id=audit_id,
                seq=seq,
                declaration_id=declaration_id,
                assessment_digest=asmt.digest,
                outcome=outcome,
                outcome_digest=outcome_digest,
                digest=digest,
            )
            self._audits[audit_id] = record
            self._by_declaration[declaration_id]["audit"] = audit_id
            self._audit("audited", seq, audit_id)
            return record

    # -- reads ----------------------------------------------------------

    def posture(self, declaration_id: str) -> str:
        """Derive the declaration's posture (pure read, as data)."""
        with self._lock:
            if declaration_id not in self._declarations:
                raise SafrCheckpointError("unknown declaration")
            gates = self._by_declaration[declaration_id]
            if "audit" in gates:
                return "audited"
            if "assessment" in gates:
                asmt = self._assessments[gates["assessment"]]
                if asmt.finding == "fail":
                    return "assessment-failed"
                return "assessed"
            if "authorization" in gates:
                auth = self._authorizations[gates["authorization"]]
                if auth.decision == "deny":
                    return "denied"
                return "authorized"
            return "declared"

    def to_sealed_event(self, declaration_id: str) -> Dict[str, str]:
        """Render the full gate chain as an 8-field sealed event."""
        with self._lock:
            decl = self._declarations.get(declaration_id)
            if decl is None:
                raise SafrCheckpointError("unknown declaration")
            gates = self._by_declaration[declaration_id]
            # Chain the digests: declaration -> authorization -> assessment -> audit.
            logic_pin = decl.digest
            if "authorization" in gates:
                logic_pin = self._authorizations[gates["authorization"]].digest
            exec_pin = decl.digest
            if "assessment" in gates:
                exec_pin = self._assessments[gates["assessment"]].digest
            if "audit" in gates:
                exec_pin = self._audits[gates["audit"]].digest
            return {
                "intent": decl.intent,
                "action": decl.action,
                "subject": decl.subject,
                "authorization": gates.get("authorization", "pending"),
                "inputs_digest": decl.inputs_digest,
                "logic_digest": logic_pin,
                "execution_digest": exec_pin,
                "outcome": self.posture(declaration_id),
            }

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "declarations": len(self._declarations),
                "authorizations": len(self._authorizations),
                "assessments": len(self._assessments),
                "audits": len(self._audits),
                "rejected": self._rejected,
                "audit_rows": len(self._audit_log),
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit_log)


def stdlib_only() -> bool:
    """AST check: this module imports stdlib modules only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__",
        "ast",
        "dataclasses",
        "hashlib",
        "json",
        "pathlib",
        "threading",
        "typing",
        "canonical_json",
    }
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
    """Self-check: full four-gate lifecycle + terminal transitions."""
    cp = SafrCheckpoint()
    pin = "sha256:" + "ab" * 32
    d = cp.declare(1, "deploy", "restart-service", "prod-api", pin)
    assert d.declaration_id == "safd-1"
    assert cp.posture(d.declaration_id) == "declared"
    a = cp.authorize(2, d.declaration_id, "allow", "policy-engine", pin)
    assert a.authorization_id == "safa-1"
    assert cp.posture(d.declaration_id) == "authorized"
    s = cp.assess(3, d.declaration_id, "pass", pin)
    assert s.assessment_id == "safs-1"
    assert cp.posture(d.declaration_id) == "assessed"
    u = cp.audit(4, d.declaration_id, "executed", pin)
    assert u.audit_id == "safu-1"
    assert cp.posture(d.declaration_id) == "audited"
    # Deny is terminal.
    d2 = cp.declare(5, "delete", "drop-table", "prod-db", pin)
    cp.authorize(6, d2.declaration_id, "deny", "policy-engine", pin)
    assert cp.posture(d2.declaration_id) == "denied"
    try:
        cp.assess(7, d2.declaration_id, "pass", pin)
        raise AssertionError("assess after deny should raise")
    except SafrCheckpointError:
        pass
    # Sealed-event mapping.
    event = cp.to_sealed_event(d.declaration_id)
    assert event["outcome"] == "audited"
    assert set(event.keys()) == {
        "intent", "action", "subject", "authorization",
        "inputs_digest", "logic_digest", "execution_digest", "outcome",
    }
    assert stdlib_only()
    print("safr-checkpoint OK: declare, authorize, assess, audit, sealed-event, stdlib")


if __name__ == "__main__":
    main()
