"""Deterministic evidence-completion agendas for non-ready plan decisions.

The agenda helps a caller see which evidence needs collection, re-verification,
or external conflict escalation.  It deliberately contains no executable action
or authorization: execution remains an owning host decision.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from evidence_readiness_gate import EvidenceReadinessGate, GateError
from evidence_state_projection import ClaimProjection, ProjectionError
from plan_evidence_decision import EvidencePlanManifest, PlanDecisionError, PlanEvidenceDecision

SCHEMA = "northstar.evidence-resolution-agenda.v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_ITEM_FIELDS = frozenset({
    "claim_digest", "disposition", "evidence_state", "reasons", "unverified",
    "execution_authorized",
})
_AGENDA_FIELDS = frozenset({
    "schema_version", "plan_id", "decision_digest", "decision_state", "items",
    "execution_authorized", "agenda_digest",
})
_SEVERITY = {"escalate-conflict": 0, "reacquire-evidence": 1, "collect-evidence": 2}


class AgendaError(ValueError):
    """Malformed, stale, substituted, or non-resolvable evidence agenda."""


@dataclass(frozen=True)
class ResolutionItem:
    claim_digest: str
    disposition: str
    evidence_state: str
    reasons: tuple[str, ...]
    unverified: tuple[str, ...]
    execution_authorized: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_digest": self.claim_digest,
            "disposition": self.disposition,
            "evidence_state": self.evidence_state,
            "reasons": list(self.reasons),
            "unverified": list(self.unverified),
            "execution_authorized": self.execution_authorized,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ResolutionItem":
        if not isinstance(value, dict) or set(value) != _ITEM_FIELDS:
            raise AgendaError("resolution item fields are invalid")
        claim = _digest(value["claim_digest"], "claim_digest")
        disposition = value["disposition"]
        state = value["evidence_state"]
        if disposition not in _SEVERITY:
            raise AgendaError("resolution disposition is invalid")
        if disposition == "escalate-conflict" and state != "conflicted":
            raise AgendaError("conflict disposition/state mismatch")
        if disposition == "reacquire-evidence" and state not in {"insufficient", "unverifiable"}:
            raise AgendaError("reacquire disposition/state mismatch")
        if disposition == "collect-evidence" and state not in {"unknown", "missing"}:
            raise AgendaError("collect disposition/state mismatch")
        reasons = _strings(value["reasons"], "item reasons")
        unverified = _strings(value["unverified"], "item unverified", allow_empty=True)
        if not isinstance(value["execution_authorized"], bool) or value["execution_authorized"]:
            raise AgendaError("resolution item cannot authorize execution")
        return cls(claim, disposition, state, reasons, unverified, False)


@dataclass(frozen=True)
class EvidenceResolutionAgenda:
    schema_version: str
    plan_id: str
    decision_digest: str
    decision_state: str
    items: tuple[ResolutionItem, ...]
    execution_authorized: bool
    agenda_digest: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "plan_id": self.plan_id,
            "decision_digest": self.decision_digest,
            "decision_state": self.decision_state,
            "items": [item.to_dict() for item in self.items],
            "execution_authorized": self.execution_authorized,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "agenda_digest": self.agenda_digest}

    @property
    def computed_digest(self) -> str:
        return _hash(b"northstar.evidence-resolution-agenda.v1\0", self.unsigned_dict())

    @classmethod
    def from_dict(cls, value: Any) -> "EvidenceResolutionAgenda":
        if not isinstance(value, dict) or set(value) != _AGENDA_FIELDS:
            raise AgendaError("agenda fields are invalid")
        if value["schema_version"] != SCHEMA:
            raise AgendaError("agenda schema is invalid")
        plan_id = _id(value["plan_id"], "plan_id")
        decision_digest = _digest(value["decision_digest"], "decision_digest")
        decision_state = value["decision_state"]
        if decision_state not in {"blocked", "unknown"}:
            raise AgendaError("agenda decision state is invalid")
        raw_items = value["items"]
        if not isinstance(raw_items, list) or not raw_items:
            raise AgendaError("agenda items are invalid")
        items = tuple(ResolutionItem.from_dict(item) for item in raw_items)
        if _item_order(items) != items:
            raise AgendaError("agenda items are not canonical")
        if len({item.claim_digest for item in items}) != len(items):
            raise AgendaError("agenda claims are duplicated")
        if not isinstance(value["execution_authorized"], bool) or value["execution_authorized"]:
            raise AgendaError("agenda cannot authorize execution")
        digest = _digest(value["agenda_digest"], "agenda_digest")
        agenda = cls(SCHEMA, plan_id, decision_digest, decision_state, items, False, digest)
        if agenda.computed_digest != digest:
            raise AgendaError("agenda digest mismatch")
        return agenda


@dataclass(frozen=True)
class AgendaVerification:
    state: str
    claimed_decision_state: str
    reasons: tuple[str, ...] = ()
    unverified: tuple[str, ...] = ()
    execution_authorized: bool = False
    agenda_digest: str = ""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AgendaError("agenda is not canonical JSON") from exc


def _hash(prefix: bytes, value: Any) -> str:
    return "sha256:" + hashlib.sha256(prefix + _canonical(value)).hexdigest()


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise AgendaError(f"{field} is invalid")
    return value


def _id(value: Any, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise AgendaError(f"{field} is invalid")
    return value


def _strings(value: Any, field: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if (not isinstance(value, list)
            or (not allow_empty and not value)
            or len(set(value)) != len(value)
            or value != sorted(value)
            or not all(isinstance(item, str) and item for item in value)):
        raise AgendaError(f"{field} are invalid")
    return tuple(value)


def _item_order(items: tuple[ResolutionItem, ...]) -> tuple[ResolutionItem, ...]:
    return tuple(sorted(items, key=lambda item: (_SEVERITY[item.disposition], item.claim_digest)))


def _decision(value: Any) -> PlanEvidenceDecision:
    try:
        return PlanEvidenceDecision.from_dict(value.to_dict())
    except (AttributeError, PlanDecisionError) as exc:
        raise AgendaError("plan evidence decision is invalid") from exc


def _manifest(decision: PlanEvidenceDecision) -> EvidencePlanManifest:
    try:
        return EvidencePlanManifest.from_dict(decision.manifest)
    except PlanDecisionError as exc:
        raise AgendaError("decision manifest is invalid") from exc


def _gate_projections(decision: PlanEvidenceDecision) -> dict[str, ClaimProjection]:
    try:
        gate = EvidenceReadinessGate.from_dict(decision.gate)
    except GateError as exc:
        raise AgendaError("decision gate is invalid") from exc
    projections: dict[str, ClaimProjection] = {}
    for raw in gate.projections:
        try:
            projection = ClaimProjection.from_dict(raw)
        except ProjectionError as exc:
            raise AgendaError("decision projection is invalid") from exc
        projections[projection.claim_digest] = projection
    return projections


def _derive_items(decision: PlanEvidenceDecision) -> tuple[ResolutionItem, ...]:
    manifest = _manifest(decision)
    projections = _gate_projections(decision)
    if decision.state == "ready":
        raise AgendaError("ready decision requires no evidence resolution agenda")
    items: list[ResolutionItem] = []
    for step in manifest.steps:
        claim = step.claim_digest
        projection = projections.get(claim)
        if projection is None:
            items.append(ResolutionItem(
                claim, "collect-evidence", "missing", ("missing_claim_projection",), (), False,
            ))
            continue
        if projection.state == "conflicted":
            items.append(ResolutionItem(
                claim, "escalate-conflict", "conflicted", projection.reasons,
                projection.unverified, False,
            ))
        elif projection.state in {"insufficient", "unverifiable"}:
            items.append(ResolutionItem(
                claim, "reacquire-evidence", projection.state, projection.reasons,
                projection.unverified, False,
            ))
        elif projection.state == "unknown":
            items.append(ResolutionItem(
                claim, "collect-evidence", "unknown", projection.reasons,
                projection.unverified, False,
            ))
    if not items:
        raise AgendaError("non-ready decision has no evidence resolution item")
    return _item_order(tuple(items))


def make_resolution_agenda(decision: PlanEvidenceDecision) -> EvidenceResolutionAgenda:
    decision = _decision(decision)
    manifest = _manifest(decision)
    items = _derive_items(decision)
    agenda = EvidenceResolutionAgenda(
        SCHEMA, "plan-evidence:" + manifest.manifest_digest[7:23], decision.decision_digest,
        decision.state, items, False, "",
    )
    return EvidenceResolutionAgenda(
        agenda.schema_version, agenda.plan_id, agenda.decision_digest,
        agenda.decision_state, agenda.items, False, agenda.computed_digest,
    )


def verify_resolution_agenda(
    agenda: EvidenceResolutionAgenda,
    decision: PlanEvidenceDecision,
    *,
    expected_agenda_digest: str | None = None,
    expected_decision_digest: str | None = None,
) -> AgendaVerification:
    if not isinstance(agenda, EvidenceResolutionAgenda):
        raise AgendaError("agenda is invalid")
    parsed = EvidenceResolutionAgenda.from_dict(agenda.to_dict())
    decision = _decision(decision)
    manifest = _manifest(decision)
    expected_plan_id = "plan-evidence:" + manifest.manifest_digest[7:23]
    if parsed.plan_id != expected_plan_id:
        raise AgendaError("agenda plan id mismatch")
    if parsed.decision_digest != decision.decision_digest:
        raise AgendaError("agenda decision digest mismatch")
    if expected_agenda_digest is not None:
        if _digest(expected_agenda_digest, "expected_agenda_digest") != parsed.agenda_digest:
            raise AgendaError("external agenda digest mismatch")
    if expected_decision_digest is not None:
        if _digest(expected_decision_digest, "expected_decision_digest") != decision.decision_digest:
            raise AgendaError("external decision digest mismatch")
    replay = make_resolution_agenda(decision)
    if replay.to_dict() != parsed.to_dict():
        raise AgendaError("agenda replay mismatch")
    unresolved = [
        field for item in replay.items for field in item.unverified
    ]
    if expected_agenda_digest is None:
        unresolved.append("agenda_digest_unpinned")
    if expected_decision_digest is None:
        unresolved.append("decision_digest_unpinned")
    return AgendaVerification(
        "agenda-verified" if expected_agenda_digest is not None and expected_decision_digest is not None else "agenda-verified-unpinned",
        replay.decision_state, (), tuple(sorted(set(unresolved))), False, parsed.agenda_digest,
    )


__all__ = [
    "SCHEMA", "AgendaError", "ResolutionItem", "EvidenceResolutionAgenda",
    "AgendaVerification", "make_resolution_agenda", "verify_resolution_agenda",
]
