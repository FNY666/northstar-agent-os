"""Supply-chain AI discipline gates (one-hundred-forty-fourth batch).

Absorbs the 2026 AI-supply-chain research thread (mechanism ideas only,
honestly scoped):

* **Agentic AI as the logistics mainstream** — DHL Trendradar rates
  agentic AI the most impactful logistics trend; McKinsey self-reports
  4-7% manufacturing-cost cuts and +20-50% supply-chain productivity;
  Flexport claims its AI agents process 21M tasks/year (auto-booking,
  exceptions to humans); SAP/IFS 2026 roadmaps embed agentic AI; KPMG
  says AI moved from pilots into source-to-pay/planning/risk core
  systems. Governance takeaway: vendor AI claims (21M tasks, -80%
  triage time) are NON_AUTHORITATIVE unless bound to a measurement
  protocol (``supplychain.unverified_claim``) — the module refuses to
  trust self-reported capability numbers.
* **Supplier risk scoring** — acedit case: 3,400 suppliers AI
  risk-scored, 91-day average warning before disruption, 18%
  false-positive rate; Korea Tier-1 electronics plant procurement
  copilot: risk coverage +300%, avoided $5.5M loss; Zip AI Risk
  Orchestration 2x coverage. Governance takeaway: risk scores are
  decision inputs only when bound to an evidence chain disclosing the
  warning lead time and false-positive rate — an evidence-free score
  is NON_AUTHORITATIVE (``supplychain:no_risk_evidence``), and an
  alert channel whose false-alarm rate exceeds its pinned budget
  auto-degrades to human triage (``supplychain:false_alarm_budget_exceeded``).
* **AI decides alone** — RELEX 2026: 67% of leaders are more
  confident in AI decisions, but 54% insist AI only advises and only
  10% trust AI to decide alone. Governance takeaway: AI-independent
  supply-chain decisions are refused whole-class
  (``supplychain:autonomous_decision``); an AI decision is
  enforceable only with a named-human approval bound to the exact
  AI-decision digest.
* **Algorithmic labor management** — paulchenglaw: algorithms mark
  legally-resting drivers "inefficient" and bathroom-taking pickers
  "low scan rate"; the technology is automated, the employer's legal
  obligations are not. Kenya Sama data annotators: ~$230/month,
  algorithmic management deciding employment, contracts withdrawable
  without appeal — accountability subcontracted away. Governance
  takeaway: counting legally-mandated rest against workers is a
  violation (``supplychain.rest_violation``), and subcontracted AI
  labor management still binds the contracting principal (the
  127th-batch ``labor_algo.py`` line, extended here to supply-chain
  workforces).
* **Deskilling and brittleness** — 2026 WID: AI-augmented jobs pay 3x
  automated-squeezed jobs; prism scenario analysis: deskilling
  produces "efficient in steady state, brittle under stress".
  Governance takeaway: deskilling audits run on a clock; resilience
  below the pinned floor is ``supplychain.brittle``; a lapsed audit
  is NON_AUTHORITATIVE (``supplychain:audit_overdue``).
* **Tariff/trade scenarios** — DMCC 2026: ~20% of global goods
  imports face tariffs/restrictions, 4/5 leaders expect permanent
  disruption; strategy is regionalization + AI predictive compliance
  + shorter planning cycles. Governance takeaway: planning scenarios
  bind a versioned assumption digest; an unbound or version-mismatched
  scenario is NON_AUTHORITATIVE (``supplychain.unbound_scenario``),
  and single-source concentration beyond tolerance triggers a
  diversification audit (``supplychain:concentration_breach``).

Northstar mapping:

* ``human_final_gate()`` — an AI supply-chain decision (reroute,
  expedite, supplier switch, PO approval, forecast commit) is
  enforceable only with a named-human approval bound to the exact
  AI-decision digest. No approval -> ``supplychain:autonomous_decision``
  (RELEX lesson).
* ``risk_score_evidence()`` — supplier risk scores bind an evidence
  chain disclosing warning lead days and false-positive rate; an
  evidence-free score is NON_AUTHORITATIVE
  (``supplychain:no_risk_evidence``).
* ``check_alarm_budget()`` — alert channels pin a false-alarm
  budget; exceeding it auto-degrades the channel to human triage
  (``supplychain:false_alarm_budget_exceeded``); no budget at all is
  fail-closed (``supplychain:no_alarm_budget``).
* ``algorithmic_labor_probe()`` — labor-management metrics are
  probed; legally-mandated rest counted as inefficiency, scan-rate
  penalties for restroom use -> ``supplychain.rest_violation``
  (paulchenglaw lesson).
* ``deskilling_clock()`` — deskilling audits on a clock; resilience
  below the pinned floor -> ``supplychain.brittle`` (WID/prism
  lesson).
* ``check_scenario()`` — tariff/trade scenarios bind a versioned
  assumption digest; unbound -> ``supplychain.unbound_scenario``
  (DMCC lesson).
* ``concentration_probe()`` — single-source concentration beyond
  tolerance -> ``supplychain:concentration_breach`` (diversification
  audit trigger).
* ``vendor_claim_receipt()`` — vendor AI capability claims bind a
  measurement protocol; self-reported only ->
  ``supplychain.unverified_claim`` (Flexport lesson).

Honest scoping: this module enforces *declared supply-chain
discipline* — the software cannot authorize what is not declared,
pinned, and fresh. It does not make supply chains resilient, does not
audit real suppliers or vendors (self-reported numbers stay
NON_AUTHORITATIVE until bound to a measurement protocol), and does
not replace labor-law enforcement. Everything is offline and
deterministic; the only clock is the ``now`` the caller injects
(integer epoch seconds). All digest comparisons use
:func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any

try:  # ninety-fifth batch: the single canonicalizer
    from canonical_json import jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(
            _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True).encode("utf-8")
        ).hexdigest()

from ed25519 import public_key as _ed25519_pubkey  # noqa: F401 (re-exported for tests)
from ed25519 import sign as _ed25519_sign
from ed25519 import verify as _ed25519_verify

#: Schema marker, pinned into every digest.
SCHEMA_VERSION = "northstar.supplychain_agents.v1"

#: Denial reason codes. Mostly ``supplychain:`` for audit filtering;
#: ``supplychain.rest_violation`` and ``supplychain.brittle`` use the
#: dotted form from the research absorption brief.
DENY_AUTONOMOUS_DECISION = "supplychain:autonomous_decision"
DENY_DECISION_DIGEST_MISMATCH = "supplychain:decision_digest_mismatch"
DENY_DECISION_SIGNATURE_INVALID = "supplychain:decision_signature_invalid"
DENY_NO_RISK_EVIDENCE = "supplychain:no_risk_evidence"
DENY_RISK_SIGNATURE_INVALID = "supplychain:risk_signature_invalid"
DENY_NO_ALARM_BUDGET = "supplychain:no_alarm_budget"
DENY_BUDGET_STALE = "supplychain:budget_stale"
DENY_FALSE_ALARM_BUDGET_EXCEEDED = "supplychain:false_alarm_budget_exceeded"
DENY_REST_VIOLATION = "supplychain.rest_violation"
DENY_PROBE_STALE = "supplychain:probe_stale"
DENY_PROBE_SIGNATURE_INVALID = "supplychain:probe_signature_invalid"
DENY_NO_DESKILLING_AUDIT = "supplychain:no_deskilling_audit"
DENY_AUDIT_OVERDUE = "supplychain:audit_overdue"
DENY_BRITTLE = "supplychain.brittle"
DENY_UNBOUND_SCENARIO = "supplychain.unbound_scenario"
DENY_SCENARIO_VERSION_MISMATCH = "supplychain.unbound_scenario"
DENY_CONCENTRATION_BREACH = "supplychain:concentration_breach"
DENY_UNVERIFIED_CLAIM = "supplychain.unverified_claim"
DENY_CLAIM_SIGNATURE_INVALID = "supplychain:claim_signature_invalid"
DENY_MALFORMED = "supplychain:malformed"
DENY_UNKNOWN_AUTHORITY = "supplychain:unknown_authority"

#: Audit events.
DECISION_DENIED_EVENT = "supplychain.decision_denied"
RISK_EVIDENCE_DENIED_EVENT = "supplychain.risk_evidence_denied"
BUDGET_EXCEEDED_EVENT = "supplychain.budget_exceeded"
LABOR_VIOLATION_EVENT = "supplychain.labor_violation"
BRITTLE_EVENT = "supplychain.brittle"
CLAIM_DENIED_EVENT = "supplychain.claim_denied"

#: Classification tiers.
SUPPLYCHAIN_AUTHORITATIVE = "supplychain-authoritative"
SUPPLYCHAIN_NON_AUTHORITATIVE = "supplychain-non-authoritative"

#: Deskilling resilience floor, in basis points of 10000. A bench
#: parameter, not a legal threshold — verify against engineering
#: practice before operational use.
RESILIENCE_FLOOR_BPS = 5000


class SupplyChainAgentsError(ValueError):
    """Malformed supply-chain AI input. Fail loud, never guess."""


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise SupplyChainAgentsError(f"{name} must be a non-empty string")
    return value


def _require_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise SupplyChainAgentsError(f"{name} must be an integer")
    return value


def _require_bps(value: Any, name: str) -> int:
    v = _require_int(value, name)
    if not 0 <= v <= 10000:
        raise SupplyChainAgentsError(f"{name} must be in 0..10000 (basis points)")
    return v


def _require_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise SupplyChainAgentsError(f"{name} must be a bool")
    return value


def _check_ts(value: Any, name: str) -> int:
    v = _require_int(value, name)
    if v < 0:
        raise SupplyChainAgentsError(f"{name} must be a non-negative epoch")
    return v


def _is_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(c in "0123456789abcdef" for c in value)
    )


def _check_hex64(value: Any, name: str) -> str:
    if not _is_hex(value, 64):
        raise SupplyChainAgentsError(f"{name} must be 64 lowercase hex chars")
    return value


def _check_sig_hex(value: Any, name: str) -> str:
    if not _is_hex(value, 128):
        raise SupplyChainAgentsError(f"{name} must be 128 lowercase hex chars (64-byte Ed25519 signature)")
    return value


def _check_secret(value: Any, name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise SupplyChainAgentsError(f"{name} must be 32 bytes")
    return value


def _check_pubkey_hex(value: Any, name: str) -> str:
    if not _is_hex(value, 64):
        raise SupplyChainAgentsError(f"{name} must be 64 lowercase hex chars (32-byte Ed25519 public key)")
    return value


def _check_vocab(value: Any, name: str, vocab: tuple[str, ...]) -> str:
    v = _require_str(value, name)
    if v not in vocab:
        raise SupplyChainAgentsError(f"{name} must be one of {vocab}, got {v!r}")
    return v


class AuthorityRegistry:
    """Registered human authorities (authority_id -> Ed25519 public key).

    The AI platform is never in this registry: there is no code path
    that adds a platform id, and every gate refuses signatures from
    unregistered keys. Registration itself is a host-side operation
    outside this module — the module only reads the table.
    """

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}

    def register(self, authority_id: str, public_key: bytes) -> None:
        _require_str(authority_id, "authority_id")
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise SupplyChainAgentsError("public_key must be 32 bytes")
        self._keys[authority_id] = public_key

    def public_key_for(self, authority_id: str) -> bytes | None:
        return self._keys.get(authority_id)


def _verify_signature(
    authorities: AuthorityRegistry,
    *,
    authority_id: str,
    digest_hex: str,
    signature_hex: str,
    deny_code: str,
) -> str | None:
    """Return a denial code if the signature is invalid, else None."""
    pub = authorities.public_key_for(authority_id)
    if pub is None:
        return DENY_UNKNOWN_AUTHORITY
    try:
        ok = _ed25519_verify(
            pub, digest_hex.encode("utf-8"), bytes.fromhex(signature_hex)
        )
    except Exception:
        ok = False
    return None if ok else deny_code


def _sign(secret: bytes, digest_hex: str) -> str:
    return _ed25519_sign(secret, digest_hex.encode("utf-8")).hex()


@dataclass(frozen=True)
class SupplyChainVerdict:
    """Outcome of one supply-chain AI discipline check."""

    allowed: bool
    deny_code: str | None
    classification: str
    receipt_digest: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "supplychain-verdict",
            "allowed": self.allowed,
            "deny_code": self.deny_code,
            "classification": self.classification,
            "receipt_digest": self.receipt_digest,
            "schema_version": SCHEMA_VERSION,
        }


def _allow(receipt_digest: str = "") -> SupplyChainVerdict:
    return SupplyChainVerdict(
        allowed=True,
        deny_code=None,
        classification=SUPPLYCHAIN_AUTHORITATIVE,
        receipt_digest=receipt_digest,
    )


def _deny(deny_code: str) -> SupplyChainVerdict:
    return SupplyChainVerdict(
        allowed=False,
        deny_code=deny_code,
        classification=SUPPLYCHAIN_NON_AUTHORITATIVE,
    )


# ---------------------------------------------------------------------------
# Human-final gates: no AI-independent supply-chain decisions (RELEX lesson)
# ---------------------------------------------------------------------------

#: Closed decision-kind vocabulary. There is no sixth value; an
#: unknown kind is malformed, not a default.
DECISION_KINDS = (
    "reroute",
    "expedite",
    "supplier_switch",
    "po_approval",
    "forecast_commit",
)

DECISION_SCHEMA = "northstar.supplychain_agents.decision.v1"


def _decision_payload(
    *,
    decision_id: str,
    decision_kind: str,
    ai_decision_digest: str,
    human_approver_id: str,
    approved_at: int,
) -> dict[str, Any]:
    return {
        "schema": DECISION_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "decision_id": decision_id,
        "decision_kind": decision_kind,
        "ai_decision_digest": ai_decision_digest,
        "human_approver_id": human_approver_id,
        "approved_at": approved_at,
    }


@dataclass(frozen=True)
class DecisionApproval:
    """A named-human approval of one AI supply-chain decision."""

    decision_id: str
    decision_kind: str
    ai_decision_digest: str
    human_approver_id: str
    approved_at: int
    signature_hex: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "supplychain-decision-approval",
            "decision_id": self.decision_id,
            "decision_kind": self.decision_kind,
            "ai_decision_digest": self.ai_decision_digest,
            "human_approver_id": self.human_approver_id,
            "approved_at": self.approved_at,
            "signature_hex": self.signature_hex,
            "schema_version": SCHEMA_VERSION,
        }


class DecisionRegistry:
    """Named-human approvals of AI supply-chain decisions."""

    def __init__(self) -> None:
        self._approvals: dict[str, DecisionApproval] = {}

    def record(self, approval: DecisionApproval) -> None:
        self._approvals[approval.decision_id] = approval

    def approval_for(self, decision_id: str) -> DecisionApproval | None:
        return self._approvals.get(decision_id)


def issue_decision_approval(
    *,
    decision_id: str,
    decision_kind: str,
    ai_decision_digest: str,
    human_approver_id: str,
    approved_at: int,
    approver_secret: bytes,
) -> DecisionApproval:
    """Issue a named-human approval of an AI supply-chain decision.

    The signature binds the exact AI-decision digest; executing a
    different decision than the one approved is a digest mismatch.
    """
    decision_id = _require_str(decision_id, "decision_id")
    decision_kind = _check_vocab(decision_kind, "decision_kind", DECISION_KINDS)
    ai_decision_digest = _check_hex64(ai_decision_digest, "ai_decision_digest")
    human_approver_id = _require_str(human_approver_id, "human_approver_id")
    approved_at = _check_ts(approved_at, "approved_at")
    approver_secret = _check_secret(approver_secret, "approver_secret")
    digest = jcs_sha256_hex(
        _decision_payload(
            decision_id=decision_id,
            decision_kind=decision_kind,
            ai_decision_digest=ai_decision_digest,
            human_approver_id=human_approver_id,
            approved_at=approved_at,
        )
    )
    return DecisionApproval(
        decision_id=decision_id,
        decision_kind=decision_kind,
        ai_decision_digest=ai_decision_digest,
        human_approver_id=human_approver_id,
        approved_at=approved_at,
        signature_hex=_sign(approver_secret, digest),
    )


def human_final_gate(
    approvals: DecisionRegistry,
    authorities: AuthorityRegistry,
    *,
    decision_id: str,
    decision_kind: str,
    ai_decision_digest: str,
    decided_at: int,
    approver_id: str,
) -> SupplyChainVerdict:
    """Check that an AI supply-chain decision carries a human approval.

    An AI decision with no named-human approval is refused
    whole-class (``supplychain:autonomous_decision``) — the RELEX
    lesson: only 10% trust AI to decide alone, and the module trusts
    none of it.
    """
    decision_id = _require_str(decision_id, "decision_id")
    decision_kind = _check_vocab(decision_kind, "decision_kind", DECISION_KINDS)
    ai_decision_digest = _check_hex64(ai_decision_digest, "ai_decision_digest")
    decided_at = _check_ts(decided_at, "decided_at")
    approver_id = _require_str(approver_id, "approver_id")
    approval = approvals.approval_for(decision_id)
    if approval is None:
        return _deny(DENY_AUTONOMOUS_DECISION)
    if not hmac.compare_digest(approval.ai_decision_digest, ai_decision_digest):
        return _deny(DENY_DECISION_DIGEST_MISMATCH)
    if approval.approved_at > decided_at:
        return _deny(DENY_AUTONOMOUS_DECISION)
    digest = jcs_sha256_hex(
        _decision_payload(
            decision_id=approval.decision_id,
            decision_kind=approval.decision_kind,
            ai_decision_digest=approval.ai_decision_digest,
            human_approver_id=approval.human_approver_id,
            approved_at=approval.approved_at,
        )
    )
    code = _verify_signature(
        authorities,
        authority_id=approver_id,
        digest_hex=digest,
        signature_hex=approval.signature_hex,
        deny_code=DENY_DECISION_SIGNATURE_INVALID,
    )
    if code is not None:
        return _deny(code)
    return _allow(digest)


# ---------------------------------------------------------------------------
# Risk-score evidence: scores bind their evidence (acedit lesson)
# ---------------------------------------------------------------------------

RISK_SCHEMA = "northstar.supplychain_agents.risk_score.v1"


def _risk_payload(
    *,
    score_id: str,
    supplier_id: str,
    score_bps: int,
    warning_lead_days: int,
    false_positive_bps: int,
    evidence_digest: str,
    measured_at: int,
    expires_at: int,
    issuer_id: str,
) -> dict[str, Any]:
    return {
        "schema": RISK_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "score_id": score_id,
        "supplier_id": supplier_id,
        "score_bps": score_bps,
        "warning_lead_days": warning_lead_days,
        "false_positive_bps": false_positive_bps,
        "evidence_digest": evidence_digest,
        "measured_at": measured_at,
        "expires_at": expires_at,
        "issuer_id": issuer_id,
    }


@dataclass(frozen=True)
class RiskScoreReceipt:
    """A supplier risk score with a bound evidence chain."""

    score_id: str
    supplier_id: str
    score_bps: int
    warning_lead_days: int
    false_positive_bps: int
    evidence_digest: str
    measured_at: int
    expires_at: int
    issuer_id: str
    signature_hex: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "supplychain-risk-score",
            "score_id": self.score_id,
            "supplier_id": self.supplier_id,
            "score_bps": self.score_bps,
            "warning_lead_days": self.warning_lead_days,
            "false_positive_bps": self.false_positive_bps,
            "evidence_digest": self.evidence_digest,
            "measured_at": self.measured_at,
            "expires_at": self.expires_at,
            "issuer_id": self.issuer_id,
            "signature_hex": self.signature_hex,
            "schema_version": SCHEMA_VERSION,
        }


class RiskScoreRegistry:
    """Supplier risk scores with bound evidence chains."""

    def __init__(self) -> None:
        self._scores: dict[str, RiskScoreReceipt] = {}

    def record(self, receipt: RiskScoreReceipt) -> None:
        self._scores[receipt.score_id] = receipt

    def score_for(self, score_id: str) -> RiskScoreReceipt | None:
        return self._scores.get(score_id)


def issue_risk_score(
    *,
    score_id: str,
    supplier_id: str,
    score_bps: int,
    warning_lead_days: int,
    false_positive_bps: int,
    evidence_digest: str,
    measured_at: int,
    expires_at: int,
    issuer_id: str,
    issuer_secret: bytes,
) -> RiskScoreReceipt:
    """Issue a risk score bound to its evidence chain.

    The warning lead time and the false-positive rate are disclosed
    in the signed payload — the acedit lesson (91-day warning, 18%
    FP). A score that cannot show its evidence cannot be issued.
    """
    score_id = _require_str(score_id, "score_id")
    supplier_id = _require_str(supplier_id, "supplier_id")
    score_bps = _require_bps(score_bps, "score_bps")
    warning_lead_days = _require_int(warning_lead_days, "warning_lead_days")
    if warning_lead_days < 0:
        raise SupplyChainAgentsError("warning_lead_days must be non-negative")
    false_positive_bps = _require_bps(false_positive_bps, "false_positive_bps")
    evidence_digest = _check_hex64(evidence_digest, "evidence_digest")
    measured_at = _check_ts(measured_at, "measured_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= measured_at:
        raise SupplyChainAgentsError("expires_at must be after measured_at")
    issuer_id = _require_str(issuer_id, "issuer_id")
    issuer_secret = _check_secret(issuer_secret, "issuer_secret")
    digest = jcs_sha256_hex(
        _risk_payload(
            score_id=score_id,
            supplier_id=supplier_id,
            score_bps=score_bps,
            warning_lead_days=warning_lead_days,
            false_positive_bps=false_positive_bps,
            evidence_digest=evidence_digest,
            measured_at=measured_at,
            expires_at=expires_at,
            issuer_id=issuer_id,
        )
    )
    return RiskScoreReceipt(
        score_id=score_id,
        supplier_id=supplier_id,
        score_bps=score_bps,
        warning_lead_days=warning_lead_days,
        false_positive_bps=false_positive_bps,
        evidence_digest=evidence_digest,
        measured_at=measured_at,
        expires_at=expires_at,
        issuer_id=issuer_id,
        signature_hex=_sign(issuer_secret, digest),
    )


def risk_score_evidence(
    scores: RiskScoreRegistry,
    authorities: AuthorityRegistry,
    *,
    score_id: str,
    supplier_id: str,
    used_at: int,
    issuer_id: str,
) -> SupplyChainVerdict:
    """Check that a supplier risk score binds live evidence.

    An evidence-free score is NON_AUTHORITATIVE
    (``supplychain:no_risk_evidence``) — a bare number from an
    anonymous model is not a decision input.
    """
    score_id = _require_str(score_id, "score_id")
    supplier_id = _require_str(supplier_id, "supplier_id")
    used_at = _check_ts(used_at, "used_at")
    issuer_id = _require_str(issuer_id, "issuer_id")
    receipt = scores.score_for(score_id)
    if receipt is None or receipt.supplier_id != supplier_id:
        return _deny(DENY_NO_RISK_EVIDENCE)
    if receipt.expires_at <= used_at:
        return _deny(DENY_NO_RISK_EVIDENCE)
    digest = jcs_sha256_hex(
        _risk_payload(
            score_id=receipt.score_id,
            supplier_id=receipt.supplier_id,
            score_bps=receipt.score_bps,
            warning_lead_days=receipt.warning_lead_days,
            false_positive_bps=receipt.false_positive_bps,
            evidence_digest=receipt.evidence_digest,
            measured_at=receipt.measured_at,
            expires_at=receipt.expires_at,
            issuer_id=receipt.issuer_id,
        )
    )
    code = _verify_signature(
        authorities,
        authority_id=issuer_id,
        digest_hex=digest,
        signature_hex=receipt.signature_hex,
        deny_code=DENY_RISK_SIGNATURE_INVALID,
    )
    if code is not None:
        return _deny(code)
    return _allow(digest)


# ---------------------------------------------------------------------------
# False-alarm budgets: channels degrade to human triage (alert fatigue)
# ---------------------------------------------------------------------------

BUDGET_SCHEMA = "northstar.supplychain_agents.alarm_budget.v1"


def _budget_payload(
    *,
    budget_id: str,
    channel_id: str,
    budget_bps: int,
    alerts_total: int,
    false_alerts: int,
    window_start: int,
    window_end: int,
    issuer_id: str,
) -> dict[str, Any]:
    return {
        "schema": BUDGET_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "budget_id": budget_id,
        "channel_id": channel_id,
        "budget_bps": budget_bps,
        "alerts_total": alerts_total,
        "false_alerts": false_alerts,
        "window_start": window_start,
        "window_end": window_end,
        "issuer_id": issuer_id,
    }


@dataclass(frozen=True)
class AlarmBudgetReceipt:
    """A pinned false-alarm budget for one risk-alert channel."""

    budget_id: str
    channel_id: str
    budget_bps: int
    alerts_total: int
    false_alerts: int
    window_start: int
    window_end: int
    issuer_id: str
    signature_hex: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "supplychain-alarm-budget",
            "budget_id": self.budget_id,
            "channel_id": self.channel_id,
            "budget_bps": self.budget_bps,
            "alerts_total": self.alerts_total,
            "false_alerts": self.false_alerts,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "issuer_id": self.issuer_id,
            "signature_hex": self.signature_hex,
            "schema_version": SCHEMA_VERSION,
        }


class AlarmBudgetRegistry:
    """False-alarm budgets pinned per alert channel."""

    def __init__(self) -> None:
        self._budgets: dict[str, AlarmBudgetReceipt] = {}

    def record(self, receipt: AlarmBudgetReceipt) -> None:
        self._budgets[receipt.channel_id] = receipt

    def budget_for(self, channel_id: str) -> AlarmBudgetReceipt | None:
        return self._budgets.get(channel_id)


def issue_alarm_budget(
    *,
    budget_id: str,
    channel_id: str,
    budget_bps: int,
    alerts_total: int,
    false_alerts: int,
    window_start: int,
    window_end: int,
    issuer_id: str,
    issuer_secret: bytes,
) -> AlarmBudgetReceipt:
    """Issue a false-alarm budget for one risk-alert channel.

    The budget pins the maximum tolerable false-alarm rate; a
    channel whose measured rate exceeds it is auto-degraded to human
    triage at check time.
    """
    budget_id = _require_str(budget_id, "budget_id")
    channel_id = _require_str(channel_id, "channel_id")
    budget_bps = _require_bps(budget_bps, "budget_bps")
    alerts_total = _require_int(alerts_total, "alerts_total")
    if alerts_total < 0:
        raise SupplyChainAgentsError("alerts_total must be non-negative")
    false_alerts = _require_int(false_alerts, "false_alerts")
    if false_alerts < 0:
        raise SupplyChainAgentsError("false_alerts must be non-negative")
    if false_alerts > alerts_total:
        raise SupplyChainAgentsError("false_alerts cannot exceed alerts_total")
    window_start = _check_ts(window_start, "window_start")
    window_end = _check_ts(window_end, "window_end")
    if window_end <= window_start:
        raise SupplyChainAgentsError("window_end must be after window_start")
    issuer_id = _require_str(issuer_id, "issuer_id")
    issuer_secret = _check_secret(issuer_secret, "issuer_secret")
    digest = jcs_sha256_hex(
        _budget_payload(
            budget_id=budget_id,
            channel_id=channel_id,
            budget_bps=budget_bps,
            alerts_total=alerts_total,
            false_alerts=false_alerts,
            window_start=window_start,
            window_end=window_end,
            issuer_id=issuer_id,
        )
    )
    return AlarmBudgetReceipt(
        budget_id=budget_id,
        channel_id=channel_id,
        budget_bps=budget_bps,
        alerts_total=alerts_total,
        false_alerts=false_alerts,
        window_start=window_start,
        window_end=window_end,
        issuer_id=issuer_id,
        signature_hex=_sign(issuer_secret, digest),
    )


def check_alarm_budget(
    budgets: AlarmBudgetRegistry,
    authorities: AuthorityRegistry,
    *,
    channel_id: str,
    checked_at: int,
    issuer_id: str,
) -> SupplyChainVerdict:
    """Check that an alert channel is within its false-alarm budget.

    No pinned budget is fail-closed
    (``supplychain:no_alarm_budget``); a stale window is
    ``supplychain:budget_stale``; a measured false-alarm rate above
    the budget degrades the channel to human triage —
    NON_AUTHORITATIVE (``supplychain:false_alarm_budget_exceeded``).
    """
    channel_id = _require_str(channel_id, "channel_id")
    checked_at = _check_ts(checked_at, "checked_at")
    issuer_id = _require_str(issuer_id, "issuer_id")
    receipt = budgets.budget_for(channel_id)
    if receipt is None:
        return _deny(DENY_NO_ALARM_BUDGET)
    if receipt.window_end <= checked_at:
        return _deny(DENY_BUDGET_STALE)
    digest = jcs_sha256_hex(
        _budget_payload(
            budget_id=receipt.budget_id,
            channel_id=receipt.channel_id,
            budget_bps=receipt.budget_bps,
            alerts_total=receipt.alerts_total,
            false_alerts=receipt.false_alerts,
            window_start=receipt.window_start,
            window_end=receipt.window_end,
            issuer_id=receipt.issuer_id,
        )
    )
    code = _verify_signature(
        authorities,
        authority_id=issuer_id,
        digest_hex=digest,
        signature_hex=receipt.signature_hex,
        deny_code=DENY_RISK_SIGNATURE_INVALID,
    )
    if code is not None:
        return _deny(code)
    if receipt.alerts_total == 0:
        return _allow(digest)
    false_rate_bps = (receipt.false_alerts * 10000) // receipt.alerts_total
    if false_rate_bps > receipt.budget_bps:
        return _deny(DENY_FALSE_ALARM_BUDGET_EXCEEDED)
    return _allow(digest)


# ---------------------------------------------------------------------------
# Algorithmic-labor probes: rest is not inefficiency (paulchenglaw lesson)
# ---------------------------------------------------------------------------

LABOR_PROBE_SCHEMA = "northstar.supplychain_agents.labor_probe.v1"


def _labor_probe_payload(
    *,
    probe_id: str,
    workforce_id: str,
    rest_minutes_counted_as_inefficiency: int,
    scan_rate_penalty_applied: bool,
    toilet_break_penalized: bool,
    measured_at: int,
    expires_at: int,
    issuer_id: str,
) -> dict[str, Any]:
    return {
        "schema": LABOR_PROBE_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "probe_id": probe_id,
        "workforce_id": workforce_id,
        "rest_minutes_counted_as_inefficiency": rest_minutes_counted_as_inefficiency,
        "scan_rate_penalty_applied": scan_rate_penalty_applied,
        "toilet_break_penalized": toilet_break_penalized,
        "measured_at": measured_at,
        "expires_at": expires_at,
        "issuer_id": issuer_id,
    }


@dataclass(frozen=True)
class LaborProbe:
    """A signed probe of algorithmic labor-management metrics."""

    probe_id: str
    workforce_id: str
    rest_minutes_counted_as_inefficiency: int
    scan_rate_penalty_applied: bool
    toilet_break_penalized: bool
    measured_at: int
    expires_at: int
    issuer_id: str
    signature_hex: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "supplychain-labor-probe",
            "probe_id": self.probe_id,
            "workforce_id": self.workforce_id,
            "rest_minutes_counted_as_inefficiency": self.rest_minutes_counted_as_inefficiency,
            "scan_rate_penalty_applied": self.scan_rate_penalty_applied,
            "toilet_break_penalized": self.toilet_break_penalized,
            "measured_at": self.measured_at,
            "expires_at": self.expires_at,
            "issuer_id": self.issuer_id,
            "signature_hex": self.signature_hex,
            "schema_version": SCHEMA_VERSION,
        }


def issue_labor_probe(
    *,
    probe_id: str,
    workforce_id: str,
    rest_minutes_counted_as_inefficiency: int,
    scan_rate_penalty_applied: bool,
    toilet_break_penalized: bool,
    measured_at: int,
    expires_at: int,
    issuer_id: str,
    issuer_secret: bytes,
) -> LaborProbe:
    """Issue a signed probe of algorithmic labor-management metrics.

    The probe records the measured facts — including violations —
    so the gate can see them. Issuance never refuses; the *gate*
    refuses.
    """
    probe_id = _require_str(probe_id, "probe_id")
    workforce_id = _require_str(workforce_id, "workforce_id")
    rest_minutes_counted_as_inefficiency = _require_int(
        rest_minutes_counted_as_inefficiency, "rest_minutes_counted_as_inefficiency"
    )
    if rest_minutes_counted_as_inefficiency < 0:
        raise SupplyChainAgentsError(
            "rest_minutes_counted_as_inefficiency must be non-negative"
        )
    scan_rate_penalty_applied = _require_bool(
        scan_rate_penalty_applied, "scan_rate_penalty_applied"
    )
    toilet_break_penalized = _require_bool(
        toilet_break_penalized, "toilet_break_penalized"
    )
    measured_at = _check_ts(measured_at, "measured_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= measured_at:
        raise SupplyChainAgentsError("expires_at must be after measured_at")
    issuer_id = _require_str(issuer_id, "issuer_id")
    issuer_secret = _check_secret(issuer_secret, "issuer_secret")
    digest = jcs_sha256_hex(
        _labor_probe_payload(
            probe_id=probe_id,
            workforce_id=workforce_id,
            rest_minutes_counted_as_inefficiency=rest_minutes_counted_as_inefficiency,
            scan_rate_penalty_applied=scan_rate_penalty_applied,
            toilet_break_penalized=toilet_break_penalized,
            measured_at=measured_at,
            expires_at=expires_at,
            issuer_id=issuer_id,
        )
    )
    return LaborProbe(
        probe_id=probe_id,
        workforce_id=workforce_id,
        rest_minutes_counted_as_inefficiency=rest_minutes_counted_as_inefficiency,
        scan_rate_penalty_applied=scan_rate_penalty_applied,
        toilet_break_penalized=toilet_break_penalized,
        measured_at=measured_at,
        expires_at=expires_at,
        issuer_id=issuer_id,
        signature_hex=_sign(issuer_secret, digest),
    )


def algorithmic_labor_probe(
    probe: LaborProbe,
    authorities: AuthorityRegistry,
    *,
    issuer_id: str,
    checked_at: int,
) -> SupplyChainVerdict:
    """Check an algorithmic labor-management probe for violations.

    Legally-mandated rest counted as inefficiency, scan-rate
    penalties, or restroom penalties are ``supplychain.rest_violation``
    — the technology is automated, the employer's legal obligations
    are not (paulchenglaw lesson).
    """
    if not isinstance(probe, LaborProbe):
        raise SupplyChainAgentsError("probe must be a LaborProbe")
    issuer_id = _require_str(issuer_id, "issuer_id")
    checked_at = _check_ts(checked_at, "checked_at")
    digest = jcs_sha256_hex(
        _labor_probe_payload(
            probe_id=probe.probe_id,
            workforce_id=probe.workforce_id,
            rest_minutes_counted_as_inefficiency=probe.rest_minutes_counted_as_inefficiency,
            scan_rate_penalty_applied=probe.scan_rate_penalty_applied,
            toilet_break_penalized=probe.toilet_break_penalized,
            measured_at=probe.measured_at,
            expires_at=probe.expires_at,
            issuer_id=probe.issuer_id,
        )
    )
    code = _verify_signature(
        authorities,
        authority_id=issuer_id,
        digest_hex=digest,
        signature_hex=probe.signature_hex,
        deny_code=DENY_PROBE_SIGNATURE_INVALID,
    )
    if code is not None:
        return _deny(code)
    if probe.expires_at <= checked_at:
        return _deny(DENY_PROBE_STALE)
    if (
        probe.rest_minutes_counted_as_inefficiency > 0
        or probe.scan_rate_penalty_applied
        or probe.toilet_break_penalized
    ):
        return _deny(DENY_REST_VIOLATION)
    return _allow(digest)


# ---------------------------------------------------------------------------
# Deskilling clocks: resilience audits (WID/prism lesson)
# ---------------------------------------------------------------------------

DESKILL_SCHEMA = "northstar.supplychain_agents.deskilling_audit.v1"


def _deskilling_payload(
    *,
    audit_id: str,
    facility_id: str,
    resilience_score_bps: int,
    stress_test_digest: str,
    measured_at: int,
    next_audit_due: int,
    issuer_id: str,
) -> dict[str, Any]:
    return {
        "schema": DESKILL_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "audit_id": audit_id,
        "facility_id": facility_id,
        "resilience_score_bps": resilience_score_bps,
        "stress_test_digest": stress_test_digest,
        "measured_at": measured_at,
        "next_audit_due": next_audit_due,
        "issuer_id": issuer_id,
    }


@dataclass(frozen=True)
class DeskillingAudit:
    """A deskilling/resilience audit of one facility."""

    audit_id: str
    facility_id: str
    resilience_score_bps: int
    stress_test_digest: str
    measured_at: int
    next_audit_due: int
    issuer_id: str
    signature_hex: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "supplychain-deskilling-audit",
            "audit_id": self.audit_id,
            "facility_id": self.facility_id,
            "resilience_score_bps": self.resilience_score_bps,
            "stress_test_digest": self.stress_test_digest,
            "measured_at": self.measured_at,
            "next_audit_due": self.next_audit_due,
            "issuer_id": self.issuer_id,
            "signature_hex": self.signature_hex,
            "schema_version": SCHEMA_VERSION,
        }


class DeskillingRegistry:
    """Deskilling/resilience audits per facility."""

    def __init__(self) -> None:
        self._audits: dict[str, DeskillingAudit] = {}

    def record(self, audit: DeskillingAudit) -> None:
        self._audits[audit.facility_id] = audit

    def audit_for(self, facility_id: str) -> DeskillingAudit | None:
        return self._audits.get(facility_id)


def issue_deskilling_audit(
    *,
    audit_id: str,
    facility_id: str,
    resilience_score_bps: int,
    stress_test_digest: str,
    measured_at: int,
    next_audit_due: int,
    issuer_id: str,
    issuer_secret: bytes,
) -> DeskillingAudit:
    """Issue a deskilling/resilience audit for one facility.

    The resilience score binds a stress-test digest — a bare number
    without a bound stress test cannot be issued.
    """
    audit_id = _require_str(audit_id, "audit_id")
    facility_id = _require_str(facility_id, "facility_id")
    resilience_score_bps = _require_bps(resilience_score_bps, "resilience_score_bps")
    stress_test_digest = _check_hex64(stress_test_digest, "stress_test_digest")
    measured_at = _check_ts(measured_at, "measured_at")
    next_audit_due = _check_ts(next_audit_due, "next_audit_due")
    if next_audit_due <= measured_at:
        raise SupplyChainAgentsError("next_audit_due must be after measured_at")
    issuer_id = _require_str(issuer_id, "issuer_id")
    issuer_secret = _check_secret(issuer_secret, "issuer_secret")
    digest = jcs_sha256_hex(
        _deskilling_payload(
            audit_id=audit_id,
            facility_id=facility_id,
            resilience_score_bps=resilience_score_bps,
            stress_test_digest=stress_test_digest,
            measured_at=measured_at,
            next_audit_due=next_audit_due,
            issuer_id=issuer_id,
        )
    )
    return DeskillingAudit(
        audit_id=audit_id,
        facility_id=facility_id,
        resilience_score_bps=resilience_score_bps,
        stress_test_digest=stress_test_digest,
        measured_at=measured_at,
        next_audit_due=next_audit_due,
        issuer_id=issuer_id,
        signature_hex=_sign(issuer_secret, digest),
    )


def deskilling_clock(
    audits: DeskillingRegistry,
    authorities: AuthorityRegistry,
    *,
    facility_id: str,
    checked_at: int,
    issuer_id: str,
) -> SupplyChainVerdict:
    """Check a facility's deskilling audit on its clock.

    No audit is NON_AUTHORITATIVE
    (``supplychain:no_deskilling_audit``); a lapsed clock is
    ``supplychain:audit_overdue``; resilience below the pinned floor
    is ``supplychain.brittle`` — efficient in steady state, fragile
    under stress (prism lesson).
    """
    facility_id = _require_str(facility_id, "facility_id")
    checked_at = _check_ts(checked_at, "checked_at")
    issuer_id = _require_str(issuer_id, "issuer_id")
    audit = audits.audit_for(facility_id)
    if audit is None:
        return _deny(DENY_NO_DESKILLING_AUDIT)
    if audit.next_audit_due <= checked_at:
        return _deny(DENY_AUDIT_OVERDUE)
    digest = jcs_sha256_hex(
        _deskilling_payload(
            audit_id=audit.audit_id,
            facility_id=audit.facility_id,
            resilience_score_bps=audit.resilience_score_bps,
            stress_test_digest=audit.stress_test_digest,
            measured_at=audit.measured_at,
            next_audit_due=audit.next_audit_due,
            issuer_id=audit.issuer_id,
        )
    )
    code = _verify_signature(
        authorities,
        authority_id=issuer_id,
        digest_hex=digest,
        signature_hex=audit.signature_hex,
        deny_code=DENY_PROBE_SIGNATURE_INVALID,
    )
    if code is not None:
        return _deny(code)
    if audit.resilience_score_bps < RESILIENCE_FLOOR_BPS:
        return _deny(DENY_BRITTLE)
    return _allow(digest)


# ---------------------------------------------------------------------------
# Scenario version binding: tariff/trade assumptions (DMCC lesson)
# ---------------------------------------------------------------------------

SCENARIO_SCHEMA = "northstar.supplychain_agents.scenario.v1"


def _scenario_payload(
    *,
    scenario_id: str,
    scenario_version: str,
    assumption_digest: str,
    valid_from: int,
    valid_until: int,
    issuer_id: str,
) -> dict[str, Any]:
    return {
        "schema": SCENARIO_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "scenario_id": scenario_id,
        "scenario_version": scenario_version,
        "assumption_digest": assumption_digest,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "issuer_id": issuer_id,
    }


@dataclass(frozen=True)
class ScenarioReceipt:
    """A versioned planning-scenario assumption binding."""

    scenario_id: str
    scenario_version: str
    assumption_digest: str
    valid_from: int
    valid_until: int
    issuer_id: str
    signature_hex: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "supplychain-scenario",
            "scenario_id": self.scenario_id,
            "scenario_version": self.scenario_version,
            "assumption_digest": self.assumption_digest,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "issuer_id": self.issuer_id,
            "signature_hex": self.signature_hex,
            "schema_version": SCHEMA_VERSION,
        }


class ScenarioRegistry:
    """Versioned tariff/trade scenario bindings."""

    def __init__(self) -> None:
        self._scenarios: dict[tuple[str, str], ScenarioReceipt] = {}

    def record(self, receipt: ScenarioReceipt) -> None:
        self._scenarios[(receipt.scenario_id, receipt.scenario_version)] = receipt

    def scenario_for(
        self, scenario_id: str, scenario_version: str
    ) -> ScenarioReceipt | None:
        return self._scenarios.get((scenario_id, scenario_version))


def issue_scenario(
    *,
    scenario_id: str,
    scenario_version: str,
    assumption_digest: str,
    valid_from: int,
    valid_until: int,
    issuer_id: str,
    issuer_secret: bytes,
) -> ScenarioReceipt:
    """Issue a versioned planning-scenario assumption binding.

    The assumption digest pins the exact tariff/trade assumptions —
    regionalization mix, predictive-compliance rules, planning-cycle
    length — so a plan cannot silently swap scenarios.
    """
    scenario_id = _require_str(scenario_id, "scenario_id")
    scenario_version = _require_str(scenario_version, "scenario_version")
    assumption_digest = _check_hex64(assumption_digest, "assumption_digest")
    valid_from = _check_ts(valid_from, "valid_from")
    valid_until = _check_ts(valid_until, "valid_until")
    if valid_until <= valid_from:
        raise SupplyChainAgentsError("valid_until must be after valid_from")
    issuer_id = _require_str(issuer_id, "issuer_id")
    issuer_secret = _check_secret(issuer_secret, "issuer_secret")
    digest = jcs_sha256_hex(
        _scenario_payload(
            scenario_id=scenario_id,
            scenario_version=scenario_version,
            assumption_digest=assumption_digest,
            valid_from=valid_from,
            valid_until=valid_until,
            issuer_id=issuer_id,
        )
    )
    return ScenarioReceipt(
        scenario_id=scenario_id,
        scenario_version=scenario_version,
        assumption_digest=assumption_digest,
        valid_from=valid_from,
        valid_until=valid_until,
        issuer_id=issuer_id,
        signature_hex=_sign(issuer_secret, digest),
    )


def scenario_version_binding(
    scenarios: ScenarioRegistry,
    authorities: AuthorityRegistry,
    *,
    scenario_id: str,
    scenario_version: str,
    used_at: int,
    issuer_id: str,
) -> SupplyChainVerdict:
    """Check that a planning scenario binds a live versioned assumption.

    An unknown scenario or version is NON_AUTHORITATIVE
    (``supplychain.unbound_scenario``) — a plan built on an unbound
    tariff assumption is a guess, not a plan (DMCC lesson).
    """
    scenario_id = _require_str(scenario_id, "scenario_id")
    scenario_version = _require_str(scenario_version, "scenario_version")
    used_at = _check_ts(used_at, "used_at")
    issuer_id = _require_str(issuer_id, "issuer_id")
    receipt = scenarios.scenario_for(scenario_id, scenario_version)
    if receipt is None:
        return _deny(DENY_UNBOUND_SCENARIO)
    if not (receipt.valid_from <= used_at < receipt.valid_until):
        return _deny(DENY_UNBOUND_SCENARIO)
    digest = jcs_sha256_hex(
        _scenario_payload(
            scenario_id=receipt.scenario_id,
            scenario_version=receipt.scenario_version,
            assumption_digest=receipt.assumption_digest,
            valid_from=receipt.valid_from,
            valid_until=receipt.valid_until,
            issuer_id=receipt.issuer_id,
        )
    )
    code = _verify_signature(
        authorities,
        authority_id=issuer_id,
        digest_hex=digest,
        signature_hex=receipt.signature_hex,
        deny_code=DENY_RISK_SIGNATURE_INVALID,
    )
    if code is not None:
        return _deny(code)
    return _allow(digest)


# ---------------------------------------------------------------------------
# Concentration probes: single-source dependence (resilience)
# ---------------------------------------------------------------------------

CONCENTRATION_SCHEMA = "northstar.supplychain_agents.concentration.v1"


def _concentration_payload(
    *,
    probe_id: str,
    sku_family: str,
    top_supplier_share_bps: int,
    tolerance_bps: int,
    measured_at: int,
    expires_at: int,
    issuer_id: str,
) -> dict[str, Any]:
    return {
        "schema": CONCENTRATION_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "probe_id": probe_id,
        "sku_family": sku_family,
        "top_supplier_share_bps": top_supplier_share_bps,
        "tolerance_bps": tolerance_bps,
        "measured_at": measured_at,
        "expires_at": expires_at,
        "issuer_id": issuer_id,
    }


@dataclass(frozen=True)
class ConcentrationProbe:
    """A signed single-source concentration measurement."""

    probe_id: str
    sku_family: str
    top_supplier_share_bps: int
    tolerance_bps: int
    measured_at: int
    expires_at: int
    issuer_id: str
    signature_hex: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "supplychain-concentration-probe",
            "probe_id": self.probe_id,
            "sku_family": self.sku_family,
            "top_supplier_share_bps": self.top_supplier_share_bps,
            "tolerance_bps": self.tolerance_bps,
            "measured_at": self.measured_at,
            "expires_at": self.expires_at,
            "issuer_id": self.issuer_id,
            "signature_hex": self.signature_hex,
            "schema_version": SCHEMA_VERSION,
        }


def issue_concentration_probe(
    *,
    probe_id: str,
    sku_family: str,
    top_supplier_share_bps: int,
    tolerance_bps: int,
    measured_at: int,
    expires_at: int,
    issuer_id: str,
    issuer_secret: bytes,
) -> ConcentrationProbe:
    """Issue a single-source concentration measurement.

    The tolerance is declared in the signed payload; a share above
    it trips the diversification-audit gate at check time.
    """
    probe_id = _require_str(probe_id, "probe_id")
    sku_family = _require_str(sku_family, "sku_family")
    top_supplier_share_bps = _require_bps(
        top_supplier_share_bps, "top_supplier_share_bps"
    )
    tolerance_bps = _require_bps(tolerance_bps, "tolerance_bps")
    measured_at = _check_ts(measured_at, "measured_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= measured_at:
        raise SupplyChainAgentsError("expires_at must be after measured_at")
    issuer_id = _require_str(issuer_id, "issuer_id")
    issuer_secret = _check_secret(issuer_secret, "issuer_secret")
    digest = jcs_sha256_hex(
        _concentration_payload(
            probe_id=probe_id,
            sku_family=sku_family,
            top_supplier_share_bps=top_supplier_share_bps,
            tolerance_bps=tolerance_bps,
            measured_at=measured_at,
            expires_at=expires_at,
            issuer_id=issuer_id,
        )
    )
    return ConcentrationProbe(
        probe_id=probe_id,
        sku_family=sku_family,
        top_supplier_share_bps=top_supplier_share_bps,
        tolerance_bps=tolerance_bps,
        measured_at=measured_at,
        expires_at=expires_at,
        issuer_id=issuer_id,
        signature_hex=_sign(issuer_secret, digest),
    )


def concentration_probe(
    probe: ConcentrationProbe,
    authorities: AuthorityRegistry,
    *,
    issuer_id: str,
    checked_at: int,
) -> SupplyChainVerdict:
    """Check a single-source concentration measurement.

    A top-supplier share above the declared tolerance trips
    ``supplychain:concentration_breach`` — the diversification-audit
    trigger. A stale probe is NON_AUTHORITATIVE
    (``supplychain:probe_stale``).
    """
    if not isinstance(probe, ConcentrationProbe):
        raise SupplyChainAgentsError("probe must be a ConcentrationProbe")
    issuer_id = _require_str(issuer_id, "issuer_id")
    checked_at = _check_ts(checked_at, "checked_at")
    digest = jcs_sha256_hex(
        _concentration_payload(
            probe_id=probe.probe_id,
            sku_family=probe.sku_family,
            top_supplier_share_bps=probe.top_supplier_share_bps,
            tolerance_bps=probe.tolerance_bps,
            measured_at=probe.measured_at,
            expires_at=probe.expires_at,
            issuer_id=probe.issuer_id,
        )
    )
    code = _verify_signature(
        authorities,
        authority_id=issuer_id,
        digest_hex=digest,
        signature_hex=probe.signature_hex,
        deny_code=DENY_PROBE_SIGNATURE_INVALID,
    )
    if code is not None:
        return _deny(code)
    if probe.expires_at <= checked_at:
        return _deny(DENY_PROBE_STALE)
    if probe.top_supplier_share_bps > probe.tolerance_bps:
        return _deny(DENY_CONCENTRATION_BREACH)
    return _allow(digest)


# ---------------------------------------------------------------------------
# Vendor-claim receipts: capability claims bind a protocol (Flexport lesson)
# ---------------------------------------------------------------------------

#: Closed vendor-capability metric vocabulary. There is no fifth
#: value; an unknown metric is malformed, not a default.
CLAIM_METRICS = (
    "tasks_per_year",
    "auto_booking_share",
    "triage_time_reduction",
    "cost_reduction",
)

VENDOR_CLAIM_SCHEMA = "northstar.supplychain_agents.vendor_claim.v1"


def _vendor_claim_payload(
    *,
    claim_id: str,
    vendor_id: str,
    metric_name: str,
    claimed_value: int,
    measurement_protocol_digest: str,
    self_reported: bool,
    measured_at: int,
    issuer_id: str,
) -> dict[str, Any]:
    return {
        "schema": VENDOR_CLAIM_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "claim_id": claim_id,
        "vendor_id": vendor_id,
        "metric_name": metric_name,
        "claimed_value": claimed_value,
        "measurement_protocol_digest": measurement_protocol_digest,
        "self_reported": self_reported,
        "measured_at": measured_at,
        "issuer_id": issuer_id,
    }


@dataclass(frozen=True)
class VendorClaimReceipt:
    """A vendor AI-capability claim with its measurement protocol."""

    claim_id: str
    vendor_id: str
    metric_name: str
    claimed_value: int
    measurement_protocol_digest: str
    self_reported: bool
    measured_at: int
    issuer_id: str
    signature_hex: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "supplychain-vendor-claim",
            "claim_id": self.claim_id,
            "vendor_id": self.vendor_id,
            "metric_name": self.metric_name,
            "claimed_value": self.claimed_value,
            "measurement_protocol_digest": self.measurement_protocol_digest,
            "self_reported": self.self_reported,
            "measured_at": self.measured_at,
            "issuer_id": self.issuer_id,
            "signature_hex": self.signature_hex,
            "schema_version": SCHEMA_VERSION,
        }


class VendorClaimRegistry:
    """Vendor AI-capability claims with measurement protocols."""

    def __init__(self) -> None:
        self._claims: dict[str, VendorClaimReceipt] = {}

    def record(self, receipt: VendorClaimReceipt) -> None:
        self._claims[receipt.claim_id] = receipt

    def claim_for(self, claim_id: str) -> VendorClaimReceipt | None:
        return self._claims.get(claim_id)


def issue_vendor_claim(
    *,
    claim_id: str,
    vendor_id: str,
    metric_name: str,
    claimed_value: int,
    measurement_protocol_digest: str,
    self_reported: bool,
    measured_at: int,
    issuer_id: str,
    issuer_secret: bytes,
) -> VendorClaimReceipt:
    """Issue a vendor AI-capability claim.

    The measurement protocol digest pins how the number was
    measured. A self-reported-only claim *can* be issued — the gate
    then degrades it to NON_AUTHORITATIVE at check time, so the claim
    is visible but never trusted.
    """
    claim_id = _require_str(claim_id, "claim_id")
    vendor_id = _require_str(vendor_id, "vendor_id")
    metric_name = _check_vocab(metric_name, "metric_name", CLAIM_METRICS)
    claimed_value = _require_int(claimed_value, "claimed_value")
    if claimed_value <= 0:
        raise SupplyChainAgentsError("claimed_value must be positive")
    measurement_protocol_digest = _check_hex64(
        measurement_protocol_digest, "measurement_protocol_digest"
    )
    self_reported = _require_bool(self_reported, "self_reported")
    measured_at = _check_ts(measured_at, "measured_at")
    issuer_id = _require_str(issuer_id, "issuer_id")
    issuer_secret = _check_secret(issuer_secret, "issuer_secret")
    digest = jcs_sha256_hex(
        _vendor_claim_payload(
            claim_id=claim_id,
            vendor_id=vendor_id,
            metric_name=metric_name,
            claimed_value=claimed_value,
            measurement_protocol_digest=measurement_protocol_digest,
            self_reported=self_reported,
            measured_at=measured_at,
            issuer_id=issuer_id,
        )
    )
    return VendorClaimReceipt(
        claim_id=claim_id,
        vendor_id=vendor_id,
        metric_name=metric_name,
        claimed_value=claimed_value,
        measurement_protocol_digest=measurement_protocol_digest,
        self_reported=self_reported,
        measured_at=measured_at,
        issuer_id=issuer_id,
        signature_hex=_sign(issuer_secret, digest),
    )


def vendor_claim_receipt(
    claims: VendorClaimRegistry,
    authorities: AuthorityRegistry,
    *,
    claim_id: str,
    vendor_id: str,
    checked_at: int,
    issuer_id: str,
) -> SupplyChainVerdict:
    """Check a vendor AI-capability claim.

    A self-reported-only claim is NON_AUTHORITATIVE
    (``supplychain.unverified_claim``) — the Flexport lesson: "21M
    tasks/year" is a marketing number until bound to a measurement
    protocol. Only protocol-bound claims pass.
    """
    claim_id = _require_str(claim_id, "claim_id")
    vendor_id = _require_str(vendor_id, "vendor_id")
    checked_at = _check_ts(checked_at, "checked_at")
    issuer_id = _require_str(issuer_id, "issuer_id")
    receipt = claims.claim_for(claim_id)
    if receipt is None or receipt.vendor_id != vendor_id:
        return _deny(DENY_UNVERIFIED_CLAIM)
    digest = jcs_sha256_hex(
        _vendor_claim_payload(
            claim_id=receipt.claim_id,
            vendor_id=receipt.vendor_id,
            metric_name=receipt.metric_name,
            claimed_value=receipt.claimed_value,
            measurement_protocol_digest=receipt.measurement_protocol_digest,
            self_reported=receipt.self_reported,
            measured_at=receipt.measured_at,
            issuer_id=receipt.issuer_id,
        )
    )
    code = _verify_signature(
        authorities,
        authority_id=issuer_id,
        digest_hex=digest,
        signature_hex=receipt.signature_hex,
        deny_code=DENY_CLAIM_SIGNATURE_INVALID,
    )
    if code is not None:
        return _deny(code)
    if receipt.self_reported:
        return _deny(DENY_UNVERIFIED_CLAIM)
    return _allow(digest)


def supplychain_audit_event(
    verdict: SupplyChainVerdict, *, action: str
) -> dict[str, Any]:
    """Emit an audit event for a supply-chain AI decision (allowed or denied)."""
    return {
        "kind": "audit-event",
        "schema_version": SCHEMA_VERSION,
        "event": f"supplychain.{action}",
        "allowed": verdict.allowed,
        "deny_code": verdict.deny_code,
        "classification": verdict.classification,
        "receipt_digest": verdict.receipt_digest,
    }
