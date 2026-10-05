"""AP2-inspired mandate credentials: open/closed two-phase authorization.

Absorbs the *mechanism ideas* of Google AP2's mandate model
(https://github.com/google-agentic-commerce/AP2, Apache-2.0, read 2026-10-05;
**no code copied** — the field names and wire format below are original):

* **Two-phase authorization**: Mandate Delegation (user approves once, in a
  trusted surface the agent cannot touch) -> Action Authorization (agent
  presents the mandate per action, verifier checks coverage, returns a
  signed receipt).
* **Open/Closed states**: an Open mandate carries constraints + a ``cnf``
  (confirmation) key; a Closed mandate binds the open mandate to one
  specific action via a key-binding signature from the ``cnf`` key holder.
  Human-present: sign closed directly. Human-not-present: sign open once,
  agent closes per action within constraints.
* **Constraints as a self-describing array**: each constraint is
  ``{"type": "<dotted-name>", ...}``. Four hard rules:
  1. Unknown constraint type -> evaluation FAILS CLOSED.
  2. Pre-set claims in the open mandate must appear verbatim in the closed
     mandate (narrowing only, never rewriting).
  3. Stateful constraints (budgets, recurrence) need a verifier-side usage
     context; recurrence limits must be paired with a budget constraint.
  4. The verifier returns a signed Receipt; the agent narrows or retires the
     open mandate after a successful receipt (anti-reuse).

Cryptography is Northstar-native: Ed25519 signatures over canonical JSON
(see :mod:`ed25519`, :mod:`audit_chain`). No SD-JWT, no OpenID4VP, no
verifiable-credential stack.

The closed mandate's ``action`` references an action-card hash, so the
mandate ("the user allowed it") and the action card ("this is what was
done") hash-link into an authorization-action evidence chain.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

import ed25519
from audit_chain import canonical_json

#: Wire version of this credential format.
MANDATE_VERSION = "northstar-mandate/v1"

#: Constraint type identifiers (dotted names; unknown types fail closed).
C_ACTION_ALLOW = "action.allow"
C_BUDGET_MAX_SPEND = "budget.max_spend"
C_RECURRENCE_MAX_USES = "recurrence.max_uses"
C_TIME_WINDOW = "time.window"

_KNOWN_CONSTRAINTS = frozenset(
    {C_ACTION_ALLOW, C_BUDGET_MAX_SPEND, C_RECURRENCE_MAX_USES, C_TIME_WINDOW}
)


class MandateError(Exception):
    """Raised for malformed mandates; verification returns False, never raises."""


def _canonical(mapping: Mapping[str, Any]) -> bytes:
    return canonical_json(dict(mapping))


def _hash(mapping: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(mapping)).hexdigest()


@dataclass
class UsageContext:
    """Verifier-side state for stateful constraints (budgets, recurrence)."""

    spent: dict[str, float] = field(default_factory=dict)  # currency -> amount
    uses: int = 0
    last_used_at: int = 0


@dataclass
class MandateVerdict:
    ok: bool
    violations: tuple[str, ...] = ()
    receipt: dict[str, Any] | None = None


def issue_open(
    *,
    issuer_secret: bytes,
    delegate_to_did: str,
    cnf_pubkey: bytes,
    constraints: Sequence[Mapping[str, Any]],
    preset_claims: Mapping[str, Any] | None = None,
    expires_at: int = 0,
) -> dict[str, Any]:
    """Issue an Open mandate (user approves once, in a trusted surface)."""
    issuer_pub = ed25519.public_key(issuer_secret)
    mandate = {
        "format": MANDATE_VERSION,
        "state": "open",
        "mandate_id": str(uuid.uuid4()),
        "issuer": issuer_pub.hex(),
        "delegate_to": delegate_to_did,
        "cnf": cnf_pubkey.hex(),
        "issued_at": int(time.time()),
        "expires_at": expires_at,
        "constraints": [dict(c) for c in constraints],
        "preset_claims": dict(preset_claims or {}),
    }
    mandate["signature"] = ed25519.sign(issuer_secret, _canonical(mandate)).hex()
    return mandate


def _verify_open_signature(mandate: Mapping[str, Any]) -> bool:
    try:
        sig = bytes.fromhex(str(mandate["signature"]))
        issuer_pub = bytes.fromhex(str(mandate["issuer"]))
        body = {k: v for k, v in mandate.items() if k != "signature"}
        return ed25519.verify(issuer_pub, _canonical(body), sig)
    except Exception:
        return False


def close_mandate(
    *,
    open_mandate: Mapping[str, Any],
    cnf_secret: bytes,
    action: Mapping[str, Any],
    verifier_id: str,
    nonce: bytes,
) -> dict[str, Any]:
    """Bind an open mandate to one action (agent-side, per action).

    The ``cnf`` key holder signs the closed mandate: this is the
    key-binding step. ``action`` must include the action-card hash the
    verifier will check coverage against.
    """
    if open_mandate.get("format") != MANDATE_VERSION:
        raise MandateError("not a northstar mandate")
    if open_mandate.get("state") != "open":
        raise MandateError("can only close an open mandate")
    cnf_pub = bytes.fromhex(str(open_mandate["cnf"]))
    if ed25519.public_key(cnf_secret) != cnf_pub:
        raise MandateError("cnf key mismatch: not the bound key holder")
    closed = {
        "format": MANDATE_VERSION,
        "state": "closed",
        "mandate_id": str(uuid.uuid4()),
        "open_ref": _hash(open_mandate),
        "open_mandate_id": open_mandate["mandate_id"],
        "action": dict(action),
        "aud": verifier_id,
        "nonce": nonce.hex(),
    }
    # Pre-set claims carry over verbatim (narrowing, never rewriting).
    closed["preset_claims"] = dict(open_mandate.get("preset_claims", {}))
    closed["signature"] = ed25519.sign(cnf_secret, _canonical(closed)).hex()
    return closed


def _evaluate_constraint(
    constraint: Mapping[str, Any],
    action: Mapping[str, Any],
    ctx: UsageContext,
    now: int,
) -> list[str]:
    """Evaluate one constraint; returns violations (empty = satisfied)."""
    ctype = constraint.get("type")
    if ctype not in _KNOWN_CONSTRAINTS:
        return [f"unknown constraint type: {ctype!r} (fail-closed)"]
    if ctype == C_ACTION_ALLOW:
        allowed = constraint.get("actions", [])
        if action.get("type") not in allowed:
            return [f"action {action.get('type')!r} not in allow-list"]
    elif ctype == C_BUDGET_MAX_SPEND:
        currency = str(constraint.get("currency", ""))
        limit = float(constraint.get("amount", 0))
        spent = ctx.spent.get(currency, 0.0)
        cost = float(action.get("cost", 0))
        if spent + cost > limit:
            return [f"budget exceeded: {spent}+{cost} > {limit} {currency}"]
    elif ctype == C_RECURRENCE_MAX_USES:
        max_uses = int(constraint.get("max", 0))
        if ctx.uses + 1 > max_uses:
            return [f"recurrence exceeded: {ctx.uses + 1} > {max_uses}"]
    elif ctype == C_TIME_WINDOW:
        nb = int(constraint.get("not_before", 0))
        na = int(constraint.get("not_after", 0))
        if not (nb <= now <= na):
            return ["outside time window"]
    return []


def verify_closed(
    *,
    closed_mandate: Mapping[str, Any],
    open_mandate: Mapping[str, Any],
    ctx: UsageContext,
    now: int,
) -> MandateVerdict:
    """Verifier-side: check a closed mandate covers the action.

    Checks, in order: (1) open mandate signature valid and not expired;
    (2) closed signature valid under the open mandate's ``cnf`` key;
    (3) ``open_ref`` matches the open mandate hash; (4) pre-set claims
    carried over verbatim; (5) every constraint evaluates clean
    (unknown types fail closed). Returns a verdict; never raises.
    """
    violations: list[str] = []
    # 1. Open mandate integrity + expiry.
    if not _verify_open_signature(open_mandate):
        return MandateVerdict(ok=False, violations=("open mandate signature invalid",))
    exp = int(open_mandate.get("expires_at", 0))
    if exp and exp <= now:
        violations.append("open mandate expired")
    # 2. Closed signature under cnf key.
    try:
        cnf_pub = bytes.fromhex(str(open_mandate["cnf"]))
        sig = bytes.fromhex(str(closed_mandate["signature"]))
        body = {k: v for k, v in closed_mandate.items() if k != "signature"}
        if not ed25519.verify(cnf_pub, _canonical(body), sig):
            return MandateVerdict(ok=False, violations=("closed signature invalid",))
    except Exception:
        return MandateVerdict(ok=False, violations=("closed signature malformed",))
    # 3. Binding to the open mandate.
    if closed_mandate.get("open_ref") != _hash(open_mandate):
        violations.append("open_ref mismatch")
    # 4. Pre-set claims verbatim.
    if closed_mandate.get("preset_claims") != open_mandate.get("preset_claims", {}):
        violations.append("preset_claims rewritten (must be verbatim)")
    # 5. Constraints.
    action = closed_mandate.get("action", {})
    for c in open_mandate.get("constraints", []):
        violations.extend(_evaluate_constraint(c, action, ctx, now))
    return MandateVerdict(ok=not violations, violations=tuple(violations))


def issue_receipt(
    *,
    verifier_secret: bytes,
    closed_mandate: Mapping[str, Any],
    ok: bool,
    error_code: str = "",
) -> dict[str, Any]:
    """Issue a signed receipt for a presented closed mandate.

    The receipt references the closed mandate by hash. The agent must
    narrow or retire the open mandate after a successful receipt
    (anti-reuse).
    """
    verifier_pub = ed25519.public_key(verifier_secret)
    receipt = {
        "format": MANDATE_VERSION,
        "kind": "receipt",
        "receipt_id": str(uuid.uuid4()),
        "verifier": verifier_pub.hex(),
        "mandate_ref": _hash(closed_mandate),
        "result": "success" if ok else "error",
        "error_code": error_code,
        "issued_at": int(time.time()),
    }
    receipt["signature"] = ed25519.sign(verifier_secret, _canonical(receipt)).hex()
    return receipt


def verify_receipt(
    receipt: Mapping[str, Any], *, verifier_pubkey: bytes
) -> bool:
    """Verify a receipt's signature. False on any problem, never raises."""
    try:
        if receipt.get("format") != MANDATE_VERSION:
            return False
        if receipt.get("verifier") != verifier_pubkey.hex():
            return False
        sig = bytes.fromhex(str(receipt["signature"]))
        body = {k: v for k, v in receipt.items() if k != "signature"}
        return ed25519.verify(verifier_pubkey, _canonical(body), sig)
    except Exception:
        return False


__all__ = [
    "MANDATE_VERSION",
    "C_ACTION_ALLOW",
    "C_BUDGET_MAX_SPEND",
    "C_RECURRENCE_MAX_USES",
    "C_TIME_WINDOW",
    "MandateError",
    "MandateVerdict",
    "UsageContext",
    "close_mandate",
    "issue_open",
    "issue_receipt",
    "verify_closed",
    "verify_receipt",
]
