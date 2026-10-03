"""Verifiable action cards: approval UX the agent cannot forge.

Absorbs two mechanisms, both read as code/spec rather than marketing:

1. The Verifiable Action Card (arXiv:2609.18411) - the answer to deceptive
   confirmation attacks. Approval information is reconstructed from the
   ground-truth pending action plus trusted intent provenance, rendered
   out-of-band in trusted UI chrome, and the approval is bound to the exact
   action re-verified at dispatch. Reported result: deceptive-confirmation
   attack success 68-100% -> 0% on every evaluated model, 78% legitimate-task
   completion, 0% false-block rate. This module ports the architecture, not
   their benchmark numbers:

   - *provenance fencing*: the card is built from runtime ground truth (tool
     name, call id, arguments digest, trusted provenance). Anything the agent
     *said* about the action is quarantined as untrusted, never rendered as
     the action description.
   - *ground-truth action descriptor*: the card names the exact pending call,
     not the agent's summary of it.
   - *out-of-band rendering*: the card travels a channel the agent cannot
     write to. The terminal renderer below prints to stderr with a trust
     banner; ``as_dict()`` gives hosts a machine-readable card for their own
     trusted chrome. An "approval" that appears inside agent output is never
     consulted - there is no code path that reads one.
   - *default-deny confirmation*: no answer, a timeout, or an approver error
     is a denial, never a pass.
   - *provenance-aware risk gating*: the deterministic gate decides
     auto-approve vs one-tap, and the card states the policy basis.
   - *execution binding*: the approval pins ``(call_id, arguments_digest)``
     and :func:`verify_card_binding` re-checks the pin at dispatch, so a
     card issued for one call cannot authorize another.

2. opsagent's deterministic gate (jasondhaki/opsagent, CLAUDE.md - read in
   full): a *pure function* decides per action whether it may auto-proceed or
   needs a human's one-tap approval. The model never decides its own
   oversight; the gate computes ``would_auto_approve`` as the AND of named
   checks even when auto-approve is disabled ("shadow mode"), so the
   organization can measure what *would* have auto-approved before turning it
   on. Auto-approve ships OFF. The full decision (every check, pass/fail) is
   persisted and rendered as a checklist.

Fail-closed by construction:

- the card is the *only* approval surface: agent-rendered confirmations are
  not a thing this module can see;
- an approval that does not name the exact ``(call_id, arguments_digest)``
  is rejected at dispatch by :func:`verify_card_binding`;
- the deterministic gate's inputs (risk flags, tier, digest, provenance) are
  computed by the runtime, never suggested by the model;
- auto-approve is disabled unless the host explicitly enables it, and even
  then only for tiers the host allowlisted.
"""
from __future__ import annotations

import secrets
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Mapping, Sequence

from permissions import digest_arguments

from approver_separation import (
    SELF_ATTESTATION_DENIED_EVENT,
    eligible_approvers,
    proposer_of,
)

#: One-tap answers the card approver understands.
APPROVE = "approve"
DENY = "deny"
CANCEL = "cancel"

CardDecision = Literal["approve", "deny", "cancel"]

#: Gate check ids. Every check is a named, auditable predicate - the opsagent
#: shape: the decision is the AND of its checks, and the checklist is the audit.
CHECK_TIER_AUTO_ALLOWED = "tier_auto_allowed"
CHECK_NO_RISK_FLAGS = "no_risk_flags"
CHECK_DIGEST_PINNED = "digest_pinned"
CHECK_PROVENANCE_TRUSTED = "provenance_trusted"
CHECK_NOT_DEMO = "not_demo"
CHECK_WITHIN_BUDGET = "within_budget"

GATE_CHECKS: tuple[str, ...] = (
    CHECK_TIER_AUTO_ALLOWED,
    CHECK_NO_RISK_FLAGS,
    CHECK_DIGEST_PINNED,
    CHECK_PROVENANCE_TRUSTED,
    CHECK_NOT_DEMO,
    CHECK_WITHIN_BUDGET,
)

#: Card ids are unguessable so a card reference cannot be forged by naming.
CARD_ID_BYTES = 16

#: Cap on agent-supplied framing text kept for context. It is labelled
#: untrusted wherever it appears; the cap bounds how much screen real estate
#: an untrusted string can occupy in the trusted chrome.
MAX_AGENT_HINT_CHARS = 500


class ActionCardError(ValueError):
    """A card or approval that refuses to be built or honored."""


@dataclass(frozen=True)
class GateCheck:
    """One named predicate in the deterministic gate."""

    id: str
    passed: bool
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "passed": self.passed, "detail": self.detail}


@dataclass(frozen=True)
class GateDecision:
    """The deterministic gate's verdict for one action.

    ``would_auto_approve`` is computed even when auto-approve is disabled
    (shadow mode): the host can measure what *would* have auto-approved
    before ever turning it on. ``auto_approved`` additionally requires the
    host to have opted in.
    """

    would_auto_approve: bool
    auto_approved: bool
    policy_basis: str
    checks: tuple[GateCheck, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "would_auto_approve": self.would_auto_approve,
            "auto_approved": self.auto_approved,
            "policy_basis": self.policy_basis,
            "checks": [check.as_dict() for check in self.checks],
        }


@dataclass(frozen=True)
class ActionProvenance:
    """Who asked for the action, from runtime-trusted state.

    None of these fields are agent claims: the runtime fills them from the
    session it owns. A delegation chain is the sequence of agent names from
    the outermost principal to the acting agent; an empty chain means the
    principal acted directly.
    """

    agent: str = "main"
    session_id: str = ""
    turn_index: int = 0
    depth: int = 0
    delegation_chain: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "session_id": self.session_id,
            "turn_index": self.turn_index,
            "depth": self.depth,
            "delegation_chain": list(self.delegation_chain),
        }


@dataclass(frozen=True)
class ActionCard:
    """One approval request, built from ground truth.

    The card is *constructed*, never *parsed*: there is no constructor that
    takes agent text and treats it as the action. ``agent_hint`` carries at
    most a short, explicitly untrusted framing string for human context - it
    is never the authority for what the action is.
    """

    card_id: str
    tool: str
    call_id: str
    arguments_digest: str
    risk_tier: str
    provenance: ActionProvenance
    gate: GateDecision
    #: The agent's own words about the action. UNTRUSTED. Rendered only under
    #: an explicit "the agent claims" label, never as the action description.
    agent_hint: str = ""
    created_unix: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "verifiable-action-card",
            "card_id": self.card_id,
            "tool": self.tool,
            "call_id": self.call_id,
            "arguments_digest": self.arguments_digest,
            "risk_tier": self.risk_tier,
            "provenance": self.provenance.as_dict(),
            "gate": self.gate.as_dict(),
            "agent_hint_untrusted": self.agent_hint,
            "created_unix": self.created_unix,
        }

    def render_terminal(self, width: int = 70) -> str:
        """Out-of-band rendering for a terminal.

        Goes to stderr (never the agent's stdout), framed by a trust banner
        that names the one property that matters: this card was built by the
        runtime from the pending action, and the agent cannot forge one.
        """
        bar = "=" * width
        thin = "-" * width
        lines = [
            bar,
            " NORTHSTAR ACTION CARD - approval requested",
            " Built by the runtime from the pending action. The agent cannot",
            " forge this card. Verify the digest matches what you expect.",
            thin,
            f" tool:             {self.tool}",
            f" call:             {self.call_id}",
            f" arguments:        {self.arguments_digest}",
            f" risk tier:        {self.risk_tier}",
            f" policy basis:     {self.gate.policy_basis}",
            " provenance:       "
            f"agent={self.provenance.agent} session={self.provenance.session_id or '-'} "
            f"turn={self.provenance.turn_index} depth={self.provenance.depth}",
        ]
        if self.provenance.delegation_chain:
            lines.append(f" delegated via:    {' -> '.join(self.provenance.delegation_chain)}")
        if self.agent_hint:
            lines.append(f' agent claims:     "{self.agent_hint}"  (UNTRUSTED - the agent\'s words)')
        lines.append(" gate checks:")
        for check in self.gate.checks:
            mark = "pass" if check.passed else "FAIL"
            detail = f" - {check.detail}" if check.detail else ""
            lines.append(f"   [{mark}] {check.id}{detail}")
        lines.append(bar)
        return "\n".join(lines)


def evaluate_gate(
    *,
    tool: str,
    risk_tier: str,
    auto_approve_tiers: Sequence[str] = (),
    risk_flags: Sequence[str] = (),
    arguments_digest: str = "",
    provenance: ActionProvenance | None = None,
    auto_approve_enabled: bool = False,
    is_demo: bool = False,
    budget_ok: bool = True,
) -> GateDecision:
    """Pure deterministic gate: auto-approve or one-tap human approval.

    Every input is runtime-computed; the model never decides its own
    oversight (opsagent rule 2). ``would_auto_approve`` is true only if every
    named check passes; ``auto_approved`` additionally requires the host to
    have enabled auto-approve (default off) for this run. Callers that only
    want the measurement call this with ``auto_approve_enabled=False`` -
    shadow mode.
    """
    tier = str(risk_tier or "").strip().lower()
    allowed = {str(name).strip().lower() for name in auto_approve_tiers}
    flags = tuple(str(name) for name in risk_flags if str(name).strip())
    digest = str(arguments_digest or "")

    checks = (
        GateCheck(
            CHECK_TIER_AUTO_ALLOWED,
            tier in allowed,
            f"tier {tier!r} {'is' if tier in allowed else 'is not'} in the auto-approve allowlist",
        ),
        GateCheck(
            CHECK_NO_RISK_FLAGS,
            not flags,
            "no risk flags" if not flags else f"risk flags present: {', '.join(flags)}",
        ),
        GateCheck(
            CHECK_DIGEST_PINNED,
            digest.startswith("sha256:") and len(digest) == len("sha256:") + 64,
            "arguments digest pinned to the call" if digest.startswith("sha256:") else "no arguments digest: cannot auto-approve an unpinned call",
        ),
        GateCheck(
            CHECK_PROVENANCE_TRUSTED,
            provenance is not None and bool(provenance.agent),
            "provenance from runtime state" if provenance is not None and provenance.agent else "no trusted provenance",
        ),
        GateCheck(
            CHECK_NOT_DEMO,
            not is_demo,
            "not a demo run" if not is_demo else "demo runs never auto-approve",
        ),
        GateCheck(
            CHECK_WITHIN_BUDGET,
            bool(budget_ok),
            "within budget" if budget_ok else "budget exhausted: human must decide",
        ),
    )
    would = all(check.passed for check in checks)
    approved = bool(would and auto_approve_enabled)
    if approved:
        basis = (
            f"auto-approved: tier {tier!r} is allowlisted, no risk flags, digest pinned, "
            "provenance trusted, within budget (auto-approve explicitly enabled for this run)"
        )
    elif would:
        basis = (
            f"one-tap approval required: gate would auto-approve (tier {tier!r} allowlisted, "
            "all checks pass) but auto-approve is disabled - shadow mode"
        )
    else:
        failed = ", ".join(check.id for check in checks if not check.passed)
        basis = f"one-tap approval required: gate checks failed ({failed})"
    return GateDecision(
        would_auto_approve=would,
        auto_approved=approved,
        policy_basis=basis,
        checks=checks,
    )


def build_action_card(
    *,
    tool: str,
    call_id: str,
    arguments: Mapping[str, Any] | None,
    risk_tier: str,
    provenance: ActionProvenance,
    gate: GateDecision | None = None,
    agent_hint: str = "",
    auto_approve_tiers: Sequence[str] = (),
    risk_flags: Sequence[str] = (),
    auto_approve_enabled: bool = False,
    is_demo: bool = False,
    budget_ok: bool = True,
    created_unix: float | None = None,
) -> ActionCard:
    """Build a card from ground truth. The digest is computed here, from the
    actual arguments object the runtime is about to dispatch - not from any
    agent-supplied description of them."""
    name = str(tool or "").strip()
    if not name:
        raise ActionCardError("refusing to build an action card with no tool name")
    cid = str(call_id or "").strip()
    if not cid:
        raise ActionCardError("refusing to build an action card with no call id")
    digest = digest_arguments(arguments if arguments is not None else {})
    decision = gate if gate is not None else evaluate_gate(
        tool=name,
        risk_tier=risk_tier,
        auto_approve_tiers=auto_approve_tiers,
        risk_flags=risk_flags,
        arguments_digest=digest,
        provenance=provenance,
        auto_approve_enabled=auto_approve_enabled,
        is_demo=is_demo,
        budget_ok=budget_ok,
    )
    hint = str(agent_hint or "").strip()[:MAX_AGENT_HINT_CHARS]
    return ActionCard(
        card_id=secrets.token_hex(CARD_ID_BYTES),
        tool=name,
        call_id=cid,
        arguments_digest=digest,
        risk_tier=str(risk_tier or "unknown"),
        provenance=provenance,
        gate=decision,
        agent_hint=hint,
        created_unix=time.time() if created_unix is None else float(created_unix),
    )


@dataclass(frozen=True)
class CardVerdict:
    """The audit record of one card's resolution."""

    card_id: str
    tool: str
    call_id: str
    arguments_digest: str
    decision: CardDecision
    reason: str
    gate: GateDecision

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "action-card-verdict",
            "card_id": self.card_id,
            "tool": self.tool,
            "call_id": self.call_id,
            "arguments_digest": self.arguments_digest,
            "decision": self.decision,
            "reason": self.reason,
            "gate": self.gate.as_dict(),
        }


def verify_card_binding(card: ActionCard, *, call_id: str, arguments: Mapping[str, Any] | None) -> bool:
    """Re-verify at dispatch that this card authorizes *this* call.

    The VAC execution-binding property: the approval is worthless unless the
    call about to execute carries the same call id and the same arguments
    digest the card was built for. A replayed or mutated call fails closed.
    """
    if card.call_id != str(call_id or ""):
        return False
    try:
        digest = digest_arguments(arguments if arguments is not None else {})
    except ValueError:
        return False
    # Constant-time compare: the digest is the security boundary.
    return secrets.compare_digest(card.arguments_digest, digest)


def resolve_card(
    card: ActionCard,
    *,
    approver: Callable[[ActionCard], Any] | None,
    approver_identity: str = "",
    registered_approvers: Sequence[str] | None = None,
    delegation_graph: Mapping[str, Sequence[str]] | None = None,
) -> CardVerdict:
    """Resolve one card to approve/deny/cancel. Default-deny throughout.

    If the deterministic gate already auto-approved, no human is consulted
    and the verdict says so. Otherwise ``approver`` is the *only* source of a
    human decision - it receives the card (never agent output) and returns
    ``True`` (approve), ``False``/``None`` (deny), or ``"cancel"``. Any
    exception, timeout-shaped error, or unrecognized answer is a denial.

    No-self-attestation (ERC-8004 rule, ninety-fourth batch): when
    ``approver_identity`` is given or ``registered_approvers`` is provided,
    the separation gate runs *before* everything else, including the
    auto-approve shortcut. The proposer is the card's outermost principal
    (first hop of the delegation chain, else the acting agent - both
    runtime-owned). The eligible set is the registered approvers minus the
    proposer minus the proposer's delegation subtree. When the only
    available approver is the proposer, the eligible set is empty and the
    card denies - it does not fall back to auto-approve, and an approver
    callback whose identity fails the check is never consulted. Denials
    name the ``approval.self_attestation_denied`` audit event.
    """
    separation_active = bool(str(approver_identity or "").strip()) or registered_approvers is not None
    if separation_active:
        proposer = proposer_of(
            agent=card.provenance.agent,
            delegation_chain=card.provenance.delegation_chain,
        )
        pool: Sequence[str] = (
            registered_approvers if registered_approvers is not None
            else (str(approver_identity or ""),)
        )

        def _separation_deny(reason: str) -> CardVerdict:
            return CardVerdict(
                card_id=card.card_id,
                tool=card.tool,
                call_id=card.call_id,
                arguments_digest=card.arguments_digest,
                decision=DENY,
                reason=f"{SELF_ATTESTATION_DENIED_EVENT}: {reason}",
                gate=card.gate,
            )

        eligible = eligible_approvers(
            proposer=proposer,
            approvers=pool,
            delegation_graph=delegation_graph,
        )
        if not eligible:
            return _separation_deny(
                f"no eligible approver for proposer {proposer!r}: the only "
                "available approver is the proposer itself (or its delegation "
                "subtree) - an unattended run never self-approves"
            )
        me = str(approver_identity or "").strip()
        if not me:
            return _separation_deny(
                "the approver has no identity: an unknown approver is not a "
                "verified third party"
            )
        if me not in eligible:
            if me == proposer:
                why = (
                    f"approver {me!r} is the action's proposer: self-approval "
                    "is never evidence"
                )
            else:
                why = (
                    f"approver {me!r} sits in proposer {proposer!r}'s delegation "
                    "subtree: sock-puppet approval is self-approval with "
                    "extra hops"
                )
            return _separation_deny(why)
    if card.gate.auto_approved:
        return CardVerdict(
            card_id=card.card_id,
            tool=card.tool,
            call_id=card.call_id,
            arguments_digest=card.arguments_digest,
            decision=APPROVE,
            reason="deterministic gate auto-approved: " + card.gate.policy_basis,
            gate=card.gate,
        )
    if approver is None:
        return CardVerdict(
            card_id=card.card_id,
            tool=card.tool,
            call_id=card.call_id,
            arguments_digest=card.arguments_digest,
            decision=DENY,
            reason="no approver attached: an unattended run never approves by default",
            gate=card.gate,
        )
    try:
        answer = approver(card)
    except Exception as error:  # noqa: BLE001 - an approver fault must not become an approval
        return CardVerdict(
            card_id=card.card_id,
            tool=card.tool,
            call_id=card.call_id,
            arguments_digest=card.arguments_digest,
            decision=DENY,
            reason=f"approver raised {type(error).__name__}: {error}",
            gate=card.gate,
        )
    if answer is True:
        decision: CardDecision = APPROVE
        reason = "approved by the human approver (one-tap)"
    elif isinstance(answer, str) and answer.strip().lower() == CANCEL:
        decision = CANCEL
        reason = "the approver cancelled the call"
    else:
        # False, None, "", unrecognized shapes: all deny. There is no
        # "maybe" in an approval gate.
        decision = DENY
        reason = "the approver did not approve (declined or no answer)"
    return CardVerdict(
        card_id=card.card_id,
        tool=card.tool,
        call_id=card.call_id,
        arguments_digest=card.arguments_digest,
        decision=decision,
        reason=reason,
        gate=card.gate,
    )


def make_terminal_card_approver(
    read_line: Callable[[str], str] = input,
    *,
    echo: Callable[[str], None] | None = None,
    timeout_note: str = "",
) -> Callable[[ActionCard], CardDecision]:
    """One-tap human approval on a terminal, rendered out-of-band.

    The card is printed to stderr - the agent's stdout is never the approval
    channel, which is what defeats deceptive confirmation: an agent that
    renders its own fake "approve?" prompt inside its output is talking to
    the wrong stream. ``read_line`` is injectable so the gate is testable
    offline. Empty input is a denial; ``cancel`` abandons the call.
    """
    say = echo or (lambda text: print(text, file=sys.stderr, flush=True))

    def approve(card: ActionCard) -> CardDecision:
        say(card.render_terminal())
        if timeout_note:
            say(f" ({timeout_note})")
        try:
            raw = read_line(" Approve this action? [y/N] (or 'cancel') ")
        except (EOFError, KeyboardInterrupt) as error:
            return DENY if isinstance(error, EOFError) else CANCEL
        text = (raw or "").strip().lower()
        if text in {"y", "yes"}:
            return APPROVE
        if text == CANCEL:
            return CANCEL
        return DENY

    return approve


def card_summary(verdict: CardVerdict) -> dict[str, Any]:
    """The record shape written into the session transcript."""
    return verdict.as_dict()


__all__ = [
    "APPROVE",
    "CANCEL",
    "DENY",
    "CARD_ID_BYTES",
    "CHECK_DIGEST_PINNED",
    "CHECK_NOT_DEMO",
    "CHECK_NO_RISK_FLAGS",
    "CHECK_PROVENANCE_TRUSTED",
    "CHECK_TIER_AUTO_ALLOWED",
    "CHECK_WITHIN_BUDGET",
    "GATE_CHECKS",
    "ActionCard",
    "ActionCardError",
    "ActionProvenance",
    "CardDecision",
    "CardVerdict",
    "GateCheck",
    "GateDecision",
    "build_action_card",
    "card_summary",
    "evaluate_gate",
    "make_terminal_card_approver",
    "resolve_card",
    "verify_card_binding",
]
