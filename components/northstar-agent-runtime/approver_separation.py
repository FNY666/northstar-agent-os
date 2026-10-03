"""No-self-attestation: the proposer is never its own approver.

Absorbs the ERC-8004 no-self-attestation rule (ERC-8004 live on Ethereum
mainnet 2026-01-29, per the 2026 research sweep): ``giveFeedback`` forbids
the owner as the submitter — reputation feedback must come from a third
party, because self-issued feedback is not evidence. The same invariant is
ported to Northstar's approval gates (the eighty-fourth batch action cards,
the sixty-sixth approval-gate red team): an action's approver set must
never contain the action's proposer, and sock-puppet approval — the
proposer approving through a delegated sub-agent — is excluded too, by
subtracting the proposer's whole delegation subtree. Self-approval with
extra hops is still self-approval.

Mechanics (all pure functions, stdlib only, deterministic):

- :func:`eligible_approvers` — the approvers that may approve one action:
  the registered approvers minus the proposer minus every identity in the
  proposer's delegation subtree. Subtree membership is computed by
  breadth-first traversal of the delegation graph with a visited set, so a
  cyclic or hostile graph still terminates and still excludes the proposer.
- :func:`check_approver` — the verdict for one ``(proposer, approver)``
  pair: ``self_approval``, ``sock_puppet_delegatee``, ``unknown_approver``
  (not in the registered set, or no identity at all), or allow.
- :func:`self_attestation_denied_event` — the audit record, event name
  ``approval.self_attestation_denied``, shaped for the ``audit.ndjson/1``
  hash chain.
- :func:`proposer_of` — who the proposer is from runtime provenance: the
  outermost principal (first hop of the delegation chain) when the action
  was delegated, otherwise the acting agent. This module takes plain
  strings, never agent claims: callers pass the runtime-owned values.

Fail-closed by construction:

- an empty or malformed proposer yields an empty eligible set — deny,
  never guess who the proposer "probably" is;
- a malformed delegation graph yields an empty eligible set — an
  unverifiable subtree is treated as "exclude everyone", not "exclude
  no one";
- an approver with no identity, or one absent from the registered set,
  is denied: an unknown approver is not a third party;
- when the only available approver is the proposer, the eligible set is
  empty and the card denies — there is no fallback to auto-approve (see
  the ``resolve_card`` wiring in ``action_card``).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

#: Audit event name for self-attestation denials, for the audit.ndjson/1 chain.
SELF_ATTESTATION_DENIED_EVENT = "approval.self_attestation_denied"

#: Failure rule ids for :class:`ApproverVerdict`.
RULE_SELF_APPROVAL = "self_approval"
RULE_SOCK_PUPPET_DELEGATEE = "sock_puppet_delegatee"
RULE_UNKNOWN_APPROVER = "unknown_approver"
RULE_NO_ELIGIBLE_APPROVER = "no_eligible_approver"
RULE_MALFORMED = "malformed_input"


class ApproverSeparationError(ValueError):
    """Refused approver-set construction (reserved for callers that want
    raise-on-misconfiguration; the check path itself returns verdicts)."""


@dataclass(frozen=True)
class ApproverVerdict:
    """The verdict for one (proposer, approver) pair."""

    allowed: bool
    reason: str
    failed_rule: str = ""
    eligible: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "approver-separation-verdict",
            "allowed": self.allowed,
            "reason": self.reason,
            "failed_rule": self.failed_rule,
            "eligible_approvers": list(self.eligible),
        }


def _norm(value: Any) -> str:
    """Normalize an identity to a stripped string; anything non-string or
    blank becomes ``""``."""
    if not isinstance(value, str):
        return ""
    return value.strip()


def proposer_of(*, agent: str, delegation_chain: Sequence[str] = ()) -> str:
    """The proposer identity from runtime provenance.

    The outermost principal proposes the action: the first hop of the
    delegation chain when the action was delegated, otherwise the acting
    agent. Both inputs are runtime-owned (never agent claims); a blank
    result means the provenance was unusable and callers must fail closed.
    """
    chain = [_norm(hop) for hop in (delegation_chain or ())]
    chain = [hop for hop in chain if hop]
    if chain:
        return chain[0]
    return _norm(agent)


def _valid_graph(delegation_graph: Any) -> dict[str, tuple[str, ...]] | None:
    """Validate the delegation graph, or ``None`` when it is malformed.

    Malformed means: not a mapping, a non-string delegator key, or a
    non-iterable / non-string delegatee entry. A malformed graph is not
    repaired — the caller treats it as "subtree unverifiable".
    """
    if delegation_graph is None:
        return {}
    if not isinstance(delegation_graph, Mapping):
        return None
    clean: dict[str, tuple[str, ...]] = {}
    for delegator, delegatees in delegation_graph.items():
        delegator = _norm(delegator)
        if not delegator:
            return None
        if isinstance(delegatees, str) or not isinstance(delegatees, Iterable):
            return None
        names = tuple(_norm(d) for d in delegatees)
        if any(not name for name in names):
            return None
        clean[delegator] = names
    return clean


def delegation_subtree(
    proposer: str,
    delegation_graph: Mapping[str, Iterable[str]] | None = None,
) -> tuple[str, ...]:
    """Every identity in the proposer's delegation subtree, proposer first.

    Breadth-first traversal of delegator -> delegatee edges with a visited
    set: cyclic graphs terminate, self-loops are harmless, and identities
    unreachable from the proposer are never included. An empty proposer or
    a malformed graph yields ``()`` — the subtree is unverifiable, so
    callers must exclude everyone (fail closed), not no one.
    """
    proposer = _norm(proposer)
    graph = _valid_graph(delegation_graph)
    if not proposer or graph is None:
        return ()
    seen: list[str] = []
    visited = {proposer}
    queue = [proposer]
    while queue:
        current = queue.pop(0)
        seen.append(current)
        for child in graph.get(current, ()):
            if child not in visited:
                visited.add(child)
                queue.append(child)
    return tuple(seen)


def eligible_approvers(
    *,
    proposer: str,
    approvers: Iterable[str],
    delegation_graph: Mapping[str, Iterable[str]] | None = None,
) -> tuple[str, ...]:
    """The approvers that may approve the proposer's action.

    ``approvers`` minus the proposer minus the proposer's delegation
    subtree. Order of ``approvers`` is preserved and duplicates are
    removed. An empty proposer, an empty approver list, or a malformed
    delegation graph yields ``()``: with no verifiable third party, the
    answer is deny, never "approve anyway".
    """
    proposer = _norm(proposer)
    if not proposer:
        return ()
    graph = _valid_graph(delegation_graph)
    if graph is None:
        return ()
    excluded = set(delegation_subtree(proposer, graph))
    eligible: list[str] = []
    for approver in approvers or ():
        name = _norm(approver)
        if not name or name in excluded or name in eligible:
            continue
        eligible.append(name)
    return tuple(eligible)


def check_approver(
    *,
    proposer: str,
    approver_identity: str,
    approvers: Iterable[str] | None = None,
    delegation_graph: Mapping[str, Iterable[str]] | None = None,
) -> ApproverVerdict:
    """Verdict for one ``(proposer, approver_identity)`` pair.

    Deny rules, checked in order:

    1. ``malformed_input`` — the proposer identity is blank;
    2. ``unknown_approver`` — the approver has no identity, or is absent
       from the registered approver set (when one is given);
    3. ``self_approval`` — the approver *is* the proposer;
    4. ``sock_puppet_delegatee`` — the approver sits in the proposer's
       delegation subtree;
    5. otherwise allow.

    When ``approvers`` is ``None`` the registered-set check is skipped —
    the host did not name a set, so only the self/subtree checks run.
    Pass ``approvers`` to also reject unregistered approvers.
    """
    proposer = _norm(proposer)
    approver = _norm(approver_identity)
    if not proposer:
        return ApproverVerdict(
            False,
            "no-self-attestation check refused: the proposer identity is blank",
            RULE_MALFORMED,
            (),
        )
    if not approver:
        return ApproverVerdict(
            False,
            "no-self-attestation check refused: the approver has no identity "
            "(an unknown approver is not a third party)",
            RULE_UNKNOWN_APPROVER,
            (),
        )
    pool = list(approvers) if approvers is not None else None
    if pool is not None and approver not in {_norm(a) for a in pool}:
        return ApproverVerdict(
            False,
            f"approver {approver!r} is not in the registered approver set",
            RULE_UNKNOWN_APPROVER,
            eligible_approvers(
                proposer=proposer, approvers=pool, delegation_graph=delegation_graph
            ),
        )
    eligible = eligible_approvers(
        proposer=proposer,
        approvers=pool if pool is not None else (approver,),
        delegation_graph=delegation_graph,
    )
    if approver == proposer:
        return ApproverVerdict(
            False,
            f"approver {approver!r} is the action's proposer: self-approval "
            "is never evidence (ERC-8004 no-self-attestation)",
            RULE_SELF_APPROVAL,
            eligible,
        )
    if approver not in eligible:
        return ApproverVerdict(
            False,
            f"approver {approver!r} sits in the proposer's delegation subtree: "
            "sock-puppet approval is self-approval with extra hops",
            RULE_SOCK_PUPPET_DELEGATEE,
            eligible,
        )
    return ApproverVerdict(
        True,
        f"approver {approver!r} is a third party to proposer {proposer!r}",
        "",
        eligible,
    )


def self_attestation_denied_event(
    *,
    proposer: str,
    approver_identity: str,
    failed_rule: str,
    reason: str,
    card_id: str = "",
    call_id: str = "",
) -> dict[str, Any]:
    """The audit record for a self-attestation denial.

    Feed into ``audit_chain.chain_record`` / ``chain_records`` in order,
    alongside the card verdict. The event pins who proposed, who tried to
    approve, and which rule fired, so the ``audit.ndjson/1`` chain anchors
    the separation decision.
    """
    return {
        "event": SELF_ATTESTATION_DENIED_EVENT,
        "proposer": _norm(proposer),
        "approver": _norm(approver_identity),
        "failed_rule": str(failed_rule or ""),
        "reason": str(reason or ""),
        "card_id": str(card_id or ""),
        "call_id": str(call_id or ""),
    }


__all__ = [
    "SELF_ATTESTATION_DENIED_EVENT",
    "RULE_MALFORMED",
    "RULE_NO_ELIGIBLE_APPROVER",
    "RULE_SELF_APPROVAL",
    "RULE_SOCK_PUPPET_DELEGATEE",
    "RULE_UNKNOWN_APPROVER",
    "ApproverSeparationError",
    "ApproverVerdict",
    "check_approver",
    "delegation_subtree",
    "eligible_approvers",
    "proposer_of",
    "self_attestation_denied_event",
]
