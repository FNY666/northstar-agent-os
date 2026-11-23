"""Physical/irreversible dispatch edge gate: a human at the boundary.

A dispatch that moves the physical world, or that cannot be undone, is not
a routine tool call. The agent runtime can *propose* such an action, and it
can *prepare* it, but it must not *perform* it on its own authority. The
edge gate is the last checkpoint before the action leaves the agent's
sandbox: reversible reads flow through, everything else stops for a human.

Risk tiers (in order of restrictiveness):

- ``PHYSICAL`` — the action touches the physical world: robotics, IoT
  actuation, doors, motors, drones. Always requires a human. There is no
  allowlist for the physical world.
- ``IRREVERSIBLE`` — the action cannot be taken back once performed:
  delete, send, pay, publish, deploy. Requires a human unless the exact
  action type sits on the gate's allowlist (e.g. a pre-approved
  ``newsletter.send`` that the operator explicitly blessed).
- ``REVERSIBLE`` — reads, queries, previews, dry runs. Allowed through.

Classification is derived from the action's ``action_type`` (falling back
to ``type``), never from a caller-supplied ``risk`` claim: a claimed risk
is a claim, not a fact, and honoring it would hand the agent a downgrade
path. A physical token anywhere always wins; otherwise the trailing token
(the effect head in ``resource.verb`` names) decides first. Unknown or
malformed action types classify as ``PHYSICAL`` — fail closed, because an
action we cannot name is an action we cannot bound.

``EdgeGate.check`` is the dispatch-time verdict: ``"allow"``,
``"require_human"``, or ``"deny"``. ``"deny"`` is reserved for
structurally malformed input (not a mapping, or no usable action type) —
there is nothing coherent for a human to confirm, so the action is refused
outright. ``HumanConfirmation`` binds a human's decision to one specific
action via a digest pin, so a confirmation for ``newsletter.send`` cannot
be replayed to authorize ``db.delete``; ``EdgeGate.resolve`` verifies the
binding before the dispatch proceeds.

Honest scope: this is a *policy checkpoint*, not a physical interlock.
It runs on host-reported action records — if the host lies about what an
action does, the gate classifies the lie. It also does not stop a human
from confirming something reckless; it only guarantees that nothing
physical or irreversible happens *without* a human in the loop. The audit
event helper (``edge_gate_event``) shapes gate verdicts for the
``audit.ndjson/1`` hash chain so the human's decision is itself on the
record.

Everything here is offline and deterministic. No network, no clock reads:
sequence numbers (``requested_seq``) are caller-supplied integers.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

#: Module version, stamped on audit events.
GATE_VERSION = "edge-gate.v1"

#: Schema pin for gate records and audit events.
SCHEMA_PIN = "northstar.edge-gate.v1"

#: Verdict vocabulary returned by :meth:`EdgeGate.check` and
#: :meth:`EdgeGate.resolve`.
DECISION_ALLOW = "allow"
DECISION_DENY = "deny"
DECISION_REQUIRE_HUMAN = "require_human"

_DECISIONS = frozenset({DECISION_ALLOW, DECISION_DENY, DECISION_REQUIRE_HUMAN})

#: Audit event names for the ``audit.ndjson/1`` chain.
EVENT_GATE_REQUIRE_HUMAN = "edge_gate.require_human"
EVENT_GATE_ALLOWED = "edge_gate.allowed"
EVENT_GATE_DENIED = "edge_gate.denied"
EVENT_GATE_CONFIRMED = "edge_gate.human_confirmed"


class ActionRisk(str, Enum):
    """Risk tier of an action. Ordered by restrictiveness."""

    REVERSIBLE = "reversible"
    IRREVERSIBLE = "irreversible"
    PHYSICAL = "physical"


_TOKEN_RE = re.compile(r"[a-z0-9]+")

#: Tokens that mark an action as touching the physical world. Checked first;
#: physical always wins over every other tier.
_PHYSICAL_TOKENS = frozenset({
    "robot", "robotic", "robotics",
    "move", "navigate", "navigation", "drive", "steer",
    "actuate", "actuator", "actuation",
    "gpio", "motor", "servo",
    "drone", "uav", "fly", "takeoff", "land",
    "arm", "grasp", "grip", "gripper", "manipulator",
    "iot", "device", "hardware",
    "switch", "relay", "valve", "pump", "fan",
    "lock", "unlock", "door", "gate", "window",
    "hvac", "thermostat", "heater", "cooler",
    "siren", "alarm",
})

#: Tokens that mark an action as irreversible once performed. Checked after
#: physical; any physical token present keeps the PHYSICAL tier.
_IRREVERSIBLE_TOKENS = frozenset({
    "delete", "remove", "destroy", "erase", "wipe", "purge", "drop",
    "send", "email", "mail", "sms", "message", "notify",
    "pay", "payment", "purchase", "buy", "order", "checkout",
    "transfer", "withdraw", "deposit", "refund",
    "publish", "post", "share", "tweet", "broadcast",
    "commit", "push", "deploy", "release", "ship",
    "grant", "revoke", "rotate",
    "execute", "exec", "shell", "command", "script", "subprocess",
    "format", "reboot", "shutdown", "restart",
})

#: Tokens that mark an action as reversible. Checked last; anything that
#: matches no tier at all is treated as PHYSICAL (fail closed).
_REVERSIBLE_TOKENS = frozenset({
    "read", "get", "list", "query", "search", "find", "fetch",
    "describe", "preview", "dry", "plan", "simulate",
    "summarize", "translate", "calculate", "compute",
    "check", "verify", "inspect", "view", "show", "status",
    "ping", "health",
})


def _action_type_of(action: Any) -> str:
    """Extract the action type string, or ``""`` when unusable."""
    if not isinstance(action, Mapping):
        return ""
    raw = action.get("action_type", action.get("type", ""))
    if not isinstance(raw, str):
        return ""
    return raw.strip().lower()


def _tokens(action_type: str) -> frozenset[str]:
    """Lowercase alphanumeric tokens of an action type string."""
    return frozenset(_TOKEN_RE.findall(action_type))


def classify_action(action: Any) -> ActionRisk:
    """Classify an action into a risk tier. Never raises.

    The tier is derived from the action's ``action_type`` (falling back to
    ``type``). A physical token anywhere always wins — the physical world
    has no downgrade path. Otherwise the *last* token decides first: in
    dot-namespaced action types (``resource.verb``) the trailing token is
    the effect head, so ``email.preview`` is a read even though ``email``
    names an irreversible domain, and ``payment.status`` is a read even
    though ``payment`` is not. When the last token is unknown, any-token
    matching applies (irreversible, then reversible). Anything else —
    unknown types, empty types, non-mapping input — classifies as
    ``PHYSICAL``: fail closed, because an action we cannot name is an
    action we cannot bound.

    A caller-supplied ``risk`` field is deliberately ignored: honoring it
    would give the agent a downgrade path.
    """
    action_type = _action_type_of(action)
    if not action_type:
        return ActionRisk.PHYSICAL
    ordered = _TOKEN_RE.findall(action_type)
    toks = frozenset(ordered)
    if toks & _PHYSICAL_TOKENS:
        return ActionRisk.PHYSICAL
    last = ordered[-1] if ordered else ""
    if last in _IRREVERSIBLE_TOKENS:
        return ActionRisk.IRREVERSIBLE
    if last in _REVERSIBLE_TOKENS:
        return ActionRisk.REVERSIBLE
    if toks & _IRREVERSIBLE_TOKENS:
        return ActionRisk.IRREVERSIBLE
    if toks & _REVERSIBLE_TOKENS:
        return ActionRisk.REVERSIBLE
    return ActionRisk.PHYSICAL


def action_digest(action: Mapping[str, Any]) -> str:
    """Digest pin binding a confirmation to one specific action.

    ``sha256:`` hex of the JCS-canonical bytes of the action mapping, so a
    confirmation issued for one action cannot be replayed for another.
    """
    canonical = json.dumps(
        dict(action), sort_keys=True, separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True)
class HumanConfirmation:
    """A human's decision on one specific action.

    ``action`` is the exact action mapping the human reviewed;
    ``action_digest`` pins it so the confirmation cannot be replayed for a
    different action. ``requested_seq`` is the caller-supplied sequence
    number of the gate request this answers (no wall-clock anywhere).
    ``confirmed`` is the human's yes/no; ``confirmed_by`` names the human.
    Use :meth:`bind` to construct one with the digest filled in.
    """

    action: Mapping[str, Any]
    requested_seq: int
    confirmed: bool
    confirmed_by: str
    action_digest: str = ""

    @classmethod
    def bind(
        cls,
        action: Mapping[str, Any],
        requested_seq: int,
        confirmed: bool,
        confirmed_by: str,
    ) -> "HumanConfirmation":
        """Build a confirmation with the action digest pin filled in."""
        return cls(
            action=dict(action),
            requested_seq=requested_seq,
            confirmed=confirmed,
            confirmed_by=confirmed_by,
            action_digest=action_digest(action),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": GATE_VERSION,
            "action": dict(self.action),
            "action_digest": self.action_digest,
            "requested_seq": self.requested_seq,
            "confirmed": self.confirmed,
            "confirmed_by": self.confirmed_by,
        }


@dataclass(frozen=True)
class EdgeDecision:
    """The gate's verdict on one action, with the reason attached."""

    verdict: str
    risk: ActionRisk
    action_type: str
    rule: str
    seq: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": GATE_VERSION,
            "verdict": self.verdict,
            "risk": self.risk.value,
            "action_type": self.action_type,
            "rule": self.rule,
            "seq": self.seq,
        }


#: Rule ids carried on :class:`EdgeDecision`.
RULE_REVERSIBLE_ALLOW = "reversible_allow"
RULE_PHYSICAL_REQUIRE_HUMAN = "physical_require_human"
RULE_IRREVERSIBLE_ALLOWLISTED = "irreversible_allowlisted"
RULE_IRREVERSIBLE_REQUIRE_HUMAN = "irreversible_require_human"
RULE_MALFORMED_DENY = "malformed_deny"
RULE_CONFIRMATION_OK = "confirmation_ok"
RULE_CONFIRMATION_MISMATCH = "confirmation_mismatch"
RULE_CONFIRMATION_DECLINED = "confirmation_declined"
RULE_CONFIRMATION_ANONYMOUS = "confirmation_anonymous"
RULE_CONFIRMATION_STALE = "confirmation_stale"


class EdgeGate:
    """Dispatch-time edge gate for physical/irreversible actions.

    ``irreversible_allowlist`` names the exact irreversible action types an
    operator has pre-approved (matched case-insensitively against the full
    normalized action type). The allowlist never covers ``PHYSICAL``: there
    is no pre-approval for the physical world.

    ``max_confirmation_age_seq`` optionally bounds how many sequence ticks
    a human confirmation stays valid; ``None`` means confirmations never
    expire by age (the caller still re-checks every dispatch).
    """

    def __init__(
        self,
        *,
        irreversible_allowlist: Sequence[str] = (),
        max_confirmation_age_seq: int | None = None,
    ) -> None:
        self._allowlist = frozenset(
            str(a).strip().lower() for a in irreversible_allowlist
            if isinstance(a, str) and a.strip()
        )
        if max_confirmation_age_seq is not None and (
            isinstance(max_confirmation_age_seq, bool)
            or not isinstance(max_confirmation_age_seq, int)
            or max_confirmation_age_seq < 0
        ):
            raise ValueError("max_confirmation_age_seq must be a non-negative int or None")
        self._max_age = max_confirmation_age_seq

    @property
    def irreversible_allowlist(self) -> frozenset[str]:
        return self._allowlist

    def check(
        self,
        action: Any,
        context: Mapping[str, Any] | None = None,
        *,
        seq: int = 0,
    ) -> str:
        """Dispatch-time verdict: ``"allow"``, ``"deny"``, or
        ``"require_human"``. Never raises on any input.

        Malformed input (not a mapping, or no usable action type) is
        denied outright — there is nothing coherent for a human to
        confirm. ``PHYSICAL`` always requires a human; ``IRREVERSIBLE``
        requires a human unless allowlisted; ``REVERSIBLE`` is allowed.
        """
        decision = self.check_detailed(action, context, seq=seq)
        return decision.verdict

    def check_detailed(
        self,
        action: Any,
        context: Mapping[str, Any] | None = None,
        *,
        seq: int = 0,
    ) -> EdgeDecision:
        """Same as :meth:`check` but returns the full decision record."""
        action_type = _action_type_of(action)
        if not action_type:
            return EdgeDecision(
                verdict=DECISION_DENY,
                risk=ActionRisk.PHYSICAL,
                action_type="",
                rule=RULE_MALFORMED_DENY,
                seq=seq,
            )
        risk = classify_action(action)
        if risk is ActionRisk.PHYSICAL:
            return EdgeDecision(
                verdict=DECISION_REQUIRE_HUMAN,
                risk=risk,
                action_type=action_type,
                rule=RULE_PHYSICAL_REQUIRE_HUMAN,
                seq=seq,
            )
        if risk is ActionRisk.IRREVERSIBLE:
            if action_type in self._allowlist:
                return EdgeDecision(
                    verdict=DECISION_ALLOW,
                    risk=risk,
                    action_type=action_type,
                    rule=RULE_IRREVERSIBLE_ALLOWLISTED,
                    seq=seq,
                )
            return EdgeDecision(
                verdict=DECISION_REQUIRE_HUMAN,
                risk=risk,
                action_type=action_type,
                rule=RULE_IRREVERSIBLE_REQUIRE_HUMAN,
                seq=seq,
            )
        return EdgeDecision(
            verdict=DECISION_ALLOW,
            risk=risk,
            action_type=action_type,
            rule=RULE_REVERSIBLE_ALLOW,
            seq=seq,
        )

    def resolve(
        self,
        action: Mapping[str, Any],
        confirmation: HumanConfirmation,
        *,
        current_seq: int,
    ) -> str:
        """Apply a human confirmation to a gated action. Never raises.

        Returns ``"allow"`` only when every binding check passes: the
        confirmation's digest matches this exact action, the human said
        yes, the human is named, and the confirmation is not stale. Any
        failure returns ``"deny"`` — a declined or mismatched confirmation
        is a refusal, not a retry.
        """
        if not isinstance(action, Mapping):
            return DECISION_DENY
        if not isinstance(confirmation, HumanConfirmation):
            return DECISION_DENY
        if not confirmation.confirmed:
            return DECISION_DENY
        if not isinstance(confirmation.confirmed_by, str) or not confirmation.confirmed_by.strip():
            return DECISION_DENY
        if confirmation.action_digest != action_digest(action):
            return DECISION_DENY
        if self._max_age is not None:
            if (
                not isinstance(confirmation.requested_seq, int)
                or isinstance(confirmation.requested_seq, bool)
                or not isinstance(current_seq, int)
                or isinstance(current_seq, bool)
                or current_seq < confirmation.requested_seq
                or current_seq - confirmation.requested_seq > self._max_age
            ):
                return DECISION_DENY
        return DECISION_ALLOW


def edge_gate_event(
    decision: EdgeDecision,
    *,
    confirmation: HumanConfirmation | None = None,
    seq: int = 0,
) -> dict[str, Any]:
    """Audit record for a gate verdict, shaped for ``audit.ndjson/1``.

    The human's decision is itself on the record: when a confirmation
    resolved the action, its digest and confirmer are pinned here.
    """
    if decision.verdict == DECISION_ALLOW and confirmation is not None:
        name = EVENT_GATE_CONFIRMED
    elif decision.verdict == DECISION_ALLOW:
        name = EVENT_GATE_ALLOWED
    elif decision.verdict == DECISION_REQUIRE_HUMAN:
        name = EVENT_GATE_REQUIRE_HUMAN
    else:
        name = EVENT_GATE_DENIED
    body: dict[str, Any] = {
        "schema": SCHEMA_PIN,
        "version": GATE_VERSION,
        "event": name,
        "verdict": decision.verdict,
        "risk": decision.risk.value,
        "action_type": decision.action_type,
        "rule": decision.rule,
        "seq": seq,
    }
    if confirmation is not None:
        body["confirmation"] = {
            "action_digest": confirmation.action_digest,
            "requested_seq": confirmation.requested_seq,
            "confirmed": confirmation.confirmed,
            "confirmed_by": confirmation.confirmed_by,
        }
    return body


def main() -> None:
    gate = EdgeGate(irreversible_allowlist=["newsletter.send"])
    corpus = [
        ({"action_type": "db.query"}, "allow"),
        ({"action_type": "file.read"}, "allow"),
        ({"action_type": "db.delete"}, "require_human"),
        ({"action_type": "email.send"}, "require_human"),
        ({"action_type": "newsletter.send"}, "allow"),
        ({"action_type": "robot.move_to"}, "require_human"),
        ({"action_type": "iot.relay_on"}, "require_human"),
        ({}, "deny"),
        ("not-a-mapping", "deny"),
    ]
    bad = 0
    for action, expected in corpus:
        got = gate.check(action, {})
        status = "ok" if got == expected else "MISMATCH"
        if got != expected:
            bad += 1
        print(f"[{status}] {action!r} -> {got} (expected {expected})")
    print(f"edge-gate corpus: {len(corpus) - bad}/{len(corpus)} correct")
    if bad:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
