"""A2A handoff gates: sabotage detection and turf-war detection.

P0 wiring: ``real proxy/A2A dispatch -> delegation + handoff +
sabotage/turf-war gates``. When one agent hands work to another (or
claims shared resources to do it), this module is the checkpoint that
runs *before* the handoff is accepted:

- **sabotage**: a handoff whose action undoes another agent's recorded
  work, or whose structured claims contradict another agent's recorded
  claims, is refused. Undoing your *own* prior work is a revision, not
  sabotage, and is allowed.
- **turf war**: a handoff whose resource requests overlap resources
  already claimed by a *different* agent is refused. Re-claiming your
  own resources is idempotent and allowed.

No wall clock anywhere: ordering is caller-supplied integer sequence
numbers, so every decision is deterministic and testable.

Hard doctrine (enforced, not aspirational):

- a handoff that reverses another agent's recorded action on the same
  target is sabotage, whichever direction the reversal runs;
- a handoff whose claims contradict another agent's recorded claims on
  the same key is sabotage;
- a resource held by one agent cannot be taken by another through a
  handoff -- the holder must release it first;
- sabotage is checked before turf war: a handoff that is both is
  reported as ``deny_sabotage``;
- malformed handoffs fail closed: a handoff the gate cannot parse
  might be undoing work the gate cannot see, so it is denied;
- only ``allow`` records history and claims resources -- denied
  handoffs leave no trace in the gate's log and claim nothing.

Honest scope: these are *detectors on host-reported records*, not a
defense against a hostile agent runtime. The gate sees action types,
targets, and claims the agents chose to report; a saboteur who lies
in its records lies to this gate too. Contradiction is checked on
structured ``claims`` mappings, not on free-text prose -- two
paragraphs that "sound opposite" are out of scope; use the claims
field for machine-checkable assertions. The resource registry is
in-memory; persistence across restarts is the host's job.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Mapping

#: Version pin for this module's record shape.
A2A_GATES_VERSION = "a2a-gates.v1"

#: Verdict vocabulary returned by :meth:`A2AGate.check_handoff`.
ALLOW = "allow"
DENY_SABOTAGE = "deny_sabotage"
DENY_TURF_WAR = "deny_turf_war"

_VERDICTS = (ALLOW, DENY_SABOTAGE, DENY_TURF_WAR)

#: Action pairs where the second undoes the first (checked both ways).
_UNDOES = {
    "create": "delete",
    "delete": "create",
    "add": "remove",
    "remove": "add",
    "approve": "revoke",
    "revoke": "approve",
    "grant": "revoke",
    "enable": "disable",
    "disable": "enable",
    "write": "revert",
    "revert": "write",
    "open": "close",
    "close": "open",
    "start": "stop",
    "stop": "start",
    "deploy": "rollback",
    "rollback": "deploy",
    "lock": "unlock",
    "unlock": "lock",
    "publish": "retract",
    "retract": "publish",
    "send": "recall",
}

_ZERO_DIGEST = "sha256:" + "00" * 32


class A2AError(Exception):
    """Raised for malformed gate inputs that must never be silent."""


def _check_seq(value: object, name: str) -> int:
    """Validate a sequence number: int, not bool, non-negative."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise A2AError(f"{name} must be an int, got {value!r}")
    if value < 0:
        raise A2AError(f"{name} must be non-negative, got {value}")
    return value


def _check_agent(value: object, name: str) -> str:
    """Validate an agent id: non-empty string."""
    if not isinstance(value, str) or not value.strip():
        raise A2AError(f"{name} must be a non-empty string, got {value!r}")
    return value


def _check_resource(value: object) -> str:
    """Validate a resource name: non-empty string."""
    if not isinstance(value, str) or not value.strip():
        raise A2AError(f"resource must be a non-empty string, got {value!r}")
    return value


def _norm_action(value: object) -> str:
    """Normalize an action type for comparison: lowercase, stripped."""
    if not isinstance(value, str):
        return ""
    return value.strip().lower()


def _norm_target(value: object) -> str:
    """Normalize a target for comparison: stripped string, else empty."""
    if not isinstance(value, str):
        return ""
    return value.strip()


def _norm_claims(value: object) -> dict[str, Any]:
    """Normalize a claims mapping; non-mappings become empty."""
    if not isinstance(value, Mapping):
        return {}
    return {str(k): v for k, v in value.items()}


def _canonical(obj: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest_of(obj: Any) -> str:
    """``sha256:`` hex digest of the canonical JSON of *obj*."""
    return "sha256:" + hashlib.sha256(_canonical(obj)).hexdigest()


def _claims_contradict(a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    """True if *a* and *b* assert different values for the same key.

    Keys present in only one side are not contradictions. ``None``
    values are treated as "no assertion" and never contradict.
    """
    for key, aval in a.items():
        if key in b:
            bval = b[key]
            if aval is not None and bval is not None and aval != bval:
                return True
    return False


def detect_sabotage(handoff: Mapping[str, Any], history: Iterable[Mapping[str, Any]]) -> bool:
    """Detect whether *handoff* sabotages another agent's recorded work.

    *handoff* is a mapping with ``agent`` (the agent about to act),
    ``action_type``, ``target``, and optional ``claims`` (a mapping of
    machine-checkable assertions). *history* is an iterable of mappings
    with the same shape plus ``agent`` identifying who recorded them.

    Returns True when the handoff, performed by its agent, would undo
    *another* agent's recorded action on the same target, or when its
    claims contradict another agent's recorded claims on the same key.
    Undoing your own prior work is a revision and returns False.

    Fail-closed: a non-mapping handoff, or a handoff missing its
    ``agent``, returns True -- a handoff the gate cannot parse might
    be undoing work the gate cannot see.
    """
    if not isinstance(handoff, Mapping):
        return True
    agent = handoff.get("agent")
    if not isinstance(agent, str) or not agent.strip():
        return True

    action = _norm_action(handoff.get("action_type"))
    target = _norm_target(handoff.get("target"))
    claims = _norm_claims(handoff.get("claims"))

    try:
        entries = list(history)
    except TypeError:
        return True

    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        other = entry.get("agent")
        if not isinstance(other, str) or other.strip() == agent.strip():
            # Same agent: a revision, not sabotage. Malformed entries
            # carry no attributable work, so they cannot be sabotaged.
            continue
        other_action = _norm_action(entry.get("action_type"))
        other_target = _norm_target(entry.get("target"))
        # Undo pair on the same non-empty target, either direction.
        if (
            action
            and other_action
            and target
            and target == other_target
            and _UNDOES.get(other_action) == action
        ):
            return True
        # Contradictory structured claims.
        if claims and _claims_contradict(claims, _norm_claims(entry.get("claims"))):
            return True
    return False


class ResourceRegistry:
    """Tracks which agent holds which resource. In-memory, fail-closed.

    Claims are exclusive: a resource held by one agent cannot be
    claimed by another until the holder releases it. All mutations
    validate their inputs and raise :class:`A2AError` on misuse.
    """

    def __init__(self) -> None:
        self._holders: dict[str, str] = {}
        self._claims: dict[str, tuple[str, int]] = {}  # resource -> (agent, seq)

    def claim(self, agent_id: str, resource: str, seq: int) -> bool:
        """Claim *resource* for *agent_id*.

        Returns True when the claim is recorded (including the
        idempotent re-claim by the current holder). Returns False when
        another agent holds the resource -- the claim is refused and
        nothing changes.
        """
        agent = _check_agent(agent_id, "agent_id")
        res = _check_resource(resource)
        _check_seq(seq, "seq")
        holder = self._holders.get(res)
        if holder is None:
            self._holders[res] = agent
            self._claims[res] = (agent, seq)
            return True
        if holder == agent:
            return True
        return False

    def release(self, agent_id: str, resource: str) -> bool:
        """Release *resource* held by *agent_id*.

        Returns True when the resource is now free (including when it
        was already free). Returns False when another agent holds it --
        you cannot release someone else's resource.
        """
        agent = _check_agent(agent_id, "agent_id")
        res = _check_resource(resource)
        holder = self._holders.get(res)
        if holder is None:
            return True
        if holder != agent:
            return False
        del self._holders[res]
        del self._claims[res]
        return True

    def holder(self, resource: str) -> str | None:
        """Return the agent holding *resource*, or None if free."""
        res = _check_resource(resource)
        return self._holders.get(res)

    def held_by(self, agent_id: str) -> tuple[str, ...]:
        """Return the resources currently held by *agent_id*, sorted."""
        agent = _check_agent(agent_id, "agent_id")
        return tuple(sorted(r for r, h in self._holders.items() if h == agent))

    def __len__(self) -> int:
        return len(self._holders)

    def __contains__(self, resource: object) -> bool:
        return isinstance(resource, str) and resource in self._holders


#: Module-level registry used by :func:`detect_turf_war` when no
#: explicit registry is passed. Tests should pass their own registry
#: (or call :func:`reset_default_registry`) to stay isolated.
_DEFAULT_REGISTRY = ResourceRegistry()


def reset_default_registry() -> None:
    """Replace the module-level default registry with a fresh one."""
    global _DEFAULT_REGISTRY
    _DEFAULT_REGISTRY = ResourceRegistry()


def default_registry() -> ResourceRegistry:
    """Return the module-level default resource registry."""
    return _DEFAULT_REGISTRY


def detect_turf_war(
    agent_id: str,
    resource_requests: Iterable[str],
    registry: ResourceRegistry | None = None,
) -> bool:
    """Detect whether *agent_id*'s resource requests start a turf war.

    Returns True when any requested resource is currently held by a
    *different* agent. Requesting a free resource, or re-requesting one
    you already hold, returns False.

    Fail-closed: a malformed agent id or malformed resource list
    returns True -- a request the gate cannot parse might be reaching
    for resources the gate cannot see.
    """
    reg = _DEFAULT_REGISTRY if registry is None else registry
    if not isinstance(reg, ResourceRegistry):
        return True
    try:
        agent = _check_agent(agent_id, "agent_id")
        requests = list(resource_requests)
    except (A2AError, TypeError):
        return True
    for raw in requests:
        try:
            res = _check_resource(raw)
        except A2AError:
            return True
        holder = reg.holder(res)
        if holder is not None and holder != agent:
            return True
    return False


@dataclass(frozen=True)
class HandoffRecord:
    """One accepted handoff, digest-chained into the gate's history.

    ``claims`` pins the machine-checkable assertions the handoff
    carried, as ``(key, canonical_json(value))`` pairs, so a later
    handoff's claims can be checked for contradiction against them.
    """

    gate_id: str
    seq: int
    from_agent: str
    to_agent: str
    action_type: str
    target: str
    verdict: str
    prev_digest: str = _ZERO_DIGEST
    resources: tuple[str, ...] = ()
    claims: tuple[tuple[str, str], ...] = ()

    def claims_dict(self) -> dict[str, Any]:
        """Reconstruct the claims mapping from pinned pairs."""
        return {k: json.loads(v) for k, v in self.claims}

    def as_dict(self) -> dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "seq": self.seq,
            "from_agent": self.from_agent,
            "to_agent": self.to_agent,
            "action_type": self.action_type,
            "target": self.target,
            "verdict": self.verdict,
            "prev_digest": self.prev_digest,
            "resources": list(self.resources),
            "claims": [[k, v] for k, v in self.claims],
            "a2a_gates_version": A2A_GATES_VERSION,
        }

    def record_digest(self) -> str:
        """Digest pinning this record's content (excludes nothing)."""
        return _digest_of(self.as_dict())


class A2AGate:
    """Checkpoint for agent-to-agent handoffs.

    Holds the handoff history (for sabotage detection) and the
    resource registry (for turf-war detection). Sabotage is checked
    before turf war; only ``allow`` verdicts are recorded and claim
    resources.
    """

    def __init__(self, gate_id: str = "a2a-gate") -> None:
        self._gate_id = _check_agent(gate_id, "gate_id")
        self._records: list[HandoffRecord] = []
        self._registry = ResourceRegistry()
        self._seq = 0

    @property
    def gate_id(self) -> str:
        return self._gate_id

    @property
    def registry(self) -> ResourceRegistry:
        """The gate's resource registry (claims happen on allow)."""
        return self._registry

    def _history_entries(self) -> list[dict[str, Any]]:
        return [
            {
                "agent": r.to_agent,
                "action_type": r.action_type,
                "target": r.target,
                "claims": r.claims_dict(),
                "seq": r.seq,
            }
            for r in self._records
        ]

    def _next_seq(self) -> int:
        seq = self._seq
        self._seq += 1
        return seq

    def check_handoff(
        self,
        from_agent: str,
        to_agent: str,
        payload: Mapping[str, Any],
    ) -> str:
        """Check a handoff from *from_agent* to *to_agent*.

        *payload* may carry ``action_type``, ``target``,
        ``instruction``, ``claims`` (mapping), and ``resources`` (list
        of resource names the receiving agent wants to hold).

        Returns ``allow``, ``deny_sabotage``, or ``deny_turf_war``.
        Sabotage is evaluated first. Malformed agents or payloads are
        denied as ``deny_sabotage`` (fail closed). Only ``allow``
        appends to history and claims resources.
        """
        try:
            src = _check_agent(from_agent, "from_agent")
            dst = _check_agent(to_agent, "to_agent")
        except A2AError:
            return DENY_SABOTAGE
        if not isinstance(payload, Mapping):
            return DENY_SABOTAGE

        action = _norm_action(payload.get("action_type"))
        target = _norm_target(payload.get("target"))
        claims = _norm_claims(payload.get("claims"))
        raw_resources = payload.get("resources", ())
        try:
            resources = tuple(_check_resource(r) for r in list(raw_resources))
        except (A2AError, TypeError):
            return DENY_SABOTAGE

        handoff = {
            "agent": dst,
            "action_type": action,
            "target": target,
            "instruction": payload.get("instruction"),
            "claims": claims,
        }
        if detect_sabotage(handoff, self._history_entries()):
            return DENY_SABOTAGE
        if detect_turf_war(dst, resources, self._registry):
            return DENY_TURF_WAR

        seq = self._next_seq()
        prev = self._records[-1].record_digest() if self._records else _ZERO_DIGEST
        try:
            pinned_claims = tuple(
                sorted((k, _canonical(v).decode("utf-8")) for k, v in claims.items())
            )
        except (TypeError, ValueError):
            # Claims that cannot be pinned cannot be audited or
            # contradiction-checked later: fail closed.
            return DENY_SABOTAGE
        record = HandoffRecord(
            gate_id=self._gate_id,
            seq=seq,
            from_agent=src,
            to_agent=dst,
            action_type=action,
            target=target,
            verdict=ALLOW,
            prev_digest=prev,
            resources=resources,
            claims=pinned_claims,
        )
        self._records.append(record)
        for res in resources:
            # Cannot fail: turf-war check just cleared every resource.
            self._registry.claim(dst, res, seq)
        return ALLOW

    def release(self, agent_id: str, resources: Iterable[str]) -> dict[str, bool]:
        """Release resources held by *agent_id*; returns per-resource results."""
        agent = _check_agent(agent_id, "agent_id")
        try:
            items = list(resources)
        except TypeError:
            raise A2AError(f"resources must be iterable, got {resources!r}")
        return { _check_resource(r): self._registry.release(agent, r) for r in items }

    def history(self) -> tuple[HandoffRecord, ...]:
        """Accepted handoffs, oldest first."""
        return tuple(self._records)

    def verify_chain(self) -> bool:
        """Verify the history digest chain; True when intact."""
        prev = _ZERO_DIGEST
        for record in self._records:
            if record.prev_digest != prev:
                return False
            # Recompute under constant-time comparison.
            recomputed = record.record_digest()
            if not hmac.compare_digest(recomputed, _digest_of(record.as_dict())):
                return False
            if record.verdict != ALLOW:
                return False
            prev = record.record_digest()
        return True


def a2a_gate_audit_events(
    record: HandoffRecord,
    *,
    note: str = "",
) -> list[dict[str, Any]]:
    """Audit events for one accepted handoff.

    Pins the gate, both agents, the action/target, the claimed
    resources, and the chain position, so the ``audit.ndjson/1`` hash
    chain anchors "this handoff passed the sabotage/turf-war gates at
    this point in the gate's log".
    """
    if not isinstance(record, HandoffRecord):
        raise A2AError(f"needs a HandoffRecord, got {record!r}")
    return [
        {
            "event": "a2a_gates.handoff_allowed",
            "gate_id": record.gate_id,
            "from_agent": record.from_agent,
            "to_agent": record.to_agent,
            "action_type": record.action_type,
            "target": record.target,
            "resources": list(record.resources),
            "seq": record.seq,
            "record_digest": record.record_digest(),
            "a2a_gates_version": A2A_GATES_VERSION,
            "note": note,
        }
    ]


def main() -> None:
    """Self-check: exercise the gate end to end."""
    gate = A2AGate("self-check")
    assert gate.check_handoff("x", "a", {"action_type": "create", "target": "t1"}) == ALLOW
    assert gate.check_handoff("a", "b", {"action_type": "delete", "target": "t1"}) == DENY_SABOTAGE
    gate2 = A2AGate("self-check-2")
    assert gate2.check_handoff("a", "b", {"resources": ["gpu-0"]}) == ALLOW
    assert gate2.check_handoff("a", "c", {"resources": ["gpu-0"]}) == DENY_TURF_WAR
    assert gate2.verify_chain()
    print("a2a-gates OK: sabotage denied, turf war denied, chain verifies")


if __name__ == "__main__":
    main()


__all__ = [
    "A2A_GATES_VERSION",
    "ALLOW",
    "DENY_SABOTAGE",
    "DENY_TURF_WAR",
    "A2AError",
    "HandoffRecord",
    "ResourceRegistry",
    "A2AGate",
    "detect_sabotage",
    "detect_turf_war",
    "default_registry",
    "reset_default_registry",
    "a2a_gate_audit_events",
    "main",
]
