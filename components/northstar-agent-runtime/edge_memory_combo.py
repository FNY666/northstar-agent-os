"""Edge gate + bitemporal memory integration: risk context from the past.

The :class:`edge_gate.EdgeGate` decides each action in isolation — it has no
memory of what happened before. An agent that was denied ``db.drop`` by a
human yesterday, allowlisted today under a different action type alias, and
re-tries tomorrow is exactly the pattern the gate alone cannot see. This
module composes the two:

- the gate supplies the dispatch-time verdict;
- the :class:`memory_bitemporal.BitemporalMemoryStore` supplies the risk
  context: past denials recorded as memory records;
- :class:`EdgeMemoryGate` escalates ``"allow"`` to ``"require_human"`` when
  the action type carries enough past denials.

The composition is **monotonic**: memory can only move a verdict toward
restrictiveness, never away from it. A past denial never turns
``"require_human"`` into ``"allow"``, and ``"deny"`` (structurally
malformed input — nothing coherent to confirm) never escalates anywhere.
Memory is not a second allowlist; it is a suspicion index.

History is written through :meth:`EdgeMemoryGate.note_outcome`, and
:meth:`EdgeMemoryGate.resolve` notes the human's decision automatically, so
every confirmation feeds the memory the next check reads. Records are
plain text with a strict marker format::

    edge_gate.decision: action_type=db.drop outcome=human_declined seq=42

Expired or superseded records are invisible to the gate — the bitemporal
store's own lifecycle governs what counts as "current risk context". A
denial that has decayed or been superseded no longer escalates, which is
the intended semantics: stale suspicion should not outlive the memory
policy.

Honest scope: the gate reads host-reported memory. If the host rewrites
history, the gate classifies the rewrite. Escalation is advisory context,
not a second policy engine — the base gate's ``PHYSICAL``/deny semantics
are unchanged. Everything is offline and deterministic; no clock reads,
caller-supplied sequence numbers only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from edge_gate import (
    DECISION_ALLOW,
    DECISION_DENY,
    DECISION_REQUIRE_HUMAN,
    EdgeDecision,
    EdgeGate,
    HumanConfirmation,
)
from memory_bitemporal import BitemporalMemoryStore, MemoryRecord

#: Module version, stamped on decision records.
EDGE_MEMORY_COMBO_VERSION = "edge-memory-combo.v1"

#: Schema pin for decision records.
SCHEMA_PIN = "northstar.edge-memory-combo.v1"

#: Marker format for gate-history records in the memory store.
MARKER_PREFIX = "edge_gate.decision:"
_DECISION_RE = re.compile(
    r"^edge_gate\.decision:\s+action_type=([a-z0-9._-]+)\s+outcome=([a-z_]+)\s+seq=\d+\s*$"
)

#: Outcomes that count as denials for escalation purposes.
DENIAL_OUTCOMES = frozenset({"denied", "human_declined"})

#: All outcomes :meth:`EdgeMemoryGate.note_outcome` accepts.
VALID_OUTCOMES = frozenset(
    {"allowed", "denied", "human_confirmed", "human_declined"}
)

#: Rule id carried on :class:`MemoryAwareDecision` when memory escalated.
RULE_MEMORY_ESCALATED = "memory_escalated"


def _check_seq(name: str, value: Any) -> int:
    """Validate a caller-supplied sequence number (no wall-clock)."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative int, got {value!r}")
    return value


@dataclass(frozen=True)
class MemoryAwareDecision:
    """The combined verdict: base gate decision plus memory context.

    ``verdict`` is the final verdict after memory escalation; ``base_verdict``
    is what the inner gate decided alone. ``memory_denials`` is how many
    current denial records the store held for this action type at check time.
    ``rule`` is the base rule, or ``"memory_escalated"`` when memory moved
    the verdict.
    """

    verdict: str
    base_verdict: str
    risk: str
    action_type: str
    rule: str
    memory_denials: int
    seq: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": EDGE_MEMORY_COMBO_VERSION,
            "verdict": self.verdict,
            "base_verdict": self.base_verdict,
            "risk": self.risk,
            "action_type": self.action_type,
            "rule": self.rule,
            "memory_denials": self.memory_denials,
            "seq": self.seq,
        }


class EdgeMemoryGate:
    """Edge gate with bitemporal memory risk context.

    ``gate`` is the underlying :class:`EdgeGate`; ``store`` is the
    :class:`BitemporalMemoryStore` holding past decision records.
    ``denial_threshold`` is how many current denial records for one action
    type it takes to escalate an ``"allow"`` to ``"require_human"``
    (default 1 — any past denial escalates).

    The store is owned by the caller: the gate only reads current records
    and appends history via :meth:`note_outcome` / :meth:`resolve`.
    """

    def __init__(
        self,
        gate: EdgeGate,
        store: BitemporalMemoryStore,
        *,
        denial_threshold: int = 1,
    ) -> None:
        if not isinstance(gate, EdgeGate):
            raise TypeError(f"gate must be an EdgeGate, got {type(gate).__name__}")
        if not isinstance(store, BitemporalMemoryStore):
            raise TypeError(
                f"store must be a BitemporalMemoryStore, got {type(store).__name__}"
            )
        if (
            isinstance(denial_threshold, bool)
            or not isinstance(denial_threshold, int)
            or denial_threshold < 1
        ):
            raise ValueError(
                f"denial_threshold must be a positive int, got {denial_threshold!r}"
            )
        self._gate = gate
        self._store = store
        self._threshold = denial_threshold

    @property
    def denial_threshold(self) -> int:
        return self._threshold

    def _denial_count(self, action_type: str) -> int:
        """Current denial records for one action type.

        Reads only live (current) records, so expired or superseded history
        does not escalate. Never raises.
        """
        count = 0
        try:
            records = self._store.get_current()
        except Exception:
            return 0
        for record in records:
            parsed = _DECISION_RE.match(record.content.strip())
            if parsed is None:
                continue
            if parsed.group(1) == action_type and parsed.group(2) in DENIAL_OUTCOMES:
                count += 1
        return count

    def check(
        self,
        action: Any,
        context: Mapping[str, Any] | None = None,
        *,
        seq: int = 0,
    ) -> str:
        """Memory-aware verdict. Never raises on any input."""
        return self.check_detailed(action, context, seq=seq).verdict

    def check_detailed(
        self,
        action: Any,
        context: Mapping[str, Any] | None = None,
        *,
        seq: int = 0,
    ) -> MemoryAwareDecision:
        """Same as :meth:`check` but returns the full decision record.

        Escalation is monotonic: only ``"allow"`` can move, and only to
        ``"require_human"``. Never raises.
        """
        base = self._gate.check_detailed(action, context, seq=seq)
        denials = (
            self._denial_count(base.action_type) if base.action_type else 0
        )
        verdict = base.verdict
        rule = base.rule
        if base.verdict == DECISION_ALLOW and denials >= self._threshold:
            verdict = DECISION_REQUIRE_HUMAN
            rule = RULE_MEMORY_ESCALATED
        return MemoryAwareDecision(
            verdict=verdict,
            base_verdict=base.verdict,
            risk=base.risk.value,
            action_type=base.action_type,
            rule=rule,
            memory_denials=denials,
            seq=seq,
        )

    def note_outcome(
        self,
        action: Mapping[str, Any],
        outcome: str,
        seq: int,
    ) -> MemoryRecord:
        """Record a gate outcome in memory for future checks to read.

        ``outcome`` is one of ``"allowed"``, ``"denied"``,
        ``"human_confirmed"``, ``"human_declined"``. Raises on malformed
        input — history is only as good as its writes, so writes are
        fail-closed.
        """
        if not isinstance(action, Mapping):
            raise TypeError(f"action must be a mapping, got {type(action).__name__}")
        raw = action.get("action_type", action.get("type", ""))
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError("action has no usable action_type")
        if outcome not in VALID_OUTCOMES:
            raise ValueError(f"outcome must be one of {sorted(VALID_OUTCOMES)}, got {outcome!r}")
        seq = _check_seq("seq", seq)
        action_type = raw.strip().lower()
        content = (
            f"{MARKER_PREFIX} action_type={action_type} outcome={outcome} seq={seq}"
        )
        return self._store.write(content, seq)

    def resolve(
        self,
        action: Mapping[str, Any],
        confirmation: HumanConfirmation,
        *,
        current_seq: int,
    ) -> str:
        """Apply a human confirmation; the outcome is noted in memory.

        Returns the inner gate's verdict (``"allow"`` or ``"deny"``) and
        records ``"human_confirmed"`` / ``"human_declined"`` so future
        checks see it. Never raises.
        """
        verdict = self._gate.resolve(action, confirmation, current_seq=current_seq)
        try:
            if isinstance(action, Mapping) and isinstance(
                confirmation, HumanConfirmation
            ):
                raw = action.get("action_type", action.get("type", ""))
                if isinstance(raw, str) and raw.strip():
                    outcome = (
                        "human_confirmed" if verdict == DECISION_ALLOW else "human_declined"
                    )
                    self.note_outcome(action, outcome, current_seq)
        except (TypeError, ValueError):
            pass
        return verdict


def main() -> None:
    """Self-check: base gate alone allows, memory escalates after a denial."""
    gate = EdgeGate(irreversible_allowlist=["newsletter.send"])
    store = BitemporalMemoryStore()
    combo = EdgeMemoryGate(gate, store)

    action = {"action_type": "newsletter.send"}
    first = combo.check_detailed(action, seq=1)
    assert first.verdict == "allow", first
    assert first.memory_denials == 0, first

    # A human declines once; memory now escalates the allowlisted action.
    combo.note_outcome(action, "human_declined", 2)
    second = combo.check_detailed(action, seq=3)
    assert second.verdict == "require_human", second
    assert second.rule == RULE_MEMORY_ESCALATED, second
    assert second.memory_denials == 1, second

    # Physical actions were already at max restrictiveness; memory adds nothing.
    physical = combo.check_detailed({"action_type": "robot.move_to"}, seq=4)
    assert physical.base_verdict == "require_human", physical
    assert physical.verdict == "require_human", physical

    # A different action type is unaffected.
    other = combo.check_detailed({"action_type": "db.query"}, seq=5)
    assert other.verdict == "allow", other

    print("edge-memory-combo OK: allow -> declined -> escalated; unrelated actions untouched")


if __name__ == "__main__":
    main()
