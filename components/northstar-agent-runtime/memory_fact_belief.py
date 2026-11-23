"""Fact/belief distinction with privilege-at-recall (P0 memory wiring).

Not all memory is equal:

* **FACT** — verifiable, e.g. "the user's name is X". Facts are pinned at
  confidence ``1.0``: a fact is asserted, not estimated. Anything with
  confidence ``!= 1.0`` is not a fact and the constructor rejects it.
* **BELIEF** — inferred, e.g. "the user probably likes Y". Beliefs carry a
  confidence in ``[0.0, 1.0]``. A belief with confidence below
  ``BELIEF_RECALL_THRESHOLD`` (0.7) is *never* recalled, regardless of the
  reader's privilege: it is too uncertain to act on or to surface.

**Privilege-at-recall**: the reader's privilege determines what they can
see. ``PrivilegeLevel`` is ordered ``PUBLIC < PRIVATE < SECRET``. Recall
requires ``reader_privilege >= entry.privilege``. Beliefs additionally
require the confidence threshold. Privilege is re-checked on *every*
recall — a reader who was authorized yesterday is not authorized today
unless their current privilege still covers the entry.

Honest scope: this module decides *whether* a memory entry may be
surfaced to a given reader. It does not verify that facts are true
(truth verification belongs to the write-path admission gate), does not
audit recalls (recall logging belongs to the audit chain), and does not
manage consent lifecycle (see the memory admission gate). It runs on
host-reported reader privileges: if the host lies about privilege, the
decision is only as good as that claim.

Everything here is deterministic. No wall-clock, no model calls.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Any

#: Schema version pin for this module's decision semantics.
MEMORY_FACT_BELIEF_VERSION = "memory-fact-belief.v1"

#: Schema pin stamped into any record that crosses a trust boundary.
SCHEMA_PIN = "northstar.memory-fact-belief.v1"

#: Beliefs below this confidence are never recalled, at any privilege.
BELIEF_RECALL_THRESHOLD = 0.7

#: Confidence pinned on facts: facts are asserted, not estimated.
FACT_CONFIDENCE = 1.0


class MemoryType(Enum):
    """Whether a memory entry is a verifiable fact or an inference."""

    FACT = "fact"
    BELIEF = "belief"


class PrivilegeLevel(IntEnum):
    """Reader/entry privilege, ordered low to high.

    The ordering is what ``recall`` compares: ``PUBLIC < PRIVATE <
    SECRET``. Higher values see everything at or below their level.
    """

    PUBLIC = 1
    PRIVATE = 2
    SECRET = 3


def _validate_confidence(mem_type: MemoryType, confidence: Any) -> float:
    """Validate confidence per memory type. Raises on malformed input."""
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise TypeError("confidence must be a number")
    confidence = float(confidence)
    if math.isnan(confidence) or math.isinf(confidence):
        raise ValueError("confidence must be a finite number")
    if mem_type is MemoryType.FACT:
        if confidence != FACT_CONFIDENCE:
            raise ValueError("FACT confidence must be exactly 1.0")
    else:
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("BELIEF confidence must be in [0.0, 1.0]")
    return confidence


@dataclass(frozen=True)
class MemoryEntry:
    """A single memory entry with type, confidence, source, and privilege.

    Invariants (enforced at construction):

    * ``content`` and ``source`` are non-empty strings.
    * FACTs carry confidence exactly ``1.0``.
    * BELIEFs carry confidence in ``[0.0, 1.0]``.
    * ``privilege`` is a ``PrivilegeLevel``.
    """

    content: str
    type: MemoryType
    confidence: float
    source: str
    privilege: PrivilegeLevel

    def __post_init__(self) -> None:
        if not isinstance(self.content, str) or not self.content:
            raise ValueError("content must be a non-empty string")
        if not isinstance(self.source, str) or not self.source:
            raise ValueError("source must be a non-empty string")
        if not isinstance(self.type, MemoryType):
            raise TypeError("type must be a MemoryType")
        if not isinstance(self.privilege, PrivilegeLevel):
            raise TypeError("privilege must be a PrivilegeLevel")
        object.__setattr__(
            self, "confidence", _validate_confidence(self.type, self.confidence)
        )

    def is_belief_below_threshold(self) -> bool:
        """True when this belief is too uncertain to ever recall."""
        return (
            self.type is MemoryType.BELIEF
            and self.confidence < BELIEF_RECALL_THRESHOLD
        )


def recall(entry: MemoryEntry, reader_privilege: PrivilegeLevel) -> bool:
    """Decide whether ``entry`` may be surfaced to a reader.

    Fail-closed rules, in order:

    1. Malformed reader privilege -> ``TypeError`` (programming error, not
       a policy decision).
    2. ``reader_privilege < entry.privilege`` -> denied.
    3. BELIEF with confidence ``< 0.7`` -> denied, at any privilege.
    4. Otherwise -> allowed.

    Never raises on well-formed input: it returns ``False``, never throws,
    for policy denials.
    """
    if not isinstance(entry, MemoryEntry):
        raise TypeError("entry must be a MemoryEntry")
    if not isinstance(reader_privilege, PrivilegeLevel):
        raise TypeError("reader_privilege must be a PrivilegeLevel")
    if reader_privilege < entry.privilege:
        return False
    if entry.is_belief_below_threshold():
        return False
    return True


def main() -> None:
    """Self-check smoke: exercise recall across the decision matrix."""
    fact = MemoryEntry(
        content="user's name is X",
        type=MemoryType.FACT,
        confidence=1.0,
        source="onboarding",
        privilege=PrivilegeLevel.PRIVATE,
    )
    belief_strong = MemoryEntry(
        content="user probably likes Y",
        type=MemoryType.BELIEF,
        confidence=0.8,
        source="inference",
        privilege=PrivilegeLevel.PUBLIC,
    )
    belief_weak = MemoryEntry(
        content="user might like Z",
        type=MemoryType.BELIEF,
        confidence=0.5,
        source="inference",
        privilege=PrivilegeLevel.PUBLIC,
    )
    assert recall(fact, PrivilegeLevel.PRIVATE) is True
    assert recall(fact, PrivilegeLevel.PUBLIC) is False
    assert recall(belief_strong, PrivilegeLevel.PUBLIC) is True
    assert recall(belief_weak, PrivilegeLevel.SECRET) is False
    print("memory-fact-belief OK: fact/belief + privilege-at-recall")


if __name__ == "__main__":
    main()
