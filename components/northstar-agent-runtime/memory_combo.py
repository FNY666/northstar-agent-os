"""Memory combo gate: consent OR capability admission + fact/belief + bitemporal store.

Integration layer over the four standalone memory modules:

* :mod:`memory_admission` -- consent-based write admission (the
  cookie-analog: consent, retention, prohibited inferences, revocation).
* :mod:`memory_capability` -- capability-token write admission (issuer
  signs category-scoped, expiring tokens; no per-user state).
* :mod:`memory_fact_belief` -- fact vs belief typing with confidence
  invariants and privilege-at-recall.
* :mod:`memory_bitemporal` -- bitemporal store (valid time + transaction
  time, supersession, decay).

The combo gate wires them into one write path and one read path:

* **Write**: admission runs first (consent *or* capability -- the auth
  object selects which gate; a write is admitted if its matching gate
  admits), then the fact/belief entry invariants are enforced, then the
  record lands in the bitemporal store. First failure wins, fail-closed.
* **Read**: the stored record's fact/belief metadata is checked against
  the reader's privilege (privilege-at-recall); beliefs below the
  recall threshold are never surfaced, at any privilege. Unknown ids
  are denied. A successful read refreshes the record's decay clock.

Hard doctrine: admission decides *whether* a write may exist;
fact/belief decides *what kind of claim* it is; privilege decides
*who may see it*. None of the three substitutes for another -- a
consented write can still be a low-confidence belief, and a fact can
still be too privileged for the reader. The gates compose in fixed
order and each keeps its own decision log; the combo gate adds a
summary log of its own.

Honest scope: corpus + gates, not a defense. Every sub-gate runs on
host-reported categories, consent objects, tokens, and privilege
claims; a deployment that lies about any of them has already lost.
The store is in-memory -- cross-restart durability is the host's job
(see ``audit_chain.DurableAuditWriter`` for the durability pattern).

No wall-clock anywhere: all time is caller-supplied integer sequence
numbers, matching the rest of the runtime.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Union

import memory_admission as consent_mod
import memory_bitemporal as bitemporal_mod
import memory_capability as cap_mod
import memory_fact_belief as fb_mod

#: Version of the combo contract described here. Bump when the gate
#: order, the reason vocabulary, or the auth shapes change.
MEMORY_COMBO_VERSION = "memory-combo.v1"

#: Schema pin for records crossing a trust boundary.
SCHEMA_PIN = "northstar.memory-combo.v1"

#: The two auth shapes the write path accepts.
AuthShape = Union["consent_mod.MemoryConsent", "cap_mod.CapabilityToken"]

#: Fixed reason vocabulary for combo-level decisions.
REASON_WRITE_ADMITTED_CONSENT = "write-admitted-consent"
REASON_WRITE_ADMITTED_CAPABILITY = "write-admitted-capability"
REASON_WRITE_DENIED_NO_CONSENT_GATE = "write-denied-no-consent-gate"
REASON_WRITE_DENIED_NO_CAPABILITY_GATE = "write-denied-no-capability-gate"
REASON_WRITE_DENIED_CONSENT = "write-denied-consent"
REASON_WRITE_DENIED_CAPABILITY = "write-denied-capability"
REASON_WRITE_DENIED_MALFORMED_AUTH = "write-denied-malformed-auth"
REASON_WRITE_DENIED_FACT_BELIEF = "write-denied-fact-belief"
REASON_WRITE_DENIED_STORE = "write-denied-store"
REASON_READ_ALLOWED = "read-allowed"
REASON_READ_DENIED_UNKNOWN = "read-denied-unknown"
REASON_READ_DENIED_PRIVILEGE = "read-denied-privilege"
REASON_READ_DENIED_BELIEF_THRESHOLD = "read-denied-belief-threshold"
REASON_READ_DENIED_STORE = "read-denied-store"
REASON_READ_MALFORMED = "read-malformed"


class ComboError(ValueError):
    """The combo gate was misconfigured. Raised, never silent."""


@dataclass(frozen=True)
class ComboDecision:
    """One combo-level write/read verdict, for the audit trail."""

    action: str  # "write" | "read"
    record_id: Optional[str]
    allowed: bool
    reason: str
    seq: Optional[int]


class MemoryGate:
    """One write path and one read path over the four memory modules.

    ``consent_admission`` and ``capability_admission`` are the sub-gates;
    at least one must be configured. The auth object on each write
    selects which gate runs: a :class:`MemoryConsent` runs the consent
    gate, a :class:`CapabilityToken` runs the capability gate. A write
    is admitted when its matching gate admits -- consent and capability
    are alternatives, not requirements in series.
    """

    def __init__(
        self,
        *,
        consent_admission: consent_mod.MemoryAdmission | None = None,
        capability_admission: cap_mod.CapabilityAdmission | None = None,
        store: bitemporal_mod.BitemporalMemoryStore | None = None,
    ) -> None:
        if consent_admission is None and capability_admission is None:
            raise ComboError("at least one admission gate is required")
        if consent_admission is not None and not isinstance(
            consent_admission, consent_mod.MemoryAdmission
        ):
            raise ComboError("consent_admission must be a MemoryAdmission")
        if capability_admission is not None and not isinstance(
            capability_admission, cap_mod.CapabilityAdmission
        ):
            raise ComboError("capability_admission must be a CapabilityAdmission")
        if store is not None and not isinstance(
            store, bitemporal_mod.BitemporalMemoryStore
        ):
            raise ComboError("store must be a BitemporalMemoryStore")
        self._consent_admission = consent_admission
        self._capability_admission = capability_admission
        self._store = store if store is not None else bitemporal_mod.BitemporalMemoryStore()
        # Fact/belief metadata lives beside the bitemporal record, keyed
        # by record id. The bitemporal store only carries content + time.
        self._meta: dict[str, fb_mod.MemoryEntry] = {}
        self._decisions: list[ComboDecision] = []

    def __len__(self) -> int:
        return len(self._store)

    def _record(
        self,
        action: str,
        record_id: Any,
        allowed: bool,
        reason: str,
        seq: Any,
    ) -> None:
        self._decisions.append(
            ComboDecision(
                action=action,
                record_id=record_id if isinstance(record_id, str) else None,
                allowed=allowed,
                reason=reason,
                seq=seq if isinstance(seq, int) and not isinstance(seq, bool) else None,
            )
        )

    def decisions(self) -> tuple[ComboDecision, ...]:
        """All combo-level verdicts, in order."""
        return tuple(self._decisions)

    def denied(self) -> tuple[ComboDecision, ...]:
        """Only the denials, in order."""
        return tuple(d for d in self._decisions if not d.allowed)

    def _admission_check(
        self, category: Any, content: Any, auth: Any, seq: Any
    ) -> tuple[bool, str]:
        """Run the gate matching ``auth``. Returns (admitted, reason)."""
        if isinstance(auth, consent_mod.MemoryConsent):
            gate = self._consent_admission
            if gate is None:
                return False, REASON_WRITE_DENIED_NO_CONSENT_GATE
            ok = gate.admit_write(
                category, content, consent=auth, current_seq=seq
            )
            return ok, (
                REASON_WRITE_ADMITTED_CONSENT if ok else REASON_WRITE_DENIED_CONSENT
            )
        if isinstance(auth, cap_mod.CapabilityToken):
            gate = self._capability_admission
            if gate is None:
                return False, REASON_WRITE_DENIED_NO_CAPABILITY_GATE
            ok = gate.admit_write(category, content, auth, seq)
            return ok, (
                REASON_WRITE_ADMITTED_CAPABILITY
                if ok
                else REASON_WRITE_DENIED_CAPABILITY
            )
        return False, REASON_WRITE_DENIED_MALFORMED_AUTH

    def write(
        self,
        content: Any,
        category: Any,
        auth: Any,
        seq: Any,
        *,
        mem_type: fb_mod.MemoryType = fb_mod.MemoryType.FACT,
        confidence: float = 1.0,
        source: str = "memory-combo",
        privilege: fb_mod.PrivilegeLevel = fb_mod.PrivilegeLevel.PRIVATE,
    ) -> bitemporal_mod.MemoryRecord | None:
        """Write one memory record through admission + typing + store.

        Returns the stored :class:`MemoryRecord` on success, ``None``
        on any denial (fail-closed). Gate order: admission, then
        fact/belief invariants, then the bitemporal store.
        """
        admitted, reason = self._admission_check(category, content, auth, seq)
        if not admitted:
            self._record("write", None, False, reason, seq)
            return None
        try:
            entry = fb_mod.MemoryEntry(
                content=content,
                type=mem_type,
                confidence=confidence,
                source=source,
                privilege=privilege,
            )
        except (TypeError, ValueError):
            self._record("write", None, False, REASON_WRITE_DENIED_FACT_BELIEF, seq)
            return None
        try:
            record = self._store.write(content, seq)
        except (TypeError, ValueError):
            self._record("write", None, False, REASON_WRITE_DENIED_STORE, seq)
            return None
        self._meta[record.id] = entry
        self._record("write", record.id, True, reason, seq)
        return record

    def read(
        self,
        record_id: Any,
        reader_privilege: Any,
        seq: Any,
    ) -> bitemporal_mod.MemoryRecord | None:
        """Read one record with privilege-at-recall.

        Returns the :class:`MemoryRecord` when the reader's privilege
        covers the entry and the entry is recallable; ``None`` otherwise
        (unknown id, insufficient privilege, sub-threshold belief --
        all fail closed). A successful read refreshes the record's
        decay clock via :meth:`BitemporalMemoryStore.access`.
        """
        if (
            not isinstance(record_id, str)
            or not record_id
            or not isinstance(reader_privilege, fb_mod.PrivilegeLevel)
        ):
            self._record("read", record_id, False, REASON_READ_MALFORMED, seq)
            return None
        try:
            record = self._store.get(record_id)
        except bitemporal_mod.MemoryNotFoundError:
            self._record("read", record_id, False, REASON_READ_DENIED_UNKNOWN, seq)
            return None
        entry = self._meta.get(record_id)
        if entry is None:
            # Record exists in the store but has no combo metadata --
            # fail closed rather than guess at its privilege.
            self._record("read", record_id, False, REASON_READ_DENIED_UNKNOWN, seq)
            return None
        if not fb_mod.recall(entry, reader_privilege):
            reason = (
                REASON_READ_DENIED_BELIEF_THRESHOLD
                if entry.is_belief_below_threshold()
                else REASON_READ_DENIED_PRIVILEGE
            )
            self._record("read", record_id, False, reason, seq)
            return None
        try:
            self._store.access(record_id, seq)
        except (TypeError, ValueError, bitemporal_mod.MemoryNotFoundError):
            self._record("read", record_id, False, REASON_READ_DENIED_STORE, seq)
            return None
        self._record("read", record_id, True, REASON_READ_ALLOWED, seq)
        return record


__all__ = [
    "MEMORY_COMBO_VERSION",
    "SCHEMA_PIN",
    "ComboError",
    "ComboDecision",
    "MemoryGate",
    "REASON_WRITE_ADMITTED_CONSENT",
    "REASON_WRITE_ADMITTED_CAPABILITY",
    "REASON_WRITE_DENIED_NO_CONSENT_GATE",
    "REASON_WRITE_DENIED_NO_CAPABILITY_GATE",
    "REASON_WRITE_DENIED_CONSENT",
    "REASON_WRITE_DENIED_CAPABILITY",
    "REASON_WRITE_DENIED_MALFORMED_AUTH",
    "REASON_WRITE_DENIED_FACT_BELIEF",
    "REASON_WRITE_DENIED_STORE",
    "REASON_READ_ALLOWED",
    "REASON_READ_DENIED_UNKNOWN",
    "REASON_READ_DENIED_PRIVILEGE",
    "REASON_READ_DENIED_BELIEF_THRESHOLD",
    "REASON_READ_DENIED_STORE",
    "REASON_READ_MALFORMED",
]


def main() -> None:
    import hashlib

    import ed25519

    consent = consent_mod.MemoryConsent(
        scope=("preference", "fact"), retention_days=30, granted_at=100
    )
    seed = hashlib.sha256(b"memory-combo self-check").digest()
    token = cap_mod.issue_token({"preference", "fact"}, 200, seed)
    gate = MemoryGate(
        consent_admission=consent_mod.MemoryAdmission(),
        capability_admission=cap_mod.CapabilityAdmission(ed25519.public_key(seed)),
    )
    r1 = gate.write("likes tea", "preference", consent, 110)
    assert r1 is not None
    r2 = gate.write(
        "shipped v2",
        "fact",
        token,
        110,
        mem_type=fb_mod.MemoryType.BELIEF,
        confidence=0.9,
        privilege=fb_mod.PrivilegeLevel.PUBLIC,
    )
    assert r2 is not None
    assert gate.write("sk-123", "credential", consent, 110) is None
    assert gate.write("likes tea", "preference", {"fake": 1}, 110) is None
    assert gate.read(r1.id, fb_mod.PrivilegeLevel.PRIVATE, 120) is not None
    assert gate.read(r1.id, fb_mod.PrivilegeLevel.PUBLIC, 120) is None
    r3 = gate.write(
        "maybe likes tea",
        "preference",
        consent,
        110,
        mem_type=fb_mod.MemoryType.BELIEF,
        confidence=0.5,
        privilege=fb_mod.PrivilegeLevel.PUBLIC,
    )
    assert r3 is not None  # admitted at write; recall refuses it
    assert gate.read(r3.id, fb_mod.PrivilegeLevel.SECRET, 120) is None
    assert gate.read("mem-nope", fb_mod.PrivilegeLevel.SECRET, 120) is None
    print(
        f"memory-combo OK: {len(gate)} records, "
        f"{len(gate.denied())} denials, version {MEMORY_COMBO_VERSION}"
    )


if __name__ == "__main__":
    main()
