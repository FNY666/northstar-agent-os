"""Memory write admission with consent (cookie-analog).

The memory research frames conversational memory as the "next-generation
cookie": durable, personal, and silently accumulated. A cookie regime has
four answers -- consent, retention duration, prohibited inferences, and
the right to correct/delete. This module is Northstar's cookie-analog
answer for the memory write path:

1. **Consent** -- a write is admitted only under a granted, unrevoked,
   unexpired ``MemoryConsent`` whose scope covers the write's category.
   No consent, no memory. Consent is granted per category, never
   blanket.
2. **Retention duration** -- every grant carries ``retention_days`` and
   a sequence-stamped ``granted_at`` (no wall-clock: sequence ticks are
   caller-supplied integers, like the rest of the runtime). Writes under
   an expired grant are refused; :func:`check_retention` is the public
   expiry predicate.
3. **Prohibited inferences** -- ``health``, ``political`` and
   ``sexual`` are off-limits inference categories. Writes attempting
   them are denied even with consent in hand. ``credential`` is always
   denied: secrets do not belong in memory, and consent cannot grant
   what the gate never admits.
4. **Correction / deletion** -- consent is revocable. Revocation is
   immediate and total: every later ``admit_write`` under the revoked
   grant is denied. (Physical deletion of already-stored records is
   the store's job; this gate guarantees nothing new is admitted.)

Admission runs at write time, fail-closed, in a fixed rule order; the
first failing rule names the denial reason. Every decision is recorded
in the admission's decision log so a later audit can show *why* a write
was refused.

Hard doctrine: memory is the future prompt. A write the gate admits
today is re-injected into the model's context on every future recall,
so the write path is the only choke point that matters. Consent that
cannot be checked (no sequence number to evaluate retention against)
is consent denied.

Honest scope: corpus + gates, not a defense. The gate runs on
host-reported categories and consent objects; a deployment that
miscategorizes a write (labels a health inference as a "fact") has
already lost, and no gate here can detect the lie. Retention is
measured in caller-supplied sequence ticks, not wall-clock days --
the host owns the ticking.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: Semantic version of the memory-admission-with-consent contract.
#: Bump when the category vocabulary, the rule order, or the consent
#: schema change.
MEMORY_CONSENT_VERSION = "memory-consent.v1"

#: Schema pin carried by consent records.
SCHEMA_PIN = "northstar.memory-consent.v1"

#: Categories the gate may admit under a valid, in-scope consent.
CATEGORY_PREFERENCE = "preference"
CATEGORY_FACT = "fact"
CATEGORY_CONVERSATION = "conversation"

ADMITTABLE_CATEGORIES: tuple[str, ...] = (
    CATEGORY_PREFERENCE,
    CATEGORY_FACT,
    CATEGORY_CONVERSATION,
)

#: Category that is always denied. Secrets do not belong in memory;
#: consent cannot grant what the gate never admits.
CATEGORY_CREDENTIAL = "credential"

#: Off-limits inference categories (the cookie-analog "prohibited
#: inferences"). Writes attempting these are denied even with consent.
PROHIBITED_INFERENCES: tuple[str, ...] = ("health", "political", "sexual")

#: Every category the gate recognizes, admittable or not.
KNOWN_CATEGORIES: tuple[str, ...] = (
    ADMITTABLE_CATEGORIES + (CATEGORY_CREDENTIAL,) + PROHIBITED_INFERENCES
)


class MemoryAdmissionError(ValueError):
    """A consent object or admission step failed validation. Raised, never silent."""


def _require_non_empty_str(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MemoryAdmissionError(f"{name} must be a non-empty string")
    return value


def _require_seq(name: str, value: Any) -> int:
    # bool is an int subclass; reject it explicitly.
    if isinstance(value, bool) or not isinstance(value, int):
        raise MemoryAdmissionError(f"{name} must be an integer sequence number")
    if value < 0:
        raise MemoryAdmissionError(f"{name} must be >= 0")
    return value


def check_retention(granted_at: int, retention_days: int, current_seq: int) -> bool:
    """Return True when a consent grant is expired at ``current_seq``.

    A grant is expired when ``current_seq - granted_at >= retention_days``.
    A ``current_seq`` older than ``granted_at`` is a sequence anomaly and
    is treated as expired (fail closed -- a grant from the future cannot
    be trusted). Raises :class:`MemoryAdmissionError` on malformed input.
    """
    granted_at = _require_seq("granted_at", granted_at)
    if isinstance(retention_days, bool) or not isinstance(retention_days, int):
        raise MemoryAdmissionError("retention_days must be an integer")
    if retention_days <= 0:
        raise MemoryAdmissionError("retention_days must be positive")
    current_seq = _require_seq("current_seq", current_seq)
    if current_seq < granted_at:
        return True
    return (current_seq - granted_at) >= retention_days


@dataclass(frozen=True)
class MemoryConsent:
    """A revocable, scoped, expiring grant to write to memory.

    ``scope`` names the categories this grant covers (subset of the
    admittable categories; ``credential`` and the prohibited inferences
    can never appear here -- construction raises). ``retention_days``
    bounds the grant's life in sequence ticks. ``granted_at`` is the
    caller-supplied sequence number of the grant (no wall-clock).
    ``revoked`` flips the grant off immediately and totally.
    """

    scope: tuple[str, ...]
    retention_days: int
    granted_at: int
    revoked: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.scope, tuple) or not self.scope:
            raise MemoryAdmissionError("scope must be a non-empty tuple of categories")
        for category in self.scope:
            _require_non_empty_str("scope entry", category)
            if category == CATEGORY_CREDENTIAL:
                raise MemoryAdmissionError(
                    "consent can never cover 'credential': secrets do not belong in memory"
                )
            if category in PROHIBITED_INFERENCES:
                raise MemoryAdmissionError(
                    f"consent can never cover prohibited inference {category!r}"
                )
            if category not in ADMITTABLE_CATEGORIES:
                raise MemoryAdmissionError(f"unknown category in scope: {category!r}")
        if isinstance(self.retention_days, bool) or not isinstance(
            self.retention_days, int
        ):
            raise MemoryAdmissionError("retention_days must be an integer")
        if self.retention_days <= 0:
            raise MemoryAdmissionError("retention_days must be positive")
        _require_seq("granted_at", self.granted_at)
        if not isinstance(self.revoked, bool):
            raise MemoryAdmissionError("revoked must be a bool")

    def expired(self, current_seq: int) -> bool:
        """True when this grant is expired at ``current_seq``."""
        return check_retention(self.granted_at, self.retention_days, current_seq)

    def covers(self, category: str) -> bool:
        """True when ``category`` is inside this grant's scope."""
        return category in self.scope

    def revoke(self) -> "MemoryConsent":
        """Return a revoked copy of this grant (the original is frozen)."""
        return MemoryConsent(
            scope=self.scope,
            retention_days=self.retention_days,
            granted_at=self.granted_at,
            revoked=True,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "scope": list(self.scope),
            "retention_days": self.retention_days,
            "granted_at": self.granted_at,
            "revoked": self.revoked,
        }


@dataclass(frozen=True)
class AdmissionDecision:
    """One recorded write-admission verdict."""

    category: str
    allowed: bool
    reason: str
    seq: int | None

    def __post_init__(self) -> None:
        _require_non_empty_str("category", self.category)
        if not isinstance(self.allowed, bool):
            raise MemoryAdmissionError("allowed must be a bool")
        _require_non_empty_str("reason", self.reason)
        if self.seq is not None:
            _require_seq("seq", self.seq)

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "allowed": self.allowed,
            "reason": self.reason,
            "seq": self.seq,
        }


#: Denial reasons, in the order the rules are evaluated. The first
#: failing rule wins; the vocabulary is fixed so audits stay comparable.
REASON_MALFORMED_CATEGORY = "malformed-category"
REASON_UNKNOWN_CATEGORY = "unknown-category"
REASON_CREDENTIAL_NEVER_ADMITTED = "credential-never-admitted"
REASON_PROHIBITED_INFERENCE = "prohibited-inference"
REASON_NO_CONSENT = "no-consent"
REASON_MALFORMED_CONSENT = "malformed-consent"
REASON_CONSENT_REVOKED = "consent-revoked"
REASON_RETENTION_UNVERIFIABLE = "retention-unverifiable"
REASON_CONSENT_EXPIRED = "consent-expired"
REASON_OUTSIDE_CONSENT_SCOPE = "outside-consent-scope"
REASON_MALFORMED_CONTENT = "malformed-content"
REASON_ADMITTED = "admitted"


class MemoryAdmission:
    """Write-time memory admission under consent. Fail-closed.

    ``admit_write`` evaluates the fixed rule order and returns True only
    when every rule passes. Every verdict is appended to the decision
    log. An optional default consent can be installed with
    :meth:`set_consent`; an explicitly passed consent always wins over
    the default.
    """

    def __init__(self, consent: MemoryConsent | None = None) -> None:
        if consent is not None and not isinstance(consent, MemoryConsent):
            raise MemoryAdmissionError("consent must be a MemoryConsent or None")
        self._consent = consent
        self._decisions: list[AdmissionDecision] = []

    def set_consent(self, consent: MemoryConsent | None) -> None:
        """Install (or clear) the default consent used by ``admit_write``."""
        if consent is not None and not isinstance(consent, MemoryConsent):
            raise MemoryAdmissionError("consent must be a MemoryConsent or None")
        self._consent = consent

    def revoke_consent(self) -> MemoryConsent | None:
        """Revoke the default consent in place and return the revoked grant.

        Revocation is immediate and total: every later ``admit_write``
        under this grant is denied. Returns None when no default
        consent is installed.
        """
        if self._consent is None:
            return None
        revoked = self._consent.revoke()
        self._consent = revoked
        return revoked

    def decisions(self) -> tuple[AdmissionDecision, ...]:
        """The recorded verdicts, oldest first."""
        return tuple(self._decisions)

    def denied(self) -> tuple[AdmissionDecision, ...]:
        """The recorded denials, oldest first."""
        return tuple(d for d in self._decisions if not d.allowed)

    def _record(
        self, category: str, allowed: bool, reason: str, seq: int | None
    ) -> bool:
        # The decision log must never raise: normalize malformed inputs
        # into recordable labels so the denial itself is auditable.
        if isinstance(category, str) and category.strip():
            label = category
        else:
            label = "<malformed>"
        if (
            seq is None
            or isinstance(seq, bool)
            or not isinstance(seq, int)
            or seq < 0
        ):
            seq = None
        self._decisions.append(
            AdmissionDecision(
                category=label, allowed=allowed, reason=reason, seq=seq
            )
        )
        return allowed

    def admit_write(
        self,
        category: Any,
        content: Any,
        consent: MemoryConsent | None = None,
        current_seq: int | None = None,
    ) -> bool:
        """Admit (True) or refuse (False) a memory write. Fail-closed.

        Rules, in fixed order -- the first failing rule names the
        denial reason:

        1. ``category`` must be a non-empty string.
        2. ``category`` must be a known category.
        3. ``credential`` is always denied.
        4. Prohibited inferences (``health``, ``political``,
           ``sexual``) are denied even with consent.
        5. A consent must be present (explicit argument wins over the
           default installed via :meth:`set_consent`).
        6. The consent must be a well-formed ``MemoryConsent``.
        7. The consent must not be revoked.
        8. ``current_seq`` must be a usable sequence number -- retention
           that cannot be evaluated is retention denied.
        9. The consent must not be expired at ``current_seq``.
        10. ``category`` must be inside the consent's scope.
        11. ``content`` must be a non-empty string.
        """
        grant = consent if consent is not None else self._consent

        if not isinstance(category, str) or not category.strip():
            return self._record(category, False, REASON_MALFORMED_CATEGORY, current_seq)
        if category not in KNOWN_CATEGORIES:
            return self._record(category, False, REASON_UNKNOWN_CATEGORY, current_seq)
        if category == CATEGORY_CREDENTIAL:
            return self._record(
                category, False, REASON_CREDENTIAL_NEVER_ADMITTED, current_seq
            )
        if category in PROHIBITED_INFERENCES:
            return self._record(
                category, False, REASON_PROHIBITED_INFERENCE, current_seq
            )
        if grant is None:
            return self._record(category, False, REASON_NO_CONSENT, current_seq)
        if not isinstance(grant, MemoryConsent):
            return self._record(category, False, REASON_MALFORMED_CONSENT, current_seq)
        if grant.revoked:
            return self._record(category, False, REASON_CONSENT_REVOKED, current_seq)
        if (
            current_seq is None
            or isinstance(current_seq, bool)
            or not isinstance(current_seq, int)
            or current_seq < 0
        ):
            return self._record(
                category, False, REASON_RETENTION_UNVERIFIABLE, current_seq
            )
        if grant.expired(current_seq):
            return self._record(category, False, REASON_CONSENT_EXPIRED, current_seq)
        if not grant.covers(category):
            return self._record(
                category, False, REASON_OUTSIDE_CONSENT_SCOPE, current_seq
            )
        if not isinstance(content, str) or not content.strip():
            return self._record(category, False, REASON_MALFORMED_CONTENT, current_seq)
        return self._record(category, True, REASON_ADMITTED, current_seq)


__all__ = [
    "MEMORY_CONSENT_VERSION",
    "SCHEMA_PIN",
    "CATEGORY_PREFERENCE",
    "CATEGORY_FACT",
    "CATEGORY_CONVERSATION",
    "CATEGORY_CREDENTIAL",
    "ADMITTABLE_CATEGORIES",
    "PROHIBITED_INFERENCES",
    "KNOWN_CATEGORIES",
    "MemoryAdmissionError",
    "check_retention",
    "MemoryConsent",
    "AdmissionDecision",
    "MemoryAdmission",
    "REASON_MALFORMED_CATEGORY",
    "REASON_UNKNOWN_CATEGORY",
    "REASON_CREDENTIAL_NEVER_ADMITTED",
    "REASON_PROHIBITED_INFERENCE",
    "REASON_NO_CONSENT",
    "REASON_MALFORMED_CONSENT",
    "REASON_CONSENT_REVOKED",
    "REASON_RETENTION_UNVERIFIABLE",
    "REASON_CONSENT_EXPIRED",
    "REASON_OUTSIDE_CONSENT_SCOPE",
    "REASON_MALFORMED_CONTENT",
    "REASON_ADMITTED",
]


def main() -> None:
    grant = MemoryConsent(
        scope=("preference", "fact", "conversation"),
        retention_days=30,
        granted_at=100,
    )
    gate = MemoryAdmission(grant)
    cases = [
        ("preference", "likes dark mode", 110, True),
        ("credential", "api-key-123", 110, False),
        ("health", "user seems anxious", 110, False),
        ("political", "user leans left", 110, False),
        ("sexual", "user orientation", 110, False),
        ("fact", "project deadline Friday", 200, False),  # expired grant
    ]
    for category, content, seq, expected in cases:
        got = gate.admit_write(category, content, current_seq=seq)
        status = "ok" if got == expected else "MISMATCH"
        print(f"[{status}] {category}: admitted={got} (expected {expected})")
    print(f"decisions recorded: {len(gate.decisions())}")


if __name__ == "__main__":
    main()
