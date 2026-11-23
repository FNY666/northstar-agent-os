"""Identity disclosure for user-facing agent flows.

When an agent talks to a human — chat, email, voice, SMS, social — the
counterparty is owed to know they are talking to an AI agent, who operates
it, what it can do, and what it cannot. This module is the enforcement
side of that duty:

* **context rule** (:func:`must_disclose`): user-facing channels require
  disclosure. Unknown channels fail closed toward disclosure — a channel
  the policy author never named is treated as user-facing, never as
  internal.
* **deployment policy** (:class:`DisclosureRequirement`): ALWAYS /
  ON_REQUEST / NEVER, decided per agent or per flow by the host.
* **combined decision** (:func:`disclosure_decision`): the context rule is
  a floor, not a suggestion — a user-facing channel discloses even under
  a NEVER policy. Fail-closed toward disclosure.
* **identity card** (:class:`IdentityCard`): the disclosable facts —
  agent name, operator, capability summary, limitations.
* **disclosure log** (:class:`DisclosureLog`): append-only, hash-chained
  record of every disclosure made, so "we told the user" is itself
  auditable.

Honest scope: this module decides *when* to disclose and *what* the
disclosure says, and records that it happened. It does not render UI,
does not intercept model output, and does not prove the human read or
understood the disclosure — delivery is the host's job. A disclosure log
entry proves a disclosure string was produced for a context, not that a
human saw it.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping


#: Wire version of the disclosure record format.
DISCLOSURE_VERSION = "northstar.identity-disclosure/1"

#: Zero digest: the ``prev_digest`` of the first log record.
_ZERO_DIGEST = "0" * 64


class DisclosureError(Exception):
    """Raised when a disclosure artifact cannot be built (caller bug)."""


class DisclosureRequirement(Enum):
    """Deployment policy for identity disclosure, per agent or per flow."""

    ALWAYS = "always"
    ON_REQUEST = "on_request"
    NEVER = "never"


def _canonical(obj: Any) -> bytes:
    """Canonical bytes for digesting: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


#: Channels where the counterparty is a human. Disclosure is mandatory.
_USER_FACING_CHANNELS = frozenset({
    "chat",
    "email",
    "voice",
    "phone",
    "sms",
    "social",
    "messaging",
    "video",
})


def must_disclose(context: str) -> bool:
    """Return True when ``context`` is user-facing and disclosure is required.

    Known user-facing channels (chat, email, voice, phone, sms, social,
    messaging, video) return True. Anything else — including channels the
    policy author never named — fails closed toward disclosure (True).
    Only the explicitly internal channels ``api``, ``internal``,
    ``batch``, and ``system`` return False.
    """
    if not isinstance(context, str):
        return True
    name = context.strip().lower()
    if name in _USER_FACING_CHANNELS:
        return True
    if name in ("api", "internal", "batch", "system"):
        return False
    # Unknown channel: fail closed toward disclosure.
    return True


def disclosure_decision(
    requirement: DisclosureRequirement,
    context: str,
    *,
    on_request: bool = False,
) -> bool:
    """Combine deployment policy with the context rule into one decision.

    The context rule is a floor: a user-facing channel discloses even
    under a NEVER policy. Otherwise ALWAYS discloses, ON_REQUEST discloses
    only when the counterparty asked, and NEVER stays silent.
    """
    if not isinstance(requirement, DisclosureRequirement):
        raise DisclosureError(
            f"requirement must be a DisclosureRequirement, got {requirement!r}"
        )
    if must_disclose(context):
        return True
    if requirement is DisclosureRequirement.ALWAYS:
        return True
    if requirement is DisclosureRequirement.ON_REQUEST:
        return bool(on_request)
    return False


@dataclass(frozen=True)
class IdentityCard:
    """The disclosable facts about one agent.

    ``agent_name`` names the agent; ``operator`` names who runs it (a
    person, team, or organization); ``capabilities_summary`` says what it
    can do in one or two sentences; ``limitations`` says what it cannot do
    or should not be trusted for. All four are required — a disclosure
    that omits limitations is not a disclosure.
    """

    agent_name: str
    operator: str
    capabilities_summary: str
    limitations: str

    def __post_init__(self) -> None:
        for label, value in (
            ("agent_name", self.agent_name),
            ("operator", self.operator),
            ("capabilities_summary", self.capabilities_summary),
            ("limitations", self.limitations),
        ):
            if not isinstance(value, str) or not value.strip():
                raise DisclosureError(f"IdentityCard.{label} must be a non-empty string")

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": DISCLOSURE_VERSION,
            "agent_name": self.agent_name,
            "operator": self.operator,
            "capabilities_summary": self.capabilities_summary,
            "limitations": self.limitations,
        }

    def digest(self) -> str:
        """Content digest of the card (what the log pins)."""
        return _sha256_hex(_canonical(self.as_dict()))


def format_disclosure(card: IdentityCard) -> str:
    """Render a human-readable disclosure string for ``card``.

    Names the agent as an AI agent, names the operator, states
    capabilities and limitations. Plain text, no markup — the host
    decides how to present it in each channel.
    """
    if not isinstance(card, IdentityCard):
        raise DisclosureError(f"format_disclosure needs an IdentityCard, got {card!r}")
    return (
        f"I am {card.agent_name}, an AI agent operated by {card.operator}. "
        f"What I can do: {card.capabilities_summary} "
        f"What I cannot do or should not be trusted for: {card.limitations}"
    )


@dataclass(frozen=True)
class DisclosureRecord:
    """One disclosure event: what was disclosed, where, in what order.

    ``seq`` is a caller-supplied integer sequence number (no wall clock);
    ``card_digest`` pins the exact card text disclosed; ``prev_digest``
    chains to the previous record (``"0"*64`` for the first), so the log
    is tamper-evident.
    """

    seq: int
    agent_name: str
    context: str
    card_digest: str
    prev_digest: str = _ZERO_DIGEST

    def __post_init__(self) -> None:
        if isinstance(self.seq, bool) or not isinstance(self.seq, int) or self.seq < 0:
            raise DisclosureError("DisclosureRecord.seq must be a non-negative integer")
        for label, value in (("agent_name", self.agent_name), ("context", self.context)):
            if not isinstance(value, str) or not value.strip():
                raise DisclosureError(f"DisclosureRecord.{label} must be a non-empty string")
        for label, value in (("card_digest", self.card_digest), ("prev_digest", self.prev_digest)):
            if not isinstance(value, str) or len(value) != 64:
                raise DisclosureError(
                    f"DisclosureRecord.{label} must be a 64-char hex digest"
                )
            try:
                bytes.fromhex(value)
            except ValueError:
                raise DisclosureError(
                    f"DisclosureRecord.{label} must be a 64-char hex digest"
                )

    def record_digest(self) -> str:
        """Digest of this record (what the next record's prev_digest pins)."""
        return _sha256_hex(
            _canonical(
                {
                    "version": DISCLOSURE_VERSION,
                    "seq": self.seq,
                    "agent_name": self.agent_name,
                    "context": self.context,
                    "card_digest": self.card_digest,
                    "prev_digest": self.prev_digest,
                }
            )
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": DISCLOSURE_VERSION,
            "seq": self.seq,
            "agent_name": self.agent_name,
            "context": self.context,
            "card_digest": self.card_digest,
            "prev_digest": self.prev_digest,
        }


class DisclosureLog:
    """Append-only log of disclosures made.

    Enforces non-decreasing ``seq`` and hash-chain continuity on append:
    a record whose ``prev_digest`` does not match the current tail is
    rejected. The log never mutates history — there is no delete, no
    rewrite.
    """

    def __init__(self) -> None:
        self._records: list[DisclosureRecord] = []

    def append(self, record: DisclosureRecord) -> DisclosureRecord:
        """Append one record, enforcing seq order and chain continuity."""
        if not isinstance(record, DisclosureRecord):
            raise DisclosureError(f"can only log DisclosureRecord, got {record!r}")
        if self._records:
            tail = self._records[-1]
            if record.seq < tail.seq:
                raise DisclosureError(
                    f"seq {record.seq} goes backwards (tail seq {tail.seq}); "
                    "the disclosure log is append-only"
                )
            if record.prev_digest != tail.record_digest():
                raise DisclosureError(
                    "prev_digest does not match the tail record digest; "
                    "the disclosure log is tamper-evident"
                )
        else:
            if record.prev_digest != _ZERO_DIGEST:
                raise DisclosureError(
                    "first record must chain from the zero digest"
                )
        self._records.append(record)
        return record

    def disclose(
        self,
        card: IdentityCard,
        context: str,
        *,
        seq: int,
    ) -> tuple[DisclosureRecord, str]:
        """Make a disclosure: format the string and log the event.

        Returns ``(record, disclosure_text)``. The text is what the host
        presents to the counterparty; the record is the auditable proof
        it was produced.
        """
        if not isinstance(card, IdentityCard):
            raise DisclosureError(f"disclose needs an IdentityCard, got {card!r}")
        text = format_disclosure(card)
        prev = self._records[-1].record_digest() if self._records else _ZERO_DIGEST
        record = DisclosureRecord(
            seq=seq,
            agent_name=card.agent_name,
            context=str(context),
            card_digest=card.digest(),
            prev_digest=prev,
        )
        self.append(record)
        return record, text

    def __len__(self) -> int:
        return len(self._records)

    def records(self) -> tuple[DisclosureRecord, ...]:
        return tuple(self._records)

    def records_for(self, agent_name: str) -> tuple[DisclosureRecord, ...]:
        """All disclosures made for one agent, in log order."""
        return tuple(r for r in self._records if r.agent_name == agent_name)

    def verify_chain(self) -> bool:
        """Re-verify seq order and hash linkage over the whole log."""
        prev = _ZERO_DIGEST
        last_seq: int | None = None
        for record in self._records:
            if record.prev_digest != prev:
                return False
            if last_seq is not None and record.seq < last_seq:
                return False
            prev = record.record_digest()
            last_seq = record.seq
        return True


def disclosure_audit_events(
    record: DisclosureRecord,
    *,
    note: str = "",
) -> list[dict[str, Any]]:
    """Audit events for one disclosure.

    Pins the agent, the channel, the card digest, and the chain position,
    so the ``audit.ndjson/1`` hash chain anchors "this agent disclosed
    itself to a human in this channel at this point in its log".
    """
    if not isinstance(record, DisclosureRecord):
        raise DisclosureError(f"needs a DisclosureRecord, got {record!r}")
    return [
        {
            "event": "identity_disclosure.disclosed",
            "agent_name": record.agent_name,
            "context": record.context,
            "card_digest": record.card_digest,
            "seq": record.seq,
            "record_digest": record.record_digest(),
            "disclosure_version": DISCLOSURE_VERSION,
            "note": note,
        }
    ]


__all__ = [
    "DISCLOSURE_VERSION",
    "DisclosureError",
    "DisclosureLog",
    "DisclosureRecord",
    "DisclosureRequirement",
    "IdentityCard",
    "disclosure_audit_events",
    "disclosure_decision",
    "format_disclosure",
    "must_disclose",
]
