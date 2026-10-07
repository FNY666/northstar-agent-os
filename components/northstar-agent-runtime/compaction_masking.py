"""Observation masking for conversation compaction.

When a transcript prefix is summarized away by compaction (see
``compaction.py``), whatever the summary keeps becomes durable context for
every later model call. Tool results and user pastes routinely carry secrets
— API keys, bearer tokens, passwords, emails, phone numbers — and an
unmasked summary turns a transient observation into a permanent leak.

This module is the gate between "history worth summarizing" and "the
summary": ``mask_observations`` rewrites sensitive spans into explicit
``[REDACTED:<type>]`` markers, and ``CompactionGate.approve_for_compaction``
applies that rewrite to a whole history before it is handed to any
summarizer (extractive or provider-side).

Two invariants:

* **Transparency:** masking never silently deletes. Every redaction leaves a
  typed marker, and the gate reports per-type counts, so a reviewer can see
  exactly what was hidden and why.
* **Determinism:** no wall-clock, no randomness, no model calls. The same
  input always produces the same masked output, which keeps compaction
  reproducible in tests.

Honest scope: pattern-based redaction is a backstop, not a guarantee. A
novel secret format, a secret split across lines, or a secret the patterns
do not cover will pass through untouched. Hosts handling regulated data
should layer this under their own DLP review; this module only promises
that *known* shapes never reach the summary verbatim.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Sequence

#: Version of the masking rule set. Bump when patterns change so hosts can
#: pin or audit which rule set produced a masked summary.
MASKING_VERSION = "compaction-masking.v1"

# ---------------------------------------------------------------------------
# Sensitive patterns
# ---------------------------------------------------------------------------
#
# Ordered most-specific-first so a span is claimed by the tightest pattern
# that matches it (e.g. a Stripe-style ``sk-`` key is an api_key, not a
# generic token). Each entry is ``(mask_type, compiled_pattern)``.
SENSITIVE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "password",
        re.compile(
            r"(?i)\bpassword\s*[:=]\s*[\"']?[^\s\"']+[\"']?",
        ),
    ),
    (
        "api_key",
        re.compile(
            r"(?:"
            r"sk-[A-Za-z0-9\-_]{16,}"          # Stripe / OpenAI style secret keys
            r"|AKIA[0-9A-Z]{16}"               # AWS access key id
            r"|gh[pousr]_[A-Za-z0-9]{20,}"     # GitHub tokens
            r"|xox[bpras]-[A-Za-z0-9\-]+"      # Slack tokens
            r"|AIza[0-9A-Za-z\-_]{35}"         # Google API key
            r"|(?i:\bapi[_-]?key\s*[:=]\s*)[\"']?[A-Za-z0-9\-_.]{8,}[\"']?"
            r")",
        ),
    ),
    (
        "token",
        re.compile(
            r"(?:"
            r"(?i:\bbearer\s+)[A-Za-z0-9\-_.~+/=]{8,}"
            r"|[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}"  # JWT shape
            r"|(?i:\b(?:access|auth|refresh|secret)[_-]?token\s*[:=]\s*)[\"']?[^\s\"']+[\"']?"
            r")",
        ),
    ),
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "phone",
        re.compile(
            r"(?<!\d)(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?!\d)",
        ),
    ),
]


def _marker(mask_type: str) -> str:
    return f"[REDACTED:{mask_type}]"


def mask_observations(text: str) -> str:
    """Replace sensitive spans in ``text`` with typed redaction markers.

    Raises ``TypeError`` on non-``str`` input (fail-closed: never guess what
    the caller meant). Masking is idempotent — masking already-masked text
    returns it unchanged — because no pattern matches inside a marker.
    """
    if not isinstance(text, str):
        raise TypeError(f"mask_observations expects str, got {type(text).__name__}")
    masked = text
    for mask_type, pattern in SENSITIVE_PATTERNS:
        masked = pattern.sub(_marker(mask_type), masked)
    return masked


def mask_report(text: str) -> tuple[str, dict[str, int]]:
    """Mask ``text`` and return ``(masked_text, counts_by_type)``.

    The counts are the transparency record: they say exactly which classes
    of secret were removed, without revealing the secrets themselves.
    """
    if not isinstance(text, str):
        raise TypeError(f"mask_report expects str, got {type(text).__name__}")
    counts: dict[str, int] = {}
    masked = text
    for mask_type, pattern in SENSITIVE_PATTERNS:
        masked, n = pattern.subn(_marker(mask_type), masked)
        if n:
            counts[mask_type] = counts.get(mask_type, 0) + n
    return masked, counts


# ---------------------------------------------------------------------------
# Compaction gate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MaskedHistory:
    """A history approved for compaction, with its transparency record."""

    entries: tuple[str, ...]
    redaction_counts: tuple[tuple[str, int], ...] = ()
    masked_any: bool = False
    masking_version: str = MASKING_VERSION

    @property
    def total_redactions(self) -> int:
        return sum(count for _, count in self.redaction_counts)

    def as_dict(self) -> dict:
        return {
            "entries": len(self.entries),
            "redaction_counts": dict(self.redaction_counts),
            "total_redactions": self.total_redactions,
            "masked_any": self.masked_any,
            "masking_version": self.masking_version,
        }


class CompactionGate:
    """Masks sensitive observations before a history may be compacted.

    ``approve_for_compaction`` takes the message texts that are about to be
    summarized and returns the masked copy plus a transparency record. It
    never mutates the caller's history, and it never drops the fact that
    masking happened: ``MaskedHistory.redaction_counts`` is the audit trail.
    """

    def __init__(self, *, enabled: bool = True) -> None:
        self.enabled = enabled

    def approve_for_compaction(self, history: Sequence[str]) -> MaskedHistory:
        entries = tuple(history)
        for entry in entries:
            if not isinstance(entry, str):
                raise TypeError(
                    f"history entries must be str, got {type(entry).__name__}"
                )
        if not self.enabled:
            return MaskedHistory(entries=entries)
        masked_entries: list[str] = []
        totals: dict[str, int] = {}
        for entry in entries:
            masked, counts = mask_report(entry)
            masked_entries.append(masked)
            for mask_type, n in counts.items():
                totals[mask_type] = totals.get(mask_type, 0) + n
        ordered = tuple(sorted(totals.items()))
        return MaskedHistory(
            entries=tuple(masked_entries),
            redaction_counts=ordered,
            masked_any=bool(totals),
        )


__all__ = [
    "MASKING_VERSION",
    "SENSITIVE_PATTERNS",
    "CompactionGate",
    "MaskedHistory",
    "mask_observations",
    "mask_report",
]
