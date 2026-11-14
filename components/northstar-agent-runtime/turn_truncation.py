"""Turn truncation: an interrupted turn is recorded as the delivered prefix.

What was missing
----------------
The runtime has two kinds of shortening, and they answer different questions.
``output_limits.py`` truncates because a piece of output is *too long*: the
tail is dropped to satisfy a ceiling.  The shutdown unwind pass synthesises an
``interrupted`` result for a ``tool_use`` that never got one: a *call* was cut
short.  Neither asks whether the words the model produced actually reached
the user.  A run that is interrupted half-way through an assistant turn
records the *complete generated text*, so a later resume, a compaction, or the
next turn reads words the user never heard as if they had been said.  The
model then refers back to them -- to an answer that was never delivered.

The source
----------
OpenAI Agents SDK, Realtime guide, "Interruptions and playback tracking"
section (read 2026-11-14):
https://openai.github.io/openai-agents-python/realtime/guide/

Verbatim from the source:

* "When the user interrupts the assistant, the session emits
  audio_interrupted and updates history so the server-side conversation stays
  aligned with what the user actually heard."
* "In low-latency local playback, the default playback tracker is often
  enough. In remote or delayed playback scenarios, especially telephony, use
  RealtimePlaybackTracker so the interrupted response is truncated at the
  actual playback position rather than assuming all generated audio has
  already been heard."

The Realtime API side of the same idea is the ``conversation.item.truncate``
event, which discards the unplayed audio and its transcript after
``audio_end_ms`` (worked example read via the aicassindra deep article,
https://www.aicassindra.com/blogs/gpu/gpu_openai_realtime.html): a 6-second
answer whose speaker had written 77,760 bytes of 24 kHz 16-bit mono PCM
(48,000 bytes per second -> 1.62 s) is truncated with ``audio_end_ms=1620``;
the bytes that left the output device are the ones that count, not the bytes
that were received (a 200 ms jitter buffer would otherwise make the model
think the user heard 0.2 s more than they did).

Northstar extensions (explicitly **not** from the source)
---------------------------------------------------------
* **Delivery position generalised.**  The source's position is a playback
  position in audio.  Here it is a *delivery position* ``delivered_len``,
  measured in content units and **reported by the caller** (the delivery
  layer).  The module performs no audio arithmetic and estimates no playback
  progress: 48,000 bytes per second is a speech example and does not move
  into this module.  What the caller reports is what gets truncated (after
  range validation).
* **Three states instead of two.**  ``DELIVERED`` (the whole turn reached
  the user), ``PARTIAL`` (a prefix reached the user, the rest did not) and
  ``UNKNOWN`` (no delivery report exists at all).  The source's default
  assumption -- that generated audio has already been heard -- is exactly
  what must not be assumed here: without a report the state stays
  ``UNKNOWN`` and downstream readers are told the delivery is unknown.
* **Summary pin.**  Every truncation record carries a digest pin of the item
  it truncated, so a record cannot be silently re-pointed at a different
  turn.

``sessions.py`` is read-only reuse: this module decides what a resumed
history may contain, and never writes the transcript itself.

Scope: a pure bookkeeping library.  It runs no loop, talks to no provider,
and observes no live run.
"""
from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable, Optional, Sequence

__all__ = [
    "TurnTruncationError",
    "DeliveryRangeError",
    "ReextendRefusedError",
    "PinMismatchError",
    "TurnItem",
    "TruncationRecord",
    "TruncationOutcome",
    "HistoryEntry",
    "DELIVERED",
    "PARTIAL",
    "UNKNOWN",
    "delivery_status",
    "item_pin",
    "make_item",
    "truncate",
    "delivered_prefix",
    "verify_record",
    "history_for_resume",
    "stdlib_only",
]

DELIVERED = "DELIVERED"
PARTIAL = "PARTIAL"
UNKNOWN = "UNKNOWN"

_STATUSES = (DELIVERED, PARTIAL, UNKNOWN)


class TurnTruncationError(ValueError):
    """Base class for every refusal this module makes."""


class DeliveryRangeError(TurnTruncationError):
    """A delivery position outside ``0 <= delivered_len <= generated_len``."""


class ReextendRefusedError(TurnTruncationError):
    """An attempt to restore the undelivered suffix of a truncated turn."""


class PinMismatchError(TurnTruncationError):
    """A truncation record whose summary pin does not match its item."""


def delivery_status(delivered_len: Optional[int], generated_len: int) -> str:
    """The state implied by a delivery report.

    ``None`` means *no report*: the state is ``UNKNOWN``, never ``DELIVERED``.
    A report equal to the generated length is ``DELIVERED``; anything shorter
    is ``PARTIAL``.
    """
    if delivered_len is None:
        return UNKNOWN
    if delivered_len == generated_len:
        return DELIVERED
    return PARTIAL


@dataclass(frozen=True)
class TurnItem:
    """One recorded assistant turn and what is known about its delivery.

    ``generated_text`` is the complete generated content.  ``delivered_len``
    is what the delivery layer reported as actually delivered (``None`` when
    it reported nothing).  ``status`` follows :func:`delivery_status` and is
    refused when it contradicts the report.
    """

    item_id: str
    generated_text: str
    generated_len: int
    role: str = "assistant"
    delivered_len: Optional[int] = None
    status: str = UNKNOWN

    def __post_init__(self) -> None:
        if not self.item_id:
            raise TurnTruncationError("item_id must not be empty")
        if self.role != "assistant":
            raise TurnTruncationError(f"only assistant turns are recorded, got {self.role!r}")
        if self.generated_len != len(self.generated_text):
            raise TurnTruncationError(
                f"generated_len {self.generated_len} does not match the text length {len(self.generated_text)}"
            )
        if self.status not in _STATUSES:
            raise TurnTruncationError(f"unknown status {self.status!r}")
        if self.delivered_len is not None:
            if not isinstance(self.delivered_len, int) or isinstance(self.delivered_len, bool):
                raise TurnTruncationError("delivered_len must be an int or None")
            if self.delivered_len < 0:
                raise DeliveryRangeError(f"delivered_len {self.delivered_len} is negative")
            if self.delivered_len > self.generated_len:
                raise DeliveryRangeError(
                    f"delivered_len {self.delivered_len} outside 0..{self.generated_len}"
                )
        expected = delivery_status(self.delivered_len, self.generated_len)
        if self.status != expected:
            raise TurnTruncationError(
                f"status {self.status!r} contradicts the delivery report (expected {expected!r})"
            )


def item_pin(item: TurnItem) -> str:
    """The summary pin of an item: a digest over its identity and content."""
    payload = "\x00".join(
        [item.item_id, item.role, str(item.generated_len), item.generated_text]
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def make_item(
    item_id: str,
    generated_text: str,
    delivered_len: Optional[int] = None,
) -> TurnItem:
    """Build a turn item; the status follows the delivery report."""
    return TurnItem(
        item_id=item_id,
        generated_text=generated_text,
        generated_len=len(generated_text),
        delivered_len=delivered_len,
        status=delivery_status(delivered_len, len(generated_text)),
    )


@dataclass(frozen=True)
class TruncationRecord:
    """The receipt of one truncation: what was cut and from which turn.

    ``pin`` is the summary pin of the truncated item, so a record cannot be
    re-pointed at a different turn.  ``truncated_len`` is the number of units
    that were generated but never delivered.
    """

    item_id: str
    pin: str
    delivered_len: int
    truncated_len: int
    seq: int
    generated_len: int

    def marker(self) -> str:
        """The marker a resumed history carries in place of the missing text."""
        return (
            f"[truncated: {self.truncated_len} of {self.generated_len} units were "
            f"generated but never delivered (delivered_len={self.delivered_len}, seq={self.seq})]"
        )


@dataclass(frozen=True)
class TruncationOutcome:
    """The truncated item and the record describing the truncation.

    ``record`` is ``None`` when nothing was truncated (the whole turn was
    delivered).
    """

    item: TurnItem
    record: Optional[TruncationRecord]

    @property
    def truncated(self) -> bool:
        return self.record is not None


@dataclass(frozen=True)
class HistoryEntry:
    """One entry of the history a resumed run may read.

    ``text`` is what may be treated as said: the delivered prefix for a
    partial turn, the whole text for a delivered one, and the empty string
    for a turn whose delivery is unknown.  ``delivery_unknown`` tells the
    reader that the empty text means *unknown*, not *nothing was said*.
    """

    item_id: str
    role: str
    text: str
    status: str
    delivered_len: Optional[int]
    generated_len: int
    truncated_len: int
    marker: Optional[str]

    @property
    def delivery_unknown(self) -> bool:
        return self.status == UNKNOWN


def truncate(item: TurnItem, delivered_len: int, seq: int) -> TruncationOutcome:
    """Truncate a recorded turn to the delivered prefix.

    ``delivered_len`` is what the delivery layer reports; this module does no
    arithmetic on it beyond validating ``0 <= delivered_len <= generated_len``.
    The undelivered suffix is never returned by :func:`delivered_prefix` and
    never reaches :func:`history_for_resume`.
    """
    if not isinstance(delivered_len, int) or isinstance(delivered_len, bool):
        raise DeliveryRangeError(f"delivered_len must be an int, got {delivered_len!r}")
    if delivered_len < 0:
        raise DeliveryRangeError(f"delivered_len {delivered_len} is negative")
    if delivered_len > item.generated_len:
        raise DeliveryRangeError(
            f"delivered_len {delivered_len} outside 0..{item.generated_len} for item {item.item_id!r}"
        )
    if item.delivered_len is not None:
        # The turn was already cut once.  Restoring the suffix means claiming
        # that undelivered text was said; the module refuses.
        if delivered_len > item.delivered_len:
            raise ReextendRefusedError(
                f"item {item.item_id!r} was already truncated to {item.delivered_len}; "
                f"refusing to re-extend it to {delivered_len}"
            )
        if delivered_len < item.delivered_len:
            raise DeliveryRangeError(
                f"item {item.item_id!r} was already truncated to {item.delivered_len}; "
                f"a shorter delivery ({delivered_len}) contradicts that report"
            )
    if delivered_len == item.generated_len:
        return TruncationOutcome(
            item=replace(item, delivered_len=delivered_len, status=DELIVERED),
            record=None,
        )
    record = TruncationRecord(
        item_id=item.item_id,
        pin=item_pin(item),
        delivered_len=delivered_len,
        truncated_len=item.generated_len - delivered_len,
        seq=seq,
        generated_len=item.generated_len,
    )
    return TruncationOutcome(
        item=replace(item, delivered_len=delivered_len, status=PARTIAL),
        record=record,
    )


def delivered_prefix(item: TurnItem) -> str:
    """The part of a turn that may be treated as said.

    For a delivered turn this is the whole text.  For a partial turn it is
    the delivered prefix only.  For an unknown turn it is empty: without a
    delivery report nothing may be asserted as said.
    """
    if item.status == DELIVERED:
        return item.generated_text
    if item.status == PARTIAL:
        assert item.delivered_len is not None
        return item.generated_text[: item.delivered_len]
    return ""


def verify_record(item: TurnItem, record: TruncationRecord) -> None:
    """Refuse a truncation record that does not belong to this item."""
    if record.item_id != item.item_id:
        raise PinMismatchError(
            f"record belongs to item {record.item_id!r}, not {item.item_id!r}"
        )
    if record.pin != item_pin(item):
        raise PinMismatchError(
            f"summary pin of item {item.item_id!r} does not match the record"
        )
    if record.generated_len != item.generated_len:
        raise PinMismatchError(
            f"record was taken against a {record.generated_len}-unit turn, "
            f"item has {item.generated_len} units"
        )
    if record.truncated_len != item.generated_len - record.delivered_len:
        raise PinMismatchError(
            f"record's truncated_len {record.truncated_len} does not match "
            f"delivered_len {record.delivered_len}"
        )


def history_for_resume(items: Iterable[TurnItem]) -> list[HistoryEntry]:
    """The history a resumed (or compacted, or later) turn may read.

    * ``PARTIAL`` -- the delivered prefix plus a truncation marker.  The
      undelivered suffix is not in the entry at all.
    * ``UNKNOWN`` -- no text, flagged ``delivery_unknown``: a reader must not
      assume the turn was delivered.
    * ``DELIVERED`` -- the text as it was recorded.
    """
    entries: list[HistoryEntry] = []
    for item in items:
        if item.status == PARTIAL:
            assert item.delivered_len is not None
            entries.append(
                HistoryEntry(
                    item_id=item.item_id,
                    role=item.role,
                    text=delivered_prefix(item),
                    status=PARTIAL,
                    delivered_len=item.delivered_len,
                    generated_len=item.generated_len,
                    truncated_len=item.generated_len - item.delivered_len,
                    marker=(
                        f"[truncated: {item.generated_len - item.delivered_len} of "
                        f"{item.generated_len} units were generated but never delivered]"
                    ),
                )
            )
        elif item.status == UNKNOWN:
            entries.append(
                HistoryEntry(
                    item_id=item.item_id,
                    role=item.role,
                    text="",
                    status=UNKNOWN,
                    delivered_len=None,
                    generated_len=item.generated_len,
                    truncated_len=0,
                    marker="[delivery-unknown: no delivery report; this turn may not be assumed said]",
                )
            )
        else:
            entries.append(
                HistoryEntry(
                    item_id=item.item_id,
                    role=item.role,
                    text=item.generated_text,
                    status=DELIVERED,
                    delivered_len=item.delivered_len,
                    generated_len=item.generated_len,
                    truncated_len=0,
                    marker=None,
                )
            )
    return entries


def stdlib_only() -> bool:
    """True when this module imports nothing outside the standard library."""
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "hashlib", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True

