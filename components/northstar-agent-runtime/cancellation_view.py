"""One rendering of a cancellation record, shared by every read path.

The runtime writes a ``cancellation`` record beside the conversation when
a principal revokes an action ("stop, do not publish").  The record is
structure, not prose: it carries the tombstone's canonical form so that
a compaction cannot prune it, and a digest so a handoff can carry a pin
instead of a blob.

The record is written correctly.  What was missing was every path that
READS a transcript.  Each of them fell through to a generic fallback
that rendered the record's own JSON -- and because JSON sorts its keys
alphabetically, the visible prefix was ``chain``, ``chain_hash``,
``digest``, ``genesis``, ``hlc``:  the action, the subject, the
declarer and the reason fell outside the preview.

So the revocation was technically present and practically invisible.

This module owns the ONE rendering, and the read paths call it:

  * ``audit_export`` gives a cancellation ``level: "error"`` -- a
    revocation is a WITHHELD AUTHORIZATION, the same category as a
    denial, not an informational line;
  * ``session_replay`` gives it its own frame kind, so a reader can
    filter for it and see how many there were;
  * ``session_view`` renders the same text on the ``sessions show`` path.

The rendering is deliberately DEFENSIVE.  A record that does not carry
a well-formed tombstone still produces a readable line: a reader must
never be shown a traceback instead of a revocation, and must never be
shown nothing at all.
"""
from __future__ import annotations

from typing import Any, Mapping

#: What a missing or blank field is shown as.
UNKNOWN = "?"

#: The longest reason a single line will carry.  A reason is the
#: principal's own words; it is shown, but it does not get to make the
#: frame unreadable.
REASON_LIMIT = 160


def describe_cancellation(record: Mapping[str, Any]) -> str:
    """Describe one cancellation record in a sentence a reader can act on.

    The description names WHAT was revoked, ON WHAT, WHO declared it and
    WHY -- and says whether the stop is still standing or has been
    lifted.  A reader who has only this line should be able to answer
    "what is stopped, and may I do it?".

    A record that does not carry a usable tombstone still describes
    itself, with ``?`` for whatever is missing, rather than raising.
    """
    tombstone = _tombstone_of(record)
    action = _text(tombstone.get("action"))
    subject = _text(tombstone.get("subject"))
    declarer = _text(tombstone.get("declarer"))
    channel = _text(tombstone.get("declarer_channel"))
    grant = _text(tombstone.get("grant_id"))
    kind = _text(tombstone.get("kind"))
    reason = _text(tombstone.get("reason"), "")
    lift = _lift_of(record)

    standing = True
    if isinstance(lift, Mapping) and len(lift) > 0:
        standing = False

    if subject == UNKNOWN:
        scope = action
    else:
        scope = "%s on %s" % (action, subject)

    parts = [
        "grant=%s" % grant,
        "kind=%s" % kind,
        "declared by %s via %s" % (declarer, channel),
    ]
    if reason == "":
        parts.append("reason: (none given)")
    else:
        parts.append("reason: %s" % reason)

    if standing:
        state = "STANDING - the stop has not been lifted"
    else:
        state = "LIFTED by %s via %s" % (
            _text(lift.get("declarer")),
            _text(lift.get("declarer_channel")),
        )
        words = _text(lift.get("text"), "")
        if words != "":
            state = "%s - %s" % (state, words)

    return "cancellation - %s (%s) - %s" % (scope, ", ".join(parts), state)


def _tombstone_of(record: Mapping[str, Any]) -> Mapping[str, Any]:
    """The record's tombstone, or an empty mapping when it has none."""
    payload = record.get("tombstone") if isinstance(record, Mapping) else None
    if isinstance(payload, Mapping):
        return payload
    return {}


def _lift_of(record: Mapping[str, Any]) -> Mapping[str, Any]:
    """The record's lift, or an empty mapping when it has none."""
    payload = record.get("lift") if isinstance(record, Mapping) else None
    if isinstance(payload, Mapping):
        return payload
    return {}


def _text(value: Any, fallback: str = UNKNOWN) -> str:
    """A field as readable text, with ``fallback`` for what is missing.

    A field that is present but not a string (a malformed record, a
    number where a name was expected) is still shown: ``str(value)``,
    because a surprising value in a revocation is worth seeing rather
    than hiding.
    """
    if value is None:
        return fallback
    if isinstance(value, str):
        stripped = value.strip()
        if stripped == "":
            return fallback
        return stripped
    return str(value)
