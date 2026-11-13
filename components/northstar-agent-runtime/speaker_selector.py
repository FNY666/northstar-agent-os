"""Speaker selection for Northstar group chats: round-robin + model-based.

Source (read, not guessed):

- AutoGen 0.5.5 API docs, ``RoundRobinGroupChatManager`` source page
  https://microsoft.github.io/autogen/0.5.5/_modules/autogen_agentchat/teams/_group_chat/_round_robin_group_chat.html
- AutoGen 0.5.5 API docs, ``SelectorGroupChatManager`` source page
  https://microsoft.github.io/autogen/0.5.5/_modules/autogen_agentchat/teams/_group_chat/_selector_group_chat.html
- AutoGen 0.4.5 user guide, "Selector Group Chat"
  https://microsoft.github.io/autogen/0.4.5/_sources/user-guide/agentchat-user-guide/selector-group-chat.ipynb.txt
- n4n.ai, "AutoGen SelectorGroupChat: dynamic speaker selection"
  https://www.n4n.ai/blog/autogen-selectorgroupchat-dynamic-speaker-selection/

This module defines the *selection protocol* only: it never calls a model.
The model call is injected by the caller (a callable that receives the
selection request and returns the raw model text). What this module owns:

- ``RoundRobinSelector`` -- deterministic rotation, index carried in the
  serialisable state (AutoGen's ``_next_speaker_index`` mechanic).
- ``ModelSelector`` -- parses a model reply into exactly one participant
  name, falls back to the previous speaker (or a random eligible pick)
  when the reply is blank / ambiguous / not a member, and by default does
  not select the previous speaker twice in a row.
- ``SelectionRecord`` -- one booked round: who was selected, under which
  rule, whether a fallback fired, and a digest pin of the transcript.
- ``SpeakerGroupChat`` -- drives the rounds with a ``max_rounds`` guard.

**Northstar extension, not AutoGen:** the ``SelectionRecord`` shape, the
digest pin of the transcript, the ``SpeakerGroupChat`` driver, the error
taxonomy, and the ``max_rounds`` guard. AutoGen has no selection ledger
and no transcript digest pin.

Public API:

- ``Participant(name, description="")`` -- one selectable agent.
- ``RoundRobinSelector(participants)`` -- deterministic rotation.
- ``ModelSelector(participants, model=None, selector_func=None,
  allow_repeated_speaker=False, fallback="previous", rng=None)`` --
  model-based selection with a caller-injected model callable.
- ``SelectionRecord`` -- frozen, digest-pinned record of one round.
- ``SpeakerGroupChat(selector, max_rounds=...)`` -- the driver.
- ``SpeakerSelectionError`` and friends -- fail-closed taxonomy.

Version pin: ``speaker-selector.v1`` / schema pin
``northstar.speaker-selector.v1``.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

#: Version pin for this module's record shape.
SPEAKER_SELECTOR_VERSION = "speaker-selector.v1"

#: Schema pin carried by records.
SPEAKER_SELECTOR_SCHEMA = "northstar.speaker-selector.v1"

#: Selection rules (booked on every record).
RULE_ROUND_ROBIN = "round-robin"
RULE_MODEL = "model"
RULE_CUSTOM = "custom"
RULE_FALLBACK = "fallback"

#: Fallback modes for an unusable model reply.
FALLBACK_PREVIOUS = "previous"
FALLBACK_RANDOM = "random"

_MAX_NAME_LEN = 128
_MAX_DESCRIPTION_LEN = 4096


# --- error taxonomy --------------------------------------------------------


class SpeakerSelectionError(Exception):
    """Base class for every fail-closed refusal in this module."""


class BadParticipantError(SpeakerSelectionError):
    """Participant name/description shape is malformed."""


class DuplicateParticipantError(SpeakerSelectionError):
    """Two participants share a name."""


class NoParticipantsError(SpeakerSelectionError):
    """The selector was built without any participant."""


class BadSelectionError(SpeakerSelectionError):
    """A selection result is not a member of the participant set."""


class BadRuleError(SpeakerSelectionError):
    """Selection rule is outside the pinned vocabulary."""


class BadFallbackError(SpeakerSelectionError):
    """Fallback mode is outside the pinned vocabulary."""


class MaxRoundsError(SpeakerSelectionError):
    """The round guard tripped; the chat must stop."""


class ModelSelectionError(SpeakerSelectionError):
    """The injected model callable failed or returned a non-text reply."""


# --- helpers ---------------------------------------------------------------


def _check_name(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadParticipantError(
            f"participant name must be a string, got {type(value).__name__}"
        )
    value = value.strip()
    if not value:
        raise BadParticipantError("participant name must be non-empty")
    if len(value) > _MAX_NAME_LEN:
        raise BadParticipantError(f"participant name exceeds {_MAX_NAME_LEN} chars")
    return value


def _check_description(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadParticipantError(
            f"participant description must be a string, got {type(value).__name__}"
        )
    if len(value) > _MAX_DESCRIPTION_LEN:
        raise BadParticipantError(
            f"participant description exceeds {_MAX_DESCRIPTION_LEN} chars"
        )
    return value


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_of(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(obj)).hexdigest()


def transcript_digest(transcript: Sequence[str]) -> str:
    """Digest pin of a transcript (a list of message texts).

    Northstar extension: AutoGen never pins the transcript.
    """
    return _digest_of({"transcript": list(transcript)})


# --- participants ----------------------------------------------------------


@dataclass(frozen=True)
class Participant:
    """One selectable agent: a name plus an optional description."""

    name: str
    description: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _check_name(self.name))
        object.__setattr__(
            self, "description", _check_description(self.description)
        )

    def as_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "description": self.description}


def _coerce_participants(
    participants: Sequence[Any],
) -> Tuple[Participant, ...]:
    """Accept ``Participant`` objects or plain names; dedupe-check."""
    if isinstance(participants, (str, bytes)) or not isinstance(
        participants, Sequence
    ):
        raise BadParticipantError("participants must be a sequence")
    out: List[Participant] = []
    for item in participants:
        if isinstance(item, Participant):
            out.append(item)
        elif isinstance(item, str):
            out.append(Participant(item))
        elif isinstance(item, Mapping):
            out.append(
                Participant(
                    item.get("name", ""), item.get("description", "")
                )
            )
        else:
            raise BadParticipantError(
                f"participant must be a Participant, mapping or str, got "
                f"{type(item).__name__}"
            )
    if not out:
        raise NoParticipantsError("participants must be non-empty")
    names = [p.name for p in out]
    if len(set(names)) != len(names):
        dupes = sorted({n for n in names if names.count(n) > 1})
        raise DuplicateParticipantError(f"duplicate participant names: {dupes}")
    return tuple(out)


# --- selection record -----------------------------------------------------


@dataclass(frozen=True)
class SelectionRecord:
    """One booked selection round.

    Northstar extension: AutoGen keeps no such ledger.

    Fields:
      - ``round_index``: 0-based index of the round.
      - ``speaker``: the selected participant name.
      - ``rule``: one of ``RULE_ROUND_ROBIN`` / ``RULE_MODEL`` /
        ``RULE_CUSTOM`` / ``RULE_FALLBACK``.
      - ``fallback``: True when the speaker was NOT produced by the primary
        rule (an unusable model reply, or an unusable custom function
        reply).
      - ``transcript_digest``: digest pin of the transcript the decision
        was made against ("" when there was no transcript).
      - ``reason``: short human-readable justification of the decision.
    """

    round_index: int
    speaker: str
    rule: str
    fallback: bool
    transcript_digest: str = ""
    reason: str = ""
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        if self.rule not in (
            RULE_ROUND_ROBIN,
            RULE_MODEL,
            RULE_CUSTOM,
            RULE_FALLBACK,
        ):
            raise BadRuleError(f"unknown selection rule: {self.rule!r}")
        object.__setattr__(self, "speaker", _check_name(self.speaker))
        object.__setattr__(self, "fallback", bool(self.fallback))
        object.__setattr__(
            self,
            "digest",
            _digest_of(
                {
                    "round_index": self.round_index,
                    "speaker": self.speaker,
                    "rule": self.rule,
                    "fallback": self.fallback,
                    "transcript_digest": self.transcript_digest,
                    "reason": self.reason,
                }
            ),
        )

    def verify(self) -> bool:
        """Recompute the pin; True when untampered."""
        return self.digest == _digest_of(
            {
                "round_index": self.round_index,
                "speaker": self.speaker,
                "rule": self.rule,
                "fallback": self.fallback,
                "transcript_digest": self.transcript_digest,
                "reason": self.reason,
            }
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "round_index": self.round_index,
            "speaker": self.speaker,
            "rule": self.rule,
            "fallback": self.fallback,
            "transcript_digest": self.transcript_digest,
            "reason": self.reason,
            "digest": self.digest,
            "schema": SPEAKER_SELECTOR_SCHEMA,
        }


# --- round-robin selector -------------------------------------------------


class RoundRobinSelector:
    """Deterministic rotation over the participants.

    AutoGen's ``RoundRobinGroupChatManager`` keeps ``_next_speaker_index``
    (initially 0); ``select_speaker`` reads the participant at the current
    index, advances the index by one modulo the participant count, and
    returns that participant. The index is part of the saved manager
    state, so a resumed chat continues where it left off.

    Northstar: the same mechanic, with the index in a plain serialisable
    dict (``state()`` / ``restore()``) instead of a pydantic model.
    """

    rule = RULE_ROUND_ROBIN

    def __init__(self, participants: Sequence[Any]):
        self._participants = _coerce_participants(participants)
        self._names: Tuple[str, ...] = tuple(p.name for p in self._participants)
        self._next_speaker_index = 0
        self._lock = threading.RLock()

    # -- views ---------------------------------------------------------------

    @property
    def participants(self) -> Tuple[Participant, ...]:
        return self._participants

    @property
    def participant_names(self) -> Tuple[str, ...]:
        return self._names

    @property
    def next_speaker_index(self) -> int:
        with self._lock:
            return self._next_speaker_index

    def state(self) -> Dict[str, Any]:
        """Serialisable state: the rotation index rides with the state."""
        with self._lock:
            return {
                "rule": self.rule,
                "next_speaker_index": self._next_speaker_index,
                "participant_names": list(self._names),
                "schema": SPEAKER_SELECTOR_SCHEMA,
            }

    def restore(self, state: Mapping[str, Any]) -> None:
        """Restore the rotation index from a state dict."""
        if not isinstance(state, Mapping):
            raise SpeakerSelectionError("state must be a mapping")
        index = state.get("next_speaker_index")
        if isinstance(index, bool) or not isinstance(index, int):
            raise SpeakerSelectionError(
                "state['next_speaker_index'] must be an int"
            )
        if index < 0 or index >= len(self._names):
            raise SpeakerSelectionError(
                f"state['next_speaker_index'] out of range: {index}"
            )
        names = state.get("participant_names")
        if names is not None and list(names) != list(self._names):
            raise SpeakerSelectionError(
                "state participant_names do not match this selector"
            )
        with self._lock:
            self._next_speaker_index = index

    # -- selection ----------------------------------------------------------

    def select_speaker(
        self,
        transcript: Sequence[str] = (),
        previous_speaker: Optional[str] = None,
        round_index: int = 0,
    ) -> SelectionRecord:
        """Pick the next speaker by index rotation."""
        with self._lock:
            index = self._next_speaker_index
            self._next_speaker_index = (index + 1) % len(self._names)
            speaker = self._names[index]
        return SelectionRecord(
            round_index=round_index,
            speaker=speaker,
            rule=self.rule,
            fallback=False,
            transcript_digest=transcript_digest(transcript),
            reason=f"round-robin index {index}",
        )


# --- model selector --------------------------------------------------------


def parse_selection(
    reply: str, names: Sequence[str]
) -> Optional[str]:
    """Parse a raw model reply into exactly one participant name.

    Mirrors AutoGen's ``_mentioned_agents`` behaviour: the reply is
    stripped, and every known participant name that appears in it is
    counted. Zero mentions -> no valid name (ambiguous or invalid);
    more than one mention -> ambiguous. Exactly one mention -> that
    name.

    Returns ``None`` when the reply yields no unambiguous member name.
    """
    if not isinstance(reply, str):
        return None
    text = reply.strip()
    if not text:
        return None
    mentions = [
        name for name in names if re.search(rf"(?<!\w){re.escape(name)}(?!\w)", text)
    ]
    if len(mentions) == 1:
        return mentions[0]
    return None


class ModelSelector:
    """Model-based speaker selection with a strict output contract.

    The model call is injected: ``model(request)`` receives a
    ``SelectionRequest`` (transcript + participant roster + the previous
    speaker) and returns the raw model text. This module never calls a
    model itself.

    Contract:

    - The reply is stripped and matched against the participant roster.
    - A reply naming no member, naming several members, or naming a
      non-member is unusable: the selector falls back (never hangs).
    - Default fallback is the previous speaker; ``fallback="random"``
      picks a random *eligible* participant instead.
    - By default the previous speaker is excluded from the candidate set
      (unless it is the only participant); ``allow_repeated_speaker=True``
      turns that off. Northstar tightens AutoGen here: a model reply that
      names the previous speaker is treated as an *ineligible* reply and
      the fallback lands on an eligible participant, so the same speaker
      is never selected twice in a row while the rule is active.
    - ``selector_func`` overrides the model-based selection entirely.
      Returning ``None`` from it defers to the model, exactly like
      AutoGen's ``selector_func`` contract.
    """

    rule = RULE_MODEL

    def __init__(
        self,
        participants: Sequence[Any],
        model: Optional[Callable[["SelectionRequest"], Any]] = None,
        selector_func: Optional[Callable[["SelectionRequest"], Any]] = None,
        allow_repeated_speaker: bool = False,
        fallback: str = FALLBACK_PREVIOUS,
        rng: Optional[random.Random] = None,
        max_attempts: int = 3,
    ):
        self._participants = _coerce_participants(participants)
        self._names: Tuple[str, ...] = tuple(p.name for p in self._participants)
        if fallback not in (FALLBACK_PREVIOUS, FALLBACK_RANDOM):
            raise BadFallbackError(f"unknown fallback mode: {fallback!r}")
        if model is not None and not callable(model):
            raise SpeakerSelectionError("model must be callable")
        if selector_func is not None and not callable(selector_func):
            raise SpeakerSelectionError("selector_func must be callable")
        if isinstance(max_attempts, bool) or not isinstance(max_attempts, int):
            raise SpeakerSelectionError("max_attempts must be an int")
        if max_attempts < 1:
            raise SpeakerSelectionError("max_attempts must be >= 1")
        self._model = model
        self._selector_func = selector_func
        self._allow_repeated_speaker = bool(allow_repeated_speaker)
        self._fallback = fallback
        self._rng = rng or random.Random()
        self._max_attempts = max_attempts
        self._previous_speaker: Optional[str] = None
        self._lock = threading.RLock()

    # -- views ---------------------------------------------------------------

    @property
    def participants(self) -> Tuple[Participant, ...]:
        return self._participants

    @property
    def participant_names(self) -> Tuple[str, ...]:
        return self._names

    @property
    def previous_speaker(self) -> Optional[str]:
        with self._lock:
            return self._previous_speaker

    @property
    def allow_repeated_speaker(self) -> bool:
        return self._allow_repeated_speaker

    @property
    def fallback_mode(self) -> str:
        return self._fallback

    def state(self) -> Dict[str, Any]:
        """Serialisable state: the previous speaker rides with the state."""
        with self._lock:
            return {
                "rule": self.rule,
                "previous_speaker": self._previous_speaker,
                "participant_names": list(self._names),
                "allow_repeated_speaker": self._allow_repeated_speaker,
                "fallback": self._fallback,
                "schema": SPEAKER_SELECTOR_SCHEMA,
            }

    def restore(self, state: Mapping[str, Any]) -> None:
        """Restore the previous speaker from a state dict."""
        if not isinstance(state, Mapping):
            raise SpeakerSelectionError("state must be a mapping")
        previous = state.get("previous_speaker")
        if previous is not None:
            if previous not in self._names:
                raise SpeakerSelectionError(
                    f"state['previous_speaker'] is not a participant: {previous!r}"
                )
        with self._lock:
            self._previous_speaker = previous

    # -- candidates ---------------------------------------------------------

    def candidates(self, previous_speaker: Optional[str] = None) -> Tuple[str, ...]:
        """The participant names the model may pick from.

        The previous speaker is dropped unless ``allow_repeated_speaker``
        is set or it is the only participant available.
        """
        previous = (
            previous_speaker
            if previous_speaker is not None
            else self.previous_speaker
        )
        if previous is not None and not self._allow_repeated_speaker:
            names = tuple(n for n in self._names if n != previous)
            if names:
                return names
        return self._names

    # -- selection ----------------------------------------------------------

    def select_speaker(
        self,
        transcript: Sequence[str] = (),
        previous_speaker: Optional[str] = None,
        round_index: int = 0,
    ) -> SelectionRecord:
        """Select the next speaker.

        Order of resolution:

        1. ``selector_func`` (custom rule) -- when it returns a name.
           ``None`` defers to the model.
        2. The injected model -- when it is present.
        3. The fallback (previous speaker or a random eligible pick).

        Never raises for an unusable reply and never hangs: every path
        ends in a concrete participant name.
        """
        with self._lock:
            previous = (
                previous_speaker
                if previous_speaker is not None
                else self._previous_speaker
            )
            digest = transcript_digest(transcript)
            request = SelectionRequest(
                transcript=tuple(transcript),
                participants=self._participants,
                candidates=self.candidates(previous),
                previous_speaker=previous,
            )

            # 1. custom selection function overrides the model.
            if self._selector_func is not None:
                try:
                    custom = self._selector_func(request)
                except Exception as exc:  # fail closed into the fallback
                    record = self._fallback_record(
                        round_index,
                        previous,
                        digest,
                        rule=RULE_CUSTOM,
                        reason=f"selector_func raised {type(exc).__name__}",
                    )
                    return record
                if custom is not None:
                    name = (
                        custom.strip()
                        if isinstance(custom, str)
                        else ""
                    )
                    if name in self._names:
                        self._previous_speaker = name
                        return SelectionRecord(
                            round_index=round_index,
                            speaker=name,
                            rule=RULE_CUSTOM,
                            fallback=False,
                            transcript_digest=digest,
                            reason="custom selector_func",
                        )
                    record = self._fallback_record(
                        round_index,
                        previous,
                        digest,
                        rule=RULE_CUSTOM,
                        reason=(
                            f"selector_func returned {custom!r}, not a "
                            "participant"
                        ),
                    )
                    return record

            # 2. the injected model.
            if self._model is not None:
                feedback = ""
                last_reply = ""
                repeated = False
                for _attempt in range(self._max_attempts):
                    attempt_request = SelectionRequest(
                        transcript=request.transcript,
                        participants=request.participants,
                        candidates=request.candidates,
                        previous_speaker=previous,
                        feedback=feedback,
                    )
                    try:
                        last_reply = self._call_model(attempt_request)
                    except ModelSelectionError as exc:
                        feedback = str(exc)
                        continue
                    name = parse_selection(last_reply, self._names)
                    if name is None:
                        repeated = False
                        feedback = (
                            "No valid name was mentioned. Please select from: "
                            f"{list(request.candidates)}."
                        )
                        continue
                    if name not in request.candidates:
                        # The name is a member but is not eligible: the
                        # no-repeat rule excluded the previous speaker.
                        repeated = True
                        feedback = (
                            "Repeated speaker is not allowed, please select "
                            f"a different name from: {list(request.candidates)}."
                        )
                        continue
                    self._previous_speaker = name
                    return SelectionRecord(
                        round_index=round_index,
                        speaker=name,
                        rule=RULE_MODEL,
                        fallback=False,
                        transcript_digest=digest,
                        reason=f"model selected {name}",
                    )
                reason = (
                    f"model reply unusable after {self._max_attempts} attempt(s): "
                    f"{last_reply!r}"
                )
                return self._fallback_record(
                    round_index,
                    previous,
                    digest,
                    rule=RULE_MODEL,
                    reason=reason,
                    respect_no_repeat=repeated,
                )

            # 3. no model at all: the fallback is the only path.
            return self._fallback_record(
                round_index,
                previous,
                digest,
                rule=RULE_MODEL,
                reason="no model configured",
            )

    def _call_model(self, request: "SelectionRequest") -> str:
        """Call the injected model; never raises out of the selector."""
        try:
            reply = self._model(request)  # type: ignore[misc]
        except Exception as exc:
            raise ModelSelectionError(
                f"injected model failed: {type(exc).__name__}: {exc}"
            ) from exc
        if not isinstance(reply, str):
            raise ModelSelectionError(
                f"injected model returned {type(reply).__name__}, expected str"
            )
        return reply

    def _fallback_record(
        self,
        round_index: int,
        previous: Optional[str],
        digest: str,
        rule: str,
        reason: str,
        respect_no_repeat: bool = False,
    ) -> SelectionRecord:
        """Book the fallback decision; always concrete, never a hang.

        Two fallback flavours:

        - ``respect_no_repeat=False`` (the default): AutoGen's last-resort
          fallback -- the *previous speaker* keeps the floor, even when
          the no-repeat rule excluded it from the candidate set.
        - ``respect_no_repeat=True``: the model named a member who was
          only ineligible because of the no-repeat rule; the fallback
          then lands on an eligible participant so the same speaker is
          not selected twice in a row.
        """
        eligible = self.candidates(previous)
        if self._fallback == FALLBACK_RANDOM:
            speaker = self._rng.choice(list(eligible))
        elif previous is not None and not respect_no_repeat:
            speaker = previous
        else:
            speaker = eligible[0]
        self._previous_speaker = speaker
        return SelectionRecord(
            round_index=round_index,
            speaker=speaker,
            rule=RULE_FALLBACK,
            fallback=True,
            transcript_digest=digest,
            reason=reason,
        )


# --- selection request ----------------------------------------------------


@dataclass(frozen=True)
class SelectionRequest:
    """What a model / custom selector function receives.

    AutoGen hands the selector function the message thread; the model
    prompt carries the roster and the history. Northstar bundles both
    into one frozen request object so an injected callable needs no
    knowledge of the transcript's shape.
    """

    transcript: Tuple[str, ...] = ()
    participants: Tuple[Participant, ...] = ()
    candidates: Tuple[str, ...] = ()
    previous_speaker: Optional[str] = None
    feedback: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "transcript": list(self.transcript),
            "participants": [p.as_dict() for p in self.participants],
            "candidates": list(self.candidates),
            "previous_speaker": self.previous_speaker,
            "feedback": self.feedback,
        }


# --- driver ----------------------------------------------------------------


class SpeakerGroupChat:
    """Drive speaker selection for a bounded number of rounds.

    Northstar extension: AutoGen teams own the whole chat loop; this
    driver only owns the *selection* rounds and their records, so a
    Northstar run can bolt speaker selection onto its own agent loop.

    The guard is ``max_rounds``: when the round budget is exhausted the
    driver stops -- it never rotates forever.
    """

    def __init__(
        self,
        selector: Any,
        max_rounds: int = 8,
        transcript: Optional[Sequence[str]] = None,
    ):
        if not isinstance(selector, (RoundRobinSelector, ModelSelector)):
            raise SpeakerSelectionError(
                "selector must be a RoundRobinSelector or ModelSelector"
            )
        if isinstance(max_rounds, bool) or not isinstance(max_rounds, int):
            raise SpeakerSelectionError("max_rounds must be an int")
        if max_rounds < 1:
            raise SpeakerSelectionError("max_rounds must be >= 1")
        self._selector = selector
        self._max_rounds = max_rounds
        self._transcript: List[str] = list(transcript or [])
        self._records: List[SelectionRecord] = []
        self._lock = threading.RLock()

    # -- views ---------------------------------------------------------------

    @property
    def max_rounds(self) -> int:
        return self._max_rounds

    @property
    def records(self) -> Tuple[SelectionRecord, ...]:
        with self._lock:
            return tuple(self._records)

    @property
    def rounds_used(self) -> int:
        with self._lock:
            return len(self._records)

    @property
    def transcript(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(self._transcript)

    def state(self) -> Dict[str, Any]:
        """Serialisable state of the driver plus its selector."""
        with self._lock:
            return {
                "max_rounds": self._max_rounds,
                "rounds_used": len(self._records),
                "transcript": list(self._transcript),
                "selector": self._selector.state(),
                "schema": SPEAKER_SELECTOR_SCHEMA,
            }

    def restore(self, state: Mapping[str, Any]) -> None:
        """Restore the driver + selector state (index must not slip)."""
        if not isinstance(state, Mapping):
            raise SpeakerSelectionError("state must be a mapping")
        selector_state = state.get("selector")
        if not isinstance(selector_state, Mapping):
            raise SpeakerSelectionError("state['selector'] must be a mapping")
        self._selector.restore(selector_state)
        with self._lock:
            self._transcript = list(state.get("transcript", []))
            self._records = []

    # -- driving -------------------------------------------------------------

    def select_next(self) -> SelectionRecord:
        """Select the next speaker, or raise ``MaxRoundsError``."""
        with self._lock:
            if len(self._records) >= self._max_rounds:
                raise MaxRoundsError(
                    f"max_rounds reached ({self._max_rounds}); stop the chat"
                )
            index = len(self._records)
        record = self._selector.select_speaker(
            transcript=tuple(self._transcript),
            round_index=index,
        )
        with self._lock:
            self._records.append(record)
        return record

    def append(self, message: str) -> None:
        """Append one transcript message (host side)."""
        if not isinstance(message, str):
            raise SpeakerSelectionError("transcript message must be a string")
        with self._lock:
            self._transcript.append(message)

    def run(self, speaker: Callable[[str], str], rounds: Optional[int] = None) -> Tuple[SelectionRecord, ...]:
        """Drive the chat for up to ``rounds`` (default ``max_rounds``).

        ``speaker(name)`` produces that speaker's reply, which is
        appended to the transcript. The loop stops at the round budget;
        it never runs forever.
        """
        budget = self._max_rounds if rounds is None else rounds
        if isinstance(budget, bool) or not isinstance(budget, int):
            raise SpeakerSelectionError("rounds must be an int")
        if budget < 0:
            raise SpeakerSelectionError("rounds must be >= 0")
        produced: List[SelectionRecord] = []
        for _ in range(budget):
            try:
                record = self.select_next()
            except MaxRoundsError:
                break
            produced.append(record)
            self.append(speaker(record.speaker))
        return tuple(produced)


# --- self check -----------------------------------------------------------


def main() -> None:
    """Drive the three canonical paths (round-robin, model, fallback)."""
    people = [
        Participant("Planner", "plans the work"),
        Participant("Coder", "writes the code"),
        Participant("Critic", "reviews the output"),
    ]
    chat = SpeakerGroupChat(RoundRobinSelector(people), max_rounds=4)
    for record in chat.run(lambda name: f"{name} spoke"):
        assert record.verify()
        print(f"round {record.round_index}: {record.speaker} ({record.rule})")

    def router(request: SelectionRequest) -> str:
        last = request.transcript[-1] if request.transcript else ""
        if "traceback" in last:
            return "Critic"
        return "Coder"

    model_chat = SpeakerGroupChat(ModelSelector(people, model=router), max_rounds=3)
    for record in model_chat.run(lambda name: f"{name} ok"):
        assert record.verify()
        print(f"model round {record.round_index}: {record.speaker} ({record.rule})")

    broken = SpeakerGroupChat(
        ModelSelector(people, model=lambda request: "  "), max_rounds=2
    )
    for record in broken.run(lambda name: f"{name} ok"):
        print(
            f"fallback round {record.round_index}: {record.speaker} "
            f"({record.rule}, fallback={record.fallback})"
        )
    print("speaker-selector OK: round-robin, model selection, fallback")


if __name__ == "__main__":
    main()
