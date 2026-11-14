"""Session memory: a four-operation conversation-memory protocol.

Northstar already had two unrelated things called "session":
``sessions.py`` is the append-only JSONL *transcript* recorder, and
``session_manager.py`` holds *auth* tokens (login/logout/refresh). Neither
is a conversation memory: before this module the repository had no
``get_items`` / ``add_items`` / ``pop_item`` / ``clear_session`` at all
(verified by grep over the whole tree on 2026-11-14), no runner contract
that prepends history before a run and stores only the new items after
it, no merge callback, no most-recent-N retrieval cap, and no rule
saying a session may not be combined with server-side continuation.

Source of the mechanism (OpenAI Agents SDK, official sessions docs
https://openai.github.io/openai-agents-python/sessions/, read in full on
2026-11-14). Rules taken from that source are marked ``[OpenAI]`` below;
everything else is a Northstar extension and marked ``[Northstar]``.

- [OpenAI] The session protocol is four operations: ``get_items``,
  ``add_items``, ``pop_item``, ``clear_session``.
- [OpenAI] Runner contract: with session memory enabled, the runner
  retrieves the session history before each run and prepends it to the
  input; after the run it stores every item produced during that run
  (user input, assistant responses, tool calls); the next run on the same
  session therefore sees the full history.
- [OpenAI] ``RunConfig.session_input_callback`` is a merge callback. It
  receives the retrieved history (normalized to input-item form) and the
  new input as two lists and returns the final list of input items for
  the model. The callback receives copies and may modify them safely.
  The returned list controls the model input only: the SDK still persists
  only the items belonging to the current turn, so reordering or
  filtering old history never re-saves old items as new input.
- [OpenAI] ``SessionSettings(limit=N)`` caps how much history is
  retrieved before each run; ``limit=None`` retrieves everything and
  ``limit=N`` retrieves only the most recent N items.
  ``RunConfig.session_settings`` overrides the session default per run.
- [OpenAI] Exclusion: in the same run a session may not be combined with
  the run-level continuation options ``conversation_id``,
  ``previous_response_id`` or ``auto_previous_response_id``. To continue
  server-side, use those mechanisms instead of stacking them on a
  session.
- [OpenAI] ``pop_item`` supports corrections: pop the assistant reply,
  then pop the user question, then ask the corrected question.
- [OpenAI] Trust boundary: ``SQLiteSession`` assumes the application
  trusts the database and the storage; the backend does not authenticate
  stored rows, does not detect external edits, deletions, reorderings or
  replays; a session ID selects history but never authenticates or
  authorizes; ``get_items`` selects rows by session ID, orders them by
  insertion ID and decodes each row's ``message_data`` as JSON; rows
  that fail to decode are skipped without an integrity error. The
  application must authorize access to each session itself and restrict
  access to the database file.

Northstar extensions (not in the source document):

- [Northstar] Digest-pinned history. Every stored row carries a
  ``sha256:`` digest pin over its exact stored bytes. ``get_items``
  refuses the *whole* call when any row fails to decode or its digest
  does not match; it never silently skips the row. The SDK's
  skip-undecodable-rows behavior is the weakness this slice deliberately
  does not adopt.
- [Northstar] Fail-closed exclusion. Passing a session together with any
  run-level continuation option raises; the module never silently picks
  one side.
- [Northstar] A session ID selects history and nothing more. The module
  performs no identity check and no authorization: the caller must
  authorize access to a session before handing its ID to this module.
- [Northstar] The merge callback may only reorder or filter *old*
  history. It never changes the rule that only the current turn's new
  items are persisted.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence

__all__ = [
    "SESSION_ITEM_ROLES",
    "Session",
    "SessionBackend",
    "SessionConfigError",
    "SessionContentError",
    "SessionEmptyError",
    "SessionError",
    "SessionExclusionError",
    "SessionIntegrityError",
    "SessionItem",
    "SessionSettings",
    "SessionStore",
    "MemorySessionBackend",
    "RunResult",
    "begin_turn",
    "end_turn",
    "run_session",
]

#: The roles a session item may carry. Mirrors the transcript record
#: vocabulary of ``sessions.py`` (user_prompt / assistant / tool_result
#: and friends) without importing it: ``sessions.py`` owns the JSONL
#: transcript, this module owns the conversation memory.
SESSION_ITEM_ROLES: tuple[str, ...] = ("user", "assistant", "tool_call", "tool_result")

#: Session IDs select history and nothing else. The shape mirrors
#: ``sessions.SESSION_ID_PATTERN`` so one identifier never has two
#: spellings across the two subsystems.
_SESSION_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

#: Separator between the pinned fields. A unit separator cannot appear in
#: a role or in a JSON payload's rendered text in a way that would make
#: two different rows pin identically.
_PIN_SEP = "\x1f"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SessionError(Exception):
    """Base class for every refusal this module raises."""


class SessionConfigError(SessionError):
    """An invalid setting (a bad ``limit``, a bad session ID)."""


class SessionExclusionError(SessionError):
    """A session was combined with a server-side continuation option."""


class SessionEmptyError(SessionError):
    """``pop_item`` was called on an empty session.

    The protocol refuses to answer with ``None``: ``None`` would be
    indistinguishable from a stored item whose content is ``None``.
    """


class SessionIntegrityError(SessionError):
    """A stored row failed to decode or its digest pin did not match.

    Raised by the whole ``get_items`` call, never per row: a caller
    must not be handed a silently shortened history.
    """


class SessionContentError(SessionError):
    """An item's content is not JSON-serializable."""


# ---------------------------------------------------------------------------
# Items and settings
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SessionItem:
    """One stored conversation item.

    ``seq`` is the monotonic insertion order: it is assigned by the
    store, never by the caller, and it is what lets the module tell an
    already-stored item from a new one. ``seq == -1`` means "not stored
    yet" (a freshly built turn input). ``digest`` is the Northstar
    ``sha256:`` pin over the row's exact stored bytes.
    """

    role: str
    content: Any = None
    seq: int = -1
    digest: str = ""

    def __post_init__(self) -> None:
        if self.role not in SESSION_ITEM_ROLES:
            raise SessionConfigError(
                f"unknown session item role {self.role!r}; expected one of {SESSION_ITEM_ROLES}"
            )
        if not isinstance(self.seq, int) or isinstance(self.seq, bool):
            raise SessionConfigError(f"session item seq must be an int, got {self.seq!r}")


@dataclass(frozen=True)
class SessionSettings:
    """Per-session retrieval settings.

    ``limit=None`` retrieves the whole history; ``limit=N`` retrieves
    only the most recent N items. A per-run override replaces the
    session default only when its own limit is not ``None``.
    """

    limit: int | None = None

    def __post_init__(self) -> None:
        if self.limit is None:
            return
        if isinstance(self.limit, bool) or not isinstance(self.limit, int):
            raise SessionConfigError(
                f"session limit must be a non-negative int or None, got {self.limit!r}"
            )
        if self.limit < 0:
            raise SessionConfigError(f"session limit must be non-negative, got {self.limit!r}")

    def resolved_limit(self, override: "SessionSettings | None") -> int | None:
        """Return the effective limit: a non-None override wins."""
        if override is not None and override.limit is not None:
            return override.limit
        return self.limit


def _canonical(value: Any) -> str:
    """Render a JSON-serializable value to its canonical text."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise SessionContentError(f"session item content is not JSON-serializable: {exc}") from exc


def _pin(seq: int, role: str, content_text: str) -> str:
    """The Northstar ``sha256:`` pin over a row's exact stored bytes."""
    material = f"{seq}{_PIN_SEP}{role}{_PIN_SEP}{content_text}".encode("utf-8")
    return "sha256:" + hashlib.sha256(material).hexdigest()


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------


class SessionBackend:
    """The pluggable storage interface behind a :class:`SessionStore`.

    A backend stores *rows*: a JSON document per item plus the digest
    pin computed over that document. The store owns the protocol
    semantics (ordering, limit, fail-closed reading); a backend owns
    only the bytes.

    The interface is deliberately small so that a durable backend (a
    SQLite file, a KV store) can be added without re-implementing the
    protocol rules.
    """

    def append(self, rows: Sequence[Mapping[str, Any]]) -> None:
        """Append rows in order. Each row carries ``seq``, ``role``,
        ``content`` (a JSON document) and ``digest``."""
        raise NotImplementedError

    def read(self) -> list[Mapping[str, Any]]:
        """Return every stored row, in insertion order."""
        raise NotImplementedError

    def delete_last(self) -> Mapping[str, Any] | None:
        """Remove and return the most recently inserted row, or ``None``
        when the backend is empty."""
        raise NotImplementedError

    def clear(self) -> None:
        """Remove every stored row."""
        raise NotImplementedError


class MemorySessionBackend(SessionBackend):
    """In-memory backend: rows live in a list, in insertion order."""

    def __init__(self) -> None:
        self._rows: list[dict[str, Any]] = []

    def append(self, rows: Sequence[Mapping[str, Any]]) -> None:
        for row in rows:
            self._rows.append(dict(row))

    def read(self) -> list[Mapping[str, Any]]:
        return [dict(row) for row in self._rows]

    def delete_last(self) -> Mapping[str, Any] | None:
        if not self._rows:
            return None
        return self._rows.pop()

    def clear(self) -> None:
        self._rows.clear()


@dataclass
class Session:
    """A conversation-memory session: an ID, a backend, and settings.

    The session ID *selects history and nothing else*. It never
    authenticates and never authorizes: the caller must have authorized
    access to this ID before constructing or using the session.
    """

    session_id: str
    backend: SessionBackend = field(default_factory=MemorySessionBackend)
    settings: SessionSettings = field(default_factory=SessionSettings)

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, str) or not _SESSION_ID_PATTERN.match(self.session_id):
            raise SessionConfigError(f"invalid session id {self.session_id!r}")
        if not isinstance(self.settings, SessionSettings):
            raise SessionConfigError("session settings must be a SessionSettings instance")

    @property
    def store(self) -> SessionStore:
        """The protocol store backing this session."""
        return SessionStore(self.backend, self.settings, self.session_id)

    def __len__(self) -> int:
        return len(self.store)


# ---------------------------------------------------------------------------
# The store: the four protocol operations
# ---------------------------------------------------------------------------


class SessionStore:
    """The session protocol: ``get_items`` / ``add_items`` / ``pop_item``
    / ``clear_session``, over a pluggable backend.

    The store owns the two rules that make the protocol safe:

    - **Monotonic seq.** Every appended batch gets the next sequence
      numbers. A stored item's ``seq`` is therefore the identity that
      tells an already-stored item from a new one, and it is what
      guarantees that a merge callback can never cause an old item to be
      booked as new input.
    - **Fail-closed reads.** ``get_items`` verifies every row's digest
      pin and refuses the whole call on the first mismatch or decode
      failure. It never skips the row and returns a shorter history.
    """

    def __init__(
        self,
        backend: SessionBackend | None = None,
        settings: SessionSettings | None = None,
        session_id: str = "session",
    ) -> None:
        self._backend = backend if backend is not None else MemorySessionBackend()
        self._settings = settings if settings is not None else SessionSettings()
        if not isinstance(session_id, str) or not _SESSION_ID_PATTERN.match(session_id):
            raise SessionConfigError(f"invalid session id {session_id!r}")
        if not isinstance(self._settings, SessionSettings):
            raise SessionConfigError("session settings must be a SessionSettings instance")
        self._session_id = session_id
        # A store may be opened over a backend that already holds rows
        # (a reopened durable session). The sequence counter must start
        # above every seq already stored, or a new item would reuse a
        # seq and the order check could not tell the rows apart.
        self._next_seq = 0
        for row in self._backend.read():
            seq = row.get("seq") if isinstance(row, Mapping) else None
            if isinstance(seq, int) and not isinstance(seq, bool):
                self._next_seq = max(self._next_seq, seq + 1)

    # -- properties ------------------------------------------------------
    @property
    def session_id(self) -> str:
        """The session ID. It selects history; it grants nothing."""
        return self._session_id

    @property
    def settings(self) -> SessionSettings:
        return self._settings

    @property
    def backend(self) -> SessionBackend:
        return self._backend

    def __len__(self) -> int:
        return len(self._backend.read())

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"SessionStore(session_id={self._session_id!r}, items={len(self)})"

    # -- operation 1: get_items -----------------------------------------
    def get_items(self, limit: int | None = None) -> list[SessionItem]:
        """Return the stored items in insertion order.

        ``limit=None`` returns every item; ``limit=N`` returns only the
        most recent N. A row that fails to decode, or whose digest pin
        does not match, refuses the whole call with
        :class:`SessionIntegrityError` -- the history is never silently
        shortened.
        """
        if limit is not None:
            if isinstance(limit, bool) or not isinstance(limit, int):
                raise SessionConfigError(
                    f"session limit must be a non-negative int or None, got {limit!r}"
                )
            if limit < 0:
                raise SessionConfigError(f"session limit must be non-negative, got {limit!r}")

        rows = self._backend.read()
        items: list[SessionItem] = []
        for index, row in enumerate(rows):
            items.append(self._decode_row(row, index))
        self._check_order(items)
        if limit is not None:
            items = items[-limit:] if limit else []
        return items

    @staticmethod
    def _check_order(items: Sequence[SessionItem]) -> None:
        """Refuse a history whose sequence numbers are out of order.

        Each row's pin covers its own ``seq``, so a row that travelled
        on its own is still internally consistent. The *order* of the
        rows is what the seq pins: a strictly increasing seq run means
        the history is the one that was written. An external reordering
        breaks that and is refused rather than returned.
        """
        for previous, current in zip(items, items[1:]):
            if current.seq <= previous.seq:
                raise SessionIntegrityError(
                    "session history is out of order: seq "
                    f"{current.seq} follows {previous.seq}"
                )

    def _decode_row(self, row: Mapping[str, Any], index: int) -> SessionItem:
        """Decode and verify one row. Any doubt refuses the whole call."""
        if not isinstance(row, Mapping):
            raise SessionIntegrityError(
                f"session row {index} is not a mapping: {type(row).__name__}"
            )
        missing = [key for key in ("seq", "role", "content", "digest") if key not in row]
        if missing:
            raise SessionIntegrityError(
                f"session row {index} is missing field(s) {', '.join(missing)}"
            )
        seq = row["seq"]
        role = row["role"]
        content = row["content"]
        digest = row["digest"]
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SessionIntegrityError(f"session row {index} has a non-integer seq {seq!r}")
        if not isinstance(role, str):
            raise SessionIntegrityError(f"session row {index} has a non-string role {role!r}")
        if not isinstance(digest, str) or not digest:
            raise SessionIntegrityError(f"session row {index} has no digest pin")
        if role not in SESSION_ITEM_ROLES:
            raise SessionIntegrityError(f"session row {index} has unknown role {role!r}")
        try:
            content_text = _canonical(content)
        except SessionContentError as exc:
            raise SessionIntegrityError(
                f"session row {index} content does not decode as JSON: {exc}"
            ) from exc
        expected = _pin(seq, role, content_text)
        if not hmac.compare_digest(expected, digest):
            raise SessionIntegrityError(
                f"session row {index} digest mismatch: expected {expected}, found {digest}"
            )
        return SessionItem(role=role, content=content, seq=seq, digest=digest)

    # -- operation 2: add_items -----------------------------------------
    def add_items(self, items: Iterable[Any]) -> list[SessionItem]:
        """Append a batch of items and return them with their new seqs.

        Accepts :class:`SessionItem` instances or plain ``(role,
        content)`` pairs. An item that already carries a ``seq`` is
        booked as *new*: the store assigns the next sequence number
        itself, so a stale seq can never make an old row look new, and
        a merged history can never be booked twice.
        """
        rows: list[dict[str, Any]] = []
        booked: list[SessionItem] = []
        for raw in items:
            role, content = self._split_item(raw)
            content_text = _canonical(content)
            seq = self._next_seq
            digest = _pin(seq, role, content_text)
            rows.append({"seq": seq, "role": role, "content": content, "digest": digest})
            booked.append(SessionItem(role=role, content=content, seq=seq, digest=digest))
            self._next_seq += 1
        if rows:
            self._backend.append(rows)
        return booked

    @staticmethod
    def _split_item(raw: Any) -> tuple[str, Any]:
        if isinstance(raw, SessionItem):
            return raw.role, raw.content
        if isinstance(raw, Mapping):
            if "role" not in raw:
                raise SessionConfigError("session item mapping needs a 'role' key")
            return str(raw["role"]), raw.get("content")
        if isinstance(raw, (tuple, list)) and len(raw) == 2:
            role, content = raw
            return str(role), content
        raise SessionConfigError(
            f"cannot read a session item from {type(raw).__name__}; "
            "expected a SessionItem or a (role, content) pair"
        )

    # -- operation 3: pop_item ------------------------------------------
    def pop_item(self) -> SessionItem:
        """Remove and return the most recently stored item.

        Raises :class:`SessionEmptyError` on an empty session rather
        than answering ``None``: a ``None`` answer would be
        indistinguishable from a stored item whose content is ``None``.
        """
        row = self._backend.delete_last()
        if row is None:
            raise SessionEmptyError("cannot pop from an empty session")
        item = self._decode_row(row, 0)
        # The sequence counter never goes backwards: a popped item's seq
        # is retired for good, so a later item can never reuse it.
        self._next_seq = max(self._next_seq, item.seq + 1)
        return item

    # -- operation 4: clear_session -------------------------------------
    def clear_session(self) -> None:
        """Remove every stored item from the session."""
        self._backend.clear()


# ---------------------------------------------------------------------------
# The runner contract
# ---------------------------------------------------------------------------

#: The run-level continuation options. A session may not be combined
#: with any of them in the same run: the server would then hold two
#: competing histories of the same conversation.
CONTINUATION_OPTIONS: tuple[str, ...] = (
    "conversation_id",
    "previous_response_id",
    "auto_previous_response_id",
)


def _check_exclusion(
    session: SessionStore | None,
    *,
    conversation_id: Any = None,
    previous_response_id: Any = None,
    auto_previous_response_id: Any = None,
) -> None:
    """Refuse a run that combines a session with server-side continuation.

    Fail-closed: the run is rejected, the module never silently picks
    one of the two mechanisms.
    """
    if session is None:
        return
    given = {
        "conversation_id": conversation_id,
        "previous_response_id": previous_response_id,
        "auto_previous_response_id": auto_previous_response_id,
    }
    present = [name for name, value in given.items() if value is not None]
    if present:
        raise SessionExclusionError(
            "a session may not be combined with the run-level continuation "
            f"option(s) {', '.join(present)}; use one mechanism, not both"
        )


@dataclass
class RunResult:
    """What one turn produced: the model input and the booked items.

    ``model_input`` is what went to the model (history merged with the
    new input). ``stored`` is the batch the store booked -- and only the
    current turn's new items ever appear in it.
    """

    model_input: list[Any]
    stored: list[SessionItem]
    history: list[SessionItem] = field(default_factory=list)


def begin_turn(
    session: SessionStore,
    new_input: Sequence[Any] | None = None,
    *,
    settings: SessionSettings | None = None,
    merge_callback: Callable[[list[Any], list[Any]], list[Any]] | None = None,
    conversation_id: Any = None,
    previous_response_id: Any = None,
    auto_previous_response_id: Any = None,
) -> list[Any]:
    """Retrieve the history, prepend it to the new input, return the
    model input.

    The history is retrieved according to the session's ``limit``
    setting, overridden per run by a non-``None`` ``settings.limit``.
    The merge callback, when given, receives *copies* of the history and
    the new input and returns the list of input items for the model.
    Whatever the callback returns controls the model input only: the
    store is not touched here, so reordering or filtering old history
    can never re-book an old item.
    """
    _check_exclusion(
        session,
        conversation_id=conversation_id,
        previous_response_id=previous_response_id,
        auto_previous_response_id=auto_previous_response_id,
    )
    limit = session.settings.resolved_limit(settings)
    history = session.get_items(limit=limit)
    history_input = [item.content for item in history]
    new_items = list(new_input or [])
    if merge_callback is None:
        return history_input + new_items
    merged = merge_callback(list(history_input), list(new_items))
    if merged is None:
        raise SessionConfigError("the session merge callback returned None")
    return list(merged)


def end_turn(
    session: SessionStore,
    new_items: Iterable[Any],
    *,
    conversation_id: Any = None,
    previous_response_id: Any = None,
    auto_previous_response_id: Any = None,
) -> list[SessionItem]:
    """Book only the current turn's new items.

    History is never re-booked: the store assigns a fresh, monotonic
    ``seq`` to every booked item, and ``end_turn`` books exactly the
    items it was handed -- the ones that belong to this turn.
    """
    _check_exclusion(
        session,
        conversation_id=conversation_id,
        previous_response_id=previous_response_id,
        auto_previous_response_id=auto_previous_response_id,
    )
    return session.add_items(new_items)


def run_session(
    session: SessionStore,
    new_input: Sequence[Any] | None = None,
    *,
    new_items: Iterable[Any] | None = None,
    settings: SessionSettings | None = None,
    merge_callback: Callable[[list[Any], list[Any]], list[Any]] | None = None,
    conversation_id: Any = None,
    previous_response_id: Any = None,
    auto_previous_response_id: Any = None,
) -> RunResult:
    """Run one turn: retrieve first, then store.

    The order is fixed: the history is retrieved *before* the new items
    are booked, so the model input can never contain the current turn's
    own output, and the current turn's items are booked exactly once.
    """
    model_input = begin_turn(
        session,
        new_input,
        settings=settings,
        merge_callback=merge_callback,
        conversation_id=conversation_id,
        previous_response_id=previous_response_id,
        auto_previous_response_id=auto_previous_response_id,
    )
    history = session.get_items(limit=session.settings.resolved_limit(settings))
    stored = end_turn(
        session,
        new_items if new_items is not None else new_input or [],
        conversation_id=conversation_id,
        previous_response_id=previous_response_id,
        auto_previous_response_id=auto_previous_response_id,
    )
    return RunResult(model_input=model_input, stored=stored, history=history)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def _self_check() -> None:
    """Drive the three real paths end to end."""
    # (a) Two turns: the second turn's model input carries the first
    #     turn's history, and only the new items are booked.
    store = SessionStore()
    turn1 = run_session(
        store,
        ["金门大桥在哪个城市？"],
        new_items=[
            SessionItem(role="user", content="金门大桥在哪个城市？"),
            SessionItem(role="assistant", content="旧金山。"),
        ],
    )
    assert turn1.model_input == ["金门大桥在哪个城市？"], turn1.model_input
    turn2 = run_session(
        store,
        ["在哪个州？"],
        new_items=[
            SessionItem(role="user", content="在哪个州？"),
            SessionItem(role="assistant", content="加利福尼亚州。"),
        ],
    )
    assert turn2.model_input == [
        "金门大桥在哪个城市？",
        "旧金山。",
        "在哪个州？",
    ], turn2.model_input
    assert len(store.get_items()) == 4, store.get_items()
    assert [item.seq for item in store.get_items()] == [0, 1, 2, 3]

    # (b) The merge callback controls the model input only.
    def keep_last_ten(history, new_input):
        return list(history)[-10:] + list(new_input)

    merged_store = SessionStore()
    merged_store.add_items(
        [SessionItem(role="user", content=f"旧历史 {index}") for index in range(15)]
    )
    merged = begin_turn(merged_store, ["新问题"], merge_callback=keep_last_ten)
    assert len(merged) == 11, len(merged)
    assert merged[-1] == "新问题"
    assert len(merged_store.get_items()) == 15

    # (c) A correction: pop the assistant reply, then the user question.
    corrected = SessionStore()
    corrected.add_items(
        [
            SessionItem(role="user", content="问错的问题"),
            SessionItem(role="assistant", content="错答"),
        ]
    )
    assert corrected.pop_item().role == "assistant"
    assert corrected.pop_item().role == "user"
    assert len(corrected.get_items()) == 0
    after = run_session(
        corrected,
        ["修正后的问题"],
        new_items=[
            SessionItem(role="user", content="修正后的问题"),
            SessionItem(role="assistant", content="正答"),
        ],
    )
    assert after.model_input == ["修正后的问题"], after.model_input
    assert [item.content for item in corrected.get_items()] == ["修正后的问题", "正答"]


def main() -> None:
    _self_check()
    print(
        "session-memory OK: 4-op protocol, runner contract, merge callback, "
        "most-recent-N limit, fail-closed exclusion, digest-pinned history"
    )


if __name__ == "__main__":
    main()
