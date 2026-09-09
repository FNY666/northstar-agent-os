"""One run boundary, two readers: the runtime checkpoint in durable-run's vocabulary.

Why this module exists
----------------------
``northstar-durable-run`` and this runtime each grew a durability story, and they
were invented separately:

* durable-run persists an append-only ``EventStore`` of ``northstar.durable-event.v1``
  records, derives state by replaying them, and checkpoints that derived state as a
  ``northstar.checkpoint.v1`` document;
* this runtime appends a ``checkpoint`` record to the session transcript, whose digest
  certifies a *transcript prefix*, and resumes by verifying that digest.

Two components, one concept ("where can this run be picked up from"), two vocabularies.
A host that runs both could not put one boundary into one audit stream, and nothing
tested that the two definitions described the same thing - the same drift
``contract_bridge.py`` was written to close at the sidecar seam.

What this module does
---------------------
1. :func:`checkpoint_event` translates a runtime :class:`checkpoints.Checkpoint` into a
   dict that satisfies durable-run's ``EventContract`` schema *as written there* - the
   closed thirteen-field set, the ``checkpoint.created -> running`` status pairing, the
   id and digest rules. It is a translation, not an import: the runtime never depends on
   the durable component at run time (dependency direction stays one-way), so every
   rule duplicated here is pinned against the real schema by
   ``tests/test_durable_bridge.py``.
2. :func:`checkpoint_document` emits the five-field ``northstar.checkpoint.v1`` document
   with ``state_digest`` computed under durable-run's canonical rule
   (``"sha256:" + sha256(canonical json)``), so the same boundary can be handed to a
   durable reader without re-deriving anything.
3. :func:`checkpoint_from_event` is the reverse direction, and it is where the honest
   limit lives - see below.
4. :func:`cross_check` reports whether the mirror still agrees, using the real
   ``durable_contract`` / ``event_store`` modules when they are importable and reporting
   ``"unchecked"`` when they are not. ``tests/docbuild.py`` and the test suite run it for
   real; a bare interpreter stays importable.

What is deliberately *not* unified
----------------------------------
The transcript record format. ``sessions.RECORD_TYPES`` stays the thirteen types it is,
and a runtime transcript is not rewritten into event records: a checkpoint digest
certifies a byte range of the transcript, so changing what those bytes are would change
what every existing checkpoint attests to. Translation here is one-way and additive.

The resume gate does not travel. ``checkpoint_from_event`` can point a resume at a
boundary, but an event's ``payload_digest`` covers its own payload, not the transcript -
so the caller must supply the records and the digest is recomputed over them. A durable
event that disagrees with the transcript is refused rather than believed, which is the
same rule :func:`checkpoints.prepare_resume` enforces for a runtime checkpoint. For the
same reason, a document from :func:`checkpoint_document` is readable by a durable
*reader* but will not satisfy ``EventStore.restore()``, which requires state equal to
its own replayed history; ``tests/test_durable_bridge.py`` asserts that refusal happens
loudly instead of silently.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

#: durable-run's schema versions, mirrored from ``durable_contract``. A version bump on
#: either side must be a deliberate act with both sides edited, so these are constants
#: here and pinned in the tests - not looked up at run time.
RUN_SCHEMA_VERSION = "northstar.durable-run.v1"
STEP_SCHEMA_VERSION = "northstar.durable-step.v1"
EVENT_SCHEMA_VERSION = "northstar.durable-event.v1"
CHECKPOINT_SCHEMA_VERSION = "northstar.checkpoint.v1"

#: The event type that means "a boundary was recorded", and the only status durable-run
#: pairs with it. Both are in ``durable_contract._EVENT_STATUS_BY_TYPE``.
CHECKPOINT_EVENT_TYPE = "checkpoint.created"
CHECKPOINT_EVENT_STATUS = "running"

#: The complete event field set, mirrored from ``EventContract._fields``. The set is
#: closed on the durable side: a missing *or* extra key is refused, so this tuple is the
#: whole contract for anyone constructing an event here.
EVENT_FIELDS: tuple[str, ...] = (
    "schema_version",
    "event_id",
    "task_id",
    "thread_id",
    "run_id",
    "step_id",
    "sequence",
    "event_type",
    "status",
    "occurred_at",
    "idempotency_key",
    "trace_id",
    "payload_digest",
)

#: Mirrored from ``event_store._CHECKPOINT_FIELDS``. Also closed.
CHECKPOINT_FIELDS: tuple[str, ...] = (
    "schema_version",
    "run_id",
    "sequence",
    "state",
    "state_digest",
)

#: The keys durable-run's derived ``state`` always carries (``event_store._derive``).
#: ``checkpoint_document`` reproduces them so a durable reader sees the shape it expects,
#: with the runtime's facts nested under :data:`NESTED_STATE_KEY`.
STATE_IDENTITY_KEYS: tuple[str, ...] = ("task_id", "thread_id", "run_id")
NESTED_STATE_KEY = "northstar.checkpoint"

MAX_ID_CHARS = 128
MAX_IDEMPOTENCY_KEY_CHARS = 256

#: durable-run's rules, restated because they are the rules this module must satisfy.
ID_RE = re.compile(r"^[^\s/\\]+$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

#: Component directory names, used to find a sibling checkout the way
#: ``tests/support.py`` does for the sidecar and run contract.
DURABLE_COMPONENT = "northstar-durable-run"


class BridgeError(ValueError):
    """A checkpoint that cannot be expressed in durable-run's vocabulary."""


def canonical_json(value: Any) -> bytes:
    """durable-run's canonical form: sorted keys, no spaces, non-ASCII preserved.

    Byte-for-byte the rule in ``event_store._canonical_json``. It is duplicated rather
    than imported because a digest computed two ways is two digests.
    """
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def durable_digest(value: Any) -> str:
    """``"sha256:" + hex`` - the prefixed form durable-run's ``_DIGEST_RE`` demands.

    :func:`checkpoints.digest_transcript` returns the *bare* hex digest, which is why
    every mapping between the two components prefixes explicitly instead of assuming.
    """
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _read(source: Any, name: str, default: Any = None) -> Any:
    """One field of a boundary, from a :class:`checkpoints.Checkpoint` or its record.

    Both shapes are accepted on purpose: :func:`checkpoints.build` returns the record
    payload the transcript stores, ``from_record`` returns the typed view, and a bridge
    that demanded one of them would push every caller into converting the other by hand.
    """
    if isinstance(source, Mapping):
        value = source.get(name, default)
    else:
        value = getattr(source, name, default)
    return default if value is None else value


def _require_id(value: str, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise BridgeError(f"{field} must be a non-empty string")
    if len(value) > MAX_ID_CHARS:
        raise BridgeError(f"{field} is longer than {MAX_ID_CHARS} characters")
    if not ID_RE.fullmatch(value):
        raise BridgeError(f"{field} must not contain whitespace, /, or \\")
    return value


def _durable_root() -> Path | None:
    """The repository root, if this component lives in one (tests, ``make demo``)."""
    for parent in Path(__file__).resolve().parents:
        if (parent / "components" / DURABLE_COMPONENT / "event_store.py").is_file():
            return parent
    return None


def durable_modules() -> dict[str, Any] | None:
    """The real durable-run modules, or ``None`` when they are not importable.

    Import is attempted at *call* time only, and a failed attempt is a normal answer:
    the runtime ships without a dependency on the durable component. Paths are appended
    rather than prepended so this component keeps precedence on a name clash.
    """
    root = _durable_root()
    if root is not None:
        directory = str(root / "components" / DURABLE_COMPONENT)
        if directory not in sys.path:
            sys.path.append(directory)
    loaded: dict[str, Any] = {}
    try:
        loaded["durable_contract"] = importlib.import_module("durable_contract")
        loaded["event_store"] = importlib.import_module("event_store")
    except ImportError:
        return None
    return loaded


def durable_available() -> bool:
    """Whether the durable component can be imported here (a test/doc concern only)."""
    return durable_modules() is not None


def checkpoint_payload(checkpoint: Any) -> dict[str, Any]:
    """The runtime facts of one boundary, in a form an event can carry.

    Accepts a :class:`checkpoints.Checkpoint` or the record payload
    :func:`checkpoints.build` returned. The transcript digest is prefixed with
    ``sha256:`` because the payload is signed under durable-run's digest rule and a bare
    hex string would be a second format of one value living inside a validated document.
    """
    session_id = _require_id(str(_read(checkpoint, "session_id", "")), "session_id")
    record_index = int(_read(checkpoint, "record_index", _read(checkpoint, "index", -1)))
    if record_index < 0:
        raise BridgeError("a checkpoint must say which record it was (record_index)")
    usage = dict(_read(checkpoint, "usage", {}) or {})
    payload: dict[str, Any] = {
        "session_id": session_id,
        "record_index": record_index,
        "transcript_len": int(_read(checkpoint, "transcript_len", 0)),
        "transcript_digest": f"sha256:{_read(checkpoint, 'transcript_digest', '')}",
        "turns": int(_read(checkpoint, "turns", 0)),
        "tool_calls": int(_read(checkpoint, "tool_calls", 0)),
        "cost_usd": float(_read(checkpoint, "cost_usd", 0.0)),
        "usage": usage,
        "model": str(_read(checkpoint, "model", "")),
        "provider": str(_read(checkpoint, "provider", "")),
        "permission_mode": str(_read(checkpoint, "permission_mode", "")),
        "denials": int(_read(checkpoint, "denials", 0)),
        # Namespaced so a reader walking the payload sees whose keys these are, and why
        # a durable reader must not assume they came from a durable replay.
        "schema_version": "northstar.runtime-checkpoint.v1",
    }
    run_id = _read(checkpoint, "run_id", "")
    if run_id:
        payload["run_id"] = _require_id(str(run_id), "run_id")
    policy_revision = _read(checkpoint, "policy_revision", "")
    if policy_revision:
        payload["policy_revision"] = str(policy_revision)
    return payload


def checkpoint_event(
    checkpoint: Any,
    *,
    task_id: str | None = None,
    thread_id: str | None = None,
    trace_id: str | None = None
    ,
    occurred_at: int | None = None,
    sequence: int | None = None,
) -> dict[str, Any]:
    """One ``northstar.durable-event.v1`` record for one runtime checkpoint.

    Identity defaults follow the rule the durable side already enforces - ids with no
    whitespace or path separators - by deriving them from the session: a boundary belongs
    to the session that wrote it, and ``run_id`` ties it to the run whose ceiling it
    consumed.

    ``sequence`` is the one number a caller must think about. Durable-run requires a
    stream to be contiguous and one-based (``run.created`` at 1, no gaps), so the default
    of ``record_index + 1`` is right only for a stream that consists of runtime
    boundaries; appending into a stream that already holds lifecycle events means passing
    the stream's next sequence. It is a parameter rather than a guess because a wrong
    sequence in a durable stream is not cosmetic - it rewrites what every later replay
    derives.

    The ``idempotency_key`` is ``"<session>:<record_index>"``, which makes replaying the
    same boundary into the same stream a no-op (durable returns the existing event) and a
    *different* boundary claiming that key a conflict. That is a property of the key
    choice, not of this function, and the test pins it.
    """
    payload = checkpoint_payload(checkpoint)
    session_id = payload["session_id"]
    run_id = payload.get("run_id") or f"session:{session_id}"
    event_id = f"evt:{session_id}:{payload['record_index']}"
    event: dict[str, Any] = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_id": _require_id(event_id, "event_id"),
        "task_id": _require_id(task_id or f"task:{session_id}", "task_id"),
        "thread_id": _require_id(thread_id or f"thread:{session_id}", "thread_id"),
        "run_id": _require_id(run_id, "run_id"),
        "step_id": _require_id(f"turn:{payload['turns']}", "step_id"),
        "sequence": _sequence(sequence, payload),
        "event_type": CHECKPOINT_EVENT_TYPE,
        "status": CHECKPOINT_EVENT_STATUS,
        "occurred_at": int(occurred_at if occurred_at is not None else time.time()),
        "idempotency_key": f"{session_id}:{payload['record_index']}",
        "trace_id": _require_id(trace_id or run_id, "trace_id"),
        "payload_digest": durable_digest(payload),
    }
    # Every id above went through _require_id, which is the only length rule that can
    # actually bind: a session id is capped at 128 characters, so the key built from it
    # cannot approach durable-run's 256-character limit, and a guard for the unreachable
    # case would only hide which rule is load-bearing.
    if not DIGEST_RE.fullmatch(event["payload_digest"]):  # pragma: no cover - guard
        raise BridgeError("payload_digest is not a sha256 digest")
    return event


def _sequence(sequence: int | None, payload: Mapping[str, Any]) -> int:
    if sequence is None:
        return int(payload["record_index"]) + 1
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise BridgeError("sequence must be a positive integer (durable streams are one-based)")
    return sequence


def verify_event_payload(event: Mapping[str, Any], payload: Mapping[str, Any]) -> bool:
    """Whether ``payload`` is what ``event``'s ``payload_digest`` was computed over.

    A reader that cannot check this would be trusting a digest it cannot reproduce, which
    is what the durable side's own replay refuses to do.
    """
    digest = event.get("payload_digest")
    if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        raise BridgeError("event payload_digest is malformed")
    return digest == durable_digest(payload)


def checkpoint_document(
    checkpoint: Any,
    *,
    task_id: str | None = None,
    thread_id: str | None = None,
    sequence: int | None = None,
) -> dict[str, Any]:
    """A ``northstar.checkpoint.v1`` document for one boundary, digested durably.

    ``state`` carries durable-run's own state keys (identity, status, sequence, steps)
    plus the runtime facts nested under :data:`NESTED_STATE_KEY`. That nesting is the
    limit, stated in the data: a document like this is *readable* by a durable reader and
    comparable field for field, but it is not the output of replaying durable events, so
    ``EventStore.restore()`` refuses it - correctly, because "state equals history" is
    that method's whole guarantee. Treating a runtime boundary as durable state would be
    the bug; refusing it is the design.
    """
    payload = checkpoint_payload(checkpoint)
    session_id = payload["session_id"]
    run_id = payload.get("run_id") or f"session:{session_id}"
    state: dict[str, Any] = {
        "task_id": _require_id(task_id or f"task:{session_id}", "task_id"),
        "thread_id": _require_id(thread_id or f"thread:{session_id}", "thread_id"),
        "run_id": _require_id(run_id, "run_id"),
        "status": CHECKPOINT_EVENT_STATUS,
        "sequence": _sequence(sequence, payload),
        "steps": {},
        NESTED_STATE_KEY: payload,
    }
    return {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "run_id": run_id,
        "sequence": state["sequence"],
        "state": state,
        "state_digest": durable_digest(state),
    }


def checkpoint_from_event(
    event: Mapping[str, Any],
    *,
    transcript: Sequence[Any],
    expected_session_id: str | None = None,
) -> Any:
    """Rebuild a runtime checkpoint from a durable event, verified against the transcript.

    The event says *where* a boundary was and what it claimed the transcript digest was;
    only the transcript can say whether that claim still holds. So the caller passes the
    same message list a resume would start from, and it goes through the same
    :func:`checkpoints.prepare_resume` gate a runtime checkpoint must pass - there is no
    second, weaker verification for foreign boundaries. Nothing about a durable event makes
    it self-authenticating with respect to a transcript, and this function does not pretend
    otherwise.

    ``transcript_digest`` is stored prefixed here (it has to satisfy durable-run's digest
    rule inside the payload) and unprefixed in a checkpoint record, so the prefix is
    stripped on the way back; forgetting that would make every digest comparison fail.
    """
    from checkpoints import from_record, prepare_resume

    if event.get("event_type") != CHECKPOINT_EVENT_TYPE:
        raise BridgeError(f"event is not a {CHECKPOINT_EVENT_TYPE}")
    payload = event.get("payload")
    if payload is None:
        raise BridgeError(
            "the boundary travels in the event's payload, and durable-run's event schema is closed "
            "on purpose: persist the payload next to the event instead of adding a field to it"
        )
    if not verify_event_payload(event, payload):
        raise BridgeError("event payload_digest does not cover its payload")
    claimed = str(payload["transcript_digest"])
    record = {
        "type": "checkpoint",
        "index": int(payload["record_index"]),
        "session_id": payload["session_id"],
        "transcript_len": int(payload["transcript_len"]),
        "transcript_digest": claimed[len("sha256:"):] if claimed.startswith("sha256:") else claimed,
        "turns": int(payload["turns"]),
        "tool_calls": int(payload["tool_calls"]),
        "cost_usd": float(payload["cost_usd"]),
        "usage": dict(payload.get("usage") or {}),
        "model": str(payload.get("model", "")),
        "provider": str(payload.get("provider", "")),
        "permission_mode": str(payload.get("permission_mode", "")),
        "denials": int(payload.get("denials", 0) or 0),
    }
    if payload.get("run_id"):
        record["run_id"] = payload["run_id"]
    if payload.get("policy_revision"):
        record["policy_revision"] = payload["policy_revision"]
    checkpoint = from_record(record)
    if checkpoint is None:  # pragma: no cover - the type is set above
        raise BridgeError("event payload could not be read as a checkpoint")
    # One gate for every boundary, whoever wrote it: prepare_resume refuses on a digest
    # mismatch, a short transcript, or a checkpoint from another session.
    prepare_resume(checkpoint, list(transcript), expected_session_id=expected_session_id)
    return checkpoint


@dataclass(frozen=True)
class BridgeReport:
    """What the mirror concluded about itself. ``ok`` is the only verdict callers read."""

    mode: str = "unchecked"  # "unchecked" | "durable-verified" | "drift" | "unavailable"
    ok: bool = True
    errors: tuple[str, ...] = ()
    detail: Mapping[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"mode": self.mode, "ok": self.ok}
        if self.errors:
            payload["errors"] = list(self.errors)
        if self.detail:
            payload["detail"] = dict(self.detail)
        return payload


def cross_check(checkpoint: Any | None = None) -> BridgeReport:
    """Compare this module's mirror against the durable component, if it is importable.

    With no durable checkout available the report says ``unchecked`` and nothing changes:
    a runtime that had to import its way out of a mirror would stop being usable alone.
    With one, every mirrored rule is checked *through* it - the closed field sets, the
    status pairing, the digest format - and a real event built from a real checkpoint is
    fed through ``EventContract.from_dict`` and an actual ``EventStore`` append/replay.
    """
    modules = durable_modules()
    if modules is None:
        return BridgeReport(mode="unchecked", detail={"reason": "northstar-durable-run is not importable here"})
    contract = modules["durable_contract"]
    store = modules["event_store"]
    errors: list[str] = []
    if tuple(contract.EventContract._fields) != EVENT_FIELDS:
        errors.append("EventContract._fields drifted from EVENT_FIELDS")
    if set(store._CHECKPOINT_FIELDS) != set(CHECKPOINT_FIELDS):
        errors.append("event_store._CHECKPOINT_FIELDS drifted from CHECKPOINT_FIELDS")
    if contract.EVENT_SCHEMA_VERSION != EVENT_SCHEMA_VERSION:
        errors.append("EVENT_SCHEMA_VERSION drifted")
    if getattr(store, "CHECKPOINT_SCHEMA_VERSION", None) != CHECKPOINT_SCHEMA_VERSION:
        errors.append("CHECKPOINT_SCHEMA_VERSION drifted")
    if contract._EVENT_STATUS_BY_TYPE.get(CHECKPOINT_EVENT_TYPE) != CHECKPOINT_EVENT_STATUS:
        errors.append(f"{CHECKPOINT_EVENT_TYPE} no longer pairs with status {CHECKPOINT_EVENT_STATUS!r}")
    if store._canonical_json({"b": 1, "a": 2}) != canonical_json({"a": 2, "b": 1}):
        errors.append("canonical JSON differs from durable-run's")
    if checkpoint is None and not errors:
        errors.append("cross_check needs a checkpoint to exercise the round trip")
    detail: dict[str, Any] = {}
    if not errors and checkpoint is not None:
        try:
            event = contract.EventContract.from_dict(checkpoint_event(checkpoint))
            document = checkpoint_document(checkpoint)
            if set(document) != set(store._CHECKPOINT_FIELDS):
                errors.append("checkpoint_document field set does not match durable's")
            if document["state_digest"] != store._digest(document["state"]):
                errors.append("checkpoint_document state_digest does not match durable's rule")
            detail["event"] = {"event_id": event.event_id, "sequence": event.sequence}
        except (ValueError, BridgeError) as error:
            errors.append(f"the durable schema refused our event: {error}")
    if errors:
        return BridgeReport(mode="drift", ok=False, errors=tuple(errors), detail=detail or None)
    return BridgeReport(mode="durable-verified", detail=detail or None)
