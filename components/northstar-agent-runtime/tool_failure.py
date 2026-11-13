"""Typed tool-failure normalization: every failure becomes a remedy-carrying tool_result.

Before this module existed, a tool failure had exactly one shape at the Northstar
dispatch boundary: an exception. ``UnknownToolError``, ``BadArgumentsError`` and
``ProviderFault`` are three different events -- a model asked for something that does
not exist, a model wrote a call that does not validate, the provider was down -- and
all three arrived as a raised exception that a caller had to guess at. Downstream,
"the tool was refused" (a policy decision, auditable) and "the tool crashed"
(an infrastructure event) were the same word, and a permission denial was
indistinguishable from a rejected input, so a denied tool could be retried forever.

The rule this module encodes is the one Claude Code's typed tool-failure
normalization encodes: **a failure is never an exception, a crash, or a bare
string.** Every failure path produces a *tool_result*: ``is_error: true``, the
content wrapped in a ``<tool_use_error>...</tool_use_error>`` envelope, a plain-text
summary, an optional denial kind, and an optional structured remedy that says what
to do next. Recovery is by classification plus remedy -- the model retries what the
remedy tells it to retry; the harness never silently re-executes a failed call.

Vocabularies. Two of the vocabularies here are transcribed verbatim from the
Claude Code bundle (v2.1.322, ``@anthropic-ai/claude-code-linux-x64``): the
denial-kind taxonomy and the remedy kinds. They are marked ``CC verbatim`` below and
in ``docs/design/tool-failure-normalization.md``. Anything that is *not* in that
bundle is marked ``Northstar extension`` -- it is never presented as Claude Code's.

* Denial kinds (CC verbatim): ``interrupted``, ``user-rejected``,
  ``permission-rule``, ``cancelled``. A denial may also end the turn:
  "denied" and "denied, stop the turn" are two different states, so
  :attr:`ToolFailure.ends_turn` is carried separately from the kind.
* Remedy kinds (CC verbatim): ``memory_paused``, ``staged_for_review`` (with a
  ``path``), ``sandbox_violation``, ``auth_expired`` (with a ``provider``),
  ``auth_overridden`` (with a ``provider`` and a ``managed`` flag).
* Remedy kinds (Northstar extension): ``invalid_input``, ``unknown_tool``,
  ``compaction_required``. Claude Code has no state word for "the call you wrote
  does not validate"; Northstar needs one, so it says so out loud.

A *retryable* provider fault (throttling, 5xx) is deliberately **not** a remedy
kind. It is expressed on the failure record itself: ``retryable=True`` plus the
suggested wait (``retry_after_ms``). A sixth remedy word for "wait and try again"
would be a claim about the failure's remedy that the failure does not make.

The classification is closed: every kind in every vocabulary is listed here, and a
failure never guesses a kind. A validation failure and a provider fault carry an
``error_code`` and (where one applies) a remedy, with ``denial_kind`` explicitly
``None`` -- "we could not tell" is not a denial.

No imports from the rest of the runtime: this module is imported *by* ``tool_use``
and ``provider_retry``, so it takes provider faults by duck typing
(``kind`` / ``retry_after_ms`` / ``detail`` / ``status_code`` / ``retryable_by_default``)
instead of importing ``provider_retry`` and closing a cycle.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

#: Version pin for this module's record shape.
TOOL_FAILURE_VERSION = "tool-failure.v1"

#: Schema pin carried by failure records.
TOOL_FAILURE_SCHEMA = "northstar.tool-failure.v1"

#: The envelope tag Claude Code wraps failed tool content in (CC verbatim).
ENVELOPE_TAG = "tool_use_error"

#: Denial kinds (CC verbatim, from the Claude Code bundle's ``toolDenialKind``).
#: A denial kind appears only when the failure *is* a denial.
DENIAL_KINDS: tuple[str, ...] = (
    "interrupted",
    "user-rejected",
    "permission-rule",
    "cancelled",
)

#: Remedy kinds transcribed verbatim from Claude Code's ``toolResultRemedy``.
CC_REMEDY_KINDS: tuple[str, ...] = (
    "memory_paused",
    "staged_for_review",
    "sandbox_violation",
    "auth_expired",
    "auth_overridden",
)

#: Remedy kinds that are Northstar's own, not Claude Code's. Kept in a separate
#: tuple on purpose: a reader can see at a glance which words are borrowed and
#: which are ours.
NORTHSTAR_REMEDY_KINDS: tuple[str, ...] = (
    "invalid_input",
    "unknown_tool",
    "compaction_required",
)

#: Every remedy kind this runtime may emit.
REMEDY_KINDS: tuple[str, ...] = CC_REMEDY_KINDS + NORTHSTAR_REMEDY_KINDS

#: The error code Claude Code emits for a failed input validation (CC verbatim:
#: ``toolUseResult: "InputValidationError: <message>"``).
INPUT_VALIDATION_ERROR = "InputValidationError"


class ToolFailureError(ValueError):
    """Raised when a failure record would carry a kind outside the closed set."""


@dataclass(frozen=True)
class ToolResultRemedy:
    """The structured remedy: what the model (or harness) should do next.

    Only the fields a remedy kind actually carries are set, so the serialized
    form never claims a ``path`` for a kind that has none.
    """

    kind: str
    #: ``staged_for_review`` only (CC verbatim).
    path: Optional[str] = None
    #: ``auth_expired`` / ``auth_overridden`` only (CC verbatim).
    provider: Optional[str] = None
    #: ``auth_overridden`` only (CC verbatim): the credential is managed.
    managed: Optional[bool] = None

    def __post_init__(self) -> None:
        if self.kind not in REMEDY_KINDS:
            raise ToolFailureError(
                f"unknown remedy kind {self.kind!r}; this runtime emits: "
                f"{', '.join(REMEDY_KINDS)}")

    @property
    def is_cc_verbatim(self) -> bool:
        """True when the kind is one of Claude Code's own words."""
        return self.kind in CC_REMEDY_KINDS

    def as_dict(self) -> Dict[str, Any]:
        """The remedy as data, with only the fields this kind carries."""
        payload: Dict[str, Any] = {"kind": self.kind}
        if self.path is not None:
            payload["path"] = self.path
        if self.provider is not None:
            payload["provider"] = self.provider
        if self.managed is not None:
            payload["managed"] = bool(self.managed)
        return payload


@dataclass(frozen=True)
class ToolFailure:
    """One failed tool call, as a typed result instead of an exception.

    Every field is either a closed-vocabulary kind or plain data. There is no
    "unknown" wildcard: a failure that could not be classified carries an
    ``error_code`` that says so, and ``denial_kind`` stays ``None`` rather than
    being guessed.
    """

    #: Machine-readable failure code (e.g. ``InputValidationError``,
    #: ``unknown_tool``, ``auth``). Always set.
    error_code: str
    #: The plain-text summary Claude Code calls ``toolUseResult``.
    summary: str
    #: A denial kind, or ``None`` when the failure is not itself a denial.
    denial_kind: Optional[str] = None
    #: True when the denial also ends the turn ("denied, stop the turn"). A
    #: denial that does not end the turn leaves the model free to try
    #: something else, which is exactly the loop a permission denial must not
    #: cause.
    ends_turn: bool = False
    #: The structured remedy, when there is one.
    remedy: Optional[ToolResultRemedy] = None
    #: True for a transient provider fault the retry policy may repeat.
    retryable: bool = False
    #: The wait the provider asked for (or the policy's advice), in ms.
    retry_after_ms: Optional[int] = None
    #: The tool the call named, when known.
    tool_name: str = ""
    #: The tool_use id the call carried, when known.
    tool_use_id: str = ""
    #: Extra machine-readable detail (never raw arguments).
    detail: Dict[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.denial_kind is not None and self.denial_kind not in DENIAL_KINDS:
            raise ToolFailureError(
                f"unknown denial kind {self.denial_kind!r}; this runtime "
                f"emits: {', '.join(DENIAL_KINDS)}")
        if self.detail is None:
            object.__setattr__(self, "detail", {})

    # -- the result shape ---------------------------------------------------

    @property
    def is_error(self) -> bool:
        """Always True: this record *is* a failure."""
        return True

    @property
    def content(self) -> str:
        """The enveloped content, as Claude Code wraps it."""
        return f"<{ENVELOPE_TAG}>{self.summary}</{ENVELOPE_TAG}>"

    def to_tool_result(self) -> Dict[str, Any]:
        """The typed tool_result a harness hands back to the model.

        ``toolDenialKind`` is present and explicitly ``None`` for a failure
        that is not a denial: "we could not tell" must not read as "denied".
        """
        payload: Dict[str, Any] = {
            "is_error": True,
            "content": self.content,
            "toolUseResult": self.summary,
            "toolDenialKind": self.denial_kind,
            "toolDenialEndsTurn": bool(self.ends_turn),
            "toolResultRemedy": (self.remedy.as_dict()
                                 if self.remedy is not None else None),
            "errorCode": self.error_code,
            "retryable": bool(self.retryable),
        }
        if self.retry_after_ms is not None:
            payload["retryAfterMs"] = int(self.retry_after_ms)
        if self.tool_name:
            payload["toolName"] = self.tool_name
        if self.tool_use_id:
            payload["toolUseId"] = self.tool_use_id
        if self.detail:
            payload["detail"] = dict(self.detail)
        return payload

    def to_telemetry_event(self, *, message_id: str = "",
                           is_mcp: bool = False) -> Dict[str, Any]:
        """The failure event, in the shape of Claude Code's ``tengu_tool_use_error``.

        No new telemetry sink is created here: this is data an existing sink
        may carry. The event names the message, the tool_use id, the tool, the
        error code, and the denial kind -- never the arguments.
        """
        payload: Dict[str, Any] = {
            "event": "tengu_tool_use_error",
            "messageId": message_id,
            "toolUseID": self.tool_use_id,
            "toolName": self.tool_name,
            "errorCode": self.error_code,
            "isMcp": bool(is_mcp),
            "toolDenialKind": self.denial_kind,
            "toolDenialEndsTurn": bool(self.ends_turn),
        }
        if self.retryable:
            payload["retryable"] = True
        if self.retry_after_ms is not None:
            payload["retryAfterMs"] = int(self.retry_after_ms)
        return payload


# ---------------------------------------------------------------------------
# constructors
# ---------------------------------------------------------------------------


def _error_code_for(error: BaseException) -> str:
    """The machine-readable code for a tool-use error."""
    return type(error).__name__


def _tool_error_summary(error: BaseException) -> str:
    """The plain-text summary for a tool-use error."""
    return f"{type(error).__name__}: {error}"


def from_tool_error(error: BaseException, *, tool_name: str = "",
                    tool_use_id: str = "") -> ToolFailure:
    """Map the tool-use error hierarchy onto a typed failure.

    The mapping is closed and never guesses a denial:

    * ``UnknownToolError`` -> error code ``unknown_tool``, remedy
      ``unknown_tool`` (Northstar extension): the model named a tool that
      does not exist, and the only way forward is to pick another one.
    * ``BadArgumentsError`` -> the Claude Code input-validation shape:
      ``toolUseResult`` reads ``InputValidationError: <message>`` and the
      remedy is ``invalid_input`` (Northstar extension). A call that does not
      validate is not a denial.
    * ``DuplicateToolError`` / ``BadSchemaError`` / ``BadToolError`` ->
      their own class name as the error code and **no** remedy: these are
      programming errors on the host side, and there is nothing the model
      can do about them.
    * ``SeqOrderError`` / ``AuditKindError`` -> likewise, no remedy.

    A denial kind is never produced here: a validation failure and a
    programming error are not denials, and the record says so by leaving
    ``denial_kind`` at ``None``.
    """
    name = type(error).__name__
    message = str(error)
    if name == "UnknownToolError":
        return ToolFailure(
            error_code="unknown_tool",
            summary=f"unknown_tool: {message}",
            remedy=ToolResultRemedy(kind="unknown_tool"),
            tool_name=tool_name, tool_use_id=tool_use_id,
            detail={"error": name},
        )
    if name == "BadArgumentsError":
        return ToolFailure(
            error_code=INPUT_VALIDATION_ERROR,
            summary=f"{INPUT_VALIDATION_ERROR}: {message}",
            remedy=ToolResultRemedy(kind="invalid_input"),
            tool_name=tool_name, tool_use_id=tool_use_id,
            detail={"error": name},
        )
    return ToolFailure(
        error_code=_error_code_for(error),
        summary=_tool_error_summary(error),
        tool_name=tool_name, tool_use_id=tool_use_id,
        detail={"error": name},
    )


def from_provider_fault(fault: Any, *, provider: str = "",
                        tool_name: str = "",
                        tool_use_id: str = "") -> ToolFailure:
    """Map a provider fault (``ProviderFault``) onto a typed failure.

    The retry budget is not touched here -- this only says what the failure
    *is* and what to do about it:

    * ``auth`` -> remedy ``auth_expired`` with the provider (CC verbatim).
      No credential is fixed by retrying, and no retry happens here either.
    * ``context_overflow`` -> remedy ``compaction_required`` (Northstar
      extension): the request is too big, and the answer is to shrink it.
    * ``stream_interrupted`` -> denial kind ``interrupted``: the connection
      died after text had already been forwarded, so the turn was cut, not
      refused.
    * ``rate_limited`` / ``overloaded`` / ``server_error`` / ``network`` /
      ``timeout`` -> ``retryable=True`` with the suggested wait. **No remedy
      kind is invented for these**: a wait is not one of Claude Code's five
      remedy words, and pretending otherwise would dress a Northstar choice
      up as a transcribed one.
    * anything else -> the fault's own class name as the error code, no
      remedy, and no denial kind.
    """
    kind = getattr(fault, "kind", "") or type(fault).__name__
    detail = getattr(fault, "detail", "") or ""
    status = getattr(fault, "status_code", None)
    retry_after = getattr(fault, "retry_after_ms", None)
    retryable = bool(getattr(fault, "retryable_by_default", False))
    detail_fields = {"fault": kind}
    if status is not None:
        detail_fields["status_code"] = status
    if kind == "auth":
        return ToolFailure(
            error_code="auth",
            summary=f"{kind}" + (f": {detail}" if detail else ""),
            remedy=ToolResultRemedy(kind="auth_expired", provider=provider or None),
            tool_name=tool_name, tool_use_id=tool_use_id,
            detail=detail_fields,
        )
    if kind == "context_overflow":
        return ToolFailure(
            error_code="context_overflow",
            summary=f"{kind}" + (f": {detail}" if detail else ""),
            remedy=ToolResultRemedy(kind="compaction_required"),
            tool_name=tool_name, tool_use_id=tool_use_id,
            detail=detail_fields,
        )
    if kind == "stream_interrupted":
        return ToolFailure(
            error_code="stream_interrupted",
            summary=f"{kind}" + (f": {detail}" if detail else ""),
            denial_kind="interrupted",
            ends_turn=True,
            tool_name=tool_name, tool_use_id=tool_use_id,
            detail=detail_fields,
        )
    if retryable:
        return ToolFailure(
            error_code=kind,
            summary=f"{kind}" + (f": {detail}" if detail else ""),
            retryable=True,
            retry_after_ms=retry_after,
            tool_name=tool_name, tool_use_id=tool_use_id,
            detail=detail_fields,
        )
    return ToolFailure(
        error_code=kind,
        summary=f"{kind}" + (f": {detail}" if detail else ""),
        tool_name=tool_name, tool_use_id=tool_use_id,
        detail=detail_fields,
    )


def from_denial(denial_kind: str, *, summary: str = "",
                ends_turn: bool = False,
                remedy: Optional[ToolResultRemedy] = None,
                error_code: str = "denied",
                tool_name: str = "",
                tool_use_id: str = "") -> ToolFailure:
    """Build a failure for a denial the host decided on.

    This is the path a permission gate's refusal takes: the failure *is* a
    denial, so it carries one of the four denial kinds, and it says whether
    the denial also ends the turn. "Denied" and "denied, stop the turn" are
    two different states, and the boundary must carry that difference through
    unchanged.
    """
    if denial_kind not in DENIAL_KINDS:
        raise ToolFailureError(
            f"unknown denial kind {denial_kind!r}; this runtime emits: "
            f"{', '.join(DENIAL_KINDS)}")
    text = summary or f"denied: {denial_kind}"
    return ToolFailure(
        error_code=error_code,
        summary=text,
        denial_kind=denial_kind,
        ends_turn=bool(ends_turn),
        remedy=remedy,
        tool_name=tool_name, tool_use_id=tool_use_id,
    )


__all__ = [
    "CC_REMEDY_KINDS",
    "DENIAL_KINDS",
    "ENVELOPE_TAG",
    "INPUT_VALIDATION_ERROR",
    "NORTHSTAR_REMEDY_KINDS",
    "REMEDY_KINDS",
    "TOOL_FAILURE_SCHEMA",
    "TOOL_FAILURE_VERSION",
    "ToolFailure",
    "ToolFailureError",
    "ToolResultRemedy",
    "from_denial",
    "from_provider_fault",
    "from_tool_error",
]
