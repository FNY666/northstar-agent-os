"""Turning a remote server's "ask the user" into a governed approval.

The idea
--------
MRTR (see :mod:`mcp_negotiate`) lets an MCP server answer a tool call with
``resultType: "input_required"`` plus a set of embedded requests - most usefully
``elicitation/create``, i.e. "ask the human for a value". Every client that supports
this treats it as a UI detail: pop a prompt, return what was typed.

This module treats it as what it actually is - **a permission request arriving from
across a socket** - and sends it through the same door a local ``Write`` goes through:
fail-closed, bounded, and recorded. That is the synthesis the blueprint calls for:
the remote question and the local mutation share one gate and one audit stream, so
"who approved this?" has the same answer for both.

The rules, and why each one exists
----------------------------------
1. **No approver, no answer.** Without a host-supplied elicitor every request is
   declined with a stated reason. A default answer is how an unattended run ends up
   handing a remote service credentials.
2. **Only ``elicitation/create`` is answerable here.** ``sampling/createMessage`` asks
   *us* to run a model on the server's behalf: unbounded cost, unbounded context, and
   a prompt we did not write. It is declined, always, and the reason names the method.
   ``roots/list`` reveals filesystem shape, so it is declined unless the host opts in,
   and even then it is answered with exactly one root - the workspace.
3. **A field that looks like a credential is refused outright** (``password``,
   ``api_key``, ``token``, ``secret``, ``private_key``, ``otp``...). A server that
   legitimately needs one can be given ``--mcp-allow-sensitive-input`` by a human; the
   default is that a text box across the network is not a credential store.
4. **The schema is bounded** (properties, depth, description length, total size). An
   unbounded ``requestedSchema`` is a prompt-injection payload wearing a form.
5. **Round trips are capped** (:data:`mcp_negotiate.MAX_INPUT_ROUNDS`). The spec
   explicitly permits a server to re-ask until it is satisfied; a client that allows
   that lets a remote process hold a human at a prompt indefinitely.
6. **Every decision is audited**, including the answer that was given - except that
   *values are never recorded*, only their field names and lengths. A transcript that
   stores what the user typed into an elicitation field is a secret store with an
   append-only API.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from mcp_negotiate import ELICITATION_METHOD, MAX_INPUT_ROUNDS, ROOTS_METHOD, SAMPLING_METHOD

#: Names that mean "type something secret into this box".
SENSITIVE_NAME_RE = re.compile(
    r"(password|passwd|passphrase|secret|api[_-]?key|access[_-]?key|token|credential|private[_-]?key"
    r"|otp|2fa|mfa|authorization|cookie|session[_-]?id|p12|pem|keychain)",
    re.IGNORECASE,
)

MAX_PROPERTIES = 16
MAX_SCHEMA_DEPTH = 3
MAX_DESCRIPTION_CHARS = 500
MAX_MESSAGE_CHARS = 2_000
MAX_SCHEMA_CHARS = 8_000
MAX_ANSWER_CHARS = 4_000

#: Actions an elicitation response may carry, per the spec's ``ElicitResult``.
ACCEPT = "accept"
DECLINE = "decline"
CANCEL = "cancel"


class ElicitationError(ValueError):
    """A malformed input request the client refuses to render at all."""


@dataclass(frozen=True)
class Field:
    """One requested value, as it will be shown to the approver."""

    name: str
    type: str
    description: str = ""
    required: bool = False
    sensitive: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "description": self.description,
            "required": self.required,
            "sensitive": self.sensitive,
        }


@dataclass(frozen=True)
class ElicitationRequest:
    """One embedded server request, decoded and bounded."""

    server: str
    tool: str
    key: str
    method: str
    message: str
    fields: tuple[Field, ...] = ()
    answerable: bool = True
    refuse_reason: str = ""
    workspace_root: str = ""

    @property
    def sensitive(self) -> bool:
        return any(field.sensitive for field in self.fields)

    def prompt(self) -> str:
        """Human-facing text. Values are never part of it."""
        head = f"mcp server {self.server!r} (tool {self.tool!r}) asks: {self.message}"
        if not self.fields:
            return head
        lines = [head, "  requested fields:"]
        for item in self.fields:
            marks = []
            if item.required:
                marks.append("required")
            if item.sensitive:
                marks.append("sensitive")
            suffix = f" [{', '.join(marks)}]" if marks else ""
            description = f" - {item.description}" if item.description else ""
            lines.append(f"    {item.name} ({item.type}){description}{suffix}")
        return "\n".join(lines)


@dataclass(frozen=True)
class ElicitationVerdict:
    """What the client decided about one request, in audit shape."""

    server: str
    tool: str
    key: str
    method: str
    action: str
    reason: str
    answered_fields: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "mcp-elicitation",
            "server": self.server,
            "tool": self.tool,
            "request_id": self.key,
            "method": self.method,
            "action": self.action,
            "reason": self.reason,
            # Field names and lengths only: never the value.
            "answered_fields": sorted(self.answered_fields),
        }


def _schema_size(schema: Mapping[str, Any]) -> int:
    import json

    return len(json.dumps(schema, sort_keys=True))


def _walk_depth(node: Any, depth: int = 1) -> int:
    if not isinstance(node, Mapping) or depth > MAX_SCHEMA_DEPTH + 2:
        return depth
    worst = depth
    for key in ("properties", "items", "additionalProperties"):
        child = node.get(key)
        if isinstance(child, Mapping):
            if key == "properties":
                for value in child.values():
                    worst = max(worst, _walk_depth(value, depth + 1))
            else:
                worst = max(worst, _walk_depth(child, depth + 1))
    return worst


def decode_request(
    key: str,
    entry: Mapping[str, Any],
    *,
    server: str,
    tool: str,
    workspace_root: str = "",
    allow_sensitive: bool = False,
) -> ElicitationRequest:
    """Validate and bound one ``inputRequests`` entry.

    Unanswerable methods are *described*, not dropped: the audit has to say that a
    server tried to summon a model through us, otherwise the attempt is invisible.
    """
    method = str(entry.get("method", ""))
    params = entry.get("params")
    if not isinstance(params, Mapping):
        raise ElicitationError(f"{server}/{tool}: input request {key!r} has no params object")
    raw_message = params.get("message", "")
    message = str(raw_message)[:MAX_MESSAGE_CHARS] if isinstance(raw_message, str) else ""
    base = {
        "server": server,
        "tool": tool,
        "key": key,
        "method": method,
        "message": message,
        "workspace_root": workspace_root,
    }
    if method == SAMPLING_METHOD:
        return ElicitationRequest(
            **base,
            answerable=False,
            refuse_reason=(
                "sampling/createMessage asks this client to run a model on the server's behalf: unbounded "
                "cost and a prompt we did not write; a governed run does not lend its model to a remote tool"
            ),
        )
    if method == ROOTS_METHOD:
        if not workspace_root:
            return ElicitationRequest(**base, answerable=False, refuse_reason="roots/list refused: no workspace root is exposed to remote servers")
        return ElicitationRequest(**base, answerable=True)
    if method != ELICITATION_METHOD:
        return ElicitationRequest(**base, answerable=False, refuse_reason=f"unsupported input request method {method!r}")

    schema = params.get("requestedSchema")
    if not isinstance(schema, Mapping):
        raise ElicitationError(f"{server}/{tool}: elicitation {key!r} requestedSchema is not an object")
    size = _schema_size(schema)
    if size > MAX_SCHEMA_CHARS:
        raise ElicitationError(f"{server}/{tool}: elicitation {key!r} requestedSchema is {size} chars (cap {MAX_SCHEMA_CHARS})")
    if _walk_depth(schema) > MAX_SCHEMA_DEPTH:
        raise ElicitationError(f"{server}/{tool}: elicitation {key!r} requestedSchema nests deeper than {MAX_SCHEMA_DEPTH} levels")
    properties = schema.get("properties")
    if properties is not None and not isinstance(properties, Mapping):
        raise ElicitationError(f"{server}/{tool}: elicitation {key!r} properties must be an object")
    required = schema.get("required")
    required_names = {str(name) for name in required} if isinstance(required, Sequence) and not isinstance(required, str) else set()
    if isinstance(properties, Mapping) and len(properties) > MAX_PROPERTIES:
        raise ElicitationError(
            f"{server}/{tool}: elicitation {key!r} asks for {len(properties)} fields (cap {MAX_PROPERTIES}); "
            "a form that wide is not a clarification"
        )
    fields: list[Field] = []
    for name, spec in (properties or {}).items():
        description = ""
        kind = "string"
        if isinstance(spec, Mapping):
            description = str(spec.get("description", "") or "")[:MAX_DESCRIPTION_CHARS]
            kind = str(spec.get("type", "string") or "string")
        fields.append(
            Field(
                name=str(name),
                type=kind,
                description=description,
                required=str(name) in required_names,
                sensitive=bool(SENSITIVE_NAME_RE.search(str(name))),
            )
        )
    request = ElicitationRequest(**base, fields=tuple(fields))
    if request.sensitive and not allow_sensitive:
        names = ", ".join(item.name for item in fields if item.sensitive)
        return ElicitationRequest(
            **base,
            fields=tuple(fields),
            answerable=False,
            refuse_reason=(
                f"field name(s) look like credentials ({names}): a text box over a socket is not a credential "
                "store; a human can allow this per run with --mcp-allow-sensitive-input"
            ),
        )
    return request


def decode_input_requests(
    input_requests: Mapping[str, Mapping[str, Any]],
    *,
    server: str,
    tool: str,
    workspace_root: str = "",
    allow_sensitive: bool = False,
    allow_roots: bool = False,
) -> tuple[ElicitationRequest, ...]:
    """Decode every embedded request; ``allow_roots`` gates the one that leaks paths."""
    requests: list[ElicitationRequest] = []
    for key in sorted(input_requests):
        request = decode_request(
            key,
            input_requests[key],
            server=server,
            tool=tool,
            workspace_root=workspace_root if allow_roots else "",
            allow_sensitive=allow_sensitive,
        )
        requests.append(request)
    return tuple(requests)


def _answer_shape(request: ElicitationRequest, answers: Mapping[str, Any]) -> tuple[dict[str, Any] | None, str]:
    """Validate one approver answer against the request's field list."""
    if request.method == ROOTS_METHOD:
        return {}, ""
    if not isinstance(answers, Mapping):
        return None, "the approver returned something that is not a mapping of field names to values"
    unknown = sorted(set(str(name) for name in answers) - {item.name for item in request.fields})
    if unknown:
        # Answering a field the server did not ask for is how a client starts
        # volunteering data to a remote process.
        return None, f"answer includes field(s) the server never asked for: {', '.join(unknown)}"
    content: dict[str, Any] = {}
    for item in request.fields:
        if item.name not in answers:
            if item.required:
                return None, f"required field {item.name!r} was left unanswered"
            continue
        value = answers[item.name]
        if isinstance(value, str) and len(value) > MAX_ANSWER_CHARS:
            return None, f"answer for {item.name!r} is {len(value)} chars (cap {MAX_ANSWER_CHARS})"
        content[item.name] = value
    return content, ""


def resolve_requests(
    requests: Sequence[ElicitationRequest],
    *,
    elicitor: Callable[[ElicitationRequest], Any] | None,
) -> tuple[dict[str, Any], list[ElicitationVerdict]]:
    """Produce the ``inputResponses`` map plus the audit trail of how it was decided.

    ``elicitor`` returns either ``True``/a mapping (accept), ``False``/``None``
    (decline), or the string ``"cancel"`` (abandon the call). It is the *only* source
    of an answer: there is no default, no echo, and no "accept if unattended".
    """
    responses: dict[str, Any] = {}
    verdicts: list[ElicitationVerdict] = []
    for request in requests:
        if not request.answerable:
            responses[request.key] = {"action": DECLINE}
            verdicts.append(
                ElicitationVerdict(
                    server=request.server,
                    tool=request.tool,
                    key=request.key,
                    method=request.method,
                    action=DECLINE,
                    reason=request.refuse_reason or "refused by policy",
                )
            )
            continue
        if elicitor is None:
            responses[request.key] = {"action": DECLINE}
            verdicts.append(
                ElicitationVerdict(
                    server=request.server,
                    tool=request.tool,
                    key=request.key,
                    method=request.method,
                    action=DECLINE,
                    reason=(
                        "this run has no approver attached (--mcp-elicit deny or an embedded run without "
                        "an elicitor): a remote request is never answered by a default"
                    ),
                )
            )
            continue
        try:
            answer = elicitor(request)
        except Exception as error:  # noqa: BLE001 - an approver fault must not become a silent accept
            responses[request.key] = {"action": DECLINE}
            verdicts.append(
                ElicitationVerdict(
                    server=request.server,
                    tool=request.tool,
                    key=request.key,
                    method=request.method,
                    action=DECLINE,
                    reason=f"the approver raised {type(error).__name__}: {error}",
                )
            )
            continue
        if answer is None or answer is False:
            responses[request.key] = {"action": DECLINE}
            verdicts.append(
                ElicitationVerdict(
                    server=request.server, tool=request.tool, key=request.key, method=request.method,
                    action=DECLINE, reason="the approver declined this request",
                )
            )
            continue
        if isinstance(answer, str) and answer.strip().lower() == CANCEL:
            responses[request.key] = {"action": CANCEL}
            verdicts.append(
                ElicitationVerdict(
                    server=request.server, tool=request.tool, key=request.key, method=request.method,
                    action=CANCEL, reason="the approver cancelled the call",
                )
            )
            continue
        if request.method == ROOTS_METHOD:
            responses[request.key] = {
                "action": ACCEPT,
                "roots": [{"uri": f"file://{request.workspace_root}", "name": "workspace"}],
            }
            verdicts.append(
                ElicitationVerdict(
                    server=request.server, tool=request.tool, key=request.key, method=request.method,
                    action=ACCEPT, reason="roots/list answered with the single workspace root (host opted in)",
                    answered_fields=("roots",),
                )
            )
            continue
        answers = answer if isinstance(answer, Mapping) else {}
        if answer is True:
            # An approval without values is only coherent when nothing is required.
            answers = {}
        content, problem = _answer_shape(request, answers)
        if content is None:
            responses[request.key] = {"action": DECLINE}
            verdicts.append(
                ElicitationVerdict(
                    server=request.server, tool=request.tool, key=request.key, method=request.method,
                    action=DECLINE, reason=f"answer rejected: {problem}",
                )
            )
            continue
        responses[request.key] = {"action": ACCEPT, "content": dict(content)}
        verdicts.append(
            ElicitationVerdict(
                server=request.server,
                tool=request.tool,
                key=request.key,
                method=request.method,
                action=ACCEPT,
                reason="approved by the run's approver",
                # Names only - the values never reach the transcript.
                answered_fields=tuple(sorted(str(name) for name in answers)),
            )
        )
    return responses, verdicts


# -- approvers ------------------------------------------------------------------
#
# ``resolve_requests`` takes any callable; these are the two it ships with, so that a
# host (the CLI, an embedder, a test) never has to invent the semantics of "an approver
# answered" on its own. Both raise :class:`ElicitationError` rather than returning a
# wrong-shaped answer, which ``resolve_requests`` turns into a decline that says why.


def make_answers_elicitor(answers: Mapping[str, Any]) -> Callable[[ElicitationRequest], Mapping[str, Any]]:
    """Pre-approved answers: a mapping of field name to value, applied to any request it covers.

    This is an approval granted **in advance** - "whatever a server asks for these
    fields, these are the values" - which is what lets a governed CI run carry a signed-off
    answer set instead of a human at a keyboard. Coverage is strict on purpose: a request
    that needs a field the set does not name is refused rather than guessed at, so adding a
    required field to a server is a *denial*, never a silent approval.
    """
    table = {str(name): value for name, value in answers.items()}

    def elicit(request: ElicitationRequest) -> Mapping[str, Any]:
        missing = [item.name for item in request.fields if item.required and item.name not in table]
        if missing:
            raise ElicitationError(
                "the pre-approved answer set does not cover " + ", ".join(missing) + "; refusing to guess a required field"
            )
        return {item.name: table[item.name] for item in request.fields if item.name in table}

    return elicit


def make_terminal_elicitor(
    read_line: Callable[[str], str] = input,
    *,
    echo: Callable[[str], None] | None = None,
) -> Callable[[ElicitationRequest], Mapping[str, Any] | str]:
    """Ask a human on a terminal. ``read_line`` is injectable so the gate is testable offline.

    Reading rules, all of them fail-closed: an empty answer to an optional field is
    omitted, an empty answer to a required one is a refusal, ``cancel`` abandons the whole
    call (not one field of it), and a boolean that is not y/n is a refusal - not a
    re-ask, because a human who has to read the prompt twice has already been bothered
    enough. Nothing typed here is ever echoed or returned to the transcript.
    """
    say = echo or (lambda text: print(text, file=sys.stderr, flush=True))

    def elicit(request: ElicitationRequest) -> Mapping[str, Any] | str:
        say(request.prompt())
        answers: dict[str, Any] = {}
        for item in request.fields:
            hint = " [y/N]" if item.type == "boolean" else (" (optional)" if not item.required else "")
            label = f"  {item.name} ({item.type}){hint}"
            raw = read_line(label + " ")
            text = (raw or "").strip()
            if text.lower() == CANCEL:
                return CANCEL
            if item.type == "boolean":
                if text == "" or text.lower() in {"n", "no"}:
                    continue
                if text.lower() not in {"y", "yes"}:
                    raise ElicitationError(f"{item.name} is a yes/no question, not {text!r}")
                answers[item.name] = True
                continue
            if text == "":
                if item.required:
                    raise ElicitationError(f"{item.name} is required and was left blank")
                continue
            answers[item.name] = _coerce(item, text)
        return answers

    return elicit


def _coerce(item: Field, text: str) -> Any:
    """Fit a typed line into the JSON type the schema asked for."""
    if item.type == "integer":
        try:
            return int(text)
        except ValueError as error:
            raise ElicitationError(f"{item.name} is not an integer: {text!r}") from error
    if item.type == "number":
        try:
            return float(text)
        except ValueError as error:
            raise ElicitationError(f"{item.name} is not a number: {text!r}") from error
    if len(text) > MAX_ANSWER_CHARS:
        raise ElicitationError(f"{item.name} is {len(text)} chars (cap {MAX_ANSWER_CHARS})")
    return text


def summarize_verdicts(verdicts: Sequence[ElicitationVerdict]) -> dict[str, Any]:
    """The record shape written into the session transcript."""
    return {
        "count": len(verdicts),
        "accepted": sum(1 for verdict in verdicts if verdict.action == ACCEPT),
        "declined": sum(1 for verdict in verdicts if verdict.action == DECLINE),
        "cancelled": sum(1 for verdict in verdicts if verdict.action == CANCEL),
        "decisions": [verdict.as_dict() for verdict in verdicts],
    }


__all__ = [
    "ACCEPT",
    "CANCEL",
    "DECLINE",
    "ElicitationError",
    "ElicitationRequest",
    "ElicitationVerdict",
    "Field",
    "MAX_INPUT_ROUNDS",
    "SENSITIVE_NAME_RE",
    "decode_input_requests",
    "decode_request",
    "make_answers_elicitor",
    "make_terminal_elicitor",
    "resolve_requests",
    "summarize_verdicts",
]
