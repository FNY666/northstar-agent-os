"""MCP protocol-generation logic: era detection, per-request metadata, MRTR planning.

Why a separate module
---------------------
The 2026-07-28 revision of the Model Context Protocol broke compatibility on purpose:
there is **no handshake any more**. Every request declares its version and client
capabilities in ``params._meta.io.modelcontextprotocol/*``; ``Mcp-Session-Id`` and the
connection-scoped session are gone; servers **must not** initiate JSON-RPC requests,
and the old ``elicitation/create`` / ``sampling/createMessage`` / ``roots/list``
server-calls are replaced by **Multi Round-Trip Requests** (MRTR), where the server
answers a client request with ``resultType: "input_required"`` and the client retries
the *same* request with ``inputResponses`` and an opaque ``requestState``.

A client that only speaks the 2024/2025 shape is not "slightly behind": it cannot
reach a modern gateway at all, and it silently misreads a modern server's error as a
broken server. So the detection rules live here, as pure functions with tests, and
:mod:`mcp_client` does nothing but move bytes.

The rules encoded (each traceable to the spec text)
---------------------------------------------------
* **Era is a property of the server, not of a request.** Probe once with
  ``server/discover`` and cache the answer for the life of the server process.
* **On stdio: a recognized modern error means modern.** Anything else - no reply,
  garbage, a dead process, an error that is not one of the modern codes - means fall
  back to ``initialize``. ``-32022`` (unsupported protocol version) is the decisive
  one: only a modern server can produce it, and it names the versions it does speak.
* **Never guess a version the server did not offer.** ``select_version`` returns
  ``None`` when there is no mutual version, and the caller surfaces that to the
  operator instead of trying its favourite date.
* ``_meta`` is required on *every* request once the era is modern - including
  notifications - because there is no session to carry it.
* **Capabilities are a governance lever, not a feature flag.** A server must not send
  an ``elicitation/create`` request the client did not declare support for. So
  :func:`client_capabilities` advertises ``elicitation`` *only* when the host actually
  attached an approver. A run with no human in the loop therefore cannot be asked
  anything by a remote server: the question never arrives, rather than arriving and
  being answered by a default.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

#: The per-request-metadata generation introduced by revision 2026-07-28.
MODERN_VERSION = "2026-07-28"

#: Handshake-based generations, newest first. Kept because the installed base is
#: enormous and because falling back is the only way to reach them.
LEGACY_VERSIONS: tuple[str, ...] = ("2025-11-25", "2024-11-05")

SUPPORTED_VERSIONS: tuple[str, ...] = (MODERN_VERSION, *LEGACY_VERSIONS)

#: ``_meta`` keys, per the spec's namespaced-key rule.
META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"

#: JSON-RPC error codes that only a *modern* server can produce, because the code
#: itself was introduced with per-request versioning.
MODERN_ERROR_CODES: frozenset[int] = frozenset({-32022})

#: The method every modern server implements, and the only safe stdio probe.
DISCOVER_METHOD = "server/discover"

#: The result tag that starts an MRTR round trip.
RESULT_COMPLETE = "complete"
RESULT_INPUT_REQUIRED = "input_required"

#: Methods a modern server may embed in ``inputRequests``.
ELICITATION_METHOD = "elicitation/create"
SAMPLING_METHOD = "sampling/createMessage"
ROOTS_METHOD = "roots/list"
MRTR_METHODS: frozenset[str] = frozenset({ELICITATION_METHOD, SAMPLING_METHOD, ROOTS_METHOD})

#: How many times one tool call may be bounced back for input. A server is allowed to
#: re-ask until it is satisfied; a client that allows that without limit lets a remote
#: process hold a human at a prompt indefinitely.
MAX_INPUT_ROUNDS = 3


def request_meta(
    *,
    protocol_version: str,
    client_info: Mapping[str, Any],
    capabilities: Mapping[str, Any],
) -> dict[str, Any]:
    """The ``params._meta`` object a modern request must carry."""
    return {
        META_PROTOCOL_VERSION: protocol_version,
        META_CLIENT_INFO: dict(client_info),
        META_CLIENT_CAPABILITIES: dict(capabilities),
    }


def client_capabilities(*, can_elicit: bool, can_list_roots: bool = False) -> dict[str, Any]:
    """What this client can answer, and therefore what a server may ask.

    ``elicitation`` is advertised only when an approver exists. That single condition
    is the difference between "a remote tool can ask the operator for input, through
    the same gate as a local write" and "a remote tool can ask, and the client has an
    answer ready" - the latter is what this runtime refuses to be.
    """
    capabilities: dict[str, Any] = {"tools": {}}
    if can_elicit:
        capabilities["elicitation"] = {}
    if can_list_roots:
        capabilities["roots"] = {}
    return capabilities


@dataclass(frozen=True)
class EraDecision:
    """The outcome of the stdio probe.

    ``modern`` means "speak per-request metadata at ``version``". ``legacy`` means
    "handshake with ``version``". ``reason`` is operator-facing: an era determination
    that cannot be explained is a guess with extra steps.
    """

    era: str
    version: str
    reason: str

    @property
    def modern(self) -> bool:
        return self.era == "modern"


def select_version(supported: Iterable[Any], *, prefer: Sequence[str] = SUPPORTED_VERSIONS) -> str | None:
    """The newest version both sides speak, or ``None`` when there is none.

    Ordering follows *our* preference, not the server's list order, so the result is
    stable whatever order a gateway happens to report. A missing or malformed list is
    "nothing in common": a field a server forgot to send must not become a crash in the
    client's negotiation path, because that is indistinguishable from a broken transport.
    """
    offered = {str(item) for item in (supported or ()) if isinstance(item, (str, int, float))}
    for version in prefer:
        if version in offered:
            return version
    return None


def decide_era(
    discover_result: Mapping[str, Any] | None,
    discover_error: Mapping[str, Any] | None = None,
    *,
    transport: str = "stdio",
    timed_out: bool = False,
) -> EraDecision:
    """Map the probe's outcome onto an era, following the spec's fallback rule.

    Exactly one of ``discover_result`` / ``discover_error`` is meaningful; a timeout
    or an unreadable reply is neither, and counts as "not a recognized modern error".
    """
    if timed_out:
        return EraDecision("legacy", LEGACY_VERSIONS[0], f"{DISCOVER_METHOD} timed out: no modern framing in sight")
    if isinstance(discover_result, Mapping):
        offered = discover_result.get("supportedVersions") or discover_result.get("protocolVersions") or ()
        version = select_version(offered)
        if version is None:
            reported = ", ".join(str(item) for item in offered) or "(none)"
            return EraDecision(
                "modern",
                MODERN_VERSION,
                f"{DISCOVER_METHOD} answered but offered no mutually supported version (server offered: {reported})",
            )
        # capabilities and serverInfo are read for display only: the spec says a
        # client MUST NOT rely on serverInfo for security decisions, and self-reported
        # identity is not a credential.
        return EraDecision("modern", version, f"{DISCOVER_METHOD} answered: modern server, mutually supported version {version}")
    if isinstance(discover_error, Mapping):
        code = discover_error.get("code")
        if isinstance(code, int) and code in MODERN_ERROR_CODES:
            data = discover_error.get("data") if isinstance(discover_error.get("data"), Mapping) else {}
            version = select_version(data.get("supported") or ())
            if version is not None:
                return EraDecision("modern", version, f"server reported a modern error and named {version} as supported")
            return EraDecision(
                "modern",
                MODERN_VERSION,
                f"server speaks a modern error code ({code}) but offered no version we support",
            )
        detail = str(discover_error.get("message") or "unknown error")
        return EraDecision("legacy", LEGACY_VERSIONS[0], f"{DISCOVER_METHOD} answered with a non-modern error ({code!r}: {detail}): legacy server")
    return EraDecision("legacy", LEGACY_VERSIONS[0], f"{DISCOVER_METHOD} produced no usable response: assuming a legacy server")


def result_type(result: Mapping[str, Any] | None) -> str:
    """``resultType`` with the legacy-era default spelled out.

    Generations before 2026-07-28 have no ``resultType`` field at all, so a missing one
    is "complete", not "unknown" - inferring otherwise would treat every legacy
    server as mid-round-trip forever.
    """
    if not isinstance(result, Mapping):
        return RESULT_COMPLETE
    value = result.get("resultType")
    return str(value) if value in (RESULT_COMPLETE, RESULT_INPUT_REQUIRED) else RESULT_COMPLETE


def input_requests(result: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """The ``inputRequests`` map of an ``InputRequiredResult``, validated lightly.

    Anything malformed here is dropped rather than coerced: a request we cannot name
    and type is a request we cannot show an operator, and showing a partial prompt is
    how an approval becomes a rubber stamp.
    """
    if not isinstance(result, Mapping) or result_type(result) != RESULT_INPUT_REQUIRED:
        return {}
    raw = result.get("inputRequests")
    if not isinstance(raw, Mapping):
        return {}
    clean: dict[str, dict[str, Any]] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not key or not isinstance(value, Mapping):
            continue
        method = value.get("method")
        params = value.get("params")
        if not isinstance(method, str) or not isinstance(params, Mapping):
            continue
        clean[key] = {"method": method, "params": dict(params)}
    return clean


def request_state(result: Mapping[str, Any]) -> str | None:
    """The opaque ``requestState`` to echo back, verbatim or not at all."""
    if not isinstance(result, Mapping):
        return None
    value = result.get("requestState")
    return value if isinstance(value, str) else None


def retry_params(
    *,
    tool_name: str,
    arguments: Mapping[str, Any],
    input_responses: Mapping[str, Any],
    state: str | None,
) -> dict[str, Any]:
    """The ``tools/call`` parameters for an MRTR retry.

    Two rules the spec states plainly and clients get wrong constantly: the retry is a
    **new JSON-RPC request** (fresh id, which the caller owns), and ``requestState`` is
    echoed only when the server sent one - a client that invents an empty string turns
    an integrity check into a mismatch.
    """
    params: dict[str, Any] = {"name": tool_name, "arguments": dict(arguments)}
    params["inputResponses"] = dict(input_responses)
    if state is not None:
        params["requestState"] = state
    return params


def discover_summary(result: Mapping[str, Any] | None) -> dict[str, Any]:
    """What ``server/discover`` told us, for the operator-facing ``--json`` init record.

    Deliberately display-only. The spec is explicit that ``serverInfo`` is unverified,
    so nothing here may be used to decide whether to trust a server.
    """
    if not isinstance(result, Mapping):
        return {}
    meta = result.get("_meta") if isinstance(result.get("_meta"), Mapping) else {}
    info = meta.get("io.modelcontextprotocol/serverInfo") if isinstance(meta, Mapping) else None
    capabilities = result.get("capabilities") if isinstance(result.get("capabilities"), Mapping) else {}
    return {
        "supported_versions": [str(item) for item in (result.get("supportedVersions") or ())],
        "server_info": dict(info) if isinstance(info, Mapping) else {},
        "server_capabilities": sorted(str(key) for key in capabilities),
        "instructions_chars": len(str(result.get("instructions", "") or "")),
    }


__all__ = [
    "DISCOVER_METHOD",
    "ELICITATION_METHOD",
    "LEGACY_VERSIONS",
    "MAX_INPUT_ROUNDS",
    "META_CLIENT_CAPABILITIES",
    "META_CLIENT_INFO",
    "META_PROTOCOL_VERSION",
    "MODERN_ERROR_CODES",
    "MODERN_VERSION",
    "RESULT_COMPLETE",
    "RESULT_INPUT_REQUIRED",
    "ROOTS_METHOD",
    "SAMPLING_METHOD",
    "SUPPORTED_VERSIONS",
    "EraDecision",
    "client_capabilities",
    "decide_era",
    "discover_summary",
    "input_requests",
    "request_meta",
    "request_state",
    "result_type",
    "retry_params",
    "select_version",
]
