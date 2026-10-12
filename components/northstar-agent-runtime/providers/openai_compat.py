"""Any-model provider for endpoints that speak the OpenAI Chat Completions wire.

Why this exists
---------------
The runtime's governance layer (hooks, the permission gate, ceilings, sessions,
tracing) is model-independent, but until now only one live model could reach it.
Chat Completions is the lingua franca that 2026 model serving converged on:
OpenAI, Azure OpenAI, vLLM, SGLang, Ollama, LM Studio, LiteLLM, OpenRouter,
Together, Fireworks and most self-hosted gateways all speak it, so one adapter
brings the whole "100+ models" surface into the same governed loop instead of
requiring a per-vendor harness.

Translation notes (the parts that are easy to get wrong)
--------------------------------------------------------
- The transcript is kept in Anthropic block form (that is what
  :mod:`providers.base` and the session transcript speak), so this adapter
  converts *both ways* per call: ``tool_use`` becomes a ``tool_calls`` entry with
  ``arguments`` JSON-encoded, and ``tool_result`` becomes a ``role: "tool"``
  message carrying ``tool_call_id``. Ordering is preserved because the chat API
  requires tool results to directly follow the assistant turn that asked for them.
- ``thinking`` blocks have no chat-API home: they are dropped from the *request*
  (never from the transcript) rather than pasted into content, where they would
  re-enter the model's reasoning as user text.
- Malformed ``arguments`` JSON is a ``ProviderError``, not a shrug. A truncated or
  non-JSON argument blob with a fallback of ``{}`` would let a write tool run with
  an empty payload - a hallucinated call executed as a real one. Failing the turn
  is the only safe reading, and the loop reports it as an event.
- ``max_tokens`` vs ``max_completion_tokens``: newer reasoning models reject the
  former. :attr:`token_limit_field` defaults to ``"auto"``, which picks
  ``max_completion_tokens`` for ``gpt-5*``/``o*`` ids and ``max_tokens``
  otherwise, because a wrong field name is a 400 on exactly the models people
  reach for this adapter with.
- Cost stays honest: unknown model ids are priced by ``budget.price_for``'s
  conservative fallback and flagged ``pricing_estimated``, and this adapter never
  guesses a price of its own.

The ``openai`` package is imported lazily and a ``client`` may be injected, which
is how the offline tests assert request building and response normalisation
without a network, a key, or the SDK installed at all.
"""
from __future__ import annotations

import copy
import json
from typing import Any, Sequence

from providers.base import (
    Generation,
    GenerationRequest,
    Provider,
    ProviderError,
    StreamDelta,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    Usage,
)

#: Model families that reject ``max_tokens`` and want the reasoning-era name.
_REASONING_PREFIXES = ("gpt-5", "gpt-4.1-mini-reasoning", "o1", "o3", "o4")

#: finish_reason -> the runtime's own StopReason vocabulary.
_FINISH_REASONS = {
    "stop": "end_turn",
    "length": "max_tokens",
    "tool_calls": "tool_use",
    "function_call": "tool_use",
    "content_filter": "refusal",
    "end_turn": "end_turn",
}

DEFAULT_MODEL = "gpt-4.1"
MAX_PROVIDER_TEXT_CHARS = 1_048_576
MAX_TOOL_ARGUMENT_CHARS = 1_048_576
MAX_TOOL_ARGUMENTS_TOTAL_BYTES = 4_194_304
MAX_TOOL_CALLS_PER_RESPONSE = 128
DEFAULT_MAX_HTTP_RESPONSE_BYTES = 8_388_608


def _is_reasoning_model(model: str) -> bool:
    key = (model or "").strip().lower()
    return any(key.startswith(prefix) for prefix in _REASONING_PREFIXES)


def _text_of(content: Any) -> str:
    """Flatten a chat ``content`` value (string, or a list of text parts)."""
    if content is None:
        return ""
    if isinstance(content, str):
        if len(content) > MAX_PROVIDER_TEXT_CHARS:
            raise ProviderError(f"provider text exceeds the {MAX_PROVIDER_TEXT_CHARS}-character response limit")
        return content
    if isinstance(content, (list, tuple)):
        parts: list[str] = []
        total = 0
        for part in content:
            if isinstance(part, str):
                text = part
            elif isinstance(part, dict) and part.get("type") in (None, "text"):
                text = str(part.get("text", ""))
            else:
                continue
            total += len(text)
            if total > MAX_PROVIDER_TEXT_CHARS:
                raise ProviderError(f"provider text exceeds the {MAX_PROVIDER_TEXT_CHARS}-character response limit")
            parts.append(text)
        return "".join(parts)
    text = str(content)
    if len(text) > MAX_PROVIDER_TEXT_CHARS:
        raise ProviderError(f"provider text exceeds the {MAX_PROVIDER_TEXT_CHARS}-character response limit")
    return text


def _field(obj: Any, name: str, default: Any = None) -> Any:
    """Read an attribute or a mapping key, so a test double can be a plain dict."""
    if isinstance(obj, dict):
        value = obj.get(name, default)
        return default if value is None else value
    value = getattr(obj, name, default)
    return default if value is None else value


class OpenAICompatProvider(Provider):
    """Normalising adapter over ``client.chat.completions.create``."""

    name = "openai-compatible"
    #: The wire supports it (SSE deltas), and the adapter reassembles faithfully enough
    #: that the runtime's fidelity check passes by construction. A gateway that does not
    #: implement ``stream`` will raise, which the loop turns into a provider fault.
    streams = True

    def __init__(
        self,
        *,
        model: str = DEFAULT_MODEL,
        base_url: str | None = None,
        api_key: str | None = None,
        client: Any | None = None,
        max_tokens: int = 4096,
        temperature: float | None = None,
        token_limit_field: str = "auto",
        #: ``0`` by default: the runtime owns the retry budget (provider_retry.py), and a
        #: second loop inside the SDK would multiply the request count past what any policy
        #: file approved. Set it only if you are deliberately letting the client retry.
        max_retries: int = 0,
        timeout: float | None = None,
        extra_headers: dict[str, str] | None = None,
        extra_body: dict[str, Any] | None = None,
        supports_tools: bool = True,
        stream_usage: bool = True,
        max_response_bytes: int = DEFAULT_MAX_HTTP_RESPONSE_BYTES,
    ) -> None:
        if max_tokens <= 0:
            raise ValueError("max_tokens must be positive")
        if isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int) or max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be a positive integer")
        if token_limit_field not in {"auto", "max_tokens", "max_completion_tokens", "none"}:
            raise ValueError(
                "token_limit_field must be 'auto', 'max_tokens', 'max_completion_tokens' or 'none'"
            )
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.token_limit_field = token_limit_field
        self.extra_body = dict(extra_body or {})
        self.supports_tools = bool(supports_tools)
        self.stream_usage = bool(stream_usage)
        self._client = client
        self._owns_client = client is None
        self.max_response_bytes = max_response_bytes
        self._client_kwargs: dict[str, Any] = {"max_retries": max_retries}
        if base_url is not None:
            self._client_kwargs["base_url"] = base_url
        if api_key is not None:
            self._client_kwargs["api_key"] = api_key
        elif base_url is not None:
            # Local servers (vLLM, Ollama, LM Studio) usually ignore a key but the
            # SDK still requires one, so a base_url alone must be enough to work.
            self._client_kwargs["api_key"] = "not-needed"
        if timeout is not None:
            self._client_kwargs["timeout"] = timeout
        if extra_headers:
            self._client_kwargs["default_headers"] = dict(extra_headers)

    @property
    def client(self) -> Any:
        if self._client is None:
            try:
                import openai as openai_sdk
            except ImportError as error:  # pragma: no cover - depends on host
                raise ProviderError(
                    "the 'openai' package is required for OpenAICompatProvider "
                    "(pip install openai), or use provider='scripted' for offline runs"
                ) from error
            from providers.http_response_limits import make_response_limited_http_client

            default_http_client = getattr(openai_sdk, "DefaultHttpx2Client", None)
            if default_http_client is None:
                default_http_client = getattr(openai_sdk, "DefaultHttpxClient", None)
            if not callable(default_http_client):
                raise ProviderError("the installed openai SDK does not expose a supported synchronous HTTP client")
            http_client = make_response_limited_http_client(default_http_client, self.max_response_bytes)
            self._client = openai_sdk.OpenAI(http_client=http_client, **self._client_kwargs)
        return self._client

    # -- request building --------------------------------------------------
    def resolve_token_limit_field(self, model: str) -> str | None:
        if self.token_limit_field == "none":
            return None
        if self.token_limit_field == "auto":
            return "max_completion_tokens" if _is_reasoning_model(model) else "max_tokens"
        return self.token_limit_field

    def to_chat_tools(self, tools: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
        """Anthropic tool definitions -> chat ``function`` wrappers."""
        converted: list[dict[str, Any]] = []
        for tool in tools:
            function: dict[str, Any] = {"name": tool.get("name")}
            description = tool.get("description")
            if description:
                function["description"] = description
            schema = tool.get("input_schema") or tool.get("parameters") or {}
            function["parameters"] = copy.deepcopy(schema)
            converted.append({"type": "function", "function": function})
        return converted

    def to_chat_messages(self, system: str, messages: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
        """Translate the Anthropic-shaped transcript into chat messages.

        A ``user`` turn that mixes text with tool results is split - tool results
        first, as ``role: "tool"`` - because the chat API will not accept them
        inside a user message.
        """
        out: list[dict[str, Any]] = []
        if system:
            out.append({"role": "system", "content": system})
        for message in messages:
            role = message.get("role")
            content = message.get("content")
            if isinstance(content, str):
                out.append({"role": "assistant" if role == "assistant" else "user", "content": content})
                continue
            blocks = list(content or ())
            if role == "assistant":
                tool_calls: list[dict[str, Any]] = []
                text_parts: list[str] = []
                for block in blocks:
                    kind = block.get("type")
                    if kind == "tool_use":
                        tool_calls.append(
                            {
                                "id": block.get("id") or f"call_{len(tool_calls)}",
                                "type": "function",
                                "function": {
                                    "name": block.get("name", ""),
                                    "arguments": json.dumps(block.get("input") or {}, ensure_ascii=False, default=str),
                                },
                            }
                        )
                    elif kind == "text":
                        text_parts.append(str(block.get("text", "")))
                    # "thinking" is transcript-only: see the module docstring.
                entry: dict[str, Any] = {"role": "assistant", "content": "\n".join(text_parts) or None}
                if tool_calls:
                    entry["tool_calls"] = tool_calls
                out.append(entry)
                continue
            pending_text: list[str] = []
            for block in blocks:
                kind = block.get("type")
                if kind == "tool_result":
                    if pending_text:
                        out.append({"role": "user", "content": "\n".join(pending_text)})
                        pending_text = []
                    out.append(
                        {
                            "role": "tool",
                            "tool_call_id": block.get("tool_use_id", ""),
                            "content": _text_of(block.get("content")),
                        }
                    )
                elif kind == "text":
                    pending_text.append(str(block.get("text", "")))
            if pending_text:
                out.append({"role": "user", "content": "\n".join(pending_text)})
        return out

    def build_payload(self, request: GenerationRequest) -> dict[str, Any]:
        """Translate a :class:`GenerationRequest` into ``chat.completions.create`` kwargs."""
        model = request.model or self.model
        payload: dict[str, Any] = {
            "model": model,
            "messages": self.to_chat_messages(request.system, request.messages),
        }
        limit_field = self.resolve_token_limit_field(model)
        if limit_field:
            payload[limit_field] = request.max_tokens or self.max_tokens
        if self.supports_tools and request.tools:
            payload["tools"] = self.to_chat_tools(request.tools)
            # "auto" keeps the model's freedom to answer in prose; forcing a call
            # would turn a governed loop into a form-filler.
            payload["tool_choice"] = "auto"
        if request.stop_sequences:
            payload["stop"] = list(request.stop_sequences)
        if self.temperature is not None:
            payload["temperature"] = self.temperature
        if self.extra_body:
            payload["extra_body"] = dict(self.extra_body)
        return payload

    # -- response normalisation -------------------------------------------
    def generate(self, request: GenerationRequest) -> Generation:
        payload = self.build_payload(request)
        try:
            response = self.client.chat.completions.create(**payload)
        except ProviderError:
            raise
        except Exception as error:  # noqa: BLE001 - must surface as an event
            raise ProviderError(f"chat completions request failed: {_reason(error)}", **_classify(error)) from error
        return self.normalise(response)

    def stream(self, request: GenerationRequest):  # type: ignore[override]
        """Reassemble an SSE chat completion into deltas plus one normalised turn.

        The turn is assembled into the same ``choices[0].message`` shape a
        non-streaming response would have carried and then run through
        :meth:`normalise`, because the failure rules that matter here are the ones
        already written there - above all that truncated tool arguments are a
        ``ProviderError`` and never an empty payload. Deltas carry text only: a
        half-received ``arguments`` blob is exactly what must not be shown, and a
        reasoning model's ``reasoning_content`` has no place in the transcript, so
        neither is forwarded.
        """
        payload = self.build_payload(request)
        payload["stream"] = True
        if self.stream_usage:
            # Without this the stream reports no usage at all, and a run whose cost is
            # silently zero is worse than one that refuses to stream. Older gateways
            # reject the field, so it can be turned off - but only by an operator who
            # has decided that free-looking cost is acceptable, which is why the flag
            # exists instead of a silent fallback.
            payload["stream_options"] = {"include_usage": True}
        pieces: list[str] = []
        total_text_chars = 0
        total_tool_argument_bytes = 0
        calls: dict[int, dict[str, Any]] = {}
        finish = ""
        usage: dict[str, Any] = {}
        model = ""
        try:
            for chunk in self.client.chat.completions.create(**payload):
                if chunk is None:
                    continue
                raw_usage = _field(chunk, "usage")
                if raw_usage:
                    if isinstance(raw_usage, dict):
                        usage = dict(raw_usage)
                    else:
                        usage = {
                            key: value
                            for key in ("prompt_tokens", "completion_tokens", "total_tokens")
                            if isinstance((value := getattr(raw_usage, key, None)), int) and not isinstance(value, bool)
                        }
                if _field(chunk, "model", ""):
                    model = str(_field(chunk, "model"))
                choices = _field(chunk, "choices", ()) or ()
                if not choices:
                    continue
                choice = choices[0]
                if _field(choice, "finish_reason", ""):
                    finish = str(_field(choice, "finish_reason"))
                delta = _field(choice, "delta", {}) or {}
                text = _text_of(_field(delta, "content"))
                if text:
                    total_text_chars += len(text)
                    if total_text_chars > MAX_PROVIDER_TEXT_CHARS:
                        raise ProviderError(
                            f"provider text exceeds the {MAX_PROVIDER_TEXT_CHARS}-character response limit"
                        )
                    pieces.append(text)
                    yield StreamDelta(text=text, provider=self.name)
                for fragment in _field(delta, "tool_calls", ()) or ():
                    call_index = int(_field(fragment, "index", 0) or 0)
                    if call_index < 0 or call_index >= MAX_TOOL_CALLS_PER_RESPONSE:
                        raise ProviderError(
                            f"provider returned more than {MAX_TOOL_CALLS_PER_RESPONSE} tool calls in one response"
                        )
                    slot = calls.setdefault(call_index, {"id": "", "function": {"name": "", "arguments": ""}})
                    call_id = _field(fragment, "id", "")
                    if call_id:
                        slot["id"] = str(call_id)
                    function = _field(fragment, "function", {}) or {}
                    if _field(function, "name", ""):
                        slot["function"]["name"] = str(_field(function, "name"))
                    argument_fragment = str(_field(function, "arguments", "") or "")
                    if len(slot["function"]["arguments"]) + len(argument_fragment) > MAX_TOOL_ARGUMENT_CHARS:
                        raise ProviderError(
                            f"tool call {call_index} arguments exceed the "
                            f"{MAX_TOOL_ARGUMENT_CHARS}-character response limit"
                        )
                    total_tool_argument_bytes += len(argument_fragment.encode("utf-8"))
                    if total_tool_argument_bytes > MAX_TOOL_ARGUMENTS_TOTAL_BYTES:
                        raise ProviderError(
                            f"tool arguments exceed the {MAX_TOOL_ARGUMENTS_TOTAL_BYTES}-byte per-response limit"
                        )
                    slot["function"]["arguments"] += argument_fragment
                # ``delta.reasoning_content`` is deliberately unread: it is not part of
                # the recorded turn, so streaming it would show the operator text that
                # the transcript cannot vouch for.
        except ProviderError:
            raise
        except Exception as error:  # noqa: BLE001 - must surface as an event
            raise ProviderError(f"chat completions stream failed: {_reason(error)}", **_classify(error)) from error
        message: dict[str, Any] = {"role": "assistant", "content": "".join(pieces)}
        if calls:
            message["tool_calls"] = [calls[index] for index in sorted(calls)]
        yield self.normalise(
            {
                "choices": [{"message": message, "finish_reason": finish}],
                "usage": usage,
                "model": model,
            }
        )

    @staticmethod
    def normalise(response: Any) -> Generation:
        choices = _field(response, "choices", ()) or ()
        if not choices:
            raise ProviderError("chat completion returned no choices")
        choice = choices[0]
        message = _field(choice, "message", {}) or {}
        blocks: list[Any] = []
        text = _text_of(_field(message, "content"))
        if text:
            blocks.append(TextBlock(text=text))
        total_tool_argument_bytes = 0
        total_tool_argument_nodes = 0
        for index, call in enumerate(_field(message, "tool_calls", ()) or ()):
            if index >= MAX_TOOL_CALLS_PER_RESPONSE:
                raise ProviderError(
                    f"provider returned more than {MAX_TOOL_CALLS_PER_RESPONSE} tool calls in one response"
                )
            function = _field(call, "function", {}) or {}
            name = str(_field(function, "name", "") or "")
            raw_arguments = _field(function, "arguments", "")
            if isinstance(raw_arguments, dict):
                from tool_input_schema import (
                    MAX_SCHEMA_TREE_NODES,
                    ToolInputSchemaError,
                    check_json_tree_budget_details,
                )

                try:
                    tree_bytes, tree_nodes = check_json_tree_budget_details(
                        raw_arguments, label="tool arguments"
                    )
                except ToolInputSchemaError as error:
                    raise ProviderError(f"tool call {name or index} arguments exceed runtime limits") from error
                total_tool_argument_nodes += tree_nodes
                if total_tool_argument_nodes > MAX_SCHEMA_TREE_NODES:
                    raise ProviderError(
                        f"provider tool arguments exceed the {MAX_SCHEMA_TREE_NODES}-node response limit"
                    )
                total_tool_argument_bytes += tree_bytes
                if total_tool_argument_bytes > MAX_TOOL_ARGUMENTS_TOTAL_BYTES:
                    raise ProviderError(
                        f"tool arguments exceed the {MAX_TOOL_ARGUMENTS_TOTAL_BYTES}-byte per-response limit"
                    )
                arguments: dict[str, Any] = dict(raw_arguments)
            else:
                if isinstance(raw_arguments, str) and len(raw_arguments) > MAX_TOOL_ARGUMENT_CHARS:
                    raise ProviderError(
                        f"tool call {name or index} arguments exceed the "
                        f"{MAX_TOOL_ARGUMENT_CHARS}-character response limit"
                    )
                blob = str(raw_arguments or "").strip()
                total_tool_argument_bytes += len(blob.encode("utf-8"))
                if total_tool_argument_bytes > MAX_TOOL_ARGUMENTS_TOTAL_BYTES:
                    raise ProviderError(
                        f"tool arguments exceed the {MAX_TOOL_ARGUMENTS_TOTAL_BYTES}-byte per-response limit"
                    )
                if not blob:
                    arguments = {}
                else:
                    if len(blob) > MAX_TOOL_ARGUMENT_CHARS:
                        raise ProviderError(
                            f"tool call {name or index} arguments exceed the "
                            f"{MAX_TOOL_ARGUMENT_CHARS}-character response limit"
                        )
                    from tool_input_schema import (
                        MAX_SCHEMA_TREE_NODES,
                        ToolInputSchemaError,
                        check_json_text_node_budget,
                        check_json_tree_budget_details,
                    )

                    try:
                        text_nodes = check_json_text_node_budget(blob, label="tool arguments")
                    except ToolInputSchemaError as error:
                        raise ProviderError(
                            f"tool call {name or index} arguments exceed runtime limits"
                        ) from error
                    total_tool_argument_nodes += text_nodes
                    if total_tool_argument_nodes > MAX_SCHEMA_TREE_NODES:
                        raise ProviderError(
                            f"provider tool arguments exceed the {MAX_SCHEMA_TREE_NODES}-node response limit"
                        )
                    try:
                        parsed = json.loads(blob)
                    except ValueError as error:
                        raise ProviderError(
                            f"tool call {name or index} carried arguments that are not valid JSON"
                        ) from error
                    if not isinstance(parsed, dict):
                        raise ProviderError(f"tool call {name or index} arguments must decode to an object")
                    try:
                        check_json_tree_budget_details(parsed, label="tool arguments")
                    except ToolInputSchemaError as error:
                        raise ProviderError(
                            f"tool call {name or index} arguments exceed runtime limits"
                        ) from error
                    arguments = parsed
            blocks.append(ToolUseBlock(id=str(_field(call, "id", "") or f"call_{index}"), name=name, input=arguments))
        finish = str(_field(choice, "finish_reason", "") or "")
        stop_reason = _FINISH_REASONS.get(finish, "end_turn")
        if blocks and any(isinstance(block, ToolUseBlock) for block in blocks) and finish in {"", "stop"}:
            # Some gateways omit finish_reason when a tool call is present.
            stop_reason = "tool_use"
        return Generation(
            content=tuple(blocks),
            usage=_usage(response),
            stop_reason=stop_reason,
            model=str(_field(response, "model", "") or ""),
        )

    def close(self) -> None:
        if not self._owns_client:
            return
        close = getattr(self._client, "close", None)
        if callable(close):
            close()


def _classify(error: Exception) -> dict[str, Any]:
    """Structured fields for the :class:`ProviderError` we are about to raise.

    The retry policy in :mod:`provider_retry` decides "retry or stop" from the fault class,
    and it reads a status code before it reads prose. A provider that has the number and
    keeps it to itself hands that decision to string matching, so the classification is done
    here once and attached - the loop's own classification then agrees with ours by
    construction rather than by luck.
    """
    from provider_retry import classify

    fault = classify(error)
    return {"failure_kind": fault.kind, "status_code": fault.status_code, "retry_after_ms": fault.retry_after_ms}


def _usage(response: Any) -> Usage:
    raw = _field(response, "usage", {}) or {}
    details = _field(raw, "prompt_tokens_details", {}) or {}
    return Usage(
        input_tokens=int(_field(raw, "prompt_tokens", 0) or 0),
        output_tokens=int(_field(raw, "completion_tokens", 0) or 0),
        # Providers that do server-side prefix caching report it here; mapping it
        # onto the cache fields keeps the cost view comparable across backends.
        cache_read_input_tokens=int(_field(details, "cached_tokens", 0) or 0),
    )


def _reason(error: Exception) -> str:
    for attribute in ("status_code", "code"):
        value = getattr(error, attribute, None)
        if value not in (None, ""):
            return f"{type(error).__name__}({attribute}={value}): {str(error)[:200]}"
    return f"{type(error).__name__}: {str(error)[:200]}"


__all__ = ["DEFAULT_MODEL", "OpenAICompatProvider"]
