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

import json
from typing import Any, Sequence

from providers.base import (
    Generation,
    GenerationRequest,
    Provider,
    ProviderError,
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


def _is_reasoning_model(model: str) -> bool:
    key = (model or "").strip().lower()
    return any(key.startswith(prefix) for prefix in _REASONING_PREFIXES)


def _text_of(content: Any) -> str:
    """Flatten a chat ``content`` value (string, or a list of text parts)."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, (list, tuple)):
        parts: list[str] = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict) and part.get("type") in (None, "text"):
                parts.append(str(part.get("text", "")))
        return "".join(parts)
    return str(content)


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
        max_retries: int = 2,
        timeout: float | None = None,
        extra_headers: dict[str, str] | None = None,
        extra_body: dict[str, Any] | None = None,
        supports_tools: bool = True,
    ) -> None:
        if max_tokens <= 0:
            raise ValueError("max_tokens must be positive")
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
        self._client = client
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
                from openai import OpenAI
            except ImportError as error:  # pragma: no cover - depends on host
                raise ProviderError(
                    "the 'openai' package is required for OpenAICompatProvider "
                    "(pip install openai), or use provider='scripted' for offline runs"
                ) from error
            self._client = OpenAI(**self._client_kwargs)
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
            function["parameters"] = schema
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
            raise ProviderError(f"chat completions request failed: {_reason(error)}") from error
        return self.normalise(response)

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
        for index, call in enumerate(_field(message, "tool_calls", ()) or ()):
            function = _field(call, "function", {}) or {}
            name = str(_field(function, "name", "") or "")
            raw_arguments = _field(function, "arguments", "")
            if isinstance(raw_arguments, dict):
                arguments: dict[str, Any] = dict(raw_arguments)
            else:
                blob = str(raw_arguments or "").strip()
                if not blob:
                    arguments = {}
                else:
                    try:
                        parsed = json.loads(blob)
                    except ValueError as error:
                        raise ProviderError(
                            f"tool call {name or index} carried arguments that are not valid JSON"
                        ) from error
                    if not isinstance(parsed, dict):
                        raise ProviderError(f"tool call {name or index} arguments must decode to an object")
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
        close = getattr(self._client, "close", None)
        if callable(close):
            close()


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
