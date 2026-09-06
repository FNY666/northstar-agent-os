"""Anthropic Messages API provider.

The ``anthropic`` package is imported lazily so that every other module in this
component stays importable on a host with no model SDK installed, and so tests
run offline. A ``client`` may be injected; that is the seam the offline tests use
to assert response normalisation without a network or an API key.

Limitation recorded in the component README and in the pull request: the real
API has not been exercised here (no credentials in the test environment). Only
normalisation against a fake client is verified.
"""
from __future__ import annotations

from typing import Any, Sequence

from providers.base import (
    Generation,
    GenerationRequest,
    Provider,
    ProviderError,
    TextBlock,
    ThinkingBlock,
    ToolUseBlock,
    Usage,
)

# Model families the adapter knows how to talk to. Unknown models are still
# accepted - only the pricing table refuses to guess (see budget.py).
CACHE_CONTROL_EPHEMERAL = {"type": "ephemeral"}


class AnthropicProvider(Provider):
    """Thin, normalising adapter over ``client.messages.create``."""

    name = "anthropic"

    def __init__(
        self,
        *,
        model: str = "claude-sonnet-4-5",
        client: Any | None = None,
        api_key: str | None = None,
        max_tokens: int = 4096,
        temperature: float | None = None,
        prompt_cache: bool = True,
        max_retries: int = 2,
        timeout: float | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        if max_tokens <= 0:
            raise ValueError("max_tokens must be positive")
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.prompt_cache = prompt_cache
        self._client = client
        self._owns_client = client is None
        self._client_kwargs: dict[str, Any] = {
            "max_retries": max_retries,
        }
        if api_key is not None:
            self._client_kwargs["api_key"] = api_key
        if timeout is not None:
            self._client_kwargs["timeout"] = timeout
        if extra_headers:
            self._client_kwargs["default_headers"] = dict(extra_headers)

    @property
    def client(self) -> Any:
        if self._client is None:
            try:
                from anthropic import Anthropic
            except ImportError as error:  # pragma: no cover - depends on host
                raise ProviderError(
                    "the 'anthropic' package is required for AnthropicProvider; "
                    "install requirements.txt, or use provider='scripted'"
                ) from error
            self._client = Anthropic(**self._client_kwargs)
        return self._client

    # -- request building --------------------------------------------------
    def build_payload(self, request: GenerationRequest) -> dict[str, Any]:
        """Translate a GenerationRequest into ``messages.create`` kwargs.

        Prompt caching is applied to the system block and the final tool
        definition, which is where the reuse actually shows up across turns.
        """
        payload: dict[str, Any] = {
            "model": request.model or self.model,
            "max_tokens": request.max_tokens or self.max_tokens,
            "messages": list(request.messages),
        }
        if request.system:
            if self.prompt_cache:
                payload["system"] = [
                    {"type": "text", "text": request.system, "cache_control": dict(CACHE_CONTROL_EPHEMERAL)}
                ]
            else:
                payload["system"] = request.system
        if request.tools:
            tools = [dict(tool) for tool in request.tools]
            if self.prompt_cache and tools:
                tools[-1]["cache_control"] = dict(CACHE_CONTROL_EPHEMERAL)
            payload["tools"] = tools
        if request.stop_sequences:
            payload["stop_sequences"] = list(request.stop_sequences)
        if self.temperature is not None:
            payload["temperature"] = self.temperature
        return payload

    # -- response normalisation -------------------------------------------
    def generate(self, request: GenerationRequest) -> Generation:
        payload = self.build_payload(request)
        try:
            response = self.client.messages.create(**payload)
        except ProviderError:
            raise
        except Exception as error:  # noqa: BLE001 - must surface as an event
            raise ProviderError(f"anthropic request failed: {_reason(error)}") from error
        return self.normalise(response)

    @staticmethod
    def normalise(response: Any) -> Generation:
        """Convert an SDK response (or a matching fake) into a Generation.

        Accepts both attribute and mapping shapes so a test double can be a plain
        dict without pretending to be an SDK object.
        """
        content_blocks: list[Any] = []
        for block in _field(response, "content", ()) or ():
            kind = _field(block, "type", "")
            if kind == "text":
                content_blocks.append(TextBlock(text=str(_field(block, "text", "") or "")))
            elif kind == "thinking":
                content_blocks.append(
                    ThinkingBlock(
                        text=str(_field(block, "thinking", _field(block, "text", "")) or ""),
                        signature=str(_field(block, "signature", "") or ""),
                    )
                )
            elif kind == "tool_use":
                raw_input = _field(block, "input", {}) or {}
                content_blocks.append(
                    ToolUseBlock(
                        id=str(_field(block, "id", "") or ""),
                        name=str(_field(block, "name", "") or ""),
                        input=dict(raw_input) if isinstance(raw_input, dict) else {"value": raw_input},
                    )
                )
            # Unknown block types are dropped rather than guessed at.
        stop_reason = str(_field(response, "stop_reason", "") or "")
        if not stop_reason:
            stop_reason = "tool_use" if any(isinstance(block, ToolUseBlock) for block in content_blocks) else "end_turn"
        return Generation(
            content=tuple(content_blocks),
            usage=Usage.from_mapping(_usage_mapping(response)),
            stop_reason=stop_reason,
            model=str(_field(response, "model", "") or ""),
        )

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            closer = getattr(self._client, "close", None)
            if callable(closer):  # pragma: no cover - defensive
                closer()


def _field(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _usage_mapping(response: Any) -> dict[str, int]:
    usage = _field(response, "usage", None)
    if usage is None:
        return {}
    if isinstance(usage, dict):
        return {key: value for key, value in usage.items() if isinstance(value, int) and not isinstance(value, bool)}
    mapping: dict[str, int] = {}
    for key in (
        "input_tokens",
        "output_tokens",
        "cache_read_input_tokens",
        "cache_creation_input_tokens",
    ):
        value = getattr(usage, key, None)
        if isinstance(value, int) and not isinstance(value, bool):
            mapping[key] = value
    return mapping


def _reason(error: Exception) -> str:
    """Short, secret-free reason string.

    Provider exceptions can embed request bodies; never propagate them verbatim.
    """
    text = str(error) or type(error).__name__
    return text if len(text) <= 300 else text[:297] + "..."


def _unused(blocks: Sequence[Any]) -> None:  # pragma: no cover
    return None


__all__ = ["AnthropicProvider"]
