"""Anthropic Messages API provider.

The SDK import is lazy and optional at module level: constructing an
``AnthropicProvider`` with an explicit ``client=`` (as the tests do with a
fake) never imports the ``anthropic`` package, and the normalisation helpers
are pure functions over duck-typed objects.

Real API behaviour is out of scope for the offline test suite; only request
construction and response normalisation are tested here, against fakes.
"""
from __future__ import annotations

from typing import Any

from .base import (
    Provider,
    ProviderError,
    ProviderRequest,
    ProviderResponse,
    TextBlock,
    ToolUseBlock,
    Usage,
)

DEFAULT_MAX_TOKENS = 4096


def normalize_usage(usage: Any) -> Usage:
    """Read usage off an SDK-style object; missing cache fields count as zero."""

    def _get(name: str) -> int:
        value = getattr(usage, name, 0)
        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError):
            return 0

    return Usage(
        input_tokens=_get("input_tokens"),
        output_tokens=_get("output_tokens"),
        cache_read_input_tokens=_get("cache_read_input_tokens"),
        cache_creation_input_tokens=_get("cache_creation_input_tokens"),
    )


def normalize_content_block(block: Any) -> TextBlock | ToolUseBlock:
    block_type = getattr(block, "type", None)
    if block_type == "text":
        return TextBlock(getattr(block, "text", "") or "")
    if block_type == "tool_use":
        tool_input = getattr(block, "input", None) or {}
        return ToolUseBlock(
            id=str(getattr(block, "id", "")),
            name=str(getattr(block, "name", "")),
            input=dict(tool_input),
        )
    raise ProviderError(f"unsupported content block type from provider: {block_type!r}")


def normalize_response(response: Any) -> ProviderResponse:
    content = [normalize_content_block(b) for b in (getattr(response, "content", None) or [])]
    usage_obj = getattr(response, "usage", None)
    return ProviderResponse(
        content=content,
        usage=normalize_usage(usage_obj) if usage_obj is not None else Usage.zero(),
        stop_reason=getattr(response, "stop_reason", None) or "end_turn",
    )


def build_request_kwargs(request: ProviderRequest, max_tokens: int) -> dict[str, Any]:
    """Pure request construction — the only place the wire kwargs are shaped."""
    kwargs: dict[str, Any] = {
        "model": request.model,
        "messages": list(request.messages),
        "max_tokens": request.max_tokens if request.max_tokens > 0 else max_tokens,
    }
    if request.system:
        kwargs["system"] = request.system
    if request.tools:
        kwargs["tools"] = [dict(t) for t in request.tools]
    return kwargs


class AnthropicProvider(Provider):
    """Thin adapter around an Anthropic client (real or injected fake)."""

    def __init__(self, client: Any = None, max_tokens: int = DEFAULT_MAX_TOKENS):
        if client is None:
            try:
                from anthropic import Anthropic  # lazy: keep the module importable offline
            except ImportError as exc:  # pragma: no cover - depends on environment
                raise ProviderError(
                    "the 'anthropic' package is required when no client is injected; "
                    "install it or pass client= explicitly"
                ) from exc
            client = Anthropic()
        self._client = client
        self.max_tokens = max_tokens

    def create_message(self, request: ProviderRequest) -> ProviderResponse:
        kwargs = build_request_kwargs(request, self.max_tokens)
        try:
            response = self._client.messages.create(**kwargs)
        except ProviderError:
            raise
        except Exception as exc:  # map any SDK error to a loop-safe event
            # Deliberately only the exception class name: SDK error strings can
            # carry request metadata, and this message lands in a ResultMessage.
            raise ProviderError(f"anthropic request failed: {type(exc).__name__}") from exc
        return normalize_response(response)
