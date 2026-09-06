"""Model providers for the Northstar agent runtime.

``anthropic`` SDK import stays lazy: importing this package never pulls in the
SDK, and ``AnthropicProvider(client=fake)`` works without it installed.
"""
from .base import (
    Provider,
    ProviderError,
    ProviderRequest,
    ProviderResponse,
    TextBlock,
    ToolUseBlock,
    Usage,
    assistant_wire_message,
    text_blocks,
    tool_use_blocks,
    user_text_message,
    user_tool_result_message,
)
from .anthropic import AnthropicProvider, build_request_kwargs, normalize_response, normalize_usage
from .scripted import ScriptedProvider, normalize_step

__all__ = [
    "Provider",
    "ProviderError",
    "ProviderRequest",
    "ProviderResponse",
    "TextBlock",
    "ToolUseBlock",
    "Usage",
    "assistant_wire_message",
    "text_blocks",
    "tool_use_blocks",
    "user_text_message",
    "user_tool_result_message",
    "AnthropicProvider",
    "build_request_kwargs",
    "normalize_response",
    "normalize_usage",
    "ScriptedProvider",
    "normalize_step",
]
