"""Response-body limits for provider-owned synchronous SDK HTTP clients.

The SDKs deserialize JSON before returning their response objects to provider
normalizers. This client wrapper asks the SDK transport for a streamed response,
counts decoded identity-encoded bytes, and only gives a bounded body back to the
SDK parser. It deliberately leaves caller-injected HTTP clients under the host's
control.
"""
from __future__ import annotations

import sys
from typing import Any, Callable

MAX_RESPONSE_CHUNK_BYTES = 65_536


class HTTPResponseLimitError(RuntimeError):
    """An upstream HTTP response exceeded the configured body ceiling."""


def make_response_limited_http_client(base_client: Callable[..., Any], max_response_bytes: int) -> Any:
    """Create a default-SDK-compatible HTTP client with a hard response cap.

    The SDK's public default-client factory is passed in, then its ``send``
    method is wrapped on the instance. This keeps the actual SDK HTTP client
    type and its timeout, proxy, TLS, redirect, and connection-pool behavior.
    It also works when an SDK exposes its default client as a factory function
    instead of a subclassable class.
    """
    if isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int) or max_response_bytes <= 0:
        raise ValueError("max_response_bytes must be a positive integer")

    client = base_client(headers={"Accept-Encoding": "identity"})
    try:
        client.headers["Accept-Encoding"] = "identity"
        original_send = client.send
        stream_base = _sync_stream_base(type(client))
    except Exception as error:
        close = getattr(client, "close", None)
        if callable(close):
            close()
        raise RuntimeError("SDK HTTP client cannot enforce the provider response-body limit") from error

    def send_limited(request: Any, *, stream: bool = False, **kwargs: Any) -> Any:
        # SDK per-request headers can override client defaults, so enforce the
        # identity encoding at the final transport boundary as well.
        request.headers["Accept-Encoding"] = "identity"
        response = original_send(request, stream=True, **kwargs)
        try:
            _require_identity_encoding(response, max_response_bytes)
        except Exception:
            response.close()
            raise
        if stream:
            return _stream_limited_response(response, max_response_bytes, stream_base)
        return _read_limited_response(response, max_response_bytes)

    try:
        client.send = send_limited
    except Exception as error:
        close = getattr(client, "close", None)
        if callable(close):
            close()
        raise RuntimeError("SDK HTTP client cannot enforce the provider response-body limit") from error
    return client


def _require_identity_encoding(response: Any, limit: int) -> None:
    encoding = str(response.headers.get("content-encoding", "")).strip().lower()
    if encoding not in {"", "identity"}:
        raise HTTPResponseLimitError("provider response used a compressed content encoding")
    content_length = response.headers.get("content-length")
    if content_length is not None:
        declared = str(content_length).strip()
        if declared.isascii() and declared.isdigit():
            normalized = declared.lstrip("0") or "0"
            limit_text = str(limit)
            if len(normalized) > len(limit_text) or (
                len(normalized) == len(limit_text) and normalized > limit_text
            ):
                raise HTTPResponseLimitError(f"provider response exceeds the {limit}-byte limit")


def _sync_stream_base(client_type: type[Any]) -> type[Any]:
    """Find the public sync-stream base from the SDK's actual HTTP client family."""
    for client_base in client_type.__mro__:
        module = sys.modules.get(client_base.__module__.split(".", 1)[0])
        stream_base = getattr(module, "SyncByteStream", None)
        if isinstance(stream_base, type):
            return stream_base
    return object


def _limited_byte_stream(response: Any, limit: int, stream_base: type[Any]) -> Any:
    """Build a stream instance that satisfies HTTPX or HTTPX2's public protocol."""
    class LimitedByteStream(stream_base):
        def __init__(self) -> None:
            self._closed = False

        def __iter__(self):
            total = 0
            try:
                for chunk in response.iter_bytes(chunk_size=min(MAX_RESPONSE_CHUNK_BYTES, limit + 1)):
                    if total + len(chunk) > limit:
                        raise HTTPResponseLimitError(f"provider response exceeds the {limit}-byte limit")
                    total += len(chunk)
                    yield chunk
            finally:
                self.close()

        def close(self) -> None:
            if not self._closed:
                self._closed = True
                response.close()

    return LimitedByteStream()


def _response_headers(response: Any, *, streaming: bool) -> Any:
    headers = response.headers.copy()
    headers.pop("content-encoding", None)
    if streaming:
        # The replacement stream contains decoded identity bytes and may be
        # closed before completion, so the original framing length is invalid.
        headers.pop("content-length", None)
    return headers


def _read_limited_response(response: Any, limit: int) -> Any:
    body = bytearray()
    try:
        for chunk in response.iter_bytes(chunk_size=min(MAX_RESPONSE_CHUNK_BYTES, limit + 1)):
            if len(body) + len(chunk) > limit:
                raise HTTPResponseLimitError(f"provider response exceeds the {limit}-byte limit")
            body.extend(chunk)
        content = bytes(body)
        headers = _response_headers(response, streaming=False)
        headers["content-length"] = str(len(content))
        limited = response.__class__(
            status_code=response.status_code,
            headers=headers,
            content=content,
            request=response.request,
            extensions=response.extensions,
        )
        limited.history = response.history
        return limited
    finally:
        response.close()


def _stream_limited_response(response: Any, limit: int, stream_base: type[Any]) -> Any:
    try:
        limited = response.__class__(
            status_code=response.status_code,
            headers=_response_headers(response, streaming=True),
            stream=_limited_byte_stream(response, limit, stream_base),
            request=response.request,
            extensions=response.extensions,
        )
        limited.history = response.history
        return limited
    except Exception:
        response.close()
        raise
