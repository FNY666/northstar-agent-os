"""Provider SDK response caps; all tests use a transport double, never a socket."""
from __future__ import annotations

import sys
import types
import unittest
from unittest import mock

import support  # noqa: F401 - adds the component root to sys.path

from providers.anthropic import AnthropicProvider
from providers.http_response_limits import (
    HTTPResponseLimitError,
    make_response_limited_http_client,
)
from providers.openai_compat import OpenAICompatProvider


class Headers(dict):
    def __init__(self, values=()):
        super().__init__((str(key).lower(), str(value)) for key, value in dict(values).items())

    def __getitem__(self, key):
        return super().__getitem__(str(key).lower())

    def __setitem__(self, key, value):
        super().__setitem__(str(key).lower(), str(value))

    def get(self, key, default=None):
        return super().get(str(key).lower(), default)

    def pop(self, key, *args):
        return super().pop(str(key).lower(), *args)

    def copy(self):
        return Headers(self)


class FakeResponse:
    def __init__(self, *, status_code=200, headers=(), content=None, stream=None, request=None, extensions=None):
        self.status_code = status_code
        self.headers = Headers(headers)
        self._content = content
        self._stream = stream
        self.request = request
        self.extensions = extensions or {}
        self.history = ["redirect"]
        self.closed = False
        self.iter_calls = 0

    def iter_bytes(self, chunk_size=None):  # noqa: ARG002 - mirrors HTTPX's public API
        self.iter_calls += 1
        if self._stream is not None:
            yield from self._stream
        elif self._content:
            yield self._content

    def close(self):
        self.closed = True
        close = getattr(self._stream, "close", None)
        if callable(close):
            close()


class FakeRequest:
    def __init__(self):
        self.headers = Headers()


class FakeHttpClient:
    def __init__(self, *, headers=(), response=None, **kwargs):
        self.headers = Headers(headers)
        self.response = response
        self.send_kwargs = None

    def send(self, request, *, stream=False, **kwargs):
        self.send_kwargs = {"stream": stream, **kwargs}
        self.request = request
        return self.response


class ResponseLimitTests(unittest.TestCase):
    def make_client(self, response, limit=4):
        client = make_response_limited_http_client(FakeHttpClient, limit)
        client.response = response
        return client

    def test_limit_must_be_a_positive_non_boolean_integer(self):
        for value in (0, -1, True, 1.5, "4"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                make_response_limited_http_client(FakeHttpClient, value)

    def test_declared_oversize_is_rejected_before_reading_and_closes(self):
        original = FakeResponse(headers={"Content-Length": "5"}, content=b"12345")
        client = self.make_client(original)
        with self.assertRaises(HTTPResponseLimitError):
            client.send(FakeRequest())
        self.assertEqual(original.iter_calls, 0)
        self.assertTrue(original.closed)

    def test_very_long_declared_length_is_compared_without_integer_conversion(self):
        original = FakeResponse(headers={"Content-Length": "9" * 5000}, content=b"ignored")
        with self.assertRaises(HTTPResponseLimitError):
            self.make_client(original).send(FakeRequest())
        self.assertEqual(original.iter_calls, 0)
        self.assertTrue(original.closed)

    def test_chunked_oversize_is_rejected_before_returning_and_closes(self):
        original = FakeResponse(stream=[b"123", b"45"])
        client = self.make_client(original)
        with self.assertRaises(HTTPResponseLimitError):
            client.send(FakeRequest())
        self.assertTrue(original.closed)

    def test_non_stream_body_is_bounded_and_preserves_response_metadata(self):
        original = FakeResponse(
            headers={"Content-Length": "4", "Content-Encoding": "identity", "X-Test": "ok"},
            content=b"1234",
        )
        client = self.make_client(original)
        limited = client.send(FakeRequest())
        self.assertEqual(b"".join(limited.iter_bytes()), b"1234")
        self.assertEqual(limited.headers["content-length"], "4")
        self.assertEqual(limited.headers["x-test"], "ok")
        self.assertNotIn("content-encoding", limited.headers)
        self.assertEqual(limited.history, ["redirect"])
        self.assertTrue(original.closed)
        self.assertEqual(client.request.headers["accept-encoding"], "identity")
        self.assertEqual(client.headers["accept-encoding"], "identity")
        self.assertEqual(client.send_kwargs["stream"], True)

    def test_stream_body_is_capped_when_consumed_and_has_no_stale_length(self):
        original = FakeResponse(headers={"Content-Length": "4"}, stream=[b"12", b"34"])
        client = self.make_client(original)
        limited = client.send(FakeRequest(), stream=True)
        self.assertNotIn("content-length", limited.headers)
        self.assertEqual(b"".join(limited.iter_bytes()), b"1234")
        self.assertTrue(original.closed)

    def test_stream_wrapper_uses_the_sdk_http_family_sync_stream_base(self):
        class FakeSyncByteStream:
            pass

        fake_httpx = types.ModuleType("fake_httpx_family")
        fake_httpx.SyncByteStream = FakeSyncByteStream
        original_module = FakeHttpClient.__module__
        FakeHttpClient.__module__ = "fake_httpx_family.client"
        try:
            with mock.patch.dict(sys.modules, {"fake_httpx_family": fake_httpx}):
                original = FakeResponse(stream=[b"ok"])
                limited = self.make_client(original).send(FakeRequest(), stream=True)
                self.assertIsInstance(limited._stream, FakeSyncByteStream)
                limited.close()
                self.assertTrue(original.closed)
        finally:
            FakeHttpClient.__module__ = original_module

    def test_stream_overflow_closes_underlying_response(self):
        original = FakeResponse(stream=[b"123", b"45"])
        limited = self.make_client(original).send(FakeRequest(), stream=True)
        with self.assertRaises(HTTPResponseLimitError):
            b"".join(limited.iter_bytes())
        self.assertTrue(original.closed)

    def test_closing_an_unconsumed_stream_closes_underlying_response(self):
        original = FakeResponse(stream=[b"body"])
        limited = self.make_client(original).send(FakeRequest(), stream=True)
        limited.close()
        self.assertTrue(original.closed)

    def test_compressed_response_is_rejected_before_body_decode(self):
        original = FakeResponse(headers={"Content-Encoding": "gzip"}, content=b"ignored")
        with self.assertRaises(HTTPResponseLimitError):
            self.make_client(original).send(FakeRequest())
        self.assertEqual(original.iter_calls, 0)
        self.assertTrue(original.closed)


class ProviderConstructionTests(unittest.TestCase):
    def test_both_provider_caps_reject_bad_values_and_do_not_close_injected_clients(self):
        for provider_type in (OpenAICompatProvider, AnthropicProvider):
            for value in (0, -1, True, 1.5):
                with self.subTest(provider=provider_type.__name__, value=value), self.assertRaises(ValueError):
                    provider_type(max_response_bytes=value)

            class CountingClient:
                closed = 0

                def close(self):
                    type(self).closed += 1

            injected = CountingClient()
            provider_type(client=injected).close()
            self.assertEqual(injected.closed, 0)

    def test_sdk_owned_clients_receive_bounded_transport_and_injected_clients_are_untouched(self):
        captured = {}

        class SDKHTTPClient(FakeHttpClient):
            pass

        def construct(**kwargs):
            captured.update(kwargs)
            return object()

        for module_name, provider_type, constructor_name in (
            ("openai", OpenAICompatProvider, "OpenAI"),
            ("anthropic", AnthropicProvider, "Anthropic"),
        ):
            fake_sdk = types.ModuleType(module_name)
            fake_sdk.DefaultHttpxClient = SDKHTTPClient
            setattr(fake_sdk, constructor_name, construct)
            captured.clear()
            with mock.patch.dict(sys.modules, {module_name: fake_sdk}):
                provider = provider_type(max_response_bytes=1234)
                provider.client
            self.assertIn("http_client", captured)
            self.assertEqual(captured["http_client"].headers["accept-encoding"], "identity")
            self.assertEqual(provider.max_response_bytes, 1234)

        for provider_type in (OpenAICompatProvider, AnthropicProvider):
            with self.subTest(provider=provider_type.__name__):
                provider = provider_type(client=object())
                self.assertIs(provider.client, provider._client)


if __name__ == "__main__":
    unittest.main()
