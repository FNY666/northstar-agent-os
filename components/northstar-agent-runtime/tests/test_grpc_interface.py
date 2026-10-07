"""Targeted tests for grpc_interface."""

import threading
import unittest

from grpc_interface import (
    BIDIRECTIONAL,
    CLIENT_STREAMING,
    CODE_FAILED_PRECONDITION,
    CODE_OK,
    GRPCInterface,
    GRPC_INTERFACE_VERSION,
    SCHEMA_PIN,
    SERVER_STREAMING,
    UNARY,
    CallResult,
    DuplicateMethodError,
    MethodType,
    PayloadError,
    ServiceDescriptor,
    StreamResult,
    StreamingCallError,
    UnknownMethodError,
    grpc_interface_audit_event,
    main,
)


def unary_echo(request):
    return {"echo": request}


def server_streamer(request):
    return ({"n": i, "name": request["name"]} for i in range(request["count"]))


def client_streamer(requests):
    total = 0
    for r in requests:
        total += r["v"]
    return {"total": total}


def bidi_echo(requests):
    for r in requests:
        yield {"back": r["fwd"]}


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(GRPC_INTERFACE_VERSION, "grpc-interface.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.grpc-interface.v1")

    def test_method_type_constants(self):
        self.assertEqual(
            set(MethodType.ALL),
            {"unary", "server-streaming", "client-streaming", "bidirectional"},
        )
        self.assertEqual(UNARY, "unary")
        self.assertEqual(SERVER_STREAMING, "server-streaming")
        self.assertEqual(CLIENT_STREAMING, "client-streaming")
        self.assertEqual(BIDIRECTIONAL, "bidirectional")


class TestRegistration(unittest.TestCase):
    def setUp(self):
        self.iface = GRPCInterface()

    def test_register_unary(self):
        d = self.iface.register("svc", "M", MethodType.UNARY, unary_echo, seq=0)
        self.assertIsInstance(d, ServiceDescriptor)
        self.assertEqual((d.service, d.method, d.method_type), ("svc", "M", "unary"))
        self.assertTrue(d.descriptor_digest.startswith("sha256:"))
        self.assertEqual(d.version, GRPC_INTERFACE_VERSION)
        self.assertEqual(d.schema, SCHEMA_PIN)

    def test_register_all_method_types(self):
        handlers = {
            MethodType.UNARY: unary_echo,
            MethodType.SERVER_STREAMING: server_streamer,
            MethodType.CLIENT_STREAMING: client_streamer,
            MethodType.BIDIRECTIONAL: bidi_echo,
        }
        for i, (mt, h) in enumerate(handlers.items()):
            d = self.iface.register("svc", f"M{i}", mt, h, seq=i)
            self.assertEqual(d.method_type, mt)

    def test_descriptor_digest_deterministic(self):
        a = self.iface.register("svc", "M", MethodType.UNARY, unary_echo, seq=0)
        other = GRPCInterface()
        b = other.register("svc", "M", MethodType.UNARY, unary_echo, seq=0)
        self.assertEqual(a.descriptor_digest, b.descriptor_digest)

    def test_duplicate_registration_refused(self):
        self.iface.register("svc", "M", MethodType.UNARY, unary_echo, seq=0)
        with self.assertRaises(DuplicateMethodError):
            self.iface.register("svc", "M", MethodType.UNARY, unary_echo, seq=1)

    def test_same_method_different_service_ok(self):
        self.iface.register("a", "M", MethodType.UNARY, unary_echo, seq=0)
        d = self.iface.register("b", "M", MethodType.UNARY, unary_echo, seq=1)
        self.assertEqual(d.service, "b")

    def test_bad_method_type(self):
        with self.assertRaises(ValueError):
            self.iface.register("svc", "M", "firehose", unary_echo, seq=0)

    def test_bad_names(self):
        for bad in ("", "a/b", " lead", "trail ", 123, None, True):
            with self.assertRaises((TypeError, ValueError)):
                self.iface.register(bad, "M", MethodType.UNARY, unary_echo, seq=0)
            with self.assertRaises((TypeError, ValueError)):
                self.iface.register("svc", bad, MethodType.UNARY, unary_echo, seq=0)

    def test_non_callable_handler(self):
        with self.assertRaises(TypeError):
            self.iface.register("svc", "M", MethodType.UNARY, "not-callable", seq=0)

    def test_bad_seq(self):
        for bad in (-1, True, "0", 1.5):
            with self.assertRaises((TypeError, ValueError)):
                self.iface.register("svc", "M", MethodType.UNARY, unary_echo, seq=bad)

    def test_services_and_methods_views(self):
        self.iface.register("b", "Z", MethodType.UNARY, unary_echo, seq=0)
        self.iface.register("a", "Y", MethodType.UNARY, unary_echo, seq=1)
        self.iface.register("a", "X", MethodType.UNARY, unary_echo, seq=2)
        self.assertEqual(self.iface.services(), ("a", "b"))
        self.assertEqual(self.iface.methods("a"), ("X", "Y"))
        self.assertEqual(self.iface.methods("b"), ("Z",))
        self.assertEqual(self.iface.methods("missing"), ())

    def test_descriptor_view(self):
        d = self.iface.register("svc", "M", MethodType.UNARY, unary_echo, seq=0)
        self.assertEqual(self.iface.descriptor("svc", "M"), d)
        with self.assertRaises(UnknownMethodError):
            self.iface.descriptor("svc", "Nope")


class TestUnaryCall(unittest.TestCase):
    def setUp(self):
        self.iface = GRPCInterface()
        self.iface.register("svc", "Echo", MethodType.UNARY, unary_echo, seq=0)

    def test_call_happy_path(self):
        resp, res = self.iface.call("svc", "Echo", {"x": 1}, seq=1)
        self.assertEqual(resp, {"echo": {"x": 1}})
        self.assertIsInstance(res, CallResult)
        self.assertEqual(res.code, CODE_OK)
        self.assertEqual((res.service, res.method), ("svc", "Echo"))
        self.assertTrue(res.request_digest.startswith("sha256:"))
        self.assertTrue(res.response_digest.startswith("sha256:"))
        self.assertEqual(res.seq, 1)
        self.assertIsNone(res.deadline_ms)
        self.assertEqual(res.metadata, ())

    def test_call_digest_binds_content(self):
        _, r1 = self.iface.call("svc", "Echo", {"x": 1}, seq=1)
        _, r2 = self.iface.call("svc", "Echo", {"x": 2}, seq=2)
        self.assertNotEqual(r1.request_digest, r2.request_digest)

    def test_call_count(self):
        self.assertEqual(self.iface.call_count(), 0)
        self.iface.call("svc", "Echo", {"x": 1}, seq=1)
        self.iface.call("svc", "Echo", {"x": 2}, seq=2)
        self.assertEqual(self.iface.call_count(), 2)

    def test_call_unknown_method(self):
        with self.assertRaises(UnknownMethodError):
            self.iface.call("svc", "Nope", {"x": 1}, seq=1)
        with self.assertRaises(UnknownMethodError):
            self.iface.call("nosvc", "Echo", {"x": 1}, seq=1)

    def test_call_streaming_method_refused(self):
        self.iface.register("svc", "S", MethodType.SERVER_STREAMING, server_streamer, seq=5)
        with self.assertRaises(StreamingCallError):
            self.iface.call("svc", "S", {"name": "a", "count": 2}, seq=6)

    def test_call_nan_payload_refused(self):
        with self.assertRaises(PayloadError):
            self.iface.call("svc", "Echo", {"x": float("nan")}, seq=1)

    def test_call_with_metadata_and_deadline(self):
        resp, res = self.iface.call(
            "svc",
            "Echo",
            {"x": 1},
            seq=1,
            metadata={"trace": "abc", "user": "u1"},
            deadline_ms=5000,
        )
        self.assertEqual(resp, {"echo": {"x": 1}})
        self.assertEqual(res.metadata, (("trace", "abc"), ("user", "u1")))
        self.assertEqual(res.deadline_ms, 5000)

    def test_call_bad_metadata(self):
        with self.assertRaises(TypeError):
            self.iface.call("svc", "Echo", {"x": 1}, seq=1, metadata={"k": 1})
        with self.assertRaises(TypeError):
            self.iface.call("svc", "Echo", {"x": 1}, seq=1, metadata="nope")

    def test_call_bad_deadline(self):
        for bad in (0, -5, True, "100"):
            with self.assertRaises((TypeError, ValueError)):
                self.iface.call("svc", "Echo", {"x": 1}, seq=1, deadline_ms=bad)

    def test_result_as_dict(self):
        _, res = self.iface.call("svc", "Echo", {"x": 1}, seq=1)
        d = res.as_dict()
        self.assertEqual(d["code"], CODE_OK)
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["seq"], 1)


class TestStreaming(unittest.TestCase):
    def setUp(self):
        self.iface = GRPCInterface()
        self.iface.register("svc", "S", MethodType.SERVER_STREAMING, server_streamer, seq=0)
        self.iface.register("svc", "C", MethodType.CLIENT_STREAMING, client_streamer, seq=1)
        self.iface.register("svc", "B", MethodType.BIDIRECTIONAL, bidi_echo, seq=2)

    def test_server_streaming(self):
        responses, res = self.iface.stream(
            "svc", "S", [{"name": "ada", "count": 3}], seq=3
        )
        self.assertEqual(len(responses), 3)
        self.assertEqual(responses[0], {"n": 0, "name": "ada"})
        self.assertIsInstance(res, StreamResult)
        self.assertEqual(res.method_type, SERVER_STREAMING)
        self.assertEqual(res.response_count, 3)
        self.assertEqual(res.code, CODE_OK)

    def test_server_streaming_needs_single_request(self):
        with self.assertRaises(ValueError):
            self.iface.stream("svc", "S", [{"a": 1}, {"a": 2}], seq=3)

    def test_client_streaming(self):
        responses, res = self.iface.stream(
            "svc", "C", [{"v": 1}, {"v": 2}, {"v": 3}], seq=3
        )
        self.assertEqual(responses, ({"total": 6},))
        self.assertEqual(res.method_type, CLIENT_STREAMING)
        self.assertEqual(res.response_count, 1)

    def test_bidirectional(self):
        responses, res = self.iface.stream(
            "svc", "B", [{"fwd": "a"}, {"fwd": "b"}], seq=3
        )
        self.assertEqual(responses, ({"back": "a"}, {"back": "b"}))
        self.assertEqual(res.method_type, BIDIRECTIONAL)

    def test_unary_via_stream_refused(self):
        self.iface.register("svc", "U", MethodType.UNARY, unary_echo, seq=9)
        with self.assertRaises(StreamingCallError):
            self.iface.stream("svc", "U", [{"x": 1}], seq=10)

    def test_stream_unknown_method(self):
        with self.assertRaises(UnknownMethodError):
            self.iface.stream("svc", "Nope", [{"x": 1}], seq=3)

    def test_stream_empty_requests_refused(self):
        with self.assertRaises(ValueError):
            self.iface.stream("svc", "B", [], seq=3)

    def test_stream_bad_requests_type(self):
        with self.assertRaises(TypeError):
            self.iface.stream("svc", "B", {"not": "a-list"}, seq=3)

    def test_stream_non_iterable_output_refused(self):
        self.iface.register("svc", "Bad", MethodType.BIDIRECTIONAL, lambda rs: 42, seq=9)
        with self.assertRaises(TypeError):
            self.iface.stream("svc", "Bad", [{"x": 1}], seq=10)

    def test_stream_empty_output_refused(self):
        self.iface.register(
            "svc", "Empty", MethodType.SERVER_STREAMING, lambda r: iter(()), seq=9
        )
        with self.assertRaises(ValueError):
            self.iface.stream("svc", "Empty", [{"x": 1}], seq=10)

    def test_stream_count(self):
        self.assertEqual(self.iface.stream_count(), 0)
        self.iface.stream("svc", "S", [{"name": "a", "count": 1}], seq=3)
        self.iface.stream("svc", "B", [{"fwd": "x"}], seq=4)
        self.assertEqual(self.iface.stream_count(), 2)

    def test_stream_result_as_dict(self):
        _, res = self.iface.stream("svc", "S", [{"name": "a", "count": 1}], seq=3)
        d = res.as_dict()
        self.assertEqual(d["method_type"], SERVER_STREAMING)
        self.assertEqual(d["response_count"], 1)
        self.assertEqual(d["schema"], SCHEMA_PIN)

    def test_thread_safety_smoke(self):
        errors = []

        def worker(n):
            try:
                self.iface.call("svc", "Nope-check", {"x": 1}, seq=n)
            except UnknownMethodError:
                pass
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])


class TestAudit(unittest.TestCase):
    def test_all_kinds(self):
        for kind in ("registered", "called", "streamed", "rejected"):
            ev = grpc_interface_audit_event(
                kind, seq=1, service="svc", method="M", code=CODE_OK
            )
            self.assertEqual(ev["event"], f"grpc-interface-{kind}")
            self.assertEqual(ev["audit_seq"], 1)
            self.assertEqual(ev["service"], "svc")
            self.assertEqual(ev["method"], "M")
            self.assertEqual(ev["schema"], SCHEMA_PIN)

    def test_bad_kind(self):
        with self.assertRaises(ValueError):
            grpc_interface_audit_event("fired", seq=1)

    def test_bad_seq(self):
        with self.assertRaises((TypeError, ValueError)):
            grpc_interface_audit_event("called", seq=-1)

    def test_custom_code(self):
        ev = grpc_interface_audit_event(
            "rejected", seq=2, code=CODE_FAILED_PRECONDITION
        )
        self.assertEqual(ev["code"], CODE_FAILED_PRECONDITION)
        self.assertNotIn("service", ev)

    def test_main(self):
        main()


if __name__ == "__main__":
    unittest.main()
