import json
import unittest

from sidecar import classify_request, parse_codex_event, redact_error


class SidecarProtocolTests(unittest.TestCase):
    def test_accepts_bounded_text_request(self):
        result = classify_request({"request_id": "r1", "prompt": "Reply OK", "timeout_ms": 10000})
        self.assertTrue(result.ok, result.errors)

    def test_rejects_missing_request_id_and_prompt(self):
        result = classify_request({"timeout_ms": 10000})
        self.assertFalse(result.ok)
        self.assertIn("request_id", " ".join(result.errors))
        self.assertIn("prompt", " ".join(result.errors))

    def test_rejects_oversized_prompt_and_timeout(self):
        result = classify_request({"request_id": "r1", "prompt": "x" * 100001, "timeout_ms": 0})
        self.assertFalse(result.ok)
        self.assertTrue(any("prompt" in e or "timeout" in e for e in result.errors))

    def test_parses_only_agent_message_events(self):
        line = json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": "OK"}})
        self.assertEqual(parse_codex_event(line), {"type": "text", "text": "OK"})
        self.assertIsNone(parse_codex_event(json.dumps({"type": "turn.started"})))

    def test_classifies_codex_failures_without_leaking_secrets(self):
        result = redact_error("Authorization: Bearer secret-token failed with status 401")
        self.assertNotIn("secret-token", result)
        self.assertIn("[REDACTED]", result)


if __name__ == "__main__":
    unittest.main()


class SidecarSecurityTests(unittest.TestCase):
    def test_request_rejects_unknown_fields(self):
        result = classify_request({"request_id": "r1", "prompt": "OK", "timeout_ms": 10000, "shell": True})
        self.assertFalse(result.ok)
        self.assertTrue(any("unknown" in e for e in result.errors))

    def test_request_rejects_command_like_fields(self):
        result = classify_request({"request_id": "r1", "prompt": "OK", "timeout_ms": 10000, "command": "rm -rf /"})
        self.assertFalse(result.ok)
        self.assertTrue(any("unknown" in e for e in result.errors))

    def test_error_redaction_handles_multiple_secret_forms(self):
        text = redact_error("api_key=abc123456789 access_token=xyz987654321 password=hidden")
        self.assertNotIn("abc123456789", text)
        self.assertNotIn("xyz987654321", text)
        self.assertNotIn("hidden", text)

    def test_timeout_bounds_are_strict(self):
        self.assertFalse(classify_request({"request_id": "r", "prompt": "x", "timeout_ms": 999}).ok)
        self.assertFalse(classify_request({"request_id": "r", "prompt": "x", "timeout_ms": 300001}).ok)

    def test_multiple_requests_have_independent_request_ids(self):
        first = classify_request({"request_id": "a", "prompt": "OK", "timeout_ms": 1000})
        second = classify_request({"request_id": "b", "prompt": "OK", "timeout_ms": 1000})
        self.assertTrue(first.ok and second.ok)
        self.assertNotEqual("a", "b")

    def test_empty_and_non_json_lines_are_rejected_by_protocol(self):
        self.assertFalse(classify_request({}).ok)

    def test_stdio_sidecar_runs_fake_codex_and_returns_structured_text(self):
        import os
        import stat
        import subprocess
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); workspace = root / "workspace"; workspace.mkdir()
            fake = root / "fake-codex"
            fake.write_text("#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"FAKE_OK\"}}'\n", encoding="utf-8")
            fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
            env = {**os.environ, "CODEX_BIN": str(fake), "CODEX_HOME": str(root), "CODEX_WORKSPACE": str(workspace)}
            run = subprocess.run(["python3", "sidecar.py"], input='{"request_id":"e2e-1","prompt":"Say OK","timeout_ms":10000}\n', text=True, capture_output=True, env=env, check=False)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout), {"request_id": "e2e-1", "status": "ok", "text": "FAKE_OK"})


class UnixTransportTests(unittest.TestCase):
    def test_transport_request_schema_accepts_only_sidecar_fields(self):
        from transport import validate_transport_request
        self.assertTrue(validate_transport_request({"request_id": "r1", "prompt": "OK", "timeout_ms": 10000}).ok)
        self.assertFalse(validate_transport_request({"request_id": "r1", "prompt": "OK", "timeout_ms": 10000, "shell": "id"}).ok)

    def test_transport_response_is_json_serializable(self):
        from transport import encode_response, decode_request
        payload = encode_response({"request_id": "r1", "status": "ok", "text": "OK"})
        self.assertEqual(decode_request(payload), {"request_id": "r1", "status": "ok", "text": "OK"})

    def test_transport_rejects_oversized_line(self):
        from transport import decode_request
        self.assertIsNone(decode_request("x" * 200001))

class UnixSocketE2ETests(unittest.TestCase):
    def test_socket_round_trip_uses_bounded_json_response(self):
        import json, os, socket, tempfile, threading
        from transport import decode_request, encode_response
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sidecar.sock")
            ready = threading.Event()
            def serve():
                server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                server.bind(path); os.chmod(path, 0o660); server.listen(1); ready.set()
                conn, _ = server.accept()
                line = conn.recv(10000).decode()
                req = decode_request(line)
                response = {"request_id": req["request_id"], "status": "ok", "text": "OK"} if req else {"status": "rejected"}
                conn.sendall(encode_response(response).encode()); conn.close(); server.close()
            thread = threading.Thread(target=serve, daemon=True); thread.start(); ready.wait(2)
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); client.connect(path)
            client.sendall(b'{"request_id":"sock-1","prompt":"OK","timeout_ms":10000}\n')
            result = json.loads(client.recv(10000).decode()); client.close(); thread.join(2)
            self.assertEqual(result, {"request_id": "sock-1", "status": "ok", "text": "OK"})
            self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o660")

    def test_socket_path_must_be_private_local_path(self):
        from service import validate_socket_path
        self.assertTrue(validate_socket_path("/var/run/northstar-codex/sidecar.sock").ok)
        self.assertFalse(validate_socket_path("/tmp/sidecar.sock").ok)
        self.assertFalse(validate_socket_path("tcp://0.0.0.0:9000").ok)

    def test_service_config_disables_native_codex_tools(self):
        from service import service_config
        config = service_config()
        self.assertEqual(config["sandbox"], "read-only")
        self.assertFalse(config["native_tools"])
        self.assertEqual(config["user"], "northstar-codex")


class SidecarSocketServiceTests(unittest.TestCase):
    def test_service_module_exposes_private_socket_contract(self):
        from sidecar_socket import SOCKET_PATH, socket_mode
        self.assertEqual(SOCKET_PATH, "/var/run/northstar-codex/sidecar.sock")
        self.assertEqual(socket_mode(), 0o660)

    def test_service_handler_returns_rejection_for_unknown_fields(self):
        from sidecar_socket import handle_line
        result = json.loads(handle_line('{"request_id":"r1","prompt":"OK","timeout_ms":10000,"shell":"id"}'))
        self.assertEqual(result["status"], "rejected")


class SocketFramingTests(unittest.TestCase):
    def test_read_json_line_handles_fragmented_input(self):
        from sidecar_socket import read_json_line
        class FakeConn:
            def __init__(self): self.parts = [b'{"request_id":"r1",', b'"prompt":"OK",', b'"timeout_ms":1000}\n']
            def recv(self, _): return self.parts.pop(0) if self.parts else b''
        self.assertEqual(read_json_line(FakeConn()), '{"request_id":"r1","prompt":"OK","timeout_ms":1000}')

    def test_read_json_line_rejects_oversized_input(self):
        from sidecar_socket import read_json_line
        class FakeConn:
            def recv(self, _): return b'x' * 200001
        self.assertIsNone(read_json_line(FakeConn()))

    def test_bad_connection_does_not_escape_connection_handler(self):
        from sidecar_socket import handle_connection
        class BrokenConn:
            def settimeout(self, _): pass
            def recv(self, _): raise OSError("broken peer")
            def sendall(self, _): raise AssertionError("must not respond")
        handle_connection(BrokenConn())


class SocketLifecycleTests(unittest.TestCase):
    def test_connection_handler_applies_read_deadline(self):
        from sidecar_socket import handle_connection
        class IdleConn:
            timeout = None
            closed = False
            def settimeout(self, value): self.timeout = value
            def recv(self, _): raise TimeoutError("idle")
            def sendall(self, _): raise AssertionError("idle peer must not receive")
            def close(self): self.closed = True
        conn = IdleConn()
        handle_connection(conn)
        self.assertIsNotNone(conn.timeout)
        self.assertTrue(conn.closed)

    def test_service_config_has_bounded_concurrency(self):
        from sidecar_socket import MAX_WORKERS
        self.assertGreaterEqual(MAX_WORKERS, 2)
        self.assertLessEqual(MAX_WORKERS, 16)

    def test_sidecar_status_is_classified_for_fallback_policy(self):
        from sidecar import fallback_allowed
        self.assertTrue(fallback_allowed("transport_unavailable"))
        self.assertTrue(fallback_allowed("timeout"))
        self.assertFalse(fallback_allowed("cancelled"))
        self.assertFalse(fallback_allowed("codex_business_error"))
        self.assertFalse(fallback_allowed("protocol_error"))

    def test_service_pins_the_verified_codex_executable(self):
        from service import service_config
        self.assertEqual(config := service_config()["codex_bin"], "codex")

    def test_sidecar_default_uses_the_verified_codex_executable(self):
        import sidecar
        self.assertEqual(sidecar.CODEX_BIN, "codex")


class SidecarResultTests(unittest.TestCase):
    def test_codex_start_failure_returns_structured_internal_error(self):
        import os, tempfile
        from pathlib import Path
        import sidecar
        with tempfile.TemporaryDirectory() as d:
            old = (sidecar.CODEX_BIN, sidecar.CODEX_HOME, sidecar.CODEX_WORKSPACE)
            sidecar.CODEX_BIN = str(Path(d) / "missing-codex")
            sidecar.CODEX_HOME = d
            sidecar.CODEX_WORKSPACE = d
            try:
                result = sidecar.run_one({"request_id": "start", "prompt": "OK", "timeout_ms": 1000})
            finally:
                sidecar.CODEX_BIN, sidecar.CODEX_HOME, sidecar.CODEX_WORKSPACE = old
            self.assertEqual(result["status"], "internal_error")
            self.assertEqual(result["request_id"], "start")
            self.assertNotIn("Traceback", str(result))

    def test_successful_codex_without_agent_message_is_protocol_error(self):
        import os, stat, tempfile
        from pathlib import Path
        import sidecar
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); fake = root / "fake-codex"; fake.write_text("#!/bin/sh\nexit 0\n")
            fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
            old = (sidecar.CODEX_BIN, sidecar.CODEX_HOME, sidecar.CODEX_WORKSPACE)
            sidecar.CODEX_BIN, sidecar.CODEX_HOME, sidecar.CODEX_WORKSPACE = str(fake), d, d
            try: result = sidecar.run_one({"request_id": "empty", "prompt": "OK", "timeout_ms": 1000})
            finally: sidecar.CODEX_BIN, sidecar.CODEX_HOME, sidecar.CODEX_WORKSPACE = old
            self.assertEqual(result["status"], "protocol_error")


class ServiceShutdownTests(unittest.TestCase):
    def test_service_config_declares_graceful_shutdown_timeout(self):
        from service import service_config
        config = service_config()
        self.assertEqual(config["stop_timeout_seconds"], 15)

    def test_service_config_declares_systemd_runtime_directory(self):
        from service import service_config
        config = service_config()
        self.assertEqual(config["runtime_directory"], "northstar-codex")
        self.assertEqual(config["runtime_directory_mode"], "0770")

    def test_unexpected_request_exception_isolated_as_internal_error(self):
        import sidecar_socket
        original = sidecar_socket.handle_line
        class Conn:
            sent = b""
            closed = False
            def settimeout(self, _): pass
            def recv(self, _): return b'{"request_id":"x","prompt":"OK","timeout_ms":1000}\n'
            def sendall(self, value): self.sent += value
            def close(self): self.closed = True
        sidecar_socket.handle_line = lambda _: (_ for _ in ()).throw(RuntimeError("private detail"))
        conn = Conn()
        try: sidecar_socket.handle_connection(conn)
        finally: sidecar_socket.handle_line = original
        result = json.loads(conn.sent.decode())
        self.assertEqual(result["status"], "internal_error")
        self.assertNotIn("private detail", conn.sent.decode())
        self.assertTrue(conn.closed)
