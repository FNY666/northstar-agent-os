import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath

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


UNIT_FILE = Path(__file__).resolve().parents[1] / "northstar-codex-sidecar.service"
COMPONENT_DIR = Path(__file__).resolve().parents[1]

FAKE_CODEX_ENV_PROBE = """#!/bin/sh
cat >/dev/null
{ printf 'CODEX_HOME=%s\\nHOME=%s\\nCODEX_WORKSPACE_CWD=%s\\n' "$CODEX_HOME" "$HOME" "$(pwd)"; } > __PROBE__
printf '%s\\n' '{"type":"item.completed","item":{"type":"agent_message","text":"PROBED"}}'
"""


def write_env_probing_fake_codex(directory):
    """Return a fake codex that records the environment the sidecar gave it."""
    probe = directory / "child-env.txt"
    fake = directory / "fake-codex"
    fake.write_text(FAKE_CODEX_ENV_PROBE.replace("__PROBE__", str(probe)), encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    return fake, probe


def parse_unit_environment(unit_path):
    values = {}
    for line in Path(unit_path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("Environment="):
            key, _, value = line[len("Environment="):].partition("=")
            values[key.strip()] = value.strip()
    return values


class CodexHomeContractTests(unittest.TestCase):
    """The sidecar must hand Codex the configured CODEX_HOME verbatim."""

    def test_child_receives_codex_home_without_nested_suffix(self):
        import sidecar
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            fake, probe = write_env_probing_fake_codex(root)
            configured = root / "codex-home"
            old = (sidecar.CODEX_BIN, sidecar.CODEX_HOME, sidecar.CODEX_WORKSPACE)
            sidecar.CODEX_BIN, sidecar.CODEX_HOME, sidecar.CODEX_WORKSPACE = str(fake), str(configured), str(root)
            try:
                result = sidecar.run_one({"request_id": "home", "prompt": "OK", "timeout_ms": 5000})
            finally:
                sidecar.CODEX_BIN, sidecar.CODEX_HOME, sidecar.CODEX_WORKSPACE = old
            self.assertEqual(result["status"], "ok", result)
            child = dict(line.split("=", 1) for line in probe.read_text(encoding="utf-8").splitlines())
            self.assertEqual(child["CODEX_HOME"], str(configured))
            self.assertEqual(child["HOME"], str(configured))
            self.assertNotIn("codex-home/codex-home", child["CODEX_HOME"])

    def test_systemd_unit_environment_yields_an_unnested_codex_home(self):
        """Regression: the unit's CODEX_HOME used to gain a second /codex-home."""
        unit_env = parse_unit_environment(UNIT_FILE)
        self.assertIn("CODEX_HOME", unit_env)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            fake, probe = write_env_probing_fake_codex(root)
            env = dict(unit_env)
            env["CODEX_BIN"] = str(fake)
            env["CODEX_WORKSPACE"] = str(root)
            env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
            run = subprocess.run(
                [sys.executable, "sidecar.py"],
                input='{"request_id":"unit-1","prompt":"OK","timeout_ms":5000}\n',
                text=True, capture_output=True, env=env, cwd=str(COMPONENT_DIR), check=False,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout)["status"], "ok")
            child = dict(line.split("=", 1) for line in probe.read_text(encoding="utf-8").splitlines())
        self.assertEqual(child["CODEX_HOME"], unit_env["CODEX_HOME"])
        self.assertNotIn("codex-home/codex-home", child["CODEX_HOME"])

    def test_unit_environment_agrees_with_the_static_service_contract(self):
        from service import service_config
        config = service_config()
        unit_env = parse_unit_environment(UNIT_FILE)
        self.assertEqual(unit_env["CODEX_HOME"], config["codex_home"])
        self.assertEqual(unit_env["CODEX_WORKSPACE"], config["workspace"])
        self.assertEqual(unit_env["CODEX_BIN"], config["codex_bin"])

    def test_workspace_default_is_not_inside_codex_home(self):
        from service import service_config
        config = service_config()
        self.assertFalse(
            config["workspace"].startswith(config["codex_home"] + "/"),
            "run inputs must not share a directory with Codex credentials",
        )

    def test_module_defaults_match_the_service_contract_with_a_clean_environment(self):
        from service import service_config
        clean = {k: v for k, v in os.environ.items() if not k.startswith("CODEX_")}
        run = subprocess.run(
            [sys.executable, "-c", "import sidecar; print(sidecar.CODEX_HOME); print(sidecar.CODEX_WORKSPACE)"],
            text=True, capture_output=True, env=clean, cwd=str(COMPONENT_DIR), check=True,
        )
        codex_home, workspace = run.stdout.splitlines()[:2]
        config = service_config()
        self.assertEqual(codex_home, config["codex_home"])
        self.assertEqual(workspace, config["workspace"])


class TransportBoundTests(unittest.TestCase):
    """The socket byte cap must never bind before the request validator."""

    def test_any_request_the_validator_accepts_fits_the_wire_cap(self):
        from sidecar import MAX_PROMPT_CHARS
        from transport import MAX_LINE_BYTES
        for char, label in (("a", "ascii"), ("\u6d4b", "cjk-bmp"), ("\U0001F600", "astral")):
            prompt = char * MAX_PROMPT_CHARS
            request = {"request_id": "r" * 128, "prompt": prompt, "timeout_ms": 300_000}
            self.assertTrue(classify_request(request).ok, request and label)
            for ensure_ascii in (False, True):
                wire = json.dumps(request, ensure_ascii=ensure_ascii).encode()
                self.assertLessEqual(
                    len(wire), MAX_LINE_BYTES,
                    f"{label} ensure_ascii={ensure_ascii}: {len(wire)} bytes exceeds cap {MAX_LINE_BYTES}",
                )

    def test_socket_reader_accepts_a_full_size_cjk_prompt(self):
        from sidecar_socket import read_json_line
        prompt = "\u6d4b" * 100_000
        wire = json.dumps({"request_id": "r", "prompt": prompt, "timeout_ms": 10_000}, ensure_ascii=False).encode() + b"\n"

        class ChunkedConn:
            def __init__(self): self.buffer = wire
            def recv(self, size):
                chunk, self.buffer = self.buffer[:size], self.buffer[size:]
                return chunk

        line = read_json_line(ChunkedConn())
        self.assertIsNotNone(line, "a documented-maximum CJK prompt must survive framing")
        self.assertEqual(json.loads(line)["prompt"], prompt)

    def test_socket_reader_still_rejects_input_beyond_the_byte_cap(self):
        from sidecar_socket import read_json_line
        from transport import MAX_LINE_BYTES

        class EndlessConn:
            def recv(self, _): return b"x" * 8192

        conn = EndlessConn()
        self.assertIsNone(read_json_line(conn))
        self.assertGreater(MAX_LINE_BYTES, 0)

    def test_full_size_cjk_prompt_survives_a_real_unix_socket_round_trip(self):
        import service, sidecar_socket, threading, time
        from service import validate_socket_path
        with tempfile.TemporaryDirectory() as d:
            root = PurePosixPath(d)
            path = str(root / "sidecar.sock")
            original_root = service.SOCKET_ROOT
            service.SOCKET_ROOT = root
            original_bin = sidecar_socket.run_one
            sidecar_socket.run_one = lambda request: {"request_id": request.get("request_id"), "status": "ok",
                                                     "chars": len(request.get("prompt", ""))}
            try:
                threading.Thread(target=sidecar_socket.serve, args=(path,), daemon=True).start()
                for _ in range(200):
                    if os.path.exists(path): break
                    time.sleep(0.05)
                self.assertTrue(validate_socket_path(path).ok)
                prompt = "\u6d4b" * 100_000
                wire = json.dumps({"request_id": "cjk", "prompt": prompt, "timeout_ms": 10_000}, ensure_ascii=False).encode()
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.settimeout(30); client.connect(path)
                buffer = b""
                try:
                    client.sendall(wire + b"\n")
                except OSError:
                    pass
                while b"\n" not in buffer:
                    chunk = client.recv(65536)
                    if not chunk: break
                    buffer += chunk
                client.close()
            finally:
                service.SOCKET_ROOT = original_root
                sidecar_socket.run_one = original_bin
            self.assertEqual(json.loads(buffer.decode()), {"request_id": "cjk", "status": "ok", "chars": 100_000})


class SocketPathEnforcementTests(unittest.TestCase):
    """service.validate_socket_path must gate the listener, not just the tests."""

    def attempt_serve(self, path, deadline=5.0):
        """Run serve() off-thread so a missing guard fails fast instead of hanging.

        self.serve resolves sidecar_socket.serve at call time, so removing the
        guard turns this into a clean assertion failure rather than a test that
        blocks on accept() forever.
        """
        import threading
        outcome = {}

        def run():
            try:
                self.serve(path)
            except BaseException as exc:  # noqa: BLE001 - the test asserts on the type
                outcome["error"] = exc

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(deadline)
        return outcome.get("error")

    def serve(self, path):
        from sidecar_socket import serve
        return serve(path)

    def test_serve_refuses_a_socket_outside_the_runtime_directory(self):
        stray = os.path.join(tempfile.gettempdir(), "northstar-stray-sidecar.sock")
        if os.path.exists(stray): os.unlink(stray)
        try:
            error = self.attempt_serve(stray)
            self.assertIsInstance(
                error, ValueError,
                "serve() must refuse an out-of-contract path instead of opening a listener",
            )
            self.assertIn("private sidecar runtime directory", str(error))
            self.assertFalse(os.path.exists(stray), "serve() must refuse before binding")
        finally:
            if os.path.exists(stray): os.unlink(stray)

    def test_serve_refuses_a_wrong_socket_filename(self):
        error = self.attempt_serve("/var/run/northstar-codex/public.sock")
        self.assertIsInstance(error, ValueError, "serve() must refuse a non-canonical socket filename")
        self.assertIn("sidecar.sock", str(error))

    def test_default_socket_path_satisfies_the_contract(self):
        from sidecar_socket import SOCKET_PATH
        from service import validate_socket_path
        self.assertTrue(validate_socket_path(SOCKET_PATH).ok, validate_socket_path(SOCKET_PATH).errors)


class InstallScriptTests(unittest.TestCase):
    """install.sh must leave the host able to start the unit."""

    def setUp(self):
        self.script = (COMPONENT_DIR / "install.sh").read_text(encoding="utf-8")
        self.rollback = (COMPONENT_DIR / "rollback.sh").read_text(encoding="utf-8")
        self.unit = parse_unit_environment(UNIT_FILE)

    def test_install_creates_the_service_account_the_unit_runs_as(self):
        self.assertIn("User=northstar-codex", (COMPONENT_DIR / "northstar-codex-sidecar.service").read_text())
        self.assertRegex(self.script, r"useradd|adduser")
        self.assertIn("northstar-codex", self.script)

    def test_install_creates_every_directory_the_unit_marks_writable(self):
        unit = (COMPONENT_DIR / "northstar-codex-sidecar.service").read_text(encoding="utf-8")
        readable = [line for line in unit.splitlines() if line.startswith("ReadWritePaths=")]
        self.assertTrue(readable, "unit declares ReadWritePaths")
        for path in readable[0][len("ReadWritePaths="):].split():
            if path.startswith("/var/lib/"):
                self.assertIn("/var/lib/northstar-codex", self.script)

    def test_install_creates_the_codex_home_and_workspace_the_sidecar_expects(self):
        from service import service_config
        config = service_config()
        for directory in (config["codex_home"], config["workspace"]):
            self.assertTrue(
                any(part in self.script for part in (directory, directory.rsplit("/", 1)[-1])),
                f"install.sh does not create {directory}",
            )

    def test_install_refuses_to_run_without_root(self):
        self.assertIn("id -u", self.script)

    def test_install_is_idempotent_for_an_existing_service_account(self):
        self.assertRegex(self.script, r"id -u \"\$SERVICE_USER\"")

    def test_rollback_preserves_codex_login_state(self):
        self.assertNotIn("rm -rf /var/lib/northstar-codex", self.rollback)
        self.assertIn("preserved", self.rollback)
