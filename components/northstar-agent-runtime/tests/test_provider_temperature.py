"""The provider must send ``temperature`` only when it was asked to.

The evaluation conditions are only reproducible if the sampling temperature
can be pinned, and they must stay unchanged for callers that never asked
for one.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

RUNTIME = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class _CapturingHandler(BaseHTTPRequestHandler):
    payloads: list[dict] = []

    def log_message(self, *args):  # noqa: D102 - silence the test output
        pass

    def do_POST(self):  # noqa: N802 - the http.server API names it this way
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        type(self).payloads.append(json.loads(body.decode()))
        data = json.dumps({
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "created": 1,
            "model": "test-model",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "done"},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class ProviderTemperatureTests(unittest.TestCase):
    def _run(self, extra_args: list[str]) -> list[dict]:
        handler = type("Handler", (_CapturingHandler,), {"payloads": []})
        server = HTTPServer(("127.0.0.1", 0), handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            environment = dict(os.environ)
            environment["OPENAI_API_KEY"] = "test-key"
            environment["OPENAI_BASE_URL"] = f"http://127.0.0.1:{port}/v1"
            subprocess.run(
                [
                    sys.executable, "-m", "cli", "run",
                    "--provider", "openai",
                    "--model", "test-model",
                    "--max-turns", "1",
                    "--prompt", "say done",
                    "--json",
                    "--no-policy-file", "--no-workspace-agents",
                    "--no-skills", "--no-memory", "--no-plugins",
                    *extra_args,
                ],
                cwd=RUNTIME, env=environment,
                capture_output=True, text=True, timeout=120,
            )
        finally:
            server.shutdown()
        return handler.payloads

    def test_temperature_is_sent_when_requested(self):
        payloads = self._run(["--temperature", "0"])
        self.assertTrue(payloads, "the endpoint was never called")
        self.assertEqual(payloads[0].get("temperature"), 0)

    def test_no_temperature_is_sent_when_it_was_not_requested(self):
        payloads = self._run([])
        self.assertTrue(payloads, "the endpoint was never called")
        self.assertNotIn("temperature", payloads[0])


if __name__ == "__main__":
    unittest.main()
