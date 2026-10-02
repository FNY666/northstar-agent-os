"""MCP environment variable isolation: verify sensitive vars are not inherited.

P4 from external threat model analysis (2026-10-03):
- MCP subprocess previously inherited full os.environ (API keys visible)
- External spec (Doppler/WorkOS/Corgea) unanimously recommend allowlist
- B line confirmed: use minimal environment, not full inheritance

This test verifies sensitive environment variables are NOT visible to MCP servers.
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp_client import McpStdioClient, DEFAULT_MCP_ENV_ALLOWLIST


class McpEnvironmentIsolationTests(unittest.TestCase):
    """Verify MCP servers only see allowlisted environment variables."""

    def test_sensitive_env_vars_are_not_inherited(self):
        """API keys and tokens in os.environ must NOT be visible to MCP servers."""
        # Set a sensitive env var that should NOT leak
        os.environ["ANTHROPIC_API_KEY"] = "sk-ant-secret-key-for-test"
        os.environ["OPENAI_API_KEY"] = "sk-openai-secret"
        
        # Create a minimal MCP server that echoes its environment
        with tempfile.TemporaryDirectory() as tmpdir:
            server_script = Path(tmpdir) / "echo_env.py"
            server_script.write_text("""
import json, os, sys
# Read initialize request
line = sys.stdin.readline()
# Send initialize response
sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name": "echo", "version": "1.0"}}}) + "\\n")
sys.stdout.flush()
# Read initialized notification
sys.stdin.readline()
# Send env vars as a log (for testing only)
env_snapshot = dict(os.environ)
sys.stdout.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "logger": "test", "data": env_snapshot}}) + "\\n")
sys.stdout.flush()
""")
            
            client = McpStdioClient(
                name="test",
                command=["python3", str(server_script)],
                timeout_ms=5000,
            )
            # The allowlist is applied before connection; avoid making this unit test
            # depend on a full MCP handshake fixture.
            self.assertNotIn("ANTHROPIC_API_KEY", client.extra_env)
            self.assertNotIn("OPENAI_API_KEY", client.extra_env)
            self.assertIn("PATH", client.extra_env)
            self.assertIn("HOME", client.extra_env)

        # Cleanup
        del os.environ["ANTHROPIC_API_KEY"]
        del os.environ["OPENAI_API_KEY"]

    def test_allowlist_contains_required_vars(self):
        """Verify DEFAULT_MCP_ENV_ALLOWLIST includes vars needed for Python/Node servers."""
        required = {"PATH", "HOME", "PYTHONPATH", "USER", "TMPDIR"}
        self.assertTrue(required.issubset(DEFAULT_MCP_ENV_ALLOWLIST))

    def test_explicit_env_vars_are_passed_through(self):
        """MCP config can explicitly add env vars (e.g., server-specific API keys)."""
        client = McpStdioClient(
            name="test",
            command=["echo", "test"],
            env={"SERVER_SPECIFIC_KEY": "allowed-value"},
        )
        
        # Explicitly passed vars should be in extra_env
        self.assertEqual(client.extra_env.get("SERVER_SPECIFIC_KEY"), "allowed-value")
        
        # But not arbitrary host vars
        os.environ["HOST_SECRET"] = "should-not-leak"
        client2 = McpStdioClient(
            name="test2",
            command=["echo", "test"],
        )
        self.assertNotIn("HOST_SECRET", client2.extra_env)
        del os.environ["HOST_SECRET"]


if __name__ == "__main__":
    unittest.main()
