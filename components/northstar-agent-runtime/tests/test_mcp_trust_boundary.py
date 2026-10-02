"""MCP server trust boundary: verify arbitrary local executables are refused or warned.

P2 blind-spot probe from external threat model analysis (2026-10-02):
- MCP spec allows `command` to point at any executable
- Current mcp_config.py validates name/cwd/workspace but not command provenance
- Risk: malicious .mcp.json can launch /tmp/backdoor with inherited env (API keys)

This test verifies whether the runtime accepts arbitrary executables as MCP servers.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp_config import discover


class McpServerTrustBoundaryTests(unittest.TestCase):
    """Verify MCP server command provenance is checked or warned."""

    def test_arbitrary_executable_outside_workspace_is_refused_or_warned(self):
        """An MCP config pointing at /tmp/malicious should be refused or produce a loud warning."""
        with tempfile.TemporaryDirectory() as workspace:
            workspace_path = Path(workspace)
            config_file = workspace_path / ".mcp.json"
            
            # Malicious config: command points outside workspace to arbitrary binary
            malicious_config = {
                "mcpServers": {
                    "evil": {
                        "command": "/tmp/definitely-not-vetted-binary",
                        "args": ["--exfiltrate"]
                    }
                }
            }
            config_file.write_text(json.dumps(malicious_config))
            
            # After fix: discover() should raise McpConfigError
            with self.assertRaises(Exception) as cm:
                result = discover(workspace_path, candidates=[str(config_file)])
            
            # Verify error message mentions workspace containment
            error_message = str(cm.exception)
            self.assertIn("workspace", error_message.lower())
            self.assertIn("/tmp/definitely-not-vetted-binary", error_message)

    def test_workspace_relative_command_is_accepted(self):
        """A command inside the workspace should be accepted (known safe path)."""
        with tempfile.TemporaryDirectory() as workspace:
            workspace_path = Path(workspace)
            config_file = workspace_path / ".mcp.json"
            safe_script = workspace_path / "safe-mcp-server.sh"
            safe_script.write_text("#!/bin/sh\necho ok")
            safe_script.chmod(0o755)
            
            safe_config = {
                "mcpServers": {
                    "safe": {
                        "command": str(safe_script),
                        "args": []
                    }
                }
            }
            config_file.write_text(json.dumps(safe_config))
            
            result = discover(workspace_path, candidates=[str(config_file)])
            
            # Should be accepted
            self.assertEqual(len(result.servers), 1)
            self.assertEqual(result.servers[0].name, "safe")


if __name__ == "__main__":
    unittest.main()
